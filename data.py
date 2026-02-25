from pathlib import Path
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"
SESSION_TIMEOUT_MINUTES = 5
ACTIVE_DEVICE_WINDOW_MINUTES = 5
FAILED_LOGIN_WINDOW_MINUTES = 10
FAILED_LOGIN_THRESHOLD = 7
IP_BLOCK_DURATION_MINUTES = 15
LOCAL_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost"}
AUTH_ACCESS_LOG_LIMIT = 300

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = "your-secret-key-here"
app.permanent_session_lifetime = timedelta(minutes=SESSION_TIMEOUT_MINUTES)


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    with get_db() as db:
        cur = db.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'FAILED')),
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS active_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username, ip_address)
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_login_logs_ip_status_time
            ON login_logs(ip_address, status, timestamp)
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_active_devices_last_seen
            ON active_devices(last_seen)
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_access_logs_time
            ON auth_access_logs(timestamp)
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_auth_access_logs_user
            ON auth_access_logs(username)
            """
        )

        users = [
            ("123", "123"),
            ("admin", "admin1"),
            ("venkat", "venkat11"),
            ("bharath", "bharath123"),
            ("sonu", "sonu123"),
            ("hari", "hari123"),
            ("venky", "venky123"),
            ("viewer1", "view123"),
            ("viewer2", "view234"),
            ("guest", "guest123"),
        ]

        for username, password in users:
            hashed = generate_password_hash(password)
            try:
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hashed),
                )
            except sqlite3.IntegrityError:
                pass

        db.commit()


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def record_login_event(username, ip_address, status):
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO login_logs (username, ip_address, status)
                VALUES (?, ?, ?)
                """,
                (username or "unknown", ip_address, status),
            )
            db.commit()
    except sqlite3.Error:
        pass


def record_auth_access_event(username, ip_address, event_type, endpoint, status, details):
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO auth_access_logs
                (username, ip_address, event_type, endpoint, status, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    (username or "anonymous")[:100],
                    (ip_address or "unknown")[:64],
                    (event_type or "UNKNOWN_EVENT")[:64],
                    (endpoint or "unknown")[:128],
                    (status or "UNKNOWN")[:32],
                    (details or "")[:300],
                ),
            )
            db.commit()
    except sqlite3.Error:
        pass


def touch_active_device(username, ip_address):
    if not username or not ip_address:
        return
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute(
                """
                INSERT INTO active_devices (username, ip_address, last_seen)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username, ip_address)
                DO UPDATE SET last_seen=CURRENT_TIMESTAMP
                """,
                (username, ip_address),
            )
            db.commit()
    except sqlite3.Error:
        pass


def remove_active_device(username, ip_address):
    if not username or not ip_address:
        return
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute(
                """
                DELETE FROM active_devices
                WHERE username=? AND ip_address=?
                """,
                (username, ip_address),
            )
            db.commit()
    except sqlite3.Error:
        pass


def is_ip_blocked(ip_address):
    if not ip_address:
        return False
    if ip_address in LOCAL_LOOPBACK_IPS:
        return False
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, timestamp
            FROM blocked_ips
            WHERE ip_address=?
            """,
            (ip_address,),
        )
        row = cur.fetchone()
        if not row:
            return False

        cur.execute(
            """
            SELECT 1
            WHERE datetime(?) >= datetime('now', ?)
            """,
            (row[1], f"-{IP_BLOCK_DURATION_MINUTES} minutes"),
        )
        still_blocked = cur.fetchone() is not None
        if still_blocked:
            return True

        # Auto-expire old blocks so users can log in again after cooldown.
        cur.execute("DELETE FROM blocked_ips WHERE id=?", (row[0],))
        db.commit()
        return False


def block_ip_if_needed(ip_address, threshold=FAILED_LOGIN_THRESHOLD):
    if not ip_address or ip_address in LOCAL_LOOPBACK_IPS:
        return
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute("SELECT 1 FROM blocked_ips WHERE ip_address=?", (ip_address,))
            if cur.fetchone():
                return

            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE ip_address=?
                  AND status='FAILED'
                  AND timestamp >= datetime('now', ?)
                """,
                (ip_address, f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes"),
            )
            failed_attempts = cur.fetchone()[0]

            if failed_attempts >= threshold:
                reason = (
                    f"{failed_attempts} failed login attempts in "
                    f"{FAILED_LOGIN_WINDOW_MINUTES} minutes"
                )
                cur.execute(
                    """
                    INSERT OR IGNORE INTO blocked_ips (ip_address, reason)
                    VALUES (?, ?)
                    """,
                    (ip_address, reason),
                )
                db.commit()
    except sqlite3.Error:
        pass


def detect_active_threats(cur):
    threats = []
    blocked_pairs = set()

    # Critical threats: IPs that were auto-blocked after repeated failures.
    cur.execute(
        """
        SELECT
            b.ip_address,
            b.reason,
            b.timestamp,
            COALESCE(
                (
                    SELECT l.username
                    FROM login_logs l
                    WHERE l.ip_address = b.ip_address
                    ORDER BY l.id DESC
                    LIMIT 1
                ),
                'unknown'
            ) AS username
        FROM blocked_ips b
        ORDER BY b.id DESC
        LIMIT 25
        """
    )
    for ip_address, reason, timestamp, username in cur.fetchall():
        blocked_pairs.add((username, ip_address))
        threats.append(
            {
                "threat_name": "Brute Force Attack (Auto-Blocked)",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "critical",
                "description": reason,
                "detection_source": "Authentication Guard",
                "timestamp": timestamp,
            }
        )

    # Warning threats: repeated failures from same user/IP in recent window.
    cur.execute(
        """
        SELECT username, ip_address, COUNT(*) AS failed_count, MAX(timestamp) AS last_seen
        FROM login_logs
        WHERE status='FAILED'
          AND timestamp >= datetime('now', ?)
        GROUP BY username, ip_address
        HAVING COUNT(*) >= 3
        ORDER BY failed_count DESC, last_seen DESC
        LIMIT 25
        """,
        (f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes",),
    )
    for username, ip_address, failed_count, last_seen in cur.fetchall():
        if (username, ip_address) in blocked_pairs:
            continue
        threats.append(
            {
                "threat_name": "Repeated Failed Login Attempts",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "warn",
                "description": (
                    f"{failed_count} failed attempts in last "
                    f"{FAILED_LOGIN_WINDOW_MINUTES} minutes"
                ),
                "detection_source": "Login Behavior Analytics",
                "timestamp": last_seen,
            }
        )

    # Warning/critical threats: same user attacked from multiple IPs quickly.
    cur.execute(
        """
        SELECT username, COUNT(DISTINCT ip_address) AS ip_count, MAX(timestamp) AS last_seen
        FROM login_logs
        WHERE status='FAILED'
          AND timestamp >= datetime('now', ?)
        GROUP BY username
        HAVING COUNT(DISTINCT ip_address) >= 3
        ORDER BY ip_count DESC, last_seen DESC
        LIMIT 25
        """,
        (f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes",),
    )
    for username, ip_count, last_seen in cur.fetchall():
        cur.execute(
            """
            SELECT ip_address
            FROM login_logs
            WHERE username=?
              AND status='FAILED'
            ORDER BY id DESC
            LIMIT 1
            """,
            (username,),
        )
        latest_ip = cur.fetchone()
        ip_address = latest_ip[0] if latest_ip else "unknown"
        severity = "critical" if ip_count >= 5 else "warn"
        threats.append(
            {
                "threat_name": "Credential Stuffing Suspected",
                "ip_address": ip_address,
                "user_id": username,
                "severity": severity,
                "description": (
                    f"Failed attempts from {ip_count} IPs in last "
                    f"{FAILED_LOGIN_WINDOW_MINUTES} minutes"
                ),
                "detection_source": "Identity Risk Correlation",
                "timestamp": last_seen,
            }
        )

    # Keep only most recent/highest priority items for dashboard readability.
    threats.sort(
        key=lambda t: (
            1 if t.get("severity") == "critical" else 0,
            t.get("timestamp", ""),
        ),
        reverse=True,
    )

    unique_threats = []
    seen_keys = set()
    for threat in threats:
        threat_key = (
            threat.get("threat_name"),
            threat.get("user_id"),
            threat.get("ip_address"),
        )
        if threat_key in seen_keys:
            continue
        seen_keys.add(threat_key)
        unique_threats.append(threat)

    return unique_threats[:30]


def get_overview_data(log_limit=100, blocked_limit=100):
    with get_db() as db:
        cur = db.cursor()

        # Keep the table small; stale records are not treated as active.
        cur.execute(
            "DELETE FROM active_devices WHERE last_seen < datetime('now', '-1 day')"
        )
        cur.execute(
            """
            DELETE FROM blocked_ips
            WHERE timestamp < datetime('now', ?)
            """,
            (f"-{IP_BLOCK_DURATION_MINUTES} minutes",),
        )
        cur.execute(
            "DELETE FROM blocked_ips WHERE ip_address IN ('127.0.0.1', '::1', 'localhost')"
        )
        cur.execute(
            """
            DELETE FROM auth_access_logs
            WHERE id NOT IN (
                SELECT id FROM auth_access_logs ORDER BY id DESC LIMIT ?
            )
            """,
            (AUTH_ACCESS_LOG_LIMIT,),
        )

        cur.execute("SELECT COUNT(*) FROM auth_access_logs")
        total_events = cur.fetchone()[0]
        if total_events == 0:
            cur.execute("SELECT COUNT(*) FROM login_logs")
            total_events = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_ip_count = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM login_logs
            WHERE status='FAILED'
              AND timestamp >= datetime('now', ?)
            """,
            (f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes",),
        )
        recent_failed_attempts = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        active_devices = cur.fetchone()[0]

        cur.execute(
            """
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (log_limit,),
        )
        logs = cur.fetchall()
        if not logs:
            cur.execute(
                """
                SELECT id, username, ip_address, status, timestamp
                FROM login_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (log_limit,),
            )
            legacy_logs = cur.fetchall()
            logs = [
                (
                    row[0],
                    row[1],
                    row[2],
                    "AUTH_LOGIN",
                    "/login",
                    row[3],
                    "Legacy authentication record",
                    row[4],
                )
                for row in legacy_logs
            ]

        cur.execute(
            """
            SELECT id, ip_address, timestamp
            FROM blocked_ips
            ORDER BY id DESC
            LIMIT ?
            """,
            (blocked_limit,),
        )
        blocked = cur.fetchall()

        threats = detect_active_threats(cur)

    threat_alerts = len(threats)
    critical_threats = sum(1 for threat in threats if threat.get("severity") == "critical")
    warning_threats = sum(1 for threat in threats if threat.get("severity") == "warn")

    if critical_threats > 0:
        network_status = "NOT SECURE"
        network_status_note = f"{critical_threats} critical threat(s) detected"
        network_status_class = "critical"
    elif warning_threats > 0 or recent_failed_attempts >= 3:
        network_status = "AT RISK"
        if warning_threats > 0:
            network_status_note = f"{warning_threats} warning threat(s) under analysis"
        else:
            network_status_note = (
                f"{recent_failed_attempts} failed login attempts under analysis"
            )
        network_status_class = "warn"
    else:
        network_status = "SECURE"
        network_status_note = "No active breach"
        network_status_class = "ok"

    return {
        "total_events": total_events,
        "threat_alerts": threat_alerts,
        "active_devices": active_devices,
        "network_status": network_status,
        "network_status_note": network_status_note,
        "network_status_class": network_status_class,
        "recent_failed_attempts": recent_failed_attempts,
        "blocked_ip_count": blocked_ip_count,
        "threats": threats,
        "logs": logs,
        "blocked": blocked,
    }


def get_all_time_threat_alerts(limit=500):
    with get_db() as db:
        cur = db.cursor()
        alerts = []

        # Current blocked IP records are always high severity.
        cur.execute(
            """
            SELECT
                b.ip_address,
                b.reason,
                b.timestamp,
                COALESCE(
                    (
                        SELECT l.username
                        FROM login_logs l
                        WHERE l.ip_address = b.ip_address
                        ORDER BY l.id DESC
                        LIMIT 1
                    ),
                    'unknown'
                ) AS username
            FROM blocked_ips b
            ORDER BY b.id DESC
            LIMIT ?
            """,
            (limit,),
        )
        for ip_address, reason, timestamp, username in cur.fetchall():
            alerts.append(
                {
                    "threat_name": "Brute Force Attack (Auto-Blocked)",
                    "severity": "critical",
                    "user_id": username,
                    "ip_address": ip_address,
                    "description": reason,
                    "detection_source": "Authentication Guard",
                    "timestamp": timestamp,
                }
            )

        # Repeated failures from same user/IP across all available history.
        cur.execute(
            """
            SELECT
                username,
                ip_address,
                COUNT(*) AS failed_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM login_logs
            WHERE status='FAILED'
            GROUP BY username, ip_address
            HAVING COUNT(*) >= 3
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        for username, ip_address, failed_count, first_seen, last_seen in cur.fetchall():
            severity = "critical" if failed_count >= FAILED_LOGIN_THRESHOLD else "warn"
            alerts.append(
                {
                    "threat_name": "Repeated Failed Login Attempts",
                    "severity": severity,
                    "user_id": username,
                    "ip_address": ip_address,
                    "description": (
                        f"{failed_count} failed login attempts observed "
                        f"between {first_seen} and {last_seen}"
                    ),
                    "detection_source": "Historical Login Analytics",
                    "timestamp": last_seen,
                }
            )

        # Same account being attacked from many IPs in full history.
        cur.execute(
            """
            SELECT
                username,
                COUNT(*) AS failed_count,
                COUNT(DISTINCT ip_address) AS ip_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM login_logs
            WHERE status='FAILED'
            GROUP BY username
            HAVING COUNT(DISTINCT ip_address) >= 3
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        for username, failed_count, ip_count, first_seen, last_seen in cur.fetchall():
            cur.execute(
                """
                SELECT ip_address
                FROM login_logs
                WHERE username=?
                  AND status='FAILED'
                ORDER BY id DESC
                LIMIT 1
                """,
                (username,),
            )
            latest_ip = cur.fetchone()
            ip_address = latest_ip[0] if latest_ip else "unknown"
            severity = "critical" if ip_count >= 5 else "warn"
            alerts.append(
                {
                    "threat_name": "Credential Stuffing Pattern",
                    "severity": severity,
                    "user_id": username,
                    "ip_address": ip_address,
                    "description": (
                        f"{failed_count} failed logins from {ip_count} IPs "
                        f"between {first_seen} and {last_seen}"
                    ),
                    "detection_source": "Identity Risk Correlation",
                    "timestamp": last_seen,
                }
            )

        # Security-relevant denied/failed/error events from access logs.
        cur.execute(
            """
            SELECT username, ip_address, event_type, status, details, timestamp
            FROM auth_access_logs
            WHERE status IN ('FAILED', 'DENIED', 'ERROR')
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        for username, ip_address, event_type, status, details, timestamp in cur.fetchall():
            threat_name = event_type.replace("_", " ").title()
            if event_type == "AUTH_LOGIN":
                if status == "DENIED":
                    threat_name = "Login Blocked by Security Policy"
                elif status == "FAILED":
                    threat_name = "Failed Login Attempt"
                elif status == "ERROR":
                    threat_name = "Authentication Pipeline Error"
            elif event_type == "ACCESS_ADMIN_DASHBOARD" and status == "DENIED":
                threat_name = "Unauthorized Admin Dashboard Access"

            severity = "warn"
            if status == "ERROR":
                severity = "critical"
            elif status == "DENIED" and event_type.startswith("ACCESS_ADMIN"):
                severity = "critical"

            alerts.append(
                {
                    "threat_name": threat_name,
                    "severity": severity,
                    "user_id": username,
                    "ip_address": ip_address,
                    "description": details or "Security event recorded",
                    "detection_source": "Auth Access Logs",
                    "timestamp": timestamp,
                }
            )

    # Keep unique alerts while preserving rich historical entries.
    unique_alerts = []
    seen = set()
    for alert in alerts:
        alert_key = (
            alert.get("threat_name"),
            alert.get("user_id"),
            alert.get("ip_address"),
            alert.get("timestamp"),
            alert.get("description"),
        )
        if alert_key in seen:
            continue
        seen.add(alert_key)
        unique_alerts.append(alert)

    severity_order = {"critical": 2, "warn": 1, "info": 0}
    unique_alerts.sort(
        key=lambda alert: (
            alert.get("timestamp", ""),
            severity_order.get(alert.get("severity"), 0),
        ),
        reverse=True,
    )
    return unique_alerts[:limit]


def get_network_monitor_data(event_limit=150, suspicious_limit=12):
    with get_db() as db:
        cur = db.cursor()

        # Clear stale devices so live metrics stay accurate.
        cur.execute(
            "DELETE FROM active_devices WHERE last_seen < datetime('now', '-1 day')"
        )

        cur.execute(
            """
            SELECT COUNT(*)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        active_endpoints = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM login_logs
            WHERE status='FAILED'
              AND timestamp >= datetime('now', ?)
            """,
            (f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes",),
        )
        failed_attempts_recent = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM blocked_ips")
        blocked_ip_count = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 minute')
            """
        )
        events_per_minute = cur.fetchone()[0]
        if events_per_minute == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', '-1 minute')
                """
            )
            events_per_minute = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 hour')
            """
        )
        events_last_hour = cur.fetchone()[0]
        if events_last_hour == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', '-1 hour')
                """
            )
            events_last_hour = cur.fetchone()[0]

        cur.execute(
            """
            SELECT ip_address, COUNT(*) AS failed_count, MAX(timestamp) AS last_seen
            FROM login_logs
            WHERE status='FAILED'
              AND timestamp >= datetime('now', ?)
            GROUP BY ip_address
            HAVING COUNT(*) >= 2
            ORDER BY failed_count DESC, last_seen DESC
            LIMIT ?
            """,
            (f"-{FAILED_LOGIN_WINDOW_MINUTES} minutes", suspicious_limit),
        )
        noisy_ips = [
            {
                "ip_address": row[0],
                "failed_attempts": row[1],
                "last_seen": row[2],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (event_limit,),
        )
        recent_events = [
            {
                "id": row[0],
                "username": row[1],
                "ip_address": row[2],
                "event_type": row[3],
                "endpoint": row[4],
                "status": row[5],
                "details": row[6],
                "timestamp": row[7],
            }
            for row in cur.fetchall()
        ]
        if not recent_events:
            cur.execute(
                """
                SELECT id, username, ip_address, status, timestamp
                FROM login_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (event_limit,),
            )
            recent_events = [
                {
                    "id": row[0],
                    "username": row[1],
                    "ip_address": row[2],
                    "event_type": "AUTH_LOGIN",
                    "endpoint": "/login",
                    "status": row[3],
                    "details": "Legacy authentication record",
                    "timestamp": row[4],
                }
                for row in cur.fetchall()
            ]

    if blocked_ip_count > 0 or failed_attempts_recent >= FAILED_LOGIN_THRESHOLD:
        network_health = "CRITICAL"
        network_health_class = "critical"
        network_health_note = "Active blocking or high-volume failures detected"
    elif failed_attempts_recent >= 3 or noisy_ips:
        network_health = "AT RISK"
        network_health_class = "warn"
        network_health_note = "Suspicious login patterns require monitoring"
    else:
        network_health = "STABLE"
        network_health_class = "ok"
        network_health_note = "No critical network authentication anomalies"

    return {
        "active_endpoints": active_endpoints,
        "events_per_minute": events_per_minute,
        "events_last_hour": events_last_hour,
        "failed_attempts_recent": failed_attempts_recent,
        "blocked_ip_count": blocked_ip_count,
        "network_health": network_health,
        "network_health_class": network_health_class,
        "network_health_note": network_health_note,
        "noisy_ips": noisy_ips,
        "recent_events": recent_events,
    }


def get_endpoint_activity_data(event_limit=200, active_limit=200, summary_limit=250):
    with get_db() as db:
        cur = db.cursor()

        # Keep active device table fresh so "real-time" view is meaningful.
        cur.execute(
            "DELETE FROM active_devices WHERE last_seen < datetime('now', '-1 day')"
        )

        cur.execute("SELECT COUNT(*) FROM users")
        total_users = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(DISTINCT username)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        active_users = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        active_sessions_count = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(DISTINCT endpoint)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 hour')
            """
        )
        distinct_endpoints_last_hour = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 minute')
            """
        )
        events_per_minute = cur.fetchone()[0]
        if events_per_minute == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', '-1 minute')
                """
            )
            events_per_minute = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE status IN ('FAILED', 'DENIED', 'ERROR')
              AND timestamp >= datetime('now', '-10 minutes')
            """
        )
        issue_events_10m = cur.fetchone()[0]
        if issue_events_10m == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE status='FAILED'
                  AND timestamp >= datetime('now', '-10 minutes')
                """
            )
            issue_events_10m = cur.fetchone()[0]

        cur.execute(
            """
            SELECT username, ip_address, last_seen
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes", active_limit),
        )
        active_sessions = [
            {
                "username": row[0],
                "ip_address": row[1],
                "last_seen": row[2],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT
                username,
                endpoint,
                COUNT(*) AS total_hits,
                SUM(CASE WHEN status IN ('FAILED', 'DENIED', 'ERROR') THEN 1 ELSE 0 END) AS issue_hits,
                MAX(timestamp) AS last_seen
            FROM auth_access_logs
            GROUP BY username, endpoint
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (summary_limit,),
        )
        endpoint_summary = [
            {
                "username": row[0],
                "endpoint": row[1],
                "total_hits": row[2],
                "issue_hits": row[3] or 0,
                "last_seen": row[4],
            }
            for row in cur.fetchall()
        ]
        if not endpoint_summary:
            cur.execute(
                """
                SELECT
                    username,
                    '/login' AS endpoint,
                    COUNT(*) AS total_hits,
                    SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) AS issue_hits,
                    MAX(timestamp) AS last_seen
                FROM login_logs
                GROUP BY username
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (summary_limit,),
            )
            endpoint_summary = [
                {
                    "username": row[0],
                    "endpoint": row[1],
                    "total_hits": row[2],
                    "issue_hits": row[3] or 0,
                    "last_seen": row[4],
                }
                for row in cur.fetchall()
            ]

        cur.execute(
            """
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (event_limit,),
        )
        recent_endpoint_events = [
            {
                "id": row[0],
                "username": row[1],
                "ip_address": row[2],
                "event_type": row[3],
                "endpoint": row[4],
                "status": row[5],
                "details": row[6],
                "timestamp": row[7],
            }
            for row in cur.fetchall()
        ]
        if not recent_endpoint_events:
            cur.execute(
                """
                SELECT id, username, ip_address, status, timestamp
                FROM login_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (event_limit,),
            )
            recent_endpoint_events = [
                {
                    "id": row[0],
                    "username": row[1],
                    "ip_address": row[2],
                    "event_type": "AUTH_LOGIN",
                    "endpoint": "/login",
                    "status": row[3],
                    "details": "Legacy authentication record",
                    "timestamp": row[4],
                }
                for row in cur.fetchall()
            ]

    if issue_events_10m >= FAILED_LOGIN_THRESHOLD:
        endpoint_health = "CRITICAL"
        endpoint_health_class = "critical"
        endpoint_health_note = "High issue volume detected in endpoint activity stream"
    elif issue_events_10m >= 3:
        endpoint_health = "AT RISK"
        endpoint_health_class = "warn"
        endpoint_health_note = "Multiple failed or denied endpoint events detected"
    else:
        endpoint_health = "NORMAL"
        endpoint_health_class = "ok"
        endpoint_health_note = "Endpoint traffic appears stable"

    return {
        "total_users": total_users,
        "active_users": active_users,
        "active_sessions_count": active_sessions_count,
        "distinct_endpoints_last_hour": distinct_endpoints_last_hour,
        "events_per_minute": events_per_minute,
        "issue_events_10m": issue_events_10m,
        "endpoint_health": endpoint_health,
        "endpoint_health_class": endpoint_health_class,
        "endpoint_health_note": endpoint_health_note,
        "active_sessions": active_sessions,
        "endpoint_summary": endpoint_summary,
        "recent_endpoint_events": recent_endpoint_events,
    }


def get_logs_forensics_data(
    access_limit=1000,
    login_limit=1000,
    blocked_limit=1000,
    artifact_limit=250,
):
    with get_db() as db:
        cur = db.cursor()

        cur.execute("SELECT COUNT(*) FROM auth_access_logs")
        total_auth_access_logs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM login_logs")
        total_login_logs = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM blocked_ips")
        total_blocked_records = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE status IN ('FAILED', 'DENIED', 'ERROR')
            """
        )
        issue_event_count = cur.fetchone()[0]
        if issue_event_count == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE status='FAILED'
                """
            )
            issue_event_count = cur.fetchone()[0]

        cur.execute(
            """
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (access_limit,),
        )
        auth_access_timeline = [
            {
                "id": row[0],
                "username": row[1],
                "ip_address": row[2],
                "event_type": row[3],
                "endpoint": row[4],
                "status": row[5],
                "details": row[6],
                "timestamp": row[7],
            }
            for row in cur.fetchall()
        ]
        if not auth_access_timeline:
            cur.execute(
                """
                SELECT id, username, ip_address, status, timestamp
                FROM login_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (access_limit,),
            )
            auth_access_timeline = [
                {
                    "id": row[0],
                    "username": row[1],
                    "ip_address": row[2],
                    "event_type": "AUTH_LOGIN",
                    "endpoint": "/login",
                    "status": row[3],
                    "details": "Legacy authentication record",
                    "timestamp": row[4],
                }
                for row in cur.fetchall()
            ]

        cur.execute(
            """
            SELECT id, username, ip_address, status, timestamp
            FROM login_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (login_limit,),
        )
        login_logs = [
            {
                "id": row[0],
                "username": row[1],
                "ip_address": row[2],
                "status": row[3],
                "timestamp": row[4],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT id, ip_address, reason, timestamp
            FROM blocked_ips
            ORDER BY id DESC
            LIMIT ?
            """,
            (blocked_limit,),
        )
        blocked_records = [
            {
                "id": row[0],
                "ip_address": row[1],
                "reason": row[2],
                "timestamp": row[3],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT
                ip_address,
                COUNT(*) AS failed_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM login_logs
            WHERE status='FAILED'
            GROUP BY ip_address
            HAVING COUNT(*) >= 2
            ORDER BY failed_count DESC, last_seen DESC
            LIMIT ?
            """,
            (artifact_limit,),
        )
        top_failed_ips = [
            {
                "ip_address": row[0],
                "failed_count": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT
                username,
                COUNT(*) AS failed_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM login_logs
            WHERE status='FAILED'
            GROUP BY username
            HAVING COUNT(*) >= 2
            ORDER BY failed_count DESC, last_seen DESC
            LIMIT ?
            """,
            (artifact_limit,),
        )
        top_failed_users = [
            {
                "username": row[0],
                "failed_count": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT username, ip_address, event_type, endpoint, details, timestamp
            FROM auth_access_logs
            WHERE status='DENIED'
            ORDER BY id DESC
            LIMIT ?
            """,
            (artifact_limit,),
        )
        denied_access_events = [
            {
                "username": row[0],
                "ip_address": row[1],
                "event_type": row[2],
                "endpoint": row[3],
                "details": row[4],
                "timestamp": row[5],
            }
            for row in cur.fetchall()
        ]

    forensic_findings = (
        len(top_failed_ips)
        + len(top_failed_users)
        + len(denied_access_events)
        + min(total_blocked_records, artifact_limit)
    )

    return {
        "total_auth_access_logs": total_auth_access_logs,
        "total_login_logs": total_login_logs,
        "total_blocked_records": total_blocked_records,
        "issue_event_count": issue_event_count,
        "forensic_findings": forensic_findings,
        "auth_access_timeline": auth_access_timeline,
        "login_logs": login_logs,
        "blocked_records": blocked_records,
        "top_failed_ips": top_failed_ips,
        "top_failed_users": top_failed_users,
        "denied_access_events": denied_access_events,
    }


def get_blocked_ips_data(limit=2000, audit_limit=200):
    with get_db() as db:
        cur = db.cursor()

        # Keep only active blocked entries for operational visibility.
        cur.execute(
            """
            DELETE FROM blocked_ips
            WHERE timestamp < datetime('now', ?)
            """,
            (f"-{IP_BLOCK_DURATION_MINUTES} minutes",),
        )
        cur.execute(
            "DELETE FROM blocked_ips WHERE ip_address IN ('127.0.0.1', '::1', 'localhost')"
        )
        db.commit()

        cur.execute("SELECT COUNT(*) FROM blocked_ips")
        total_blocked_ips = cur.fetchone()[0]

        cur.execute(
            """
            SELECT id, ip_address, reason, timestamp
            FROM blocked_ips
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        blocked_records = [
            {
                "id": row[0],
                "ip_address": row[1],
                "reason": row[2],
                "timestamp": row[3],
            }
            for row in cur.fetchall()
        ]

        cur.execute(
            """
            SELECT username, ip_address, details, timestamp
            FROM auth_access_logs
            WHERE event_type='ADMIN_UNBLOCK_IP'
              AND status='SUCCESS'
            ORDER BY id DESC
            LIMIT ?
            """,
            (audit_limit,),
        )
        unblock_audit = [
            {
                "username": row[0],
                "ip_address": row[1],
                "details": row[2],
                "timestamp": row[3],
            }
            for row in cur.fetchall()
        ]

    return {
        "total_blocked_ips": total_blocked_ips,
        "blocked_records": blocked_records,
        "unblock_audit": unblock_audit,
    }


def get_user_activity_logs_data(activity_limit=500, summary_limit=120):
    with get_db() as db:
        cur = db.cursor()

        cur.execute("SELECT COUNT(*) FROM auth_access_logs")
        total_events = cur.fetchone()[0]
        if total_events == 0:
            cur.execute("SELECT COUNT(*) FROM login_logs")
            total_events = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 minute')
            """
        )
        events_last_minute = cur.fetchone()[0]
        if events_last_minute == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', '-1 minute')
                """
            )
            events_last_minute = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', '-1 hour')
            """
        )
        events_last_hour = cur.fetchone()[0]
        if events_last_hour == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', '-1 hour')
                """
            )
            events_last_hour = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(*)
            FROM auth_access_logs
            WHERE status IN ('FAILED', 'DENIED', 'ERROR')
              AND timestamp >= datetime('now', '-10 minutes')
            """
        )
        alert_events_10m = cur.fetchone()[0]
        if alert_events_10m == 0:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM login_logs
                WHERE status='FAILED'
                  AND timestamp >= datetime('now', '-10 minutes')
                """
            )
            alert_events_10m = cur.fetchone()[0]

        cur.execute(
            """
            SELECT COUNT(DISTINCT username)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        active_operators = cur.fetchone()[0]

        cur.execute(
            """
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (activity_limit,),
        )
        recent_activities = [
            {
                "id": row[0],
                "username": row[1],
                "ip_address": row[2],
                "event_type": row[3],
                "endpoint": row[4],
                "status": row[5],
                "details": row[6],
                "timestamp": row[7],
            }
            for row in cur.fetchall()
        ]
        if not recent_activities:
            cur.execute(
                """
                SELECT id, username, ip_address, status, timestamp
                FROM login_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (activity_limit,),
            )
            recent_activities = [
                {
                    "id": row[0],
                    "username": row[1],
                    "ip_address": row[2],
                    "event_type": "AUTH_LOGIN",
                    "endpoint": "/login",
                    "status": row[3],
                    "details": "Legacy authentication record",
                    "timestamp": row[4],
                }
                for row in cur.fetchall()
            ]

        cur.execute(
            """
            SELECT
                username,
                COUNT(*) AS total_events,
                SUM(
                    CASE
                        WHEN status IN ('FAILED', 'DENIED', 'ERROR') THEN 1
                        ELSE 0
                    END
                ) AS issue_events,
                MAX(timestamp) AS last_seen
            FROM auth_access_logs
            GROUP BY username
            ORDER BY last_seen DESC, total_events DESC
            LIMIT ?
            """,
            (summary_limit,),
        )
        operator_summary = [
            {
                "username": row[0],
                "total_events": row[1],
                "issue_events": row[2] or 0,
                "last_seen": row[3],
            }
            for row in cur.fetchall()
        ]
        if not operator_summary:
            cur.execute(
                """
                SELECT
                    username,
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) AS issue_events,
                    MAX(timestamp) AS last_seen
                FROM login_logs
                GROUP BY username
                ORDER BY last_seen DESC, total_events DESC
                LIMIT ?
                """,
                (summary_limit,),
            )
            operator_summary = [
                {
                    "username": row[0],
                    "total_events": row[1],
                    "issue_events": row[2] or 0,
                    "last_seen": row[3],
                }
                for row in cur.fetchall()
            ]

    return {
        "total_events": total_events,
        "events_last_minute": events_last_minute,
        "events_last_hour": events_last_hour,
        "alert_events_10m": alert_events_10m,
        "active_operators": active_operators,
        "recent_activities": recent_activities,
        "operator_summary": operator_summary,
    }


def get_admin_traffic_series(window_minutes=30):
    window_minutes = max(5, min(int(window_minutes or 30), 120))
    buckets = {}

    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:%M:00Z', timestamp) AS minute_bucket, COUNT(*)
            FROM auth_access_logs
            WHERE timestamp >= datetime('now', ?)
            GROUP BY minute_bucket
            ORDER BY minute_bucket ASC
            """,
            (f"-{window_minutes} minutes",),
        )
        rows = cur.fetchall()

        if not rows:
            cur.execute(
                """
                SELECT strftime('%Y-%m-%dT%H:%M:00Z', timestamp) AS minute_bucket, COUNT(*)
                FROM login_logs
                WHERE timestamp >= datetime('now', ?)
                GROUP BY minute_bucket
                ORDER BY minute_bucket ASC
                """,
                (f"-{window_minutes} minutes",),
            )
            rows = cur.fetchall()

    for bucket_value, count in rows:
        if not bucket_value:
            continue
        try:
            bucket_dt = datetime.strptime(
                str(bucket_value), "%Y-%m-%dT%H:%M:00Z"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        buckets[bucket_dt] = int(count or 0)

    now_utc = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start_utc = now_utc - timedelta(minutes=window_minutes - 1)

    points = []
    for offset in range(window_minutes):
        bucket_dt = start_utc + timedelta(minutes=offset)
        events = buckets.get(bucket_dt, 0)
        points.append(
            {
                "timestamp_utc": bucket_dt.strftime("%Y-%m-%dT%H:%M:00Z"),
                "label": bucket_dt.strftime("%H:%M"),
                "count": events,
            }
        )

    counts = [point["count"] for point in points]
    latest_events = counts[-1] if counts else 0
    peak_events = max(counts) if counts else 0
    total_window_events = sum(counts)

    return {
        "window_minutes": window_minutes,
        "latest_events_per_minute": latest_events,
        "peak_events_per_minute": peak_events,
        "total_window_events": total_window_events,
        "points": points,
    }


def serialize_logs(logs):
    return [
        {
            "id": row[0],
            "username": row[1],
            "ip_address": row[2],
            "event_type": row[3],
            "endpoint": row[4],
            "status": row[5],
            "details": row[6],
            "timestamp": row[7],
        }
        for row in logs
    ]


def serialize_blocked(blocked):
    return [
        {
            "id": row[0],
            "ip_address": row[1],
            "timestamp": row[2],
        }
        for row in blocked
    ]


@app.before_request
def ensure_authenticated_sessions_are_permanent():
    if "username" in session and not session.permanent:
        session.permanent = True


init_db()


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@app.route("/login.html", methods=["GET"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        selected_role = request.form.get("role", "").strip().lower()
        ip_address = get_client_ip()
        endpoint = "/login"

        if is_ip_blocked(ip_address):
            record_login_event(username or "unknown", ip_address, "FAILED")
            record_auth_access_event(
                username,
                ip_address,
                "AUTH_LOGIN",
                endpoint,
                "DENIED",
                f"Blocked after repeated failures; retry in {IP_BLOCK_DURATION_MINUTES} min",
            )
            error = (
                f"Access denied. Too many failed attempts. "
                f"Try again in {IP_BLOCK_DURATION_MINUTES} minutes."
            )
            return render_template("login.html", error=error)

        if not username or not password:
            record_login_event(username or "unknown", ip_address, "FAILED")
            block_ip_if_needed(ip_address)
            record_auth_access_event(
                username,
                ip_address,
                "AUTH_LOGIN",
                endpoint,
                "FAILED",
                "Missing username or password",
            )
            error = "Username and password are required"
            return render_template("login.html", error=error)

        if selected_role not in {"admin", "user"}:
            selected_role = ""

        try:
            with get_db() as db:
                cur = db.cursor()
                cur.execute(
                    "SELECT password_hash FROM users WHERE username=?",
                    (username,),
                )
                user = cur.fetchone()

            if user and check_password_hash(user[0], password):
                # Avoid failed logins caused by stale role selection in UI.
                expected_role = "admin" if username in {"123", "admin"} else "user"
                target_endpoint = (
                    "/admin_dashboard.html" if expected_role == "admin" else "/user.html"
                )

                session.permanent = True
                session["username"] = username
                session["role"] = expected_role
                record_login_event(username, ip_address, "SUCCESS")
                touch_active_device(username, ip_address)
                record_auth_access_event(
                    username,
                    ip_address,
                    "AUTH_LOGIN",
                    endpoint,
                    "SUCCESS",
                    f"Authenticated as {expected_role}; redirect to {target_endpoint}",
                )

                if expected_role == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("user_home"))

            record_login_event(username, ip_address, "FAILED")
            block_ip_if_needed(ip_address, FAILED_LOGIN_THRESHOLD)
            record_auth_access_event(
                username,
                ip_address,
                "AUTH_LOGIN",
                endpoint,
                "FAILED",
                "Invalid username or password",
            )
            error = "Invalid username or password"
        except Exception as exc:
            record_login_event(username or "unknown", ip_address, "FAILED")
            record_auth_access_event(
                username,
                ip_address,
                "AUTH_LOGIN",
                endpoint,
                "ERROR",
                f"Exception during login: {str(exc)}",
            )
            error = f"An error occurred: {str(exc)}"

    return render_template("login.html", error=error)


@app.route("/admin")
@app.route("/admin_dashboard.html")
@app.route("/overview")
@app.route("/overview.html")
def admin_dashboard():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_ADMIN_DASHBOARD",
            "/admin_dashboard.html",
            "DENIED",
            "Unauthorized admin dashboard access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_ADMIN_DASHBOARD",
        "/admin_dashboard.html",
        "SUCCESS",
        "Admin dashboard viewed",
    )
    overview = get_overview_data()
    return render_template(
        "admin_dashboard.html",
        logs=overview["logs"],
        blocked=overview["blocked"],
        total_events=overview["total_events"],
        threat_alerts=overview["threat_alerts"],
        active_devices=overview["active_devices"],
        network_status=overview["network_status"],
        network_status_note=overview["network_status_note"],
        network_status_class=overview["network_status_class"],
        active_window_minutes=ACTIVE_DEVICE_WINDOW_MINUTES,
    )


@app.route("/admin/threat-alerts")
@app.route("/admin/threat-alerts.html")
def admin_threat_alerts():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/admin/threat-alerts"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_THREAT_ALERTS",
            endpoint,
            "DENIED",
            "Unauthorized threat alerts page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    alerts = get_all_time_threat_alerts(limit=500)
    critical_count = sum(1 for alert in alerts if alert.get("severity") == "critical")
    warn_count = sum(1 for alert in alerts if alert.get("severity") == "warn")
    info_count = sum(1 for alert in alerts if alert.get("severity") == "info")

    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_THREAT_ALERTS",
        endpoint,
        "SUCCESS",
        f"Threat alerts viewed ({len(alerts)} records)",
    )

    return render_template(
        "threat_alerts.html",
        alerts=alerts,
        total_alerts=len(alerts),
        critical_count=critical_count,
        warn_count=warn_count,
        info_count=info_count,
    )


@app.route("/admin/network-monitoring")
@app.route("/admin/network-monitoring.html")
def admin_network_monitoring():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/admin/network-monitoring"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_NETWORK_MONITORING",
            endpoint,
            "DENIED",
            "Unauthorized network monitoring page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    monitoring = get_network_monitor_data()
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_NETWORK_MONITORING",
        endpoint,
        "SUCCESS",
        "Network monitoring dashboard viewed",
    )
    return render_template(
        "network_monitoring.html",
        monitoring=monitoring,
    )


@app.route("/api/admin/network-monitoring")
def admin_network_monitoring_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    monitoring = get_network_monitor_data()
    return jsonify(monitoring)


@app.route("/admin/endpoint-activity")
@app.route("/admin/endpoint-activity.html")
def admin_endpoint_activity():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/admin/endpoint-activity"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_ENDPOINT_ACTIVITY",
            endpoint,
            "DENIED",
            "Unauthorized endpoint activity page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    endpoint_activity = get_endpoint_activity_data()
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_ENDPOINT_ACTIVITY",
        endpoint,
        "SUCCESS",
        "Endpoint activity dashboard viewed",
    )
    return render_template(
        "endpoint_activity.html",
        endpoint_activity=endpoint_activity,
    )


@app.route("/api/admin/endpoint-activity")
def admin_endpoint_activity_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    endpoint_activity = get_endpoint_activity_data()
    return jsonify(endpoint_activity)


@app.route("/admin/logs-forensics")
@app.route("/admin/logs-forensics.html")
def admin_logs_forensics():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/admin/logs-forensics"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_LOGS_FORENSICS",
            endpoint,
            "DENIED",
            "Unauthorized logs and forensics page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    forensics = get_logs_forensics_data()
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_LOGS_FORENSICS",
        endpoint,
        "SUCCESS",
        "Logs and forensics dashboard viewed",
    )
    return render_template(
        "logs_forensics.html",
        forensics=forensics,
    )


@app.route("/api/admin/logs-forensics")
def admin_logs_forensics_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    forensics = get_logs_forensics_data()
    return jsonify(forensics)


@app.route("/admin/blocked-ips")
@app.route("/admin/blocked-ips.html")
def admin_blocked_ips():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/admin/blocked-ips"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_BLOCKED_IPS",
            endpoint,
            "DENIED",
            "Unauthorized blocked IPs page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    blocked_data = get_blocked_ips_data()
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_BLOCKED_IPS",
        endpoint,
        "SUCCESS",
        f"Blocked IPs page viewed ({blocked_data['total_blocked_ips']} active)",
    )
    return render_template(
        "blocked_ips.html",
        blocked_data=blocked_data,
    )


@app.route("/api/admin/blocked-ips")
def admin_blocked_ips_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    blocked_data = get_blocked_ips_data()
    return jsonify(blocked_data)


@app.route("/api/admin/overview")
def admin_overview_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    overview = get_overview_data()
    return jsonify(
        {
            "total_events": overview["total_events"],
            "threat_alerts": overview["threat_alerts"],
            "active_devices": overview["active_devices"],
            "network_status": overview["network_status"],
            "network_status_note": overview["network_status_note"],
            "network_status_class": overview["network_status_class"],
            "recent_failed_attempts": overview["recent_failed_attempts"],
            "blocked_ip_count": overview["blocked_ip_count"],
            "threats": overview["threats"],
            "active_window_minutes": ACTIVE_DEVICE_WINDOW_MINUTES,
            "logs": serialize_logs(overview["logs"]),
            "blocked": serialize_blocked(overview["blocked"]),
        }
    )


@app.route("/session-timeout.js")
def session_timeout_script():
    timeout_ms = SESSION_TIMEOUT_MINUTES * 60 * 1000
    script = f"""
(function () {{
    const inactivityLimitMs = {timeout_ms};
    let timeoutHandle = null;

    function logoutForInactivity() {{
        window.location.replace("/logout");
    }}

    function resetInactivityTimer() {{
        window.clearTimeout(timeoutHandle);
        timeoutHandle = window.setTimeout(logoutForInactivity, inactivityLimitMs);
    }}

    const activityEvents = ["click", "mousemove", "keydown", "scroll", "touchstart"];
    activityEvents.forEach((eventName) => {{
        window.addEventListener(eventName, resetInactivityTimer, {{ passive: true }});
    }});

    window.addEventListener("focus", resetInactivityTimer);
    window.addEventListener("load", resetInactivityTimer);
    resetInactivityTimer();
}})();
    """.strip()

    response = app.response_class(script, mimetype="application/javascript")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/api/admin/traffic-series")
def admin_traffic_series_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    traffic_series = get_admin_traffic_series(window_minutes=30)
    return jsonify(traffic_series)


@app.route("/api/admin/unblock-ip", methods=["POST"])
def admin_unblock_ip_api():
    username = session.get("username", "anonymous")
    requester_ip = get_client_ip()
    endpoint = "/api/admin/unblock-ip"

    if session.get("role") != "admin":
        record_auth_access_event(
            username,
            requester_ip,
            "ADMIN_UNBLOCK_IP",
            endpoint,
            "DENIED",
            "Unauthorized IP unblock attempt",
        )
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    ip_address = str(payload.get("ip_address", "")).strip()
    if not ip_address:
        record_auth_access_event(
            username,
            requester_ip,
            "ADMIN_UNBLOCK_IP",
            endpoint,
            "FAILED",
            "Missing IP address in unblock request",
        )
        return jsonify({"error": "ip_address_required"}), 400

    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute("DELETE FROM blocked_ips WHERE ip_address=?", (ip_address,))
            removed_rows = cur.rowcount
            db.commit()
    except sqlite3.Error:
        record_auth_access_event(
            username,
            requester_ip,
            "ADMIN_UNBLOCK_IP",
            endpoint,
            "ERROR",
            f"Database error while unblocking {ip_address}",
        )
        return jsonify({"error": "database_error"}), 500

    if removed_rows == 0:
        record_auth_access_event(
            username,
            requester_ip,
            "ADMIN_UNBLOCK_IP",
            endpoint,
            "FAILED",
            f"IP {ip_address} not found in blocked list",
        )
        return jsonify({"error": "ip_not_blocked"}), 404

    record_auth_access_event(
        username,
        requester_ip,
        "ADMIN_UNBLOCK_IP",
        endpoint,
        "SUCCESS",
        f"IP {ip_address} unblocked by admin",
    )
    return jsonify({"ok": True, "ip_address": ip_address})


@app.route("/user")
@app.route("/user.html")
def user_home():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if "username" not in session:
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_USER_HOME",
            "/user.html",
            "DENIED",
            "Unauthorized user home access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_USER_HOME",
        "/user.html",
        "SUCCESS",
        "User home page viewed",
    )
    return render_template("user.html")


@app.route("/user/network-status")
@app.route("/user/network-status.html")
def user_network_status():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/user/network-status.html"
    if "username" not in session:
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_USER_NETWORK_STATUS",
            endpoint,
            "DENIED",
            "Unauthorized user network status page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_USER_NETWORK_STATUS",
        endpoint,
        "SUCCESS",
        "User network status monitor viewed",
    )
    return render_template("user_network_status.html")


@app.route("/user/activity-logs")
@app.route("/user/activity-logs.html")
def user_activity_logs():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    endpoint = "/user/activity-logs.html"
    if "username" not in session:
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_USER_ACTIVITY_LOGS",
            endpoint,
            "DENIED",
            "Unauthorized user activity logs page access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    activity_data = get_user_activity_logs_data()
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_USER_ACTIVITY_LOGS",
        endpoint,
        "SUCCESS",
        f"User activity logs monitor viewed ({activity_data['total_events']} events)",
    )
    return render_template(
        "user_activity_logs.html",
        activity_data=activity_data,
    )


@app.route("/api/user/activity-logs")
def user_activity_logs_api():
    if "username" not in session:
        return jsonify({"error": "unauthorized"}), 401

    touch_active_device(session.get("username"), get_client_ip())
    activity_data = get_user_activity_logs_data()
    return jsonify(activity_data)


@app.route("/userdashboard")
@app.route("/userdashboard.html")
def user_dashboard():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if "username" not in session:
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_USER_DASHBOARD",
            "/userdashboard.html",
            "DENIED",
            "Unauthorized user dashboard access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_USER_DASHBOARD",
        "/userdashboard.html",
        "SUCCESS",
        "User dashboard viewed",
    )
    return render_template("userdashboard.html")


@app.route("/logout")
def logout():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    record_auth_access_event(
        username,
        ip_address,
        "LOGOUT",
        "/logout",
        "SUCCESS",
        "User logged out",
    )
    remove_active_device(username, ip_address)
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, use_reloader=debug_mode)

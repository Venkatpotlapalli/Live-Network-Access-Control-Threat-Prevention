from pathlib import Path
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import datetime

# ---------------- APP CONFIG ----------------
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="templates/static",
    static_url_path="/static",
)
app.secret_key = "live_network_access_control_secret"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"
LOG_DIR = "logs"
LOG_FILE = "logs/access.log"
ACTIVE_DEVICE_WINDOW_MINUTES = 5
FAILED_LOGIN_WINDOW_MINUTES = 10
FAILED_LOGIN_THRESHOLD = 7
IP_BLOCK_DURATION_MINUTES = 15
LOCAL_LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost"}
AUTH_ACCESS_LOG_LIMIT = 300


# ---------------- DATABASE INIT ----------------
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
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                assigned_to TEXT,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT
            )
            """
        )

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS soar_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                condition_type TEXT NOT NULL,
                condition_value TEXT NOT NULL,
                action TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1
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
            ("sir", "sir11"),
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


# ---------------- LOGGING ----------------
def write_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


# ---------------- IP BLOCK CHECK ----------------
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
                "threat_name": "Brute Force",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "critical",
                "status": "Blocked",
                "description": reason,
                "detection_source": "Authentication Guard",
                "timestamp": timestamp,
            }
        )

    cur.execute(
        """
        SELECT username, ip_address, COUNT(*) AS failed_count, MAX(timestamp) AS last_seen
        FROM login_logs
        WHERE status='FAILED'
          AND timestamp >= datetime('now', ?)
        GROUP BY username, ip_address
        HAVING COUNT(*) >= 1
        ORDER BY last_seen DESC
        LIMIT 25
        """,
        (f"-10 minutes",),
    )
    for username, ip_address, failed_count, last_seen in cur.fetchall():
        if (username, ip_address) in blocked_pairs:
            continue
        threats.append(
            {
                "threat_name": "Failed Login",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "warn",
                "status": "Intercepted",
                "description": (
                    f"{failed_count} failed attempts in last 10 minutes"
                ),
                "detection_source": "Login Behavior Analytics",
                "timestamp": last_seen,
            }
        )

    cur.execute(
        """
        SELECT username, ip_address, MAX(timestamp) AS last_seen
        FROM auth_access_logs
        WHERE status='DENIED'
          AND timestamp >= datetime('now', '-10 minutes')
        GROUP BY username, ip_address
        ORDER BY last_seen DESC
        LIMIT 25
        """
    )
    for username, ip_address, last_seen in cur.fetchall():
        threats.append(
            {
                "threat_name": "Unauthorized Access",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "critical",
                "status": "Blocked",
                "description": "Attempted to access restricted resource",
                "detection_source": "Access Control Engine",
                "timestamp": last_seen,
            }
        )

    cur.execute(
        """
        SELECT username, ip_address, MAX(timestamp) AS last_seen
        FROM login_logs
        WHERE status='SUCCESS'
          AND timestamp >= datetime('now', '-10 minutes')
          AND ip_address NOT IN ('127.0.0.1', '::1', 'localhost')
        GROUP BY username, ip_address
        ORDER BY last_seen DESC
        LIMIT 25
        """
    )
    for username, ip_address, last_seen in cur.fetchall():
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            continue 
        threats.append(
            {
                "threat_name": "Anomalous Login",
                "ip_address": ip_address,
                "user_id": username,
                "severity": "warn",
                "status": "Flagged",
                "description": "Login from non-local external IP address",
                "detection_source": "Geofencing Agent",
                "timestamp": last_seen,
            }
        )

    threats.sort(
        key=lambda t: (
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
            SELECT COUNT(DISTINCT ip_address)
            FROM active_devices
            WHERE last_seen >= datetime('now', ?)
            """,
            (f"-{ACTIVE_DEVICE_WINDOW_MINUTES} minutes",),
        )
        real_active = cur.fetchone()[0]

        import time, math
        # Create a smooth sine wave based fluctuation between 15 and 45 for demo feel
        fluctuation = int(30 + 15 * math.sin(time.time() / 60))
        active_devices = real_active + fluctuation

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

    cur.execute(
        """
        SELECT id, username, ip_address, timestamp
        FROM auth_access_logs
        WHERE event_type = 'LOGOUT'
        ORDER BY id DESC
        LIMIT 5
        """
    )
    logout_rows = cur.fetchall()
    recent_logouts = [
        {
            "id": row[0],
            "username": row[1],
            "ip_address": row[2],
            "timestamp": row[3],
        }
        for row in logout_rows
    ]

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
        "recent_logouts": recent_logouts,
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


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@app.route("/login.html", methods=["GET"])
@app.route("/demo.html", methods=["GET"])
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
            return render_template("login.html", error=error), 403

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
            return render_template("login.html", error=error), 401

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
                expected_role = "admin" if username in {"123", "admin"} else "user"

                if selected_role and selected_role != expected_role:
                    record_login_event(username, ip_address, "FAILED")
                    record_auth_access_event(
                        username,
                        ip_address,
                        "AUTH_LOGIN",
                        endpoint,
                        "FAILED",
                        f"Role mismatch: attempted {selected_role} but is {expected_role}",
                    )
                    error = "Unauthorized access"
                    return render_template("login.html", error=error), 403

                target_endpoint = (
                    "/admin_dashboard.html" if expected_role == "admin" else "/user.html"
                )

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
            return render_template("login.html", error=error), 401
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
            return render_template("login.html", error=error), 500

    return render_template("login.html", error=error)


# ---------------- USER DASHBOARD ----------------
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
@app.route("/user_network_status.html")
def user_network_status():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if "username" not in session:
        record_auth_access_event(
            username,
            ip_address,
            "ACCESS_USER_NETWORK_STATUS",
            "/user/network-status",
            "DENIED",
            "Unauthorized user network status access attempt",
        )
        return redirect(url_for("login"))

    touch_active_device(username, ip_address)
    record_auth_access_event(
        username,
        ip_address,
        "ACCESS_USER_NETWORK_STATUS",
        "/user/network-status",
        "SUCCESS",
        "User network status page viewed",
    )
    return render_template("user_network_status.html")


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


@app.route("/landing_control.html")
def landing_control():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if "username" not in session:
        record_auth_access_event(username, ip_address, "ACCESS_LANDING_CONTROL", "/landing_control.html", "DENIED", "Unauthorized access")
        return redirect(url_for("login"))
    touch_active_device(username, ip_address)
    record_auth_access_event(username, ip_address, "ACCESS_LANDING_CONTROL", "/landing_control.html", "SUCCESS", "Viewed")
    return render_template("landing_control.html")


@app.route("/alerts_warnings.html")
def alerts_warnings():
    username = session.get("username", "anonymous")
    ip_address = get_client_ip()
    if "username" not in session:
        record_auth_access_event(username, ip_address, "ACCESS_ALERTS_WARNINGS", "/alerts_warnings.html", "DENIED", "Unauthorized access")
        return redirect(url_for("login"))
    touch_active_device(username, ip_address)
    record_auth_access_event(username, ip_address, "ACCESS_ALERTS_WARNINGS", "/alerts_warnings.html", "SUCCESS", "Viewed")
    return render_template("alerts_warnings.html")


# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
@app.route("/overview")
@app.route("/overview.html")
@app.route("/admin_dashboard.html")
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


@app.route("/api/soc/overview")
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
            "recent_logouts": overview.get("recent_logouts", []),
        }
    )


@app.route("/api/soc/system-data")
def admin_system_data_api():
    if session.get("role") != "admin":
        return jsonify({"error": "unauthorized"}), 401
        
    touch_active_device(session.get("username"), get_client_ip())
    
    with get_db() as db:
        cur = db.cursor()
        
        # Get all users and their last seen timestamp
        cur.execute("""
            SELECT u.id, u.username, 
                   (SELECT timestamp FROM auth_access_logs WHERE username = u.username ORDER BY id DESC LIMIT 1) as last_seen
            FROM users u
            ORDER BY u.id ASC
        """)
        users_rows = cur.fetchall()
        
        users_list = []
        for row in users_rows:
            users_list.append({
                "id": row[0],
                "username": row[1],
                "last_seen": row[2]
            })
            
        # Get all-time threats
        cur.execute("""
            SELECT id, username, ip_address, event_type, endpoint, status, details, timestamp
            FROM auth_access_logs
            WHERE status IN ('FAILED', 'DENIED', 'ERROR')
              AND event_type NOT IN ('LOGOUT')
            ORDER BY id DESC
            LIMIT 500
        """)
        threats_rows = cur.fetchall()
        
        all_time_threats = []
        for row in threats_rows:
            all_time_threats.append({
                "id": row[0],
                "user_id": row[1],
                "ip_address": row[2],
                "threat_name": row[3],
                "endpoint": row[4],
                "severity": "critical" if row[5] == "DENIED" else "warn",
                "description": row[6],
                "timestamp": row[7],
                "detection_source": "Historic System Logs"
            })
            
    return jsonify({
        "all_users": users_list,
        "all_time_threats": all_time_threats
    })


@app.route("/api/soc/unblock-ip", methods=["POST"])
def admin_unblock_ip_api():
    username = session.get("username", "anonymous")
    requester_ip = get_client_ip()
    endpoint = "/api/soc/unblock-ip"

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


@app.route("/admin/threat-alerts")
def threat_alerts():
    return render_template("threat_alerts.html")

import time
import random
import json

@app.route('/api/soc/stream')
def soc_stream():
    def generate():
        tactics = [
            ("T1110", "Brute Force"), ("T1078", "Valid Accounts"), 
            ("T1190", "Exploit Public-Facing App"), ("T1059", "Command and Scripting Interpreter"),
            ("T1003", "OS Credential Dumping"), ("T1486", "Data Encrypted for Impact")
        ]
        countries = ["RU", "CN", "KP", "IR", "US", "BR", "VN"]
        names = ["SSH Brute Force", "Anomalous Login", "SQL Injection Attempt", "Ransomware Beacon", "Unauthorized Port Scan"]
        
        while True:
            time.sleep(random.randint(2, 6))
            tactic = random.choice(tactics)
            data = {
                "id": f"EVT-{random.randint(1000,9999)}",
                "severity": random.choices(["critical", "warn", "info"], weights=[10, 30, 60])[0],
                "threat_name": random.choice(names),
                "mitre_tactic": tactic[0] + " - " + tactic[1],
                "user_id": f"user_{random.randint(10,99)}",
                "ip_address": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "geo_country": random.choice(countries),
                "reputation": random.randint(10, 99),
                "description": "Suspicious activity detected matching known threat signatures.",
                "detection_source": "AI Behavior Analytics",
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            }
            yield f"data: {json.dumps(data)}\n\n"
            
    from flask import Response
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/soc/action', methods=['POST'])
def soc_action():
    from flask import request, jsonify
    payload = request.get_json(silent=True) or {}
    action = payload.get('action')
    target = payload.get('target')
    
    # Dummy handling for specific SOAR actions
    if action == 'block':
        msg = f"Firewall rule added to drop traffic from {target}."
    elif action == 'isolate':
        msg = f"Endpoint for user {target} restricted to quarantine VLAN."
    elif action == 'incident':
        msg = f"Incident INC-{random.randint(1000,9999)} created from event {target}."
    else:
        msg = "Action registered."
        
    return jsonify({"status": "success", "message": msg})

@app.route("/admin/network-monitoring")
def network_monitoring():
    return render_template("network_monitoring.html", monitoring={})

@app.route("/admin/endpoint-activity")
def endpoint_activity():
    return render_template("endpoint_activity.html")

@app.route("/admin/logs-forensics")
def logs_forensics():
    return render_template("logs_forensics.html")

@app.route("/admin/blocked-ips")
def blocked_ips():
    return render_template("blocked_ips.html")


@app.route('/api/soc/traffic-series')
def traffic_series():
    # This is a dummy response.
    return jsonify({
        "points": [
            {"label": "10:00", "count": 10},
            {"label": "10:05", "count": 20},
            {"label": "10:10", "count": 15},
        ],
        "latest_events_per_minute": 15,
        "window_minutes": 30,
        "peak_events_per_minute": 20,
    })


@app.route('/session-timeout.js')
def session_timeout_js():
    return send_from_directory(app.static_folder, 'js/session-timeout.js')


# ---------------- LOGOUT ----------------
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


# ---------------- MAIN ----------------
if __name__ == "__main__":

    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, use_reloader=debug_mode)

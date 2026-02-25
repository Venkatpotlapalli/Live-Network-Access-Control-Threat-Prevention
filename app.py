from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import datetime
import os

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.secret_key = "live_network_access_control_secret"

DB_NAME = "database.db"
LOG_DIR = "logs"
LOG_FILE = "logs/access.log"


# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip TEXT,
        status TEXT,
        time TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE
    )
    """)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users VALUES (NULL,'admin','admin123','admin')")
        cur.execute("INSERT INTO users VALUES (NULL,'user','user123','user')")

    conn.commit()
    conn.close()


# ---------------- LOGGING ----------------
def write_log(message):
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


# ---------------- IP BLOCK CHECK ----------------
def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT * FROM blocked_ips WHERE ip=?", (ip,))
    result = cur.fetchone()
    conn.close()
    return result is not None


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if is_ip_blocked(ip):
        return "🚫 Your IP is blocked due to suspicious activity."

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cur.fetchone()

        if user:
            session["username"] = username
            session["role"] = user[3]

            cur.execute(
                "INSERT INTO login_logs VALUES (NULL,?,?,?,?)",
                (username, ip, "SUCCESS", time_now)
            )
            conn.commit()
            conn.close()

            write_log(f"[SUCCESS] {username} logged in from {ip} at {time_now}")

            if user[3] == "admin":
                return redirect("/admin")
            else:
                return redirect("/user")

        else:
            cur.execute(
                "INSERT INTO login_logs VALUES (NULL,?,?,?,?)",
                (username, ip, "FAILED", time_now)
            )
            conn.commit()

            cur.execute("""
                SELECT COUNT(*) FROM login_logs
                WHERE ip=? AND status='FAILED'
            """, (ip,))
            fail_count = cur.fetchone()[0]

            if fail_count >= 3:
                cur.execute(
                    "INSERT OR IGNORE INTO blocked_ips VALUES (NULL,?)",
                    (ip,)
                )
                conn.commit()
                write_log(f"[ALERT] IP {ip} BLOCKED (Brute Force)")

            conn.close()
            write_log(f"[FAILED] Login attempt from {ip} at {time_now}")
            return "❌ Invalid credentials"

    return render_template("login.html")


# ---------------- USER DASHBOARD ----------------
@app.route("/user")
def user():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("user.html", user=session["user"])


@app.route("/userdashboard")
def userdashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("userdashboard.html")

# ---------------- ADMIN DASHBOARD ----------------
@app.route("/admin")
def admin_dashboard():
    if "username" not in session or session["role"] != "admin":
        return redirect("/")

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("SELECT * FROM login_logs ORDER BY id DESC")
    logs = cur.fetchall()

    cur.execute("SELECT * FROM blocked_ips")
    blocked = cur.fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        logs=logs,
        blocked=blocked
    )


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- MAIN ----------------
if __name__ == "__main__":

    if not os.path.exists(LOG_DIR):
        os.mkdir(LOG_DIR)

    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    init_db()
    app.run(debug=True)

from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from werkzeug.security import check_password_hash
import os

TEMPLATES_DIR = Path(__file__).resolve().parent

app = Flask(__name__, template_folder=str(TEMPLATES_DIR))
app.secret_key = "soc_secure_secret_key"   # change in production

# -------------------------------
# MongoDB Connection
# -------------------------------
client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
db = client["security_portal"]
users_collection = db["users"]


def password_matches(stored_password, provided_password):
    if not stored_password:
        return False
    try:
        return check_password_hash(stored_password, provided_password)
    except (ValueError, TypeError):
        # Backward compatibility for records that still store plain text.
        return stored_password == provided_password

# -------------------------------
# LOGIN ROUTE
# -------------------------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            error = "Username and password are required"
            return render_template("login.html", error=error)

        try:
            user = users_collection.find_one({"username": username})
        except Exception:
            error = "Authentication service is unavailable. Please try again."
            return render_template("login.html", error=error)

        if user and password_matches(user.get("password"), password):
            role = user.get("role", "user")
            if role not in {"admin", "user"}:
                role = "user"

            session["username"] = username
            session["role"] = role

            if role == "admin":
                return redirect(url_for("admin"))
            return redirect(url_for("user"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


# -------------------------------
# ADMIN DASHBOARD
# -------------------------------
@app.route("/admin")
@app.route("/admin_dashboard.html")
def admin():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html", logs=[], blocked=[])


# -------------------------------
# USER DASHBOARD
# -------------------------------
@app.route("/user")
@app.route("/userdashboard")
@app.route("/userdashboard.html")
def user():
    if session.get("role") != "user":
        return redirect(url_for("login"))
    return render_template("userdashboard.html")


# -------------------------------
# LOGOUT
# -------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -------------------------------
# RUN SERVER
# -------------------------------
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, use_reloader=debug_mode)

from flask import Flask, render_template, request, session, redirect, url_for
from argon2 import PasswordHasher
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database import init_db, get_db_connection
import re
import sqlite3

app = Flask(__name__)

app.config["SECRET_KEY"] = "change-this-development-key"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)

init_db()

password_hasher = PasswordHasher()


def is_valid_username(username):
    return re.fullmatch(r"[A-Za-z0-9_]{3,20}", username) is not None


def is_valid_email(email):
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.fullmatch(pattern, email) is not None


def is_strong_password(password):
    if len(password) < 8:
        return False

    if not re.search(r"[A-Z]", password):
        return False

    if not re.search(r"[a-z]", password):
        return False

    if not re.search(r"[0-9]", password):
        return False

    if not re.search(r"[^A-Za-z0-9]", password):
        return False

    return True


@app.route("/")
def home():
    return "Secure Login System is running!"


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not is_valid_username(username):
            return "Invalid username. Use 3-20 letters, numbers, or underscores."

        if not is_valid_email(email):
            return "Invalid email address."

        if not is_strong_password(password):
            return "Password must be at least 8 characters and contain uppercase, lowercase, number, and special character."

        if password != confirm_password:
            return "Passwords do not match."

        password_hash = password_hasher.hash(password)

        connection = get_db_connection()

        try:
            connection.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            connection.commit()

        except sqlite3.IntegrityError:
            return "Username or email already exists."

        finally:
            connection.close()

        return "Registration successful!"

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT id, username, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        connection.close()

        if user is None:
            return "Invalid email or password."

        try:
            password_hasher.verify(
                user["password_hash"],
                password
            )

        except Exception:
            return "Invalid email or password."

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return f"Welcome, {session['username']}!"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

from flask import Flask, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]

data_folder = Path(app.instance_path)
data_folder.mkdir(exist_ok=True)
database = data_folder / "lost_and_found.db"

with closing(sqlite3.connect(database)) as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)
    db.commit()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template("register.html", message="Fill in both fields.")

    password_hash = generate_password_hash(password)

    try:
        with closing(sqlite3.connect(database)) as db:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", message="That username is already taken.")

    return render_template("register.html", message="Account created.")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        user = db.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", message="Invalid username or password.")

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("index"))


@app.get("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template("index.html", username=session["username"])
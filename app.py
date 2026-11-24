import sqlite3
from contextlib import closing
from pathlib import Path
from werkzeug.security import generate_password_hash

from flask import Flask, render_template, request

app = Flask(__name__)

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
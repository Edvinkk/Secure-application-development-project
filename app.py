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

    # Store each listing with the ID of the student who posted it
    db.execute("""
        CREATE TABLE IF NOT EXISTS listings (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            item_type TEXT NOT NULL CHECK (item_type IN ('lost', 'found')),
            description TEXT NOT NULL,
            location TEXT NOT NULL
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

    # Read the keyword from the search box.
    keyword = request.args.get("q", "").strip()

    # An empty keyword shows all listings with the newest first.
    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row
        listings = db.execute(
            """
            SELECT item_type, description, location
            FROM listings
            WHERE instr(lower(description), lower(?)) > 0
               OR instr(lower(location), lower(?)) > 0
            ORDER BY id DESC
            """,
            (keyword, keyword),
        ).fetchall()

    return render_template(
        "index.html",
        username=session["username"],
        listings=listings,
        keyword=keyword,
    )


@app.route("/listings/new", methods=["GET", "POST"])
def create_listing():
    # Students must log in before they can post an item
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("create_listing.html")

    item_type = request.form.get("item_type", "")
    description = request.form.get("description", "").strip()
    location = request.form.get("location", "").strip()

    # Check the submitted values before saving the listing
    if item_type not in ("lost", "found") or not description or not location:
        return render_template("create_listing.html", message="Enter the item type, description and location.")

    # Use the student ID from the login session
    with closing(sqlite3.connect(database)) as db:
        db.execute(
            """
            INSERT INTO listings (user_id, item_type, description, location)
            VALUES (?, ?, ?, ?)
            """,
            (session["user_id"], item_type, description, location),
        )
        db.commit()

    return redirect(url_for("index"))
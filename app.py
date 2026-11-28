import os
import sqlite3
from contextlib import closing
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

from flask import Flask, redirect, render_template, request, session, url_for, abort

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

    # Link each private claim to the listing and the student who submitted it.
    db.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY,
            listing_id INTEGER NOT NULL REFERENCES listings(id),
            claimant_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL
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
            # Vulnerable
            db.execute(
                f"INSERT INTO users (username, password_hash) VALUES ('{username}', '{password_hash}')"
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
        # Vulnerable
        user = db.execute(
            f"SELECT id, username, password_hash FROM users WHERE username = '{username}'"
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
        # Vulnerable
        listings = db.execute(
            f"""
            SELECT id, item_type, description, location
            FROM listings
            WHERE instr(lower(description), lower('{keyword}')) > 0
               OR instr(lower(location), lower('{keyword}')) > 0
            ORDER BY id DESC
            """,
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
        # Vulnerable
        db.execute(
            f"""
            INSERT INTO listings (user_id, item_type, description, location)
            VALUES ({session["user_id"]}, '{item_type}', '{description}', '{location}')
            """
        )
        db.commit()

    return redirect(url_for("index"))


@app.route("/listings/<int:listing_id>/claims", methods=["GET", "POST"])
def listing_claims(listing_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    student_id = session["user_id"]
    error = None

    with closing(sqlite3.connect(database)) as db:
        db.row_factory = sqlite3.Row

        # Claims are only available for found items.
        listing = db.execute(
            "SELECT user_id, description, location FROM listings "
            "WHERE id = ? AND item_type = 'found'",
            (listing_id,),
        ).fetchone()

        if listing is None:
            abort(404)

        is_poster = listing["user_id"] == student_id

        if request.method == "POST":
            if is_poster:
                abort(403)

            message = request.form.get("message", "").strip()
            if message:
                # Get the claimant's ID from their login session.
                db.execute(
                    f"INSERT INTO claims (listing_id, claimant_id, message) "
                    f"VALUES ({listing_id}, {student_id}, '{message}')"
                )
                db.commit()
                return redirect(url_for("listing_claims", listing_id=listing_id))

            error = "Enter a detail that helps identify the item."

        # The poster can read all claims. Other students can only read their own.
        claims = db.execute(
            """
            SELECT users.username, claims.message
            FROM claims
            JOIN users ON users.id = claims.claimant_id
            WHERE claims.listing_id = ?
              AND (? = 1 OR claims.claimant_id = ?)
            ORDER BY claims.id DESC
            """,
            (listing_id, is_poster, student_id),
        ).fetchall()

    return render_template(
        "claims.html", listing=listing, claims=claims, is_poster=is_poster, error=error
    )
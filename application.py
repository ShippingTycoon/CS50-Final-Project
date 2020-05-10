import os
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///audio_test.db")

@app.route("/")
@login_required
def index():
    # TODO
    return render_template("index.html")

@app.route("/test", methods=["GET", "POST"])
@login_required
def test():

    if request.method == "POST":

        speaker_name = request.form.get("speaker")
        speaker_from_list = request.form.get("speaker_list")

        # Ensure user didn't select speaker from list and type one in
        if speaker_name == True and speaker_from_list == True:
            return apology("Cannot select speaker from list and type one simultaneously")

        # Ensure user selected a speaker or typed a new one
        if not speaker_name and not speaker_from_list:
            return apology("Must select a speaker or provide new one")

        # Check if speaker entered already exists
        if speaker_name == True:
            duplicates = db.execute("SELECT FROM speakers WHERE name = :name", name = speaker_name)
            if duplicates == True:
                return apology("The speaker name you provided already exists")
            # Insert new speaker name into database
            else:
                db.execute("INSERT INTO speakers (name) VALUES (:name)", name = speaker_name)

        60hz = request.form.get("heard60")
        50hz = request.form.get("heard50")
        40hz = request.form.get("heard40")
        30hz = request.form.get("heard30")
        20hz = request.form.get("heard20")
        

    else:
        return render_template("test.html")




# Personal Touch change password
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "POST":

        password = request.form.get("password")

        # Ensure user entered password
        if not password:
            return apology("Type your correct password")

        user_id = session.get("user_id")

        # query database for users current hashed password
        hashed_val = db.execute("SELECT * FROM users WHERE user_id = :user_id", user_id = user_id)

        hashed_password = hashed_val[0]['hash']

        # Check user has entered their password correctly
        if check_password_hash(hashed_password, password) == True:
            current_password = check_password_hash(hashed_password, password)
        else:
            return apology("Incorrect current password")

        new_password = request.form.get("new_password")

        # Ensure user enters new password
        if not new_password:
            return apology("Must enter new password")

        confirmation = request.form.get("confirmation")

        # Ensure user enters new password confirmation
        if not confirmation:
            return apology("Must confirm new password")

        # Ensure new password and confirmation match
        if new_password != confirmation:
            return apology("New password and confirmation fields do not match")

        hashed_password = generate_password_hash(new_password)

        # Update hashed password in users table
        db.execute("UPDATE users SET hash = :hashed_password WHERE user_id = :user_id",
        hashed_password = hashed_password, user_id = user_id)

        return redirect("/logout")

    else:
        return render_template("change_password.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirmation of password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password", 403)

        # Check for discrepancies between password and confirmation
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Query database for username & check if already taken
        username = request.form.get("username")
        profile = db.execute("SELECT username FROM users WHERE username = :username", username=username)
        if username == profile:
            return apology("username already taken")

        # Enter username and password into users database
        else:
            password = request.form.get("password")
            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed_password)",
            username=username, hashed_password=hashed_password)
            # Take user to login page
            return redirect("/login")

    # Take user to register.html
    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

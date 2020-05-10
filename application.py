import os
import re
import sqlite3

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import escape
#from flask_login import LoginManager, UserMixin, current_user, login_user

from helpers import check_password, register_user, count_user, login_required, apology, get_login, get_userid, get_username, add_status

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = b'\xa9r\xd0\xd9\xc5X\r\xc8\x7f\xec\xbb\xfd\xc9\xf0\x1c\x97'
Session(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ignore cache (remove this after editing css(?))
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# index page 
@app.route('/', methods=["GET", "POST"])
def index():

    # Placeholder 
    if "user_id" in session:

        username = get_username(int(session["user_id"]))
        currUser = "Logged in as " + username + " [" + str(session["user_id"]) + "]"

    # Print user id   
    else:
        currUser = "Not logged in"


    if request.method == "POST":
        
        statusText = request.form.get("userstatus")
        
        # if status textarea is empty
        if not statusText:
            return redirect('/')
        
        add_status(statusText, session["user_id"])

   

    return render_template("index.html", test=currUser)

@app.route('/login', methods=["GET", "POST"])
def login():
    
    # forget any user_id
    session.clear()

    if request.method == "POST":
        
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username or password was submitted
        if not username or not password:
            flash('Input valid username or password')
            return render_template("login.html")

        # check if user exists in table
        if count_user(username) != 1 or check_password(username,password) == False:
            flash('Invalid username or password')
            return render_template("/login.html")

        # Query database for username
        userid = get_userid(username, password)
            
        # Remember which user has logged in
        session["user_id"] = userid
        
        # Redirect user to home page
        return redirect("/")
        
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        passwordRepeat = request.form.get("passwordRepeat")

        if not username or not password:
            flash('Input valid username or password')
            return render_template("register.html")
        elif password != passwordRepeat:
            flash('Passwords do not match')
            return render_template("register.html")
        elif re.match("^[A-Za-z0-9]*$", username) == None:
            flash('Please use only numbers and letters for username')
            return render_template("register.html")
        elif count_user(username) > 0:
            flash('Username taken')
            return render_template("register.html")

        passwordHash = generate_password_hash(password)

        register_user(username,passwordHash)

        return redirect("/login")

    else:
        return render_template("register.html")

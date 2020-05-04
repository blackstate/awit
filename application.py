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

from helpers import login_required, apology, check_login

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

# initial sql connection

# index page 
@app.route('/')
def index():
    
    # Placeholder 
    if "user_id" in session:
        test = session["user_id"]

    # Print user id   
    else:
        test = "benta bryle butaw bisakol bisaya bagsik boogieman boomer bibo bata"

    return render_template("index.html", test=test)

@app.route('/login', methods=["GET", "POST"])
def login():
    
    # forget any user_id
    session.clear()

    if request.method == "POST":
        
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not username:
            return apology("must provide password", 403)

        # Query database for username
        userid = check_login(username, password)
            
        # Remember which user has logged in
        session["user_id"] = userid
        
        # Redirect user to home page
        return redirect("/")
        
    else:

        return render_template("login.html")
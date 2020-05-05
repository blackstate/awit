import os
import re
import sqlite3

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import escape
from functools import wraps

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):

        for old, new in [("-", "--"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", code=code, message=escape(message)), code

def count_user(username):
    """checks if user exists in table"""

    con = sqlite3.connect('awit.db')

    # get rows for queries instead of a tuple
    con.row_factory = sqlite3.Row
    
    # execute query
    db = con.cursor()
    db.execute('select count(id) from users where username = :username', {"username" : username})
    rows = db.fetchall()

    # commit changes and close sqlite session
    con.commit()
    con.close()

    count = rows[0]["count(id)"]

    return count

def check_login(username, password):
    """returns userid if login is valid"""

    con = sqlite3.connect('awit.db')

    # get rows for queries instead of a tuple
    con.row_factory = sqlite3.Row
    
    # execute query
    db = con.cursor()
    db.execute('SELECT * FROM users WHERE username = :username', {"username" : username})

    # place query dict in a variable
    rows = db.fetchall()

    # commit changes and close sqlite session
    con.commit()
    con.close()

    return rows[0]["id"]

def check_password(username,password):

    con = sqlite3.connect('awit.db')

    # get rows for queries instead of a tuple
    con.row_factory = sqlite3.Row
    
    # execute query
    db = con.cursor()
    db.execute('SELECT * FROM users WHERE username = :username', {"username" : username})

    # place query dict in a variable
    rows = db.fetchall()

    # commit changes and close sqlite session
    con.commit()
    con.close()

    if not check_password_hash(rows[0]["hash"], password):
        return False
    else:
        return True

def register_user(username, password):
    """inserts user in the user table"""

    con = sqlite3.connect('awit.db')

    # get rows for queries instead of a tuple
    con.row_factory = sqlite3.Row
    
    # execute query
    db = con.cursor()
    db.execute('INSERT INTO users (username, hash) values (:username, :password)', {"username" : username, "password" : password})
    
    # commit changes and close sqlite session
    con.commit()
    con.close()

    return



def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function




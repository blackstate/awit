import os
import urllib.parse
import sqlite3

from flask import redirect, render_template, request, session
from functools import wraps

con = sqlite3.connect('awit.db')

def check_login(username, password):
    # returns userid if login is valid

    # get rows for queries instead of a tuple
    con.row_factory = sqlite3.Row
    
    # execute query
    db = con.cursor()
    db.execute('SELECT * FROM users WHERE username = :username', {"username" : username})

    # place query dict in a variable
    rows = db.fetchall()

    # check if user exists in table
    if len(rows) != 1:  #or not check_password_hash(rows[0]["hash"], request.form.get("password")):
        return apology("invalid username and/or password", 403)

    # commit changes
    con.commit()

    # close sqlite session
    con.close()

    return rows[0]["id"]


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

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):

        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", code=code, message=escape(message)), code


import sqlite3 as sql
import time
import random
# Added bcrypt to handle password hashing - previously passwords were stored as plain text
# which meant anyone who accessed the database could read every users password immediately
import bcrypt
# Added threading so we can use a lock around the visitor counter
# Without this, two users logging in at the same time would both read the same counter value
# before either one writes back, causing the count to be wrong
import threading
counter_lock = threading.Lock()

def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Previously the raw password was passed straight into the database with no protection
    # Now we run it through bcrypt before storing it, so even if the database is exposed
    # the actual passwords cannot be read directly
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()

def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Previously this query was built using an f-string which dropped the username directly
    # into the SQL query, allowing an attacker to manipulate the query logic entirely
    # Now it uses a parameterised query so the input is always treated as data, never as SQL
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if user == None:
        con.close()
        return False
    else:
        # Previously the password was checked with a second SQL query using an f-string
        # which had the same SQL injection problem as above
        # Now we fetch the stored hash and use bcrypt to compare it against what was submitted
        # This means the plain text password is never stored or compared directly
        if not bcrypt.checkpw(password.encode('utf-8'), user[2]):
            con.close()
            return False
        # Plain text log of visitor count as requested by Unsecure PWA management
        # Wrapped in a lock so only one process can read and write at a time
        # Previously two simultaneous logins would both read the same starting value
        # and both write back the same result, meaning the counter would only go up by one
        # instead of two - the lock prevents that from happening
        with counter_lock:
            with open("visitor_log.txt", "r") as file:
                number = int(file.read().strip())
                number += 1
            with open("visitor_log.txt", "w") as file:
                file.write(str(number))
        # Simulate response time of heavy app for testing purposes
        time.sleep(random.randint(80, 90) / 1000)
        con.close()
        return True


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Previously this was built with an f-string that inserted the feedback directly into
    # the query string, meaning someone could submit SQL as feedback and manipulate the database
    # Now it uses a parameterised query so the feedback is always treated as plain data
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Fetches all feedback from the database safely and stores it before writing to the HTML file
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()
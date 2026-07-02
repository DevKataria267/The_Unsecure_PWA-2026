from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
# Added session import to handle session management for the session fixation fix
from flask import session
import user_management as dbHandler
# Added Flask-WTF to handle CSRF protection
# Previously the app had no CSRF tokens on any forms, meaning a forged request from
# an external site would be accepted by the server without question
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# Secret key is required for Flask-WTF to generate and validate CSRF tokens
# Without this the CSRF protection cannot work
app.config['SECRET_KEY'] = '26.2'
csrf = CSRFProtect(app)


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    # Previously this page had no session check, meaning anyone who knew the URL
    # could navigate directly to it without ever logging in and the page would load fully
    # Now we check whether the user has an active session before serving the page
    # and redirect them back to login if they do not
    if not session.get('user'):
        return redirect("/index.html")
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Previously the URL parameter was never validated, so an attacker could craft a link
        # that started with the legitimate domain but redirected victims to any external site
        # Now we check the destination against a list of approved internal paths
        # and send anyone with an unrecognised destination to the home page instead
        allowed = ["/", "/index.html", "/success.html", "/signup.html"]
        if url not in allowed:
            return redirect("/", code=302)
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Same open redirect fix applied here as on the other routes
        # The destination is checked against the approved list before any redirect happens
        allowed = ["/", "/index.html", "/success.html", "/signup.html"]
        if url not in allowed:
            return redirect("/", code=302)
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB = request.form["dob"]
        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # Same open redirect fix applied here as on the other routes
        allowed = ["/", "/index.html", "/success.html", "/signup.html"]
        if url not in allowed:
            return redirect("/", code=302)
        return redirect(url, code=302)
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            # Previously the session ID was never regenerated after login
            # which meant an attacker who planted a known session ID on a victims browser
            # could take over their session the moment they logged in
            # Clearing the session and setting a new one invalidates anything planted beforehand
            session.clear()
            session['user'] = username
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn)
        else:
            return render_template("/index.html")
    else:
        return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    # Previously debug was set to True which meant any error would return a detailed page
    # showing internal file paths, framework versions, and line numbers to anyone who triggered one
    # Turned off so errors return a plain generic message instead of exposing application internals
    app.run(debug=False, host="0.0.0.0", port=5000)
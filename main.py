from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import session
import user_management as dbHandler
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = '26.2'
csrf = CSRFProtect(app)


@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    # User must be logged in to access this page, redirect to login if not
    if not session.get('user'):
        return redirect("/index.html")
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        # URL parameter was never validated so attackers could redirect victims to any site
        # Fix: only allow redirects to internal pages that are on the approved list
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
            # Fix: regenerate session after login so any planted session ID becomes invalid
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
    # Debug mode disabled so errors no longer expose internal file paths or stack traces
    app.run(debug=False, host="0.0.0.0", port=5000)
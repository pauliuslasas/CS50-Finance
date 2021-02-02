import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    rows = db.execute(
        "SELECT symbol, SUM(shares) as Total FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING Total > 0;", user_id=session["user_id"])
    current = []
    TotalSum = 0
    for row in rows:
        stock = lookup(row["symbol"])
        test = row["Total"]
        test2 = stock["price"]
        totals = test * test2
        TotalSum += totals
        current.append({"symbol": stock["symbol"], "name": stock["name"], "shares": row["Total"],
                        "price": usd(stock["price"]), "totals": usd(totals)})

    result = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])
    cash = result[0]["cash"]
    TotalSum += cash

    return render_template("index.html", current=current, cash=usd(cash), TotalSum=usd(TotalSum))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        shares = request.form.get("shares")
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide shares", 403)
        if shares.isdigit() == False:
            return apology("must provide valid number of shares", 400)
        if int(shares) <= 0:
            return apology("must provide valid number of shares", 400)

        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol", 400)

        shares = int(request.form.get("shares"))
        result = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = result[0]["cash"]

        updated_cash = cash - shares * stock['price']
        if updated_cash < 0:
            return apology("Insufficient funds")

        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id", updated_cash=updated_cash, id=session["user_id"])

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"], symbol=stock["symbol"], shares=shares, price=stock["price"])

        flash("Bought!")
        return redirect('/')
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    hist = db.execute("SELECT symbol, shares, price, transacted FROM transactions WHERE user_id=:user_id",
                      user_id=session["user_id"])
    return render_template("history.html", hist=hist)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)

        symbol = request.form.get("symbol").upper()

        stock = lookup(symbol)

        if stock is None:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=usd(stock["price"]))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        result = db.execute("SELECT username FROM users")
        for i in result:
            if i["username"] == request.form.get("username"):
                return apology("username already exists", 400)
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords doesn't match", 400)

        else:
            username = request.form.get("username"),
            hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
            session["user_id"] = rows[0]["id"]
            return redirect("/")
    else:
        return render_template("register.html")


@app.route("/changepass", methods=["GET", "POST"])
def changepass():
    if request.method == "POST":
        if not request.form.get("oldpass"):
            return apology("must provide old password", 403)
        elif not request.form.get("newpassword"):
            return apology("must provide new password", 403)
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 403)
        else:
            oldpass = request.form.get("oldpass")
            result = db.execute("SELECT hash FROM users WHERE id=:user_id", user_id=session["user_id"])
            oldhash = result[0]["hash"]
            if check_password_hash(oldhash, oldpass) == False:
                return apology("Incorrect password", 403)

            else:
                hash = generate_password_hash(request.form.get("newpassword"))
                db.execute("UPDATE users SET hash=:hash", hash=hash)
                flash("Password Changed")
                return redirect('/')
    else:
        return render_template("changepass.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide shares", 403)
        if int(request.form.get("shares")) <= 0:
            return apology("must provide valid number of shares")

        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)
        if stock is None:
            return apology("invalid symbol", 400)
        totals = db.execute(
            "SELECT symbol, SUM(shares) as Total FROM transactions WHERE user_id=:user_id GROUP BY symbol HAVING Total > 0", user_id=session["user_id"])
        print(totals)
        for i in totals:
            if i["symbol"] == symbol:
                if shares > i["Total"]:
                    return apology("Not enough shares!", 400)

        result = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = result[0]["cash"]

        updated_cash = cash + shares * stock['price']
        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id", updated_cash=updated_cash, id=session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"], symbol=stock["symbol"], shares=-1 * shares, price=stock["price"])

        flash("Sold!")
        return redirect('/')

    else:
        rows = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0;", user_id=session["user_id"])
        symbols = [row["symbol"] for row in rows]
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

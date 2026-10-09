from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# -----------------------------
# Create Database
# -----------------------------
def create_database():

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        password TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability TEXT,
        risk_type TEXT,
        severity TEXT,
        description TEXT
    )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# Login
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )

        user = cursor.fetchone()
        conn.close()

        if user:
            return redirect(url_for("dashboard"))
        else:
            return "Invalid Username or Password"

    return render_template("login.html")


# -----------------------------
# Register
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users(username,email,password) VALUES(?,?,?)",
            (username, email, password)
        )

        conn.commit()
        conn.close()

        return "Registration Successful"

    return render_template("register.html")
# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():
    return redirect(url_for("login"))


# -----------------------------
# Risk Assessment
# -----------------------------
@app.route("/risk_assessment", methods=["GET", "POST"])
def risk_assessment():

    if request.method == "POST":

        vulnerability = request.form["vulnerability"]

        # Automatic Risk Details
        if vulnerability == "SQL Injection":
            risk_type = "Database Attack"
            severity = "High"
            description = "Attacker can access or modify database."

        elif vulnerability == "Cross Site Scripting":
            risk_type = "Client Side Attack"
            severity = "Medium"
            description = "Attacker can execute malicious scripts."

        elif vulnerability == "Weak Password":
            risk_type = "Authentication Attack"
            severity = "High"
            description = "Weak passwords can be easily guessed."

        elif vulnerability == "Phishing":
            risk_type = "Social Engineering"
            severity = "High"
            description = "Users may disclose sensitive information."

        else:
            risk_type = "Unknown"
            severity = "Low"
            description = "No description available."

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO risks
            (vulnerability, risk_type, severity, description)
            VALUES (?, ?, ?, ?)
            """,
            (vulnerability, risk_type, severity, description)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("risk_reports"))

    return render_template("risk_assessment.html")


# -----------------------------
# Risk Reports
# -----------------------------
@app.route("/risk_reports")
def risk_reports():

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM risks")

    risks = cursor.fetchall()

    conn.close()

    return render_template("risk_reports.html", risks=risks)


# -----------------------------
# Run Application
# -----------------------------
if __name__ == "__main__":
    create_database()
    app.run(debug=True)
    

from flask import Flask, render_template, request
import re
from datetime import datetime

app = Flask(__name__)

# ================== GLOBAL ALERT STORAGE ==================
attack_alerts = []   # runtime alerts (dashboard ke liye)

# ================== ATTACK PATTERNS ==================
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(#)",
    r"(?i)(or|and)\s+\d=\d",
    r"(?i)union\s+select"
]

XSS_PATTERNS = [
    r"<script>",
    r"</script>",
    r"javascript:",
    r"onerror=",
    r"onload="
]

# ================== DETECTION FUNCTION ==================
def detect_attack(text):
    for p in SQLI_PATTERNS:
        if re.search(p, text):
            return "SQL Injection"
    for p in XSS_PATTERNS:
        if re.search(p, text, re.IGNORECASE):
            return "XSS Attack"
    return None

# ================== HOME ==================
@app.route("/")
def home():
    return render_template("index.html")

# ================== DASHBOARD ==================
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", alerts=attack_alerts)

# ================== ADMIN LOGIN ==================
@app.route("/admin-login", methods=["POST"])
def admin_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    ip = request.remote_addr
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    attack = detect_attack(username + password)

    if attack:
        alert = {
            "type": attack,
            "ip": ip,
            "time": time
        }
        attack_alerts.insert(0, alert)  # latest first

        with open("attack_log.txt", "a") as f:
            f.write(f"[{time}] {attack} from {ip}\n")

        return """
        <h2 style='color:red;'>⚠️ ATTACK DETECTED</h2>
        <p>Request blocked & logged</p>
        <a href='/dashboard'>Go to Dashboard</a>
        """

    if username == "admin" and password == "admin123":
        return """
        <h2 style='color:green;'>Login Successful</h2>
        <a href='/dashboard'>Go to Dashboard</a>
        """

    return "<h3>Invalid Credentials</h3>"

if __name__ == "__main__":
    app.run(debug=True)
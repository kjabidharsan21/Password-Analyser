from flask import Flask, render_template, request, jsonify
import re
import sqlite3
import hashlib
import secrets
import string
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "passwords.db"

COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "admin", "admin123", "letmein",
    "welcome", "abc123", "iloveyou", "monkey", "dragon"
}


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def was_used_before(user_id, password):
    password_hash = hash_password(password)
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT 1 FROM password_history WHERE user_id = ? AND password_hash = ? LIMIT 1",
            (user_id, password_hash)
        ).fetchone()
    return row is not None


def save_password_hash(user_id, password):
    password_hash = hash_password(password)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
            (user_id, password_hash)
        )
        conn.commit()


def analyze_password(password):
    score = 0
    checks = []
    suggestions = []

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))
    repeated = bool(re.search(r"(.)\1{2,}", password))
    common = password.lower() in COMMON_PASSWORDS

    # Length
    if length >= 16:
        score += 3
        checks.append(("Password length is excellent.", True))
    elif length >= 12:
        score += 2
        checks.append(("Password length is good.", True))
    elif length >= 8:
        score += 1
        checks.append(("Password has the minimum recommended length.", True))
    else:
        checks.append(("Password is too short.", False))
        suggestions.append("Use at least 12 characters.")

    # Character complexity
    if has_lower:
        score += 1
        checks.append(("Contains lowercase letters.", True))
    else:
        checks.append(("No lowercase letters found.", False))
        suggestions.append("Add lowercase letters.")

    if has_upper:
        score += 1
        checks.append(("Contains uppercase letters.", True))
    else:
        checks.append(("No uppercase letters found.", False))
        suggestions.append("Add uppercase letters.")

    if has_digit:
        score += 1
        checks.append(("Contains numbers.", True))
    else:
        checks.append(("No numbers found.", False))
        suggestions.append("Add numbers.")

    if has_special:
        score += 1
        checks.append(("Contains special characters.", True))
    else:
        checks.append(("No special characters found.", False))
        suggestions.append("Add special characters such as !, @, # or $.")

    # Predictability
    if common:
        score = max(0, score - 3)
        checks.append(("Password matches a common weak password.", False))
        suggestions.append("Avoid common passwords and predictable words.")
    else:
        checks.append(("Password is not in the common-password list.", True))

    if repeated:
        score = max(0, score - 1)
        checks.append(("Repeated characters detected.", False))
        suggestions.append("Avoid repeated characters such as aaa or 111.")
    else:
        checks.append(("No obvious repeated-character pattern.", True))

    # Simple sequential pattern check
    lower_password = password.lower()
    sequences = [
        "123456", "234567", "345678", "456789",
        "abcdef", "bcdefg", "qwerty"
    ]
    if any(seq in lower_password for seq in sequences):
        score = max(0, score - 2)
        checks.append(("Predictable sequence detected.", False))
        suggestions.append("Avoid sequences such as 123456 or abcdef.")
    else:
        checks.append(("No obvious sequential pattern detected.", True))

    if score <= 3:
        strength = "Weak"
    elif score <= 6:
        strength = "Medium"
    elif score <= 8:
        strength = "Strong"
    else:
        strength = "Very Strong"

    # Improvement message
    if not suggestions:
        suggestions.append("Good password structure. Avoid reusing it on other websites.")

    percentage = min(100, round((score / 10) * 100))

    return {
        "strength": strength,
        "score": score,
        "percentage": percentage,
        "checks": [{"message": m, "passed": p} for m, p in checks],
        "suggestions": suggestions
    }


def generate_password(length=16):
    length = max(12, min(int(length), 32))

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r"[a-z]", password)
            and re.search(r"[A-Z]", password)
            and re.search(r"\d", password)
            and re.search(r"[^A-Za-z0-9]", password)
        ):
            return password


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Please enter a password."}), 400

    return jsonify(analyze_password(password))


@app.route("/generate", methods=["GET"])
def generate():
    length = request.args.get("length", 16, type=int)
    password = generate_password(length)
    return jsonify({
        "password": password,
        "analysis": analyze_password(password)
    })


@app.route("/check-reuse", methods=["POST"])
def check_reuse():
    data = request.get_json()
    user_id = data.get("user_id", "").strip()
    password = data.get("password", "")

    if not user_id or not password:
        return jsonify({"error": "User ID and password are required."}), 400

    return jsonify({
        "reused": was_used_before(user_id, password)
    })


@app.route("/save-password", methods=["POST"])
def save_password():
    data = request.get_json()
    user_id = data.get("user_id", "").strip()
    password = data.get("password", "")

    if not user_id or not password:
        return jsonify({"error": "User ID and password are required."}), 400

    if was_used_before(user_id, password):
        return jsonify({
            "saved": False,
            "message": "This password was already used."
        })

    save_password_hash(user_id, password)

    return jsonify({
        "saved": True,
        "message": "Password hash saved successfully."
    })


init_db()

if __name__ == "__main__":
    app.run(debug=True)

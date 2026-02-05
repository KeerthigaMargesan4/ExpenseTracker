from flask import Flask, request, jsonify, session, send_from_directory, redirect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "expense-secret-key"

DB = "expenses.db"

# ---------- DB ----------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            type TEXT,
            bank TEXT,
            category TEXT,
            description TEXT,
            amount REAL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- HTML ----------
@app.route("/")
def root():
    return send_from_directory(".", "index.html")

# ---------- AUTH ----------
@app.route("/register", methods=["POST"])
def register():
    data = request.json

    if not data.get("username") or not data.get("password"):
        return jsonify({"msg": "Missing fields"}), 400

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users(username,password) VALUES (?,?)",
            (data["username"], generate_password_hash(data["password"]))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"msg": "User already exists"}), 400
    finally:
        conn.close()

    return jsonify({"msg": "Registered"}), 200

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (data["username"],)
    ).fetchone()

    if user and check_password_hash(user["password"], data["password"]):
        session["user"] = user["username"]
        return jsonify({"msg": "ok"})
    return jsonify({"msg": "Invalid"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"msg": "bye"})

# ---------- EXPENSE API ----------
@app.route("/add-expense", methods=["POST"])
def add_expense():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    d = request.json
    conn = get_db()
    conn.execute("""
        INSERT INTO expenses(date,type,bank,category,description,amount)
        VALUES (?,?,?,?,?,?)
    """, (
        d["date"], d["type"], d["bank"],
        d["category"], d["description"], d["amount"]
    ))
    conn.commit()
    return jsonify({"msg": "saved"})

@app.route("/expenses")
def expenses():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    rows = conn.execute("SELECT * FROM expenses ORDER BY date").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/expense/<int:id>", methods=["DELETE"])
def delete_expense(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    conn.execute("DELETE FROM expenses WHERE id=?", (id,))
    conn.commit()
    return jsonify({"msg": "deleted"})

@app.route("/expense/<int:id>", methods=["PUT"])
def update_expense(id):
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    d = request.json
    conn = get_db()
    conn.execute("""
        UPDATE expenses
        SET date=?, type=?, bank=?, category=?, description=?, amount=?
        WHERE id=?
    """, (
        d["date"], d["type"], d["bank"],
        d["category"], d["description"], d["amount"],
        id
    ))
    conn.commit()
    return jsonify({"msg": "updated"})

if __name__ == "__main__":
    app.run(debug=True)

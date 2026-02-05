from flask import Flask, request, jsonify, session, send_from_directory, redirect
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__, static_folder='.', static_url_path='')
SECRET_KEY = "expense-jwt-secret"
CORS(app, supports_credentials=True)
DB = "expenses.db"

# ---------- JWT helper ----------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # JWT is passed in the request header
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split()[1]
            except IndexError:
                return jsonify({"error": "Token missing"}), 401
        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
        except Exception as e:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated
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
        # Create JWT token
        token = jwt.encode({
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})  # return token instead of session
    return jsonify({"msg": "Invalid"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    return jsonify({"msg": "bye"})

# ---------- EXPENSE API ----------
def validate_expense_data(d):
    if not d.get("date"):
        return "Date is required"
    if d.get("type") not in ["Income", "Expense"]:
        return "Invalid type"
    if d.get("bank") not in ["ICICI", "Credit Card"]:
        return "Invalid bank"

    income_categories = ["Salary", "Interest", "Dividend", "Reimbursement"]
    expense_categories = ["Home Expense", "Investment", "Self Expense", "Other Expense", "Hospital"]
    categories = income_categories if d["type"]=="Income" else expense_categories
    if d.get("category") not in categories:
        return "Invalid category"

    try:
        amount = float(d.get("amount", 0))
        if amount <= 0:
            return "Amount must be positive"
    except:
        return "Invalid amount"

    if d.get("description") and len(d["description"]) > 100:
        return "Description too long"

    return None
@app.route("/add-expense", methods=["POST"])
@token_required
def add_expense(current_user):
    d = request.json
    error = validate_expense_data(d)
    if error:
        return jsonify({"msg": error}), 400
    conn = get_db()
    conn.execute("""
        INSERT INTO expenses(date,type,bank,category,description,amount)
        VALUES (?,?,?,?,?,?)
    """, (
        d["date"], d["type"], d["bank"], d["category"], d["description"], d["amount"]
    ))
    conn.commit()
    return jsonify({"msg": "saved"})

@app.route("/expenses")
@token_required
def expenses(current_user):
    conn = get_db()
    rows = conn.execute("SELECT * FROM expenses ORDER BY date").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/expense/<int:id>", methods=["DELETE"])
@token_required
def delete_expense(current_user, id):
    conn = get_db()
    conn.execute("DELETE FROM expenses WHERE id=?", (id,))
    conn.commit()
    return jsonify({"msg": "deleted"})

@app.route("/expense/<int:id>", methods=["PUT"])
@token_required
def update_expense(current_user, id):
    d = request.json
    error = validate_expense_data(d)
    if error:
        return jsonify({"msg": error}), 400
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
    app.run(host="0.0.0.0", port=5000, debug=True)

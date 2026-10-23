# DVNA / Vuln Flask App SQL Injection
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/account')
def get_account():
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Vulnerable SQL query formatting with user controlled variable
    query = f"SELECT id, username, balance FROM accounts WHERE id = {user_id}"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"id": row[0], "username": row[1], "balance": row[2]})
    return jsonify({"error": "Account not found"}), 404

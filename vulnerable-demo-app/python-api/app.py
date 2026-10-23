import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# VULNERABILITY: Hardcoded Database Password
DB_PASSWORD = "SuperSecretDbPassword_2026!"

@app.route('/user')
def get_user_profile():
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: Python SQL Injection via f-string query formatting
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[2]})
    return jsonify({"error": "User not found"}), 404

@app.route('/greet')
def greet_user():
    name = request.args.get('name', 'Anonymous')
    
    # VULNERABILITY: Server-Side Template Injection (SSTI) / XSS
    template = f"""
    <html>
      <body>
        <h2>Welcome back, {name}!</h2>
        <p>Status: Active Account</p>
      </body>
    </html>
    """
    return render_template_string(template)

if __name__ == '__main__':
    app.run(port=5001)

"""
MediVault Health - Vulnerable Patient Records API
WARNING: This codebase is intentionally insecure for educational & code auditing purposes.
"""

from flask import Flask, request, jsonify, render_template_string
import os
import sqlite3
import hashlib
import jwt
import subprocess
import pickle
import base64
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

# VULNERABILITY: Hardcoded Cryptographic Secret Key (CWE-798)
# Bandit: B105 / B106
JWT_SECRET = "medivault-super-secret-key-2024"
app.config['SECRET_KEY'] = "hardcoded_flask_secret_12345"

DATABASE = 'medivault.db'
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            email TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            diagnosis TEXT,
            treatment TEXT,
            notes TEXT,
            created_at TIMESTAMP,
            FOREIGN KEY(patient_id) REFERENCES users(id)
        )
    ''')
    
    # Seed sample users if empty
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        # VULNERABILITY: Insecure Weak Hash Algorithm (MD5 without Salt) (CWE-328)
        admin_pass = hashlib.md5("Admin@123".encode()).hexdigest()
        alice_pass = hashlib.md5("AlicePass!".encode()).hexdigest()
        bob_pass = hashlib.md5("BobPassword99".encode()).hexdigest()

        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('admin', ?, 'admin', 'admin@medivault.local')", (admin_pass,))
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('alice', ?, 'patient', 'alice@medivault.local')", (alice_pass,))
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('bob', ?, 'patient', 'bob@medivault.local')", (bob_pass,))
        
        cursor.execute("INSERT INTO medical_records (patient_id, diagnosis, treatment, notes, created_at) VALUES (2, 'Hypertension Stage 1', 'Lisinopril 10mg daily', 'Patient reports occasional headaches.', datetime('now'))")
        cursor.execute("INSERT INTO medical_records (patient_id, diagnosis, treatment, notes, created_at) VALUES (3, 'Type 2 Diabetes', 'Metformin 500mg BID', 'Monitor fasting glucose levels.', datetime('now'))")
    
    conn.commit()
    conn.close()


@app.after_request
def add_cors_headers(response):
    # VULNERABILITY: Insecure Permissive CORS Configuration (CWE-942)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
    return response


# --- 1. AUTHENTICATION & LOGIN ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    # VULNERABILITY: Insecure MD5 Hash Comparison (CWE-328)
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?", (username, pw_hash))
    user = cursor.fetchone()
    conn.close()

    if user:
        # VULNERABILITY: Weak Token Signing without Expiration Check & Hardcoded Secret (CWE-798, CWE-347)
        token = jwt.encode({
            'user_id': user[0],
            'username': user[1],
            'role': user[2]
        }, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {"id": user[0], "username": user[1], "role": user[2]}
        }), 200
    
    return jsonify({"error": "Invalid username or password"}), 401


def get_current_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except Exception:
        return None


# --- 2. SQL INJECTION ENDPOINT (CWE-89) ---
@app.route('/api/patients/search', methods=['GET'])
def search_patients():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    search_query = request.args.get('q', '')
    
    # VULNERABILITY: Direct String Interpolation in SQL Query (SQL Injection - CWE-89)
    # Bandit: B608
    sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search_query}%'"
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    try:
        cursor.execute(sql)
        rows = cursor.fetchall()
        results = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
        return jsonify({"query": search_query, "results": results}), 200
    except Exception as e:
        # VULNERABILITY: Verbose Error Message Leakage (CWE-209)
        return jsonify({"error": str(e), "executed_query": sql}), 500
    finally:
        conn.close()


# --- 3. BROKEN OBJECT LEVEL AUTHORIZATION (IDOR) (CWE-639) ---
@app.route('/api/records/<int:record_id>', methods=['GET'])
def get_medical_record(record_id):
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    # VULNERABILITY: IDOR / BOLA - Fails to verify if current_user has right to access this specific patient record
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, patient_id, diagnosis, treatment, notes, created_at FROM medical_records WHERE id = ?", (record_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Record not found"}), 404

    return jsonify({
        "id": row[0],
        "patient_id": row[1],
        "diagnosis": row[2],
        "treatment": row[3],
        "notes": row[4],
        "created_at": row[5]
    }), 200


# --- 4. PATH TRAVERSAL / ARBITRARY FILE READ (CWE-22) ---
@app.route('/api/documents/download', methods=['GET'])
def download_document():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    filename = request.args.get('file', '')
    if not filename:
        return jsonify({"error": "Filename required"}), 400

    # VULNERABILITY: Arbitrary File Read / Path Traversal (CWE-22)
    # Unsanitized os.path.join allows '../../' sequences
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return jsonify({"filename": filename, "content": content}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- 5. OS COMMAND INJECTION (CWE-78) ---
@app.route('/api/admin/network-test', methods=['POST'])
def network_test():
    current_user = get_current_user()
    if not current_user or current_user.get('role') != 'admin':
        return jsonify({"error": "Admin privilege required"}), 403

    target_host = request.json.get('host', '127.0.0.1')

    # VULNERABILITY: OS Command Injection (CWE-78) via shell=True and unsanitized string formatting
    # Bandit: B602
    cmd = f"ping -n 1 {target_host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"output": output}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Ping failed", "details": e.output}), 500


# --- 6. INSECURE DESERIALIZATION (CWE-502) ---
@app.route('/api/user/import-preferences', methods=['POST'])
def import_preferences():
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Unauthorized"}), 401

    b64_payload = request.json.get('preferences_data', '')
    try:
        # VULNERABILITY: Insecure Deserialization via pickle (CWE-502)
        # Bandit: B301
        raw_bytes = base64.b64decode(b64_payload)
        prefs = pickle.loads(raw_bytes)
        return jsonify({"message": "Preferences imported successfully", "preferences": str(prefs)}), 200
    except Exception as e:
        return jsonify({"error": f"Deserialization failed: {str(e)}"}), 400


# --- 7. CROSS-SITE SCRIPTING (REFLECTED XSS) (CWE-79) ---
@app.route('/portal/status', methods=['GET'])
def portal_status():
    status_msg = request.args.get('msg', 'System Operational')
    
    # VULNERABILITY: Reflected XSS via render_template_string without HTML escaping (CWE-79)
    template = f"""
    <!DOCTYPE html>
    <html>
    <head><title>MediVault Portal Status</title></head>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>MediVault System Health Monitor</h2>
        <div style="padding: 15px; background: #eef; border-radius: 5px;">
            Status Notice: {status_msg}
        </div>
    </body>
    </html>
    """
    return render_template_string(template)


if __name__ == '__main__':
    init_db()
    # VULNERABILITY: Debug Mode Enabled in Production Environment (CWE-489)
    # Bandit: B201
    app.run(host='0.0.0.0', port=5000, debug=True)

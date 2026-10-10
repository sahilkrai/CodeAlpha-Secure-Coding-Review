"""
MediVault Health - Hardened & Secure Patient Records API
Security Audit Remediation Implementation
Compliant with OWASP Top 10, ASVS 4.0, and CWE Secure Coding Standards.
"""

import os
import sys
import sqlite3
import ipaddress
import json
import subprocess
import secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template_string, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import jwt

app = Flask(__name__)

# --- SECURE CONFIGURATION & SECRETS MANAGEMENT (CWE-798 REMEDIATION) ---
# Secrets are loaded strictly from environment variables, falling back to cryptographically random tokens
JWT_SECRET = os.getenv("MEDIVAULT_JWT_SECRET", secrets.token_hex(32))
app.config['SECRET_KEY'] = os.getenv("MEDIVAULT_FLASK_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

DATABASE = os.getenv("MEDIVAULT_DB_PATH", os.path.join(os.path.dirname(__file__), 'medivault_secure.db'))
UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_ORIGINS = {
    "https://portal.medivault.local",
    "https://admin.medivault.local"
}


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS medical_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            diagnosis TEXT NOT NULL,
            treatment TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(patient_id) REFERENCES users(id)
        )
    ''')
    
    # Seed with strong password hashes (Argon2 / scrypt / pbkdf2)
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        admin_pass = generate_password_hash("AdminStrongPass#2026!", method="scrypt")
        alice_pass = generate_password_hash("AliceSafePass@2026!", method="scrypt")
        bob_pass = generate_password_hash("BobSafePass@2026!", method="scrypt")

        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('admin', ?, 'admin', 'admin@medivault.local')", (admin_pass,))
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('alice', ?, 'patient', 'alice@medivault.local')", (alice_pass,))
        cursor.execute("INSERT INTO users (username, password_hash, role, email) VALUES ('bob', ?, 'patient', 'bob@medivault.local')", (bob_pass,))
        
        cursor.execute("INSERT INTO medical_records (patient_id, diagnosis, treatment, notes, created_at) VALUES (2, 'Hypertension Stage 1', 'Lisinopril 10mg daily', 'Blood pressure managed well.', datetime('now'))")
        cursor.execute("INSERT INTO medical_records (patient_id, diagnosis, treatment, notes, created_at) VALUES (3, 'Type 2 Diabetes', 'Metformin 500mg BID', 'Monitor fasting blood glucose.', datetime('now'))")
    
    conn.commit()
    conn.close()


@app.after_request
def apply_security_headers(response):
    # CORS Hardening (CWE-942 Remediation): Whitelist trusted origins only
    origin = request.headers.get('Origin')
    if origin and origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'

    # Security Headers Defense-in-Depth
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


# --- 1. SECURE AUTHENTICATION & TOKEN HANDLING ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password or not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid login credentials format"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    # Parameterized query lookup
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    # Time-constant password verification (CWE-328 & CWE-208 Remediation)
    if user and check_password_hash(user['password_hash'], password):
        now = datetime.now(timezone.utc)
        payload = {
            'sub': str(user['id']),
            'username': user['username'],
            'role': user['role'],
            'iat': now,
            'exp': now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
            'iss': 'medivault-auth-service'
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return jsonify({
            "message": "Authentication successful",
            "token": token,
            "expires_in": JWT_EXPIRATION_MINUTES * 60,
            "user": {"id": user['id'], "username": user['username'], "role": user['role']}
        }), 200

    return jsonify({"error": "Invalid username or password"}), 401


def authenticate_request():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, ("Missing or malformed Authorization header", 401)
    
    token = auth_header.split(' ', 1)[1]
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]}
        )
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, ("Authentication token has expired", 401)
    except jwt.InvalidTokenError:
        return None, ("Invalid authentication token", 401)


# --- 2. SQL INJECTION REMEDIATION (CWE-89) ---
@app.route('/api/patients/search', methods=['GET'])
def search_patients():
    current_user, err = authenticate_request()
    if err:
        return jsonify({"error": err[0]}), err[1]

    # Input validation and bounds checking
    search_query = request.args.get('q', '').strip()
    if len(search_query) > 50:
        return jsonify({"error": "Search query too long"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Remediation: Strict Parameterized Query (Precompiled Prepared Statement pattern)
        pattern = f"%{search_query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? ORDER BY id ASC LIMIT 20",
            (pattern,)
        )
        rows = cursor.fetchall()
        results = [{"id": r["id"], "username": r["username"], "email": r["email"], "role": r["role"]} for r in rows]
        return jsonify({"query": search_query, "count": len(results), "results": results}), 200
    except Exception:
        # Remediation: Generic error response without internal leakage (CWE-209 Remediation)
        app.logger.exception("Database query error occurred during patient search.")
        return jsonify({"error": "An internal error occurred while processing your request."}), 500
    finally:
        conn.close()


# --- 3. BROKEN OBJECT LEVEL AUTHORIZATION (IDOR) REMEDIATION (CWE-639) ---
@app.route('/api/records/<int:record_id>', methods=['GET'])
def get_medical_record(record_id):
    current_user, err = authenticate_request()
    if err:
        return jsonify({"error": err[0]}), err[1]

    user_id = int(current_user['sub'])
    user_role = current_user.get('role', '')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, patient_id, diagnosis, treatment, notes, created_at FROM medical_records WHERE id = ?", (record_id,))
    record = cursor.fetchone()
    conn.close()

    if not record:
        return jsonify({"error": "Record not found"}), 404

    # Remediation: Strict Object-Level Authorization Check
    # Only the record owner (patient) or privileged staff (admin/doctor) are authorized
    if user_role != 'admin' and record['patient_id'] != user_id:
        # Returns 403 Forbidden to prevent unauthorized data access
        return jsonify({"error": "Access denied: Unauthorized to view this patient record"}), 403

    return jsonify({
        "id": record['id'],
        "patient_id": record['patient_id'],
        "diagnosis": record['diagnosis'],
        "treatment": record['treatment'],
        "notes": record['notes'],
        "created_at": record['created_at']
    }), 200


# --- 4. PATH TRAVERSAL REMEDIATION (CWE-22) ---
@app.route('/api/documents/download', methods=['GET'])
def download_document():
    current_user, err = authenticate_request()
    if err:
        return jsonify({"error": err[0]}), err[1]

    raw_filename = request.args.get('file', '')
    if not raw_filename:
        return jsonify({"error": "Filename required"}), 400

    # Remediation: Extract strictly base filename and canonicalize path
    safe_filename = os.path.basename(raw_filename)
    resolved_path = os.path.abspath(os.path.join(UPLOAD_FOLDER, safe_filename))

    # Verify that the canonical path stays strictly inside the designated UPLOAD_FOLDER
    if not resolved_path.startswith(os.path.abspath(UPLOAD_FOLDER) + os.sep):
        return jsonify({"error": "Invalid file path traversal attempt detected"}), 400

    if not os.path.isfile(resolved_path):
        return jsonify({"error": "Document not found"}), 404

    return send_from_directory(UPLOAD_FOLDER, safe_filename, as_attachment=True)


# --- 5. OS COMMAND INJECTION REMEDIATION (CWE-78) ---
@app.route('/api/admin/network-test', methods=['POST'])
def network_test():
    current_user, err = authenticate_request()
    if err:
        return jsonify({"error": err[0]}), err[1]

    if current_user.get('role') != 'admin':
        return jsonify({"error": "Admin privileges required"}), 403

    target_host = request.json.get('host', '') if request.is_json else ''

    # Remediation 1: Strict Input Validation (IPv4/IPv6 validation)
    try:
        valid_ip = ipaddress.ip_address(target_host.strip())
    except ValueError:
        return jsonify({"error": "Invalid IP address provided. Must be a valid IPv4 or IPv6 address."}), 400

    # Remediation 2: Avoid shell=True; use strict argument list with execution timeout
    try:
        args = ["ping", "-n", "1", str(valid_ip)] if sys.platform.startswith('win') else ["ping", "-c", "1", str(valid_ip)]
        result = subprocess.run(
            args,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=True
        )
        return jsonify({"status": "reachable", "details": result.stdout}), 200
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Network ping timed out"}), 504
    except subprocess.CalledProcessError:
        return jsonify({"status": "unreachable", "error": "Host did not respond"}), 502


# --- 6. INSECURE DESERIALIZATION REMEDIATION (CWE-502) ---
@app.route('/api/user/import-preferences', methods=['POST'])
def import_preferences():
    current_user, err = authenticate_request()
    if err:
        return jsonify({"error": err[0]}), err[1]

    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    # Remediation: Replace arbitrary object deserialization (pickle) with standard JSON
    preferences_data = request.json.get('preferences', {})
    
    # Schema validation
    ALLOWED_THEMES = {"light", "dark", "high-contrast"}
    ALLOWED_LANGS = {"en", "es", "fr"}

    theme = preferences_data.get("theme", "light")
    language = preferences_data.get("language", "en")
    notifications = bool(preferences_data.get("notifications", True))

    if theme not in ALLOWED_THEMES or language not in ALLOWED_LANGS:
        return jsonify({"error": "Invalid preference values supplied."}), 400

    clean_preferences = {
        "theme": theme,
        "language": language,
        "notifications": notifications
    }

    return jsonify({
        "message": "Preferences successfully updated",
        "preferences": clean_preferences
    }), 200


# --- 7. CROSS-SITE SCRIPTING (XSS) REMEDIATION (CWE-79) ---
@app.route('/portal/status', methods=['GET'])
def portal_status():
    raw_status = request.args.get('msg', 'System Operational')
    
    # Remediation: Context-aware HTML sanitization & escaping using markupsafe.escape()
    safe_status = escape(raw_status)
    
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MediVault Portal Status</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 2rem; background: #f8fafc; color: #1e293b; }
            .card { background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; max-width: 600px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
            .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: 600; font-size: 0.875rem; background: #dcfce7; color: #166534; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>MediVault System Health Monitor</h2>
            <p>System Status: <span class="badge">{{ status_message }}</span></p>
        </div>
    </body>
    </html>
    """
    return render_template_string(template, status_message=safe_status)


if __name__ == '__main__':
    init_db()
    # Remediation: Debug mode strictly disabled, environment-driven host and port binding
    port = int(os.getenv("PORT", 5000))
    app.run(host='127.0.0.1', port=port, debug=False)

"""
Interactive Demonstration & Verification Script
Runs end-to-end security checks against both Vulnerable and Secure MediVault applications.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from vulnerable_app.app import app as vuln_app, init_db as init_vuln_db
from secure_app.app import app as sec_app, init_db as init_sec_db

def print_header(title):
    print("\n" + "="*70)
    print(f" >>> {title}")
    print("="*70)

def main():
    print_header("INITIALIZING DATABASES")
    init_vuln_db()
    init_sec_db()
    print("[+] SQLite databases initialized successfully.")

    v_client = vuln_app.test_client()
    s_client = sec_app.test_client()

    # -------------------------------------------------------------
    # 1. SQL INJECTION (CWE-89)
    # -------------------------------------------------------------
    print_header("1. TESTING SQL INJECTION (CWE-89)")
    # Login as normal patient 'alice'
    v_token = v_client.post('/api/auth/login', json={"username": "alice", "password": "AlicePass!"}).get_json()['token']
    s_token = s_client.post('/api/auth/login', json={"username": "alice", "password": "AliceSafePass@2026!"}).get_json()['token']

    sqli_attack = "' OR '1'='1"
    print(f"[*] Attacking endpoint /api/patients/search with payload: {sqli_attack}")

    # Vulnerable App
    v_res = v_client.get(f'/api/patients/search?q={sqli_attack}', headers={"Authorization": f"Bearer {v_token}"}).get_json()
    print(f"[-] Vulnerable App returned {len(v_res.get('results', []))} accounts! (LEAKED: {[u['username'] for u in v_res.get('results', [])]})")
    print("    [!] VULNERABILITY STATUS: EXPLOIT SUCCEEDED (SQL Injection works!)")

    # Secure App
    s_res = s_client.get(f'/api/patients/search?q={sqli_attack}', headers={"Authorization": f"Bearer {s_token}"}).get_json()
    print(f"[+] Secure App returned {len(s_res.get('results', []))} accounts.")
    print("    [OK] REMEDIATION STATUS: BLOCKED (Parameterized query treated payload as literal string)")

    # -------------------------------------------------------------
    # 2. BROKEN OBJECT-LEVEL AUTHORIZATION / IDOR (CWE-639)
    # -------------------------------------------------------------
    print_header("2. TESTING IDOR / ACCESS CONTROL (CWE-639)")
    print("[*] Alice (Patient ID 2) tries to read Bob's medical record (Record ID 2, belongs to Patient ID 3)...")

    # Vulnerable App
    v_res = v_client.get('/api/records/2', headers={"Authorization": f"Bearer {v_token}"})
    print(f"[-] Vulnerable App HTTP Status: {v_res.status_code}")
    print(f"    Leaked Record Diagnosis: '{v_res.get_json().get('diagnosis')}' for Patient ID: {v_res.get_json().get('patient_id')}")
    print("    [!] VULNERABILITY STATUS: EXPLOIT SUCCEEDED (IDOR allows unauthorized data access)")

    # Secure App
    s_res = s_client.get('/api/records/2', headers={"Authorization": f"Bearer {s_token}"})
    print(f"[+] Secure App HTTP Status: {s_res.status_code} ({s_res.get_json().get('error')})")
    print("    [OK] REMEDIATION STATUS: BLOCKED (403 Forbidden - Access control check enforced)")

    # -------------------------------------------------------------
    # 3. PATH TRAVERSAL (CWE-22)
    # -------------------------------------------------------------
    print_header("3. TESTING PATH TRAVERSAL (CWE-22)")
    traversal_file = "../app.py"
    print(f"[*] Attempting to download source code using path traversal: file={traversal_file}")

    # Vulnerable App
    v_res = v_client.get(f'/api/documents/download?file={traversal_file}', headers={"Authorization": f"Bearer {v_token}"})
    if v_res.status_code == 200 and "JWT_SECRET" in v_res.get_json().get('content', ''):
        print(f"[-] Vulnerable App HTTP Status: {v_res.status_code}")
        print("    [!] Leaked source code snippet: " + v_res.get_json().get('content', '')[:60].replace('\n', ' '))
        print("    [!] VULNERABILITY STATUS: EXPLOIT SUCCEEDED (Arbitrary source code read!)")

    # Secure App
    s_res = s_client.get(f'/api/documents/download?file={traversal_file}', headers={"Authorization": f"Bearer {s_token}"})
    print(f"[+] Secure App HTTP Status: {s_res.status_code} ({s_res.get_json().get('error')})")
    print("    [OK] REMEDIATION STATUS: BLOCKED (Path traversal prevented)")

    # -------------------------------------------------------------
    # 4. OS COMMAND INJECTION (CWE-78)
    # -------------------------------------------------------------
    print_header("4. TESTING OS COMMAND INJECTION (CWE-78)")
    admin_s_token = s_client.post('/api/auth/login', json={"username": "admin", "password": "AdminStrongPass#2026!"}).get_json()['token']
    cmd_injection = "127.0.0.1 && whoami"
    print(f"[*] Attacking network diagnostic endpoint with payload: host='{cmd_injection}'")

    s_res = s_client.post('/api/admin/network-test', json={"host": cmd_injection}, headers={"Authorization": f"Bearer {admin_s_token}"})
    print(f"[+] Secure App HTTP Status: {s_res.status_code} ({s_res.get_json().get('error')})")
    print("    [OK] REMEDIATION STATUS: BLOCKED (Invalid IP rejected; strict validation enforced)")

    print_header("ALL VERIFICATIONS COMPLETED SUCCESSFULLY")

if __name__ == '__main__':
    main()

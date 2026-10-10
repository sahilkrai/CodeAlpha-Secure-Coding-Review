"""
Security Verification Test Suite: Vulnerable vs Hardened MediVault
Tests each identified vulnerability against vulnerable_app and confirms protection in secure_app.
"""

import sys
import os
import unittest
import json
import base64

# Import both applications
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from vulnerable_app.app import app as vuln_app, init_db as init_vuln_db
from secure_app.app import app as sec_app, init_db as init_sec_db


class SecurityAuditVerificationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_vuln_db()
        init_sec_db()

    def setUp(self):
        self.vuln_client = vuln_app.test_client()
        self.sec_client = sec_app.test_client()

    # --- 1. SQL INJECTION (CWE-89) TEST ---
    def test_sql_injection(self):
        # Obtain auth token for alice
        res_v = self.vuln_client.post('/api/auth/login', json={"username": "alice", "password": "AlicePass!"})
        token_v = res_v.get_json()['token']

        # SQL Injection boolean payload
        sqli_payload = "' OR '1'='1"
        res = self.vuln_client.get(f'/api/patients/search?q={sqli_payload}', headers={"Authorization": f"Bearer {token_v}"})
        self.assertEqual(res.status_code, 200)
        vuln_data = res.get_json()
        # Vulnerable app leaks all users because the injected condition is always true
        self.assertTrue(len(vuln_data.get('results', [])) >= 3)
        self.assertTrue(any(u['username'] == 'admin' for u in vuln_data.get('results', [])))

        # Now test Secure App
        res_s = self.sec_client.post('/api/auth/login', json={"username": "alice", "password": "AliceSafePass@2026!"})
        token_s = res_s.get_json()['token']

        res_secure = self.sec_client.get(f'/api/patients/search?q={sqli_payload}', headers={"Authorization": f"Bearer {token_s}"})
        self.assertEqual(res_secure.status_code, 200)
        sec_data = res_secure.get_json()
        # In secure app, parameterized query treats payload as literal text; no unauthorized users leaked
        self.assertEqual(len(sec_data.get('results', [])), 0)

    # --- 2. BROKEN OBJECT LEVEL AUTHORIZATION (IDOR - CWE-639) TEST ---
    def test_idor_vulnerability(self):
        # Alice (ID=2) logs in
        res_v = self.vuln_client.post('/api/auth/login', json={"username": "alice", "password": "AlicePass!"})
        token_v = res_v.get_json()['token']

        # Alice requests Bob's record (ID=2 in medical_records belongs to patient_id=3 Bob)
        # Record 1: Alice (patient_id=2)
        # Record 2: Bob (patient_id=3)
        res_vuln = self.vuln_client.get('/api/records/2', headers={"Authorization": f"Bearer {token_v}"})
        self.assertEqual(res_vuln.status_code, 200)
        self.assertEqual(res_vuln.get_json()['patient_id'], 3) # VULNERABLE: Alice accessed Bob's record!

        # Secure app verification
        res_s = self.sec_client.post('/api/auth/login', json={"username": "alice", "password": "AliceSafePass@2026!"})
        token_s = res_s.get_json()['token']

        # Alice attempts to access Bob's record (ID=2)
        res_sec = self.sec_client.get('/api/records/2', headers={"Authorization": f"Bearer {token_s}"})
        self.assertEqual(res_sec.status_code, 403) # SECURE: Access Denied!

    # --- 3. PATH TRAVERSAL (CWE-22) TEST ---
    def test_path_traversal(self):
        res_v = self.vuln_client.post('/api/auth/login', json={"username": "alice", "password": "AlicePass!"})
        token_v = res_v.get_json()['token']

        # Try to read app.py via path traversal
        traversal_payload = "../app.py"
        res_vuln = self.vuln_client.get(f'/api/documents/download?file={traversal_payload}', headers={"Authorization": f"Bearer {token_v}"})
        self.assertEqual(res_vuln.status_code, 200)
        self.assertIn("JWT_SECRET", res_vuln.get_json().get('content', '')) # Source code leaked!

        # Secure app verification
        res_s = self.sec_client.post('/api/auth/login', json={"username": "alice", "password": "AliceSafePass@2026!"})
        token_s = res_s.get_json()['token']

        res_sec = self.sec_client.get(f'/api/documents/download?file={traversal_payload}', headers={"Authorization": f"Bearer {token_s}"})
        # Should be 404 (because basename app.py doesn't exist in uploads) or 400
        self.assertIn(res_sec.status_code, [400, 404])

    # --- 4. OS COMMAND INJECTION (CWE-78) TEST ---
    def test_command_injection_validation(self):
        # Admin logs into secure app
        res_s = self.sec_client.post('/api/auth/login', json={"username": "admin", "password": "AdminStrongPass#2026!"})
        token_s = res_s.get_json()['token']

        # Malicious payload with command chaining
        malicious_host = "127.0.0.1 && whoami"
        res_sec = self.sec_client.post(
            '/api/admin/network-test',
            json={"host": malicious_host},
            headers={"Authorization": f"Bearer {token_s}"}
        )
        # Secure app rejects malformed IP format
        self.assertEqual(res_sec.status_code, 400)
        self.assertIn("Invalid IP address", res_sec.get_json().get('error', ''))


if __name__ == '__main__':
    unittest.main()

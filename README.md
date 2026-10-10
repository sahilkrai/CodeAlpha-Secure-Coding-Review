# CodeAlpha Secure Coding Review & Vulnerability Audit Project

This repository contains a full end-to-end security code audit project for **MediVault Healthcare Records Management API**, including vulnerable implementations, automated SAST scan artifacts, manual code review findings, remediation implementations, and verification test suites.

---

## 📁 Repository Structure

```
CodeAlpha Secure-Coding-Review/
├── vulnerable_app/                 # Audited application containing real-world vulnerabilities
│   ├── app.py                      # Intentionally insecure Flask API
│   ├── requirements.txt            # Dependencies
│   └── uploads/                    # Sample storage folder
│       └── patient_chart_101.txt
├── secure_app/                     # Hardened, remediated production-grade application
│   ├── app.py                      # Fully secured Flask API
│   ├── requirements.txt            # Dependencies
│   └── uploads/                    # Controlled storage folder
│       └── patient_chart_101.txt
├── tests/                          # Automated security verification test suite
│   └── test_vulnerabilities.py     # Unit tests verifying exploit vs remediation behavior
├── reports/                        # Security audit deliverables
│   ├── bandit_results.json         # Raw JSON report from Bandit SAST scan on vulnerable app
│   ├── bandit_results.txt          # Text summary from Bandit SAST scan on vulnerable app
│   ├── bandit_secure_results.json  # Raw JSON report from Bandit SAST scan on secure app
│   ├── bandit_secure_results.txt   # Text summary from Bandit SAST scan on secure app
│   └── SECURE_CODE_REVIEW_AUDIT_REPORT.md  # Comprehensive Audit & Remediation Report
└── README.md                       # Project overview & reproduction guide
```

---

## 🔍 Audit Scope & Identified Vulnerabilities

| Finding ID | Vulnerability | Standard | Detection Tool | Remediated in `secure_app/` |
|---|---|---|---|:---:|
| **SEC-01** | SQL Injection | CWE-89 / OWASP A03 | Bandit (B608) & Manual | ✅ Yes |
| **SEC-02** | Broken Object Level Auth (IDOR) | CWE-639 / OWASP A01 | Manual Inspection | ✅ Yes |
| **SEC-03** | Path Traversal / Arbitrary File Read | CWE-22 / OWASP A01 | Manual Inspection | ✅ Yes |
| **SEC-04** | Remote OS Command Injection | CWE-78 / OWASP A03 | Bandit (B602) & Manual | ✅ Yes |
| **SEC-05** | Weak Password Hash (Unsalted MD5) | CWE-328 / OWASP A02 | Bandit (B324) & Manual | ✅ Yes |
| **SEC-06** | Hardcoded Secrets & Missing Expiry | CWE-798 / OWASP A02 | Bandit (B105) & Manual | ✅ Yes |
| **SEC-07** | Insecure Deserialization (`pickle`) | CWE-502 / OWASP A08 | Bandit (B301) & Manual | ✅ Yes |
| **SEC-08** | Reflected Cross-Site Scripting (XSS)| CWE-79 / OWASP A03 | Manual Inspection | ✅ Yes |
| **SEC-09** | Debug Mode & Permissive CORS | CWE-489 / CWE-942 | Bandit (B201) & Manual | ✅ Yes |

---

## 🚀 How to Reproduce & Execute

### 1. Run Automated SAST Scans with Bandit

Scan the vulnerable codebase:
```powershell
bandit -r vulnerable_app/ -f txt
```

Scan the hardened codebase to verify remediation:
```powershell
bandit -r secure_app/ -f txt
```

### 2. Run the Security Verification Test Suite

Run the automated test suite comparing the vulnerable and secure applications:
```powershell
python -m unittest tests/test_vulnerabilities.py
```
Expected output:
```
Ran 4 tests ... OK
```

### 3. Review the Full Audit Report
The complete detailed report is available at:
`reports/SECURE_CODE_REVIEW_AUDIT_REPORT.md`

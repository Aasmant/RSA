# RSA Encryption Service - Setup & Run Instructions

## Project Overview

This is a Software Security SSDLC assignment demonstrating a secure RSA-based file encryption service.

**GitHub Repository:** https://github.com/Aasmant/RSA

---

## Installation & Setup

### Step 1: Clone Repository
```bash
git clone https://github.com/Aasmant/RSA.git
cd RSA
```

### Step 2: Verify Python Version
```bash
python3 --version
```
**Required:** Python 3.9 or higher

### Step 3: Install Dependencies
```bash
pip3 install -r requirements.txt
```

### Step 4: Verify Installation
```bash
pip3 list | grep -E "Flask|cryptography|PyJWT|Werkzeug"
```

Expected output:
```
Flask           2.3.0
cryptography    41.0.0
PyJWT           2.8.0
Werkzeug        2.3.0
```

---

## Running the Project

### Step 5: Start the Flask Application
```bash
python3 rsa_service.py
```

**Expected Output:**
```
 * Serving Flask app 'rsa_service'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
 * Debugger PIN: [PIN]
```

**Status:** ✅ Server running successfully on http://127.0.0.1:5000

The application will:
- Initialize SQLite database (rsa_service.db)
- Create 3 tables: users, files, audit_log
- Ready to accept API requests

---

## Testing the API (In a NEW Terminal)

**Keep the Flask server running. Open a NEW terminal tab/window to test.**

### Step 6: Test Health Endpoint
```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{"service": "RSA Encryption Service", "status": "healthy"}
```

### Step 7: Register a User
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

Expected response includes: `user_id`, `username`, `public_key`, `private_key`

### Step 8: Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

Expected response: JWT token in `token` field

### Step 9: List Files
```bash
curl -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  http://localhost:5000/api/files
```

Replace `YOUR_TOKEN_HERE` with token from Step 8

---

## Project Files

- `rsa_service.py` - Main REST API application (530+ lines)
- `requirements.txt` - Python dependencies
- `SECURITY_REPORT.md` - Security analysis (2,240+ lines)
- `THREAT_MODEL.md` - Threat modeling analysis
- `README.md` - Project documentation
- `Software_Security_Assignment.pdf` - Formatted submission

---

**Status:** ✅ READY TO RUN
**Deadline:** February 13, 2026

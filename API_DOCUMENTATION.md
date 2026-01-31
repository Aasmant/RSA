# RSA Encryption Service - API Documentation

## Overview
REST API for RSA file encryption/decryption with user authentication and file management.

## Quick Start

### 1. Start the Server
```bash
cd /path/to/rsa-encryption-service
python3 rsa_service.py
```
Server runs at: `http://localhost:5000`

### 2. Use the CLI Client
```bash
python3 client.py
```
This provides an interactive menu for all operations.

---

## API Endpoints

### 1. Health Check
```
GET /api/health
```
**Response:**
```json
{
  "status": "healthy",
  "service": "RSA Encryption Service"
}
```

---

### 2. Register User
```
POST /api/register
Content-Type: application/json
```

**Request:**
```json
{
  "username": "john",
  "password": "secure_password123"
}
```

**Response (201):**
```json
{
  "user_id": 1,
  "username": "john",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Important:** Save your private key! You'll need it to decrypt files.

---

### 3. Login
```
POST /api/login
Content-Type: application/json
```

**Request:**
```json
{
  "username": "john",
  "password": "secure_password123"
}
```

**Response (200):**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### 4. Upload & Encrypt File
```
POST /api/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

**Parameters:**
- `file`: Binary file to upload

**Response (201):**
```json
{
  "file_id": 5,
  "filename": "document.txt",
  "encrypted": true
}
```

---

### 5. List Files
```
GET /api/files
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "files": [
    {
      "id": 1,
      "filename": "photo.jpg",
      "created_at": "2026-01-31 10:30:45"
    },
    {
      "id": 2,
      "filename": "document.pdf",
      "created_at": "2026-01-31 11:15:20"
    }
  ]
}
```

---

### 6. Decrypt File
```
POST /api/decrypt/<file_id>
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**
```json
{
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

**Response (200):**
```json
{
  "file_id": 1,
  "filename": "photo.jpg",
  "data": "base64_encoded_binary_data"
}
```

---

## Testing with cURL

### 1. Health Check
```bash
curl http://localhost:5000/api/health
```

### 2. Register
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### 3. Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### 4. Upload File
```bash
TOKEN="your_token_here"
curl -X POST http://localhost:5000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@path/to/your/file.txt"
```

### 5. List Files
```bash
TOKEN="your_token_here"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/files
```

### 6. Decrypt File
```bash
TOKEN="your_token_here"
FILE_ID=1
PRIVATE_KEY=$(cat your_private_key.pem)

curl -X POST http://localhost:5000/api/decrypt/$FILE_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"private_key\": \"$PRIVATE_KEY\"}"
```

---

## Complete Workflow

### Step 1: Register
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123"
  }'
```
**Save the private_key from the response!**

### Step 2: Login
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "SecurePass123"
  }'
```
**Save the token from the response!**

### Step 3: Create a test file
```bash
echo "This is my secret data" > secret.txt
```

### Step 4: Upload & Encrypt
```bash
TOKEN="your_token_from_step_2"
curl -X POST http://localhost:5000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@secret.txt"
```
**Note the file_id from response!**

### Step 5: List Files
```bash
TOKEN="your_token_from_step_2"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/files
```

### Step 6: Decrypt File
```bash
TOKEN="your_token_from_step_2"
FILE_ID=1
PRIVATE_KEY=$(cat alice_private_key.pem)

curl -X POST http://localhost:5000/api/decrypt/$FILE_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"private_key\": $(echo $PRIVATE_KEY | jq -Rs .)}" | jq -r '.data' | base64 -d
```

---

## Error Responses

### Missing Token (401)
```json
{"error": "Missing token"}
```

### Invalid Credentials (401)
```json
{"error": "Invalid credentials"}
```

### File Not Found (404)
```json
{"error": "File not found"}
```

### Upload Failed (500)
```json
{"error": "Upload failed"}
```

### Decryption Failed (500)
```json
{"error": "Decryption failed: [reason]"}
```

---

## Security Features

✅ RSA 2048-bit encryption  
✅ JWT token authentication (1-hour expiration)  
✅ Password hashing (PBKDF2-SHA256)  
✅ Audit logging of all operations  
✅ User authorization checks  
✅ Private key auto-formatting correction  

---

## Security Vulnerabilities (Intentional for Education)

The following vulnerabilities are intentionally included for learning:

1. **Hard-coded SECRET_KEY** - Use environment variables in production
2. **Weak password validation** - Enforce min 12 chars + complexity
3. **PKCS#1 v1.5 padding** - Use OAEP padding instead
4. **Direct RSA on full file** - Use hybrid encryption (RSA + AES)
5. **No file size validation** - Enforce 100MB limit
6. **Missing authorization check** - Always verify ownership
7. **Debug mode enabled** - Disable in production
8. **Private key exposed** - Generate on server, return only public
9. **Incomplete audit logging** - Log all security events
10. **Sensitive data in logs** - Sanitize before logging

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Files Table
```sql
CREATE TABLE files (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    encrypted_data BLOB NOT NULL,
    file_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### Audit Log Table
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    action TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);
```

---

## Requirements

- Python 3.9+
- Flask 2.3.0
- cryptography 41.0.0
- PyJWT 2.8.0
- Werkzeug 2.3.0
- requests (for CLI client)

Install with:
```bash
pip install -r requirements.txt
```

---

## Support

For issues or questions, refer to the SECURITY_REPORT.md and THREAT_MODEL.md files for comprehensive documentation.

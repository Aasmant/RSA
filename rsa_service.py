"""
RSA Encryption Service - Secure SDLC Demonstration
Demonstrates secure implementation patterns with intentional vulnerabilities for educational purposes
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt
import sqlite3
import hashlib
import logging
import datetime
import base64
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# ============================================================================
# SECURITY VULNERABILITIES INTENTIONALLY INCLUDED FOR EDUCATIONAL PURPOSES
# ============================================================================
# This code demonstrates common security flaws to teach secure practices.
# Each vulnerability includes comments explaining the issue and secure solution.
# ============================================================================

app = Flask(__name__)

# VULNERABILITY 1: Hard-coded SECRET_KEY in source code
# IMPACT: Anyone with source code access can forge JWT tokens
# SOLUTION: Use environment variables or secure configuration management
SECRET_KEY = "super-secret-key-hardcoded-vulnerability"

# VULNERABILITY 2: Weak key generation settings
SECRET_KEY_WEAK = "password123"

# Database configuration
DATABASE = "rsa_service.db"

# Logging configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def get_db_connection():
    """Get database connection with proper settings for macOS"""
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    """Initialize SQLite database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create files table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        file_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Create audit log table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        details TEXT
    )
    ''')
    
    conn.commit()
    conn.close()

# ============================================================================
# CRYPTOGRAPHIC OPERATIONS
# ============================================================================

def generate_rsa_keypair(key_size=2048):
    """
    Generate RSA keypair
    
    SECURE: Uses 2048-bit keys which are industry standard.
    Modern recommendation: 4096-bit for sensitive operations.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key

def serialize_public_key(private_key):
    """Serialize public key to PEM format"""
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def serialize_private_key(private_key):
    """Serialize private key to PEM format"""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def encrypt_file(file_data, public_key_pem):
    """
    Encrypt file using Hybrid Encryption (RSA + AES)
    
    SECURE IMPLEMENTATION: Uses AES-256 for file encryption and RSA-2048 to encrypt the AES key
    This allows files of any size to be encrypted.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # Generate random AES key (32 bytes = 256 bits)
        aes_key = secrets.token_bytes(32)
        
        # Generate random IV (16 bytes)
        iv = secrets.token_bytes(16)
        
        # Encrypt file data with AES-256-CBC
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding to file data
        padding_length = 16 - (len(file_data) % 16)
        padded_data = file_data + bytes([padding_length] * padding_length)
        
        # Encrypt the padded data
        encrypted_file = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt the AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine: encrypted_aes_key + iv + encrypted_file (all base64 encoded)
        combined = encrypted_aes_key + iv + encrypted_file
        return base64.b64encode(combined).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_file(encrypted_data_b64, private_key_pem):
    """
    Decrypt file using Hybrid Encryption (RSA + AES)
    Mirrors the encryption process
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Decode from base64
        combined = base64.b64decode(encrypted_data_b64)
        
        # Extract components
        # RSA key is 256 bytes (2048-bit), IV is 16 bytes
        encrypted_aes_key = combined[:256]
        iv = combined[256:272]
        encrypted_file = combined[272:]
        
        # Decrypt AES key with RSA
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt file with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_file) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext
        
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

# ============================================================================
# AUTHENTICATION
# ============================================================================

def verify_password(username, password):
    """Verify username and password"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result and check_password_hash(result[1], password):
        return result[0]
    return None

def generate_jwt_token(user_id):
    """
    Generate JWT token with 1-hour expiration
    
    SECURE: Tokens expire automatically
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Missing token'}), 401
        
        try:
            token = token.split(' ')[1]
        except IndexError:
            return jsonify({'error': 'Invalid token format'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.user_id = user_id
        return f(*args, **kwargs)
    
    return decorated

# ============================================================================
# AUDIT LOGGING
# ============================================================================

def log_audit(user_id, action, details=""):
    """
    Log security-relevant events
    
    VULNERABILITY 5: Logging incomplete - not all security events recorded
    VULNERABILITY 6: Sensitive data may be logged (passwords, keys)
    SOLUTION: Comprehensive logging with data sanitization
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)',
        (user_id, action, details)
    )
    conn.commit()
    conn.close()

# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'RSA Encryption Service'})

@app.route('/api/register', methods=['POST'])
def register():
    """
    Register new user and generate RSA keypair
    
    VULNERABILITY 7: Returns private key to client
    IMPACT: Private key exposed over network; client may store insecurely
    SOLUTION: Generate keys on server; return only public key; use key wrapping
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    # VULNERABILITY 8: Weak password validation (4 characters minimum)
    # SOLUTION: Enforce strong password: min 12 chars, complexity requirements
    if len(password) < 4:
        return jsonify({'error': 'Password too weak'}), 400
    
    try:
        # Generate RSA keypair
        private_key = generate_rsa_keypair()
        public_key_pem = serialize_public_key(private_key)
        private_key_pem = serialize_private_key(private_key)
        
        # Hash password
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Store user
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
            (username, password_hash, public_key_pem)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        log_audit(user_id, 'USER_REGISTERED', f'Username: {username}')
        
        # VULNERABILITY 7: Returning private key to client (CRITICAL)
        return jsonify({
            'user_id': user_id,
            'username': username,
            'public_key': public_key_pem,
            'private_key': private_key_pem  # SECURITY ISSUE
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user and return JWT token"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    user_id = verify_password(username, password)
    if not user_id:
        log_audit(None, 'FAILED_LOGIN', f'Username: {username}')
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = generate_jwt_token(user_id)
    log_audit(user_id, 'LOGIN_SUCCESS', f'Username: {username}')
    
    return jsonify({
        'token': token,
        'token_type': 'Bearer',
        'expires_in': 3600
    }), 200

@app.route('/api/upload', methods=['POST'])
@token_required
def upload_file():
    """
    Upload and encrypt file
    
    VULNERABILITY 9: No file size validation
    IMPACT: Denial of service via large file upload
    SOLUTION: Enforce 100MB limit per file
    
    VULNERABILITY 10: Direct RSA encryption on entire file
    IMPACT: Files larger than key size (240 bytes) cannot be encrypted
    SOLUTION: Use hybrid encryption (RSA + AES)
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        file_data = file.read()
        
        # VULNERABILITY 9: No size validation
        # Should validate: if len(file_data) > 100_000_000: return error
        
        # Get user's public key
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT public_key FROM users WHERE id = ?', (request.user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'User not found'}), 404
        
        public_key_pem = result[0]
        
        # Encrypt file
        encrypted_data = encrypt_file(file_data, public_key_pem)
        
        # Store encrypted file
        file_hash = hashlib.sha256(file_data).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO files (user_id, filename, encrypted_data, file_hash) VALUES (?, ?, ?, ?)',
            (request.user_id, file.filename, encrypted_data, file_hash)
        )
        conn.commit()
        file_id = cursor.lastrowid
        conn.close()
        
        log_audit(request.user_id, 'FILE_UPLOADED', f'Filename: {file.filename}, ID: {file_id}')
        
        return jsonify({
            'file_id': file_id,
            'filename': file.filename,
            'encrypted': True
        }), 201
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/decrypt/<int:file_id>', methods=['POST'])
@token_required
def decrypt_file_endpoint(file_id):
    """
    Decrypt file
    
    VULNERABILITY 11: Missing authorization check
    IMPACT: Horizontal privilege escalation - users can decrypt other users' files
    SOLUTION: Verify file ownership before decryption
    """
    data = request.get_json()
    private_key_pem = data.get('private_key')
    
    if not private_key_pem:
        return jsonify({'error': 'Private key required'}), 400
    
    try:
        # Fix private key formatting if newlines are missing
        if '\\n' in private_key_pem:
            private_key_pem = private_key_pem.replace('\\n', '\n')
        
        # If key is all on one line, add newlines every 64 characters
        if '\n' not in private_key_pem:
            # Extract the base64 content between BEGIN and END
            if '-----BEGIN PRIVATE KEY-----' in private_key_pem and '-----END PRIVATE KEY-----' in private_key_pem:
                start = private_key_pem.find('-----BEGIN PRIVATE KEY-----') + len('-----BEGIN PRIVATE KEY-----')
                end = private_key_pem.find('-----END PRIVATE KEY-----')
                base64_content = private_key_pem[start:end].strip()
                
                # Add newlines every 64 characters
                formatted_lines = [base64_content[i:i+64] for i in range(0, len(base64_content), 64)]
                private_key_pem = '-----BEGIN PRIVATE KEY-----\n' + '\n'.join(formatted_lines) + '\n-----END PRIVATE KEY-----'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # VULNERABILITY 11: Missing authorization
        # Should verify: cursor.execute('SELECT * FROM files WHERE id = ? AND user_id = ?', (file_id, request.user_id))
        cursor.execute('SELECT encrypted_data, filename FROM files WHERE id = ?', (file_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'File not found'}), 404
        
        encrypted_data = result[0]
        filename = result[1]
        
        # Decrypt
        decrypted_data = decrypt_file(encrypted_data, private_key_pem)
        
        log_audit(request.user_id, 'FILE_DECRYPTED', f'File ID: {file_id}')
        
        return jsonify({
            'file_id': file_id,
            'filename': filename,
            'data': base64.b64encode(decrypted_data).decode('utf-8')
        }), 200
        
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': 'Decryption failed: ' + str(e)}), 500

@app.route('/api/files', methods=['GET'])
@token_required
def list_files():
    """List user's encrypted files"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, filename, created_at FROM files WHERE user_id = ?',
            (request.user_id,)
        )
        results = cursor.fetchall()
        conn.close()
        
        files = [{'id': r[0], 'filename': r[1], 'created_at': r[2]} for r in results]
        return jsonify({'files': files}), 200
        
    except Exception as e:
        logger.error(f"List files error: {str(e)}")
        return jsonify({'error': 'Failed to list files'}), 500

@app.route('/api/download/<int:file_id>', methods=['GET'])
@token_required
def download_file(file_id):
    """Download encrypted file"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT encrypted_data, filename FROM files WHERE id = ? AND user_id = ?',
            (file_id, request.user_id)
        )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'File not found or unauthorized'}), 404
        
        encrypted_data = result[0]
        filename = result[1]
        
        log_audit(request.user_id, 'FILE_DOWNLOADED', f'File ID: {file_id}, Filename: {filename}')
        
        return jsonify({
            'file_id': file_id,
            'filename': filename,
            'encrypted_data': encrypted_data
        }), 200
        
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Download failed'}), 500

# ============================================================================
# INITIALIZATION AND MAIN
# ============================================================================

if __name__ == '__main__':
    init_db()
    # VULNERABILITY 12: Debug mode enabled
    # IMPACT: Stack traces and sensitive information exposed to clients
    # SOLUTION: Set debug=False in production
    app.run(debug=True, host='127.0.0.1', port=5000)

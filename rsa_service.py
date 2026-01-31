"""
RSA Encryption Service - Secure SDLC Demonstration
Demonstrates secure implementation patterns with intentional vulnerabilities for educational purposes
"""

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
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

def init_db():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE)
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
    Encrypt file using RSA
    
    VULNERABILITY 3: Uses PKCS#1 v1.5 padding (susceptible to padding oracle attacks)
    VULNERABILITY 4: Direct RSA encryption not suitable for large files
    IMPACT: Files larger than key size cannot be encrypted; vulnerable to padding oracle
    SOLUTION: Use OAEP padding and hybrid encryption (RSA for key, AES for data)
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
        # VULNERABILITY: Using PKCS#1 v1.5 instead of OAEP
        ciphertext = public_key.encrypt(
            file_data[:190],  # Truncate due to RSA size limitations
            padding.PKCS1v15()  # VULNERABLE PADDING
        )
        
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_file(encrypted_data_b64, private_key_pem):
    """
    Decrypt file using RSA
    
    VULNERABILITY: Mirrors encryption flaws
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        plaintext = private_key.decrypt(
            encrypted_data,
            padding.PKCS1v15()
        )
        
        return plaintext
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise

# ============================================================================
# AUTHENTICATION
# ============================================================================

def verify_password(username, password):
    """Verify username and password"""
    conn = sqlite3.connect(DATABASE)
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
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)',
        (user_id, action, details)
    )
    conn.commit()
    conn.close()

# ============================================================================
# WEB UI ROUTES
# ============================================================================

@app.route('/', methods=['GET'])
def home():
    """Home page"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>RSA Encryption Service</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
            .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 600px; width: 90%; }
            h1 { color: #333; margin-bottom: 10px; }
            p { color: #666; margin-bottom: 30px; }
            .button-group { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
            button { padding: 15px; font-size: 16px; border: none; border-radius: 5px; cursor: pointer; transition: 0.3s; }
            .btn-register { background: #667eea; color: white; }
            .btn-register:hover { background: #5568d3; }
            .btn-login { background: #764ba2; color: white; }
            .btn-login:hover { background: #63408a; }
            .info { background: #f0f0f0; padding: 15px; border-left: 4px solid #667eea; margin-top: 20px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 RSA Encryption Service</h1>
            <p>Secure file encryption and management system</p>
            <div class="button-group">
                <button class="btn-register" onclick="location.href='/register'">Register</button>
                <button class="btn-login" onclick="location.href='/login'">Login</button>
            </div>
            <div class="info">
                <strong>Welcome!</strong><br>
                Register a new account or login to upload and manage encrypted files.
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    """Register page"""
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        
        if len(password) < 4:
            return '''<script>alert('Password too weak'); window.location.href='/register';</script>'''
        
        try:
            private_key = generate_rsa_keypair()
            public_key_pem = serialize_public_key(private_key)
            private_key_pem = serialize_private_key(private_key)
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
                (username, password_hash, public_key_pem)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            log_audit(user_id, 'USER_REGISTERED', f'Username: {username}')
            
            # Store credentials in session for display
            return f'''
            <html><head><title>Registration Success</title><style>
            body {{ font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
            .container {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 800px; width: 90%; }}
            h2 {{ color: green; }}
            .key {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0; word-break: break-all; font-family: monospace; font-size: 12px; }}
            button {{ padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }}
            </style></head><body>
            <div class="container">
                <h2>✅ Registration Successful!</h2>
                <p><strong>Username:</strong> {username}</p>
                <p><strong>User ID:</strong> {user_id}</p>
                <p style="color: red; font-weight: bold;">SAVE YOUR PRIVATE KEY (you'll need it for decryption):</p>
                <div class="key">{private_key_pem}</div>
                <button onclick="location.href='/login'">Go to Login</button>
            </div>
            </body></html>
            '''
        except sqlite3.IntegrityError:
            return '''<script>alert('Username already exists'); window.location.href='/register';</script>'''
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
            .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 400px; width: 90%; }
            h1 { color: #333; margin-bottom: 30px; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; color: #333; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-top: 10px; }
            button:hover { background: #5568d3; }
            .link { text-align: center; margin-top: 15px; }
            .link a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Register</h1>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Register</button>
                <div class="link">
                    Already have account? <a href="/login">Login</a>
                </div>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page"""
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')
        
        user_id = verify_password(username, password)
        if not user_id:
            return '''<script>alert('Invalid credentials'); window.location.href='/login';</script>'''
        
        token = generate_jwt_token(user_id)
        log_audit(user_id, 'LOGIN_SUCCESS', f'Username: {username}')
        
        # Redirect to dashboard with token
        return f'''
        <html><body>
        <script>
            localStorage.setItem('token', '{token}');
            localStorage.setItem('user_id', '{user_id}');
            localStorage.setItem('username', '{username}');
            window.location.href='/dashboard';
        </script>
        </body></html>
        '''
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
            .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 400px; width: 90%; }
            h1 { color: #333; margin-bottom: 30px; }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 5px; color: #333; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            button { width: 100%; padding: 12px; background: #764ba2; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-top: 10px; }
            button:hover { background: #63408a; }
            .link { text-align: center; margin-top: 15px; }
            .link a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Login</h1>
            <form method="POST">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit">Login</button>
                <div class="link">
                    Don't have account? <a href="/register">Register</a>
                </div>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Dashboard with upload and file management"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial; background: #f5f5f5; min-height: 100vh; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
            .card { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h2 { margin-bottom: 15px; color: #333; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; color: #333; }
            input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-family: Arial; }
            button { padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #5568d3; }
            .logout { float: right; background: #dc3545; }
            .logout:hover { background: #c82333; }
            .file-list { list-style: none; }
            .file-item { background: #f9f9f9; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
            .success { color: green; }
            .error { color: red; }
            #decryptForm { display: none; margin-top: 20px; padding: 15px; background: #f9f9f9; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>Dashboard <span id="username" style="float: right;"></span></h1>
            </div>
        </div>
        
        <div class="container">
            <button class="logout" onclick="logout()">Logout</button>
            
            <div class="card">
                <h2>Upload File</h2>
                <form id="uploadForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>Select file to encrypt:</label>
                        <input type="file" id="fileInput" required>
                    </div>
                    <button type="submit">Upload & Encrypt</button>
                    <p id="uploadStatus"></p>
                </form>
            </div>
            
            <div class="card">
                <h2>Your Encrypted Files</h2>
                <ul class="file-list" id="fileList">
                    <p>Loading files...</p>
                </ul>
            </div>
            
            <div class="card" id="decryptForm">
                <h2>Decrypt File</h2>
                <div class="form-group">
                    <label>Paste your Private Key:</label>
                    <textarea id="privateKey" rows="10" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
                </div>
                <button onclick="decryptFile()">Decrypt</button>
                <p id="decryptStatus"></p>
                <div id="decryptedData"></div>
            </div>
        </div>
        
        <script>
            // Check if logged in
            if (!localStorage.getItem('token')) {
                window.location.href = '/';
            }
            
            document.getElementById('username').textContent = 'Hi, ' + localStorage.getItem('username');
            
            // Load files on page load
            loadFiles();
            
            // Upload form submit
            document.getElementById('uploadForm').onsubmit = async (e) => {
                e.preventDefault();
                const file = document.getElementById('fileInput').files[0];
                const formData = new FormData();
                formData.append('file', file);
                
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') },
                    body: formData
                });
                
                const result = await response.json();
                if (response.ok) {
                    document.getElementById('uploadStatus').innerHTML = '<span class="success">✅ File uploaded and encrypted!</span>';
                    document.getElementById('fileInput').value = '';
                    loadFiles();
                } else {
                    document.getElementById('uploadStatus').innerHTML = '<span class="error">❌ Upload failed: ' + result.error + '</span>';
                }
            };
            
            async function loadFiles() {
                const response = await fetch('/api/files', {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                });
                const result = await response.json();
                const fileList = document.getElementById('fileList');
                
                if (result.files && result.files.length > 0) {
                    fileList.innerHTML = result.files.map(f => 
                        '<li class="file-item"><strong>' + f.filename + '</strong> (ID: ' + f.id + ') <button onclick="showDecryptForm(' + f.id + ')">Decrypt</button></li>'
                    ).join('');
                } else {
                    fileList.innerHTML = '<p>No files uploaded yet.</p>';
                }
            }
            
            function showDecryptForm(fileId) {
                window.currentFileId = fileId;
                document.getElementById('decryptForm').style.display = 'block';
                document.getElementById('decryptForm').scrollIntoView();
            }
            
            async function decryptFile() {
                const privateKey = document.getElementById('privateKey').value;
                const response = await fetch('/api/decrypt/' + window.currentFileId, {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('token'),
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ private_key: privateKey })
                });
                
                const result = await response.json();
                if (response.ok) {
                    document.getElementById('decryptStatus').innerHTML = '<span class="success">✅ Decrypted successfully!</span>';
                    
                    const filename = result.filename;
                    const base64Data = result.data;
                    const mimeType = getMimeType(filename);
                    
                    // Display preview if it's an image or text
                    let preview = '';
                    if (mimeType && mimeType.startsWith('image/')) {
                        const imageData = 'data:' + mimeType + ';base64,' + base64Data;
                        preview = '<strong>Decrypted Image:</strong><br><img src="' + imageData + '" style="max-width: 100%; max-height: 500px; border-radius: 5px; margin-top: 10px;">';
                    } else if (mimeType && mimeType.startsWith('text/')) {
                        try {
                            const decoded = atob(base64Data);
                            preview = '<strong>Decrypted Text:</strong><pre style="background: #f5f5f5; padding: 10px; border-radius: 5px; max-height: 300px; overflow-y: auto;">' + decoded + '</pre>';
                        } catch(e) {
                            preview = '';
                        }
                    }
                    
                    // Download button
                    const downloadBtn = '<button onclick="downloadDecryptedFile(\'' + base64Data + '\', \'' + filename + '\', \'' + mimeType + '\')" style="background: #28a745; margin-top: 10px;">📥 Download ' + filename + '</button>';
                    
                    document.getElementById('decryptedData').innerHTML = preview + '<br>' + downloadBtn;
                } else {
                    document.getElementById('decryptStatus').innerHTML = '<span class="error">❌ Decryption failed: ' + result.error + '</span>';
                }
            }
            
            function downloadDecryptedFile(base64Data, filename, mimeType) {
                // Create blob from base64
                const binaryString = atob(base64Data);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) {
                    bytes[i] = binaryString.charCodeAt(i);
                }
                const blob = new Blob([bytes], {type: mimeType || 'application/octet-stream'});
                
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                window.URL.revokeObjectURL(url);
            }
            
            function getMimeType(filename) {
                const ext = filename.toLowerCase().split('.').pop();
                const mimeTypes = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'gif': 'image/gif',
                    'bmp': 'image/bmp',
                    'webp': 'image/webp',
                    'txt': 'text/plain',
                    'pdf': 'application/pdf'
                };
                return mimeTypes[ext] || null;
            }
            
            function logout() {
                localStorage.clear();
                window.location.href = '/';
            }
        </script>
    </body>
    </html>
    '''

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
        conn = sqlite3.connect(DATABASE)
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
        conn = sqlite3.connect(DATABASE)
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
        conn = sqlite3.connect(DATABASE)
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
        
        conn = sqlite3.connect(DATABASE)
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
        conn = sqlite3.connect(DATABASE)
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

# ============================================================================
# INITIALIZATION AND MAIN
# ============================================================================

if __name__ == '__main__':
    init_db()
    # VULNERABILITY 12: Debug mode enabled
    # IMPACT: Stack traces and sensitive information exposed to clients
    # SOLUTION: Set debug=False in production
    app.run(debug=True, host='127.0.0.1', port=5000)

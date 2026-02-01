from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import jwt, sqlite3, hashlib, logging, datetime, base64, os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
SECRET_KEY = "secret"
DATABASE = "rsa_service.db"
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 190))
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, public_key TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
    c.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, user_id INTEGER, filename TEXT, encrypted_data TEXT, file_hash TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))')
    c.execute('CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, details TEXT)')
    conn.commit()
    conn.close()

def gen_key():
    return rsa.generate_private_key(65537, 2048, default_backend())

def pub_pem(pk):
    return pk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def priv_pem(pk):
    return pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

def encrypt_file(data, pub_pem_str):
    pub = serialization.load_pem_public_key(pub_pem_str.encode(), default_backend())
    enc = pub.encrypt(data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return base64.b64encode(enc).decode()

def decrypt_file(enc_b64, priv_pem_str):
    priv = serialization.load_pem_private_key(priv_pem_str.encode(), None, default_backend())
    enc = base64.b64decode(enc_b64)
    return priv.decrypt(enc, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

def verify_pwd(user, pwd):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (user,))
    res = c.fetchone()
    conn.close()
    return res[0] if res and check_password_hash(res[1], pwd) else None

def gen_jwt(uid):
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    return jwt.encode({'user_id': uid, 'exp': exp}, SECRET_KEY, algorithm='HS256')

def verify_jwt(tok):
    try:
        pay = jwt.decode(tok, SECRET_KEY, algorithms=['HS256'])
        return pay.get('user_id')
    except:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        tok = request.headers.get('Authorization', '').split()
        uid = verify_jwt(tok[1]) if len(tok) > 1 else None
        if not uid:
            return jsonify({'error': 'Invalid token'}), 401
        request.user_id = uid
        return f(*args, **kwargs)
    return decorated

def log_audit(uid, act, det=""):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)', (uid, act, det))
    conn.commit()
    conn.close()

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing data'}), 400
    
    user, pwd = data['username'], data['password']
    if len(pwd) < 4:
        return jsonify({'error': 'Password too weak'}), 400
    
    pk = gen_key()
    pub = pub_pem(pk)
    priv = priv_pem(pk)
    phash = generate_password_hash(pwd, method='pbkdf2:sha256')
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)', (user, phash, pub))
        conn.commit()
        uid = c.lastrowid
        conn.close()
        log_audit(uid, 'REGISTER', user)
        return jsonify({'user_id': uid, 'username': user, 'public_key': pub, 'private_key': priv}), 201
    except:
        return jsonify({'error': 'Username exists'}), 409

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing creds'}), 400
    
    uid = verify_pwd(data['username'], data['password'])
    if not uid:
        return jsonify({'error': 'Invalid creds'}), 401
    
    tok = gen_jwt(uid)
    log_audit(uid, 'LOGIN', data['username'])
    return jsonify({'token': tok, 'expires_in': 3600}), 200

@app.route('/api/upload', methods=['POST'])
@token_required
def upload():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({'error': 'No file'}), 400
    
    f = request.files['file']
    data = f.read()
    
    if len(data) > MAX_FILE_SIZE:
        return jsonify({'error': f'File too large - max {MAX_FILE_SIZE} bytes'}), 400
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE id = ?', (request.user_id,))
    res = c.fetchone()
    conn.close()
    
    if not res:
        return jsonify({'error': 'User not found'}), 404
    
    try:
        enc = encrypt_file(data, res[0])
        fh = hashlib.sha256(data).hexdigest()
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO files (user_id, filename, encrypted_data, file_hash) VALUES (?, ?, ?, ?)', (request.user_id, f.filename, enc, fh))
        conn.commit()
        fid = c.lastrowid
        conn.close()
        
        log_audit(request.user_id, 'UPLOAD', f.filename)
        return jsonify({'file_id': fid, 'filename': f.filename}), 201
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/decrypt/<int:fid>', methods=['POST'])
@token_required
def decrypt(fid):
    data = request.get_json()
    pk_str = data.get('private_key')
    if not pk_str:
        return jsonify({'error': 'No key'}), 400
    
    if '\\n' in pk_str:
        pk_str = pk_str.replace('\\n', '\n')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT encrypted_data, filename FROM files WHERE id = ?', (fid,))
    res = c.fetchone()
    conn.close()
    
    if not res:
        return jsonify({'error': 'Not found'}), 404
    
    try:
        dec = decrypt_file(res[0], pk_str)
        log_audit(request.user_id, 'DECRYPT', fid)
        return jsonify({'file_id': fid, 'filename': res[1], 'data': base64.b64encode(dec).decode()}), 200
    except Exception as e:
        logger.error(f"Decrypt error: {e}")
        return jsonify({'error': 'Decrypt failed: ' + str(e)}), 500

@app.route('/api/files', methods=['GET'])
@token_required
def list_files():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, filename, created_at FROM files WHERE user_id = ?', (request.user_id,))
    res = c.fetchall()
    conn.close()
    return jsonify({'files': [{'id': r[0], 'filename': r[1], 'created_at': r[2]} for r in res]}), 200

@app.route('/api/download/<int:fid>', methods=['GET'])
@token_required
def download(fid):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT encrypted_data, filename FROM files WHERE id = ? AND user_id = ?', (fid, request.user_id))
    res = c.fetchone()
    conn.close()
    
    if not res:
        return jsonify({'error': 'Not found'}), 404
    
    log_audit(request.user_id, 'DOWNLOAD', fid)
    return jsonify({'file_id': fid, 'filename': res[1], 'encrypted_data': res[0]}), 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=5000)

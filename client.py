#!/usr/bin/env python3
import requests, json, os, sys, base64
from pathlib import Path

API_URL = "http://localhost:5000"
TOKEN_FILE = "token.json"

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            d = json.load(f)
            return d.get('token'), d.get('user_id'), d.get('username')
    return None, None, None

def save_token(tok, uid, user):
    with open(TOKEN_FILE, 'w') as f:
        json.dump({'token': tok, 'user_id': uid, 'username': user}, f)
    print(f"✅ Logged in as: {user}")

def register(user, pwd):
    print(f"\n📝 Registering: {user}")
    res = requests.post(f"{API_URL}/api/register", json={'username': user, 'password': pwd})
    if res.status_code == 201:
        d = res.json()
        print("✅ Registration ok!")
        print(f"   User ID: {d['user_id']}")
        pk_file = f"{user}_private.pem"
        with open(pk_file, 'w') as f:
            f.write(d['private_key'])
        print(f"   Private key saved: {pk_file}")
        return d['user_id'], d['public_key'], d['private_key']
    print(f"❌ Error: {res.json()}")
    return None, None, None

def login(user, pwd):
    print(f"\n🔓 Login: {user}")
    res = requests.post(f"{API_URL}/api/login", json={'username': user, 'password': pwd})
    if res.status_code == 200:
        d = res.json()
        print("✅ Login ok!")
        return d['token']
    print(f"❌ Error: {res.json()}")
    return None

def upload(tok):
    print("\n📤 Upload file")
    fpath = input("File path: ").strip()
    if not os.path.exists(fpath):
        print("❌ File not found")
        return
    with open(fpath, 'rb') as f:
        files = {'file': f}
        res = requests.post(f"{API_URL}/api/upload", files=files, headers={'Authorization': f'Bearer {tok}'})
    if res.status_code == 201:
        d = res.json()
        print(f"✅ Upload ok! File ID: {d['file_id']}")
    else:
        print(f"❌ Error: {res.json()}")

def list_files(tok):
    print("\n📋 Your files")
    res = requests.get(f"{API_URL}/api/files", headers={'Authorization': f'Bearer {tok}'})
    if res.status_code == 200:
        files = res.json()['files']
        if files:
            for f in files:
                print(f"  ID: {f['id']}, Name: {f['filename']}")
        else:
            print("  (empty)")
    else:
        print(f"❌ Error: {res.json()}")

def download_enc(tok):
    print("\n📥 Download encrypted file")
    fid = input("File ID: ").strip()
    outdir = input("Output dir (default: ./): ").strip() or "./"
    os.makedirs(outdir, exist_ok=True)
    res = requests.get(f"{API_URL}/api/download/{fid}", headers={'Authorization': f'Bearer {tok}'})
    if res.status_code == 200:
        d = res.json()
        fname = f"{d['filename']}.encrypted"
        fpath = os.path.join(outdir, fname)
        with open(fpath, 'w') as f:
            f.write(d['encrypted_data'])
        print(f"✅ Saved: {fpath}")
    else:
        print(f"❌ Error: {res.json()}")

def decrypt_file(tok):
    print("\n🔓 Decrypt file")
    fid = input("File ID: ").strip()
    outdir = input("Output dir (default: ./): ").strip() or "./"
    os.makedirs(outdir, exist_ok=True)
    
    pk = input("Paste private key (or path to .pem file): ").strip()
    if os.path.exists(pk):
        with open(pk) as f:
            pk = f.read()
    
    res = requests.post(f"{API_URL}/api/decrypt/{fid}", json={'private_key': pk}, headers={'Authorization': f'Bearer {tok}'})
    if res.status_code == 200:
        d = res.json()
        dec_data = base64.b64decode(d['data'])
        fname = d['filename']
        fpath = os.path.join(outdir, fname)
        with open(fpath, 'wb') as f:
            f.write(dec_data)
        print(f"✅ Decrypted: {fpath} ({len(dec_data)} bytes)")
    else:
        print(f"❌ Error: {res.json()}")

def main():
    tok, uid, user = load_token()
    
    while True:
        print("\n=== RSA Encryption Service ===")
        if tok:
            print(f"User: {user} (ID: {uid})")
        print("1. Register")
        print("2. Login")
        if tok:
            print("3. Upload")
            print("4. List files")
            print("5. Download encrypted")
            print("6. Decrypt")
            print("7. Logout")
        print("8. Exit")
        
        ch = input("\nChoice: ").strip()
        
        if ch == "1":
            user_in = input("Username: ").strip()
            pwd_in = input("Password: ").strip()
            register(user_in, pwd_in)
        
        elif ch == "2":
            user_in = input("Username: ").strip()
            pwd_in = input("Password: ").strip()
            t = login(user_in, pwd_in)
            if t:
                tok = t
                uid = input("User ID: ").strip()
                save_token(tok, uid, user_in)
                user = user_in
        
        elif ch == "3" and tok:
            upload(tok)
        elif ch == "4" and tok:
            list_files(tok)
        elif ch == "5" and tok:
            download_enc(tok)
        elif ch == "6" and tok:
            decrypt_file(tok)
        
        elif ch == "7" and tok:
            os.remove(TOKEN_FILE) if os.path.exists(TOKEN_FILE) else None
            tok, uid, user = None, None, None
            print("✅ Logged out")
        
        elif ch == "8":
            print("Bye!")
            sys.exit(0)

if __name__ == '__main__':
    main()

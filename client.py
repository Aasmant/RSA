#!/usr/bin/env python3
"""
RSA Encryption Service - CLI Client
Users can upload, encrypt, download, and decrypt files via REST API
"""

import requests
import json
import os
import sys
import base64
from pathlib import Path

# API endpoint
API_URL = "http://localhost:5000"

# Store token and credentials locally
TOKEN_FILE = "token.json"

def load_token():
    """Load stored authentication token"""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            data = json.load(f)
            return data.get('token'), data.get('user_id'), data.get('username')
    return None, None, None

def save_token(token, user_id, username):
    """Save authentication token locally"""
    with open(TOKEN_FILE, 'w') as f:
        json.dump({
            'token': token,
            'user_id': user_id,
            'username': username
        }, f)
    print(f"✅ Logged in as: {username}")

def register(username, password):
    """Register new user"""
    print(f"\n📝 Registering user: {username}")
    
    response = requests.post(f"{API_URL}/api/register", json={
        'username': username,
        'password': password
    })
    
    if response.status_code == 201:
        data = response.json()
        print("✅ Registration successful!")
        print(f"   User ID: {data['user_id']}")
        print(f"   Username: {data['username']}")
        
        # Save private key to file
        private_key = data['private_key']
        key_filename = f"{username}_private_key.pem"
        with open(key_filename, 'w') as f:
            f.write(private_key)
        print(f"   ⚠️  Private key saved to: {key_filename}")
        print(f"   ⚠️  KEEP THIS FILE SAFE - You'll need it to decrypt files!")
        
        return data['user_id'], data['username'], data['public_key']
    else:
        print(f"❌ Registration failed: {response.json()['error']}")
        return None, None, None

def login(username, password):
    """Login user and get token"""
    print(f"\n🔐 Logging in: {username}")
    
    response = requests.post(f"{API_URL}/api/login", json={
        'username': username,
        'password': password
    })
    
    if response.status_code == 200:
        data = response.json()
        token = data['token']
        save_token(token, username, username)  # We'll use username as user_id for display
        return token
    else:
        print(f"❌ Login failed: {response.json()['error']}")
        return None

def get_headers(token):
    """Get authorization headers"""
    return {'Authorization': f'Bearer {token}'}

def upload_file(file_path, token):
    """Upload and encrypt file"""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return None
    
    filename = os.path.basename(file_path)
    print(f"\n📤 Uploading file: {filename}")
    
    with open(file_path, 'rb') as f:
        files = {'file': (filename, f)}
        response = requests.post(
            f"{API_URL}/api/upload",
            headers=get_headers(token),
            files=files
        )
    
    if response.status_code == 201:
        data = response.json()
        print(f"✅ File uploaded and encrypted!")
        print(f"   File ID: {data['file_id']}")
        print(f"   Filename: {data['filename']}")
        return data['file_id']
    else:
        print(f"❌ Upload failed: {response.json()['error']}")
        return None

def list_files(token):
    """List user's encrypted files"""
    print(f"\n📋 Fetching your files...")
    
    response = requests.get(
        f"{API_URL}/api/files",
        headers=get_headers(token)
    )
    
    if response.status_code == 200:
        data = response.json()
        files = data['files']
        
        if not files:
            print("   No files found")
            return []
        
        print("   Your encrypted files:")
        for f in files:
            print(f"   [{f['id']}] {f['filename']} (created: {f['created_at']})")
        
        return files
    else:
        print(f"❌ Failed to list files: {response.json()['error']}")
        return []

def download_encrypted_file(file_id, output_dir, token):
    """Download encrypted file to disk"""
    print(f"\n📥 Downloading encrypted file (ID: {file_id})...")
    
    response = requests.get(
        f"{API_URL}/api/download/{file_id}",
        headers=get_headers(token)
    )
    
    if response.status_code == 200:
        data = response.json()
        filename = data['filename']
        encrypted_data = data['encrypted_data']
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Save encrypted file with .encrypted extension
        output_path = os.path.join(output_dir, f"{filename}.encrypted")
        
        with open(output_path, 'w') as f:
            f.write(encrypted_data)
        
        print(f"✅ Encrypted file downloaded!")
        print(f"   Original filename: {filename}")
        print(f"   Saved to: {output_path}")
        print(f"   Size: {len(encrypted_data)} bytes (base64 encoded)")
        return True
    else:
        print(f"❌ Download failed: {response.json()['error']}")
        return False

def decrypt_file(file_id, private_key_path, output_path, token):
    """Decrypt file"""
    if not os.path.exists(private_key_path):
        print(f"❌ Private key file not found: {private_key_path}")
        return False
    
    print(f"\n🔓 Decrypting file (ID: {file_id})...")
    
    with open(private_key_path, 'r') as f:
        private_key = f.read()
    
    response = requests.post(
        f"{API_URL}/api/decrypt/{file_id}",
        headers=get_headers(token),
        json={'private_key': private_key}
    )
    
    if response.status_code == 200:
        data = response.json()
        filename = data['filename']
        encrypted_data = data['data']
        
        # Decode base64 to binary
        decrypted_binary = base64.b64decode(encrypted_data)
        
        # Save to file
        if not output_path:
            output_path = f"decrypted_{filename}"
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_binary)
        
        print(f"✅ File decrypted successfully!")
        print(f"   Original filename: {filename}")
        print(f"   Saved to: {output_path}")
        return True
    else:
        print(f"❌ Decryption failed: {response.json()['error']}")
        return False

def main():
    """Main CLI interface"""
    print("\n" + "="*60)
    print("🔐 RSA Encryption Service - CLI Client")
    print("="*60)
    
    token, _, username = load_token()
    
    while True:
        print("\n" + "-"*60)
        if token:
            print(f"Logged in as: {username}")
            print("\nOptions:")
            print("  1. Upload file (will be encrypted)")
            print("  2. List my encrypted files")
            print("  3. Download encrypted file")
            print("  4. Decrypt file")
            print("  5. Logout")
            print("  6. Exit")
        else:
            print("Not logged in")
            print("\nOptions:")
            print("  1. Register")
            print("  2. Login")
            print("  3. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if not token:
            # Not logged in
            if choice == '1':
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                user_id, username, _ = register(username, password)
                if user_id:
                    token = login(username, password)
            elif choice == '2':
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                token = login(username, password)
            elif choice == '3':
                print("Goodbye!")
                break
        else:
            # Logged in
            if choice == '1':
                file_path = input("Enter file path to upload: ").strip()
                upload_file(file_path, token)
            elif choice == '2':
                list_files(token)
            elif choice == '3':
                files = list_files(token)
                if files:
                    file_id = input("Enter file ID to download: ").strip()
                    output_dir = input("Enter output folder (press Enter for current directory): ").strip()
                    if not output_dir:
                        output_dir = "."
                    try:
                        file_id = int(file_id)
                        download_encrypted_file(file_id, output_dir, token)
                    except ValueError:
                        print("❌ Invalid file ID")
            elif choice == '4':
                files = list_files(token)
                if files:
                    file_id = input("Enter file ID to decrypt: ").strip()
                    private_key_path = input("Enter path to your private key file: ").strip()
                    output_path = input("Enter output filename (press Enter for default): ").strip()
                    try:
                        file_id = int(file_id)
                        decrypt_file(file_id, private_key_path, output_path or None, token)
                    except ValueError:
                        print("❌ Invalid file ID")
            elif choice == '5':
                os.remove(TOKEN_FILE)
                token = None
                print("✅ Logged out")
            elif choice == '6':
                print("Goodbye!")
                break
            else:
                print("❌ Invalid option")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

#!/usr/bin/env python3
"""
Quick check script to verify vulnerabilities exist
"""

import os
import sys

def check_file(filepath, pattern):
    """Check if file contains a pattern"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            return pattern in content
    except:
        return False

def main():
    print("🔍 Checking test_sandbox vulnerabilities...")
    
    checks = {
        'authentication/login.py': [
            'hashlib.md5',
            'hashlib.sha1',
            'admin123',
            'jwt.decode',
        ],
        'database/db_query.py': [
            'SELECT * FROM users WHERE id = ',
            'INSERT INTO users',
            'UPDATE users SET',
            'DELETE FROM users',
        ],
        'file_uploads/upload.py': [
            'file.save',
            'request.files',
            'uploads/',
        ],
        'search_parameters/search.py': [
            'render_template_string',
            'document.write',
            'eval(',
            'SELECT * FROM items',
        ],
        'secrets_config/config.json': [
            'rootpassword123',
            'sk-1234567890',
            'AKIAIOSFODNN7EXAMPLE',
            'mongodb://admin:password123',
        ],
        'session_management/session.py': [
            'set_cookie',
            'session_id',
            'session[\'user_id\']',
            'jwt.encode',
        ],
        'session_management/JS mix.js': [
            'innerHTML',
            'document.write',
            'eval(',
            'fetch(',
        ],
        'session_management/vuln_db.py': [
            'pickle.loads',
            'yaml.load',
            'subprocess.Popen',
            'eval(',
        ],
    }
    
    found = 0
    total = 0
    
    for filepath, patterns in checks.items():
        for pattern in patterns:
            total += 1
            if check_file(filepath, pattern):
                found += 1
                print(f"✅ Found: {filepath} -> {pattern[:30]}...")
            else:
                print(f"❌ Missing: {filepath} -> {pattern[:30]}...")
    
    print(f"\n📊 Found {found}/{total} vulnerability patterns")
    if found == total:
        print("✅ All vulnerabilities present!")
    else:
        print("⚠️ Some vulnerabilities missing")

if __name__ == "__main__":
    main()
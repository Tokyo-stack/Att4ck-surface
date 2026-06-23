"""
Authentication Vulnerabilities - login.py
"""

import hashlib
import jwt
from datetime import datetime, timedelta
import base64

# ================================================================
# 1. Weak Hashing (MD5)
# ================================================================

def hash_password_md5(password):
    """VULNERABLE: Uses MD5 - cryptographically broken"""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    """VULNERABLE: Uses SHA1 - cryptographically broken"""
    return hashlib.sha1(password.encode()).hexdigest()


# ================================================================
# 2. Hardcoded Credentials
# ================================================================

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # VULNERABLE: Hardcoded
DB_PASSWORD = "rootpassword123"  # VULNERABLE: Hardcoded
API_SECRET = "supersecretkey12345"  # VULNERABLE: Hardcoded

# ================================================================
# 3. JWT Vulnerabilities
# ================================================================

def decode_jwt_unverified(token):
    """VULNERABLE: JWT verification disabled"""
    return jwt.decode(token, options={"verify_signature": False})


def create_jwt_weak(user_id):
    """VULNERABLE: JWT with weak secret 'secret'"""
    payload = {'user_id': user_id, 'exp': datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, 'secret', algorithm='HS256')


def create_jwt_no_expiry(user_id):
    """VULNERABLE: JWT with no expiration"""
    payload = {'user_id': user_id}
    return jwt.encode(payload, 'secret', algorithm='HS256')


# ================================================================
# 4. Plaintext Password Storage
# ================================================================

def store_user_plaintext(username, password):
    """VULNERABLE: Storing password in plaintext"""
    return f"User: {username}, Password: {password}"


def log_user_login(username, password):
    """VULNERABLE: Logging password in plaintext"""
    print(f"Login attempt: {username}, Password: {password}")


# ================================================================
# 5. Base64 Encoding (Not Encryption)
# ================================================================

def encode_password_base64(password):
    """VULNERABLE: Base64 is encoding, NOT encryption"""
    return base64.b64encode(password.encode()).decode()


# ================================================================
# 6. Session Fixation
# ================================================================

def create_session_fixed(user_id):
    """VULNERABLE: Session ID not regenerated"""
    session_id = 'fixed_session_' + str(user_id)
    return f"Session ID: {session_id} - FIXED!"


# ================================================================
# 7. Missing MFA/2FA
# ================================================================

def login_without_mfa(username, password):
    """VULNERABLE: No MFA/2FA verification"""
    if username == "admin" and password == "admin123":
        return "Logged in - NO MFA!"
    return "Invalid credentials"
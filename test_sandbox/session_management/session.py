"""
Session Management Vulnerabilities - session.py
"""

from flask import Flask, request, session, make_response
import jwt
import hashlib
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey12345'

# ================================================================
# 1. Insecure Cookie Flags
# ================================================================

@app.route('/set-cookie-insecure')
def set_insecure_cookie():
    """VULNERABLE: Missing HttpOnly and Secure flags"""
    resp = make_response("Cookie set")
    resp.set_cookie('session_id', 'abc123')  # No HttpOnly, No Secure
    return resp


@app.route('/set-cookie-no-httponly')
def set_cookie_no_httponly():
    """VULNERABLE: Missing HttpOnly flag"""
    resp = make_response("Cookie set")
    resp.set_cookie('session_id', 'abc123', secure=True)  # No HttpOnly
    return resp


@app.route('/set-cookie-no-secure')
def set_cookie_no_secure():
    """VULNERABLE: Missing Secure flag"""
    resp = make_response("Cookie set")
    resp.set_cookie('session_id', 'abc123', httponly=True)  # No Secure
    return resp


# ================================================================
# 2. Session ID in URL
# ================================================================

@app.route('/dashboard')
def dashboard():
    """VULNERABLE: Session ID in URL"""
    session_id = request.args.get('session_id', '')
    return f"Dashboard - Session: {session_id}"


# ================================================================
# 3. Session Fixation
# ================================================================

@app.route('/login-fixation')
def login_fixation():
    """VULNERABLE: Session not regenerated on login"""
    session['user_id'] = request.args.get('user_id')
    return "Logged in - Session NOT regenerated!"


# ================================================================
# 4. Session Expiration
# ================================================================

@app.route('/set-session')
def set_session():
    """VULNERABLE: Session never expires"""
    session['user_id'] = 'admin'
    session.permanent = False  # VULNERABLE: No expiration
    return "Session set with no expiration"


# ================================================================
# 5. Session Data in URL
# ================================================================

@app.route('/share-session')
def share_session():
    """VULNERABLE: Session data in URL"""
    token = request.args.get('token', '')
    return f"Shared session token: {token}"


# ================================================================
# 6. Session without HTTPS
# ================================================================

@app.route('/login-http')
def login_http():
    """VULNERABLE: Session over HTTP"""
    session['user_id'] = 'admin'
    return "Logged in over HTTP - NO HTTPS!"


# ================================================================
# 7. Session Predictability
# ================================================================

def generate_predictable_session(user_id):
    """VULNERABLE: Predictable session ID"""
    return hashlib.md5(str(user_id).encode()).hexdigest()
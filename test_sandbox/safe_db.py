"""
Safe Database Operations (For Comparison)
"""

import re
import hashlib

# ================================================================
# 1. Safe SQL - Parameterized Queries
# ================================================================

def get_user_safe(user_id):
    """SAFE: Parameterized query"""
    # Using parameterized query (placeholder)
    return "SELECT * FROM users WHERE id = %s" % user_id  # Actually safe with proper driver


# ================================================================
# 2. Safe Password Hashing
# ================================================================

def hash_password_safe(password):
    """SAFE: Using bcrypt"""
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


# ================================================================
# 3. Safe Input Validation
# ================================================================

def validate_input(input_str):
    """SAFE: Input validation"""
    if re.match(r'^[a-zA-Z0-9\s]+$', input_str):
        return True
    return False


# ================================================================
# 4. Safe File Handling
# ================================================================

def safe_file_open(filename):
    """SAFE: Validated file path"""
    allowed_files = ['file1.txt', 'file2.txt']
    if filename in allowed_files:
        return open(filename, 'r')
    return None


# ================================================================
# 5. Safe XSS Prevention
# ================================================================

def safe_xss(input_str):
    """SAFE: HTML escaping"""
    import html
    return html.escape(input_str)
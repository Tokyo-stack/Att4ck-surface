"""
File Upload Vulnerabilities - upload.py
"""

from flask import Flask, request
import os

app = Flask(__name__)

# ================================================================
# 1. Unrestricted File Upload
# ================================================================

@app.route('/upload', methods=['POST'])
def upload_file():
    """VULNERABLE: File upload without validation"""
    file = request.files['file']
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


@app.route('/upload/no-validation', methods=['POST'])
def upload_no_validation():
    """VULNERABLE: File upload without any validation"""
    file = request.files['file']
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


# ================================================================
# 2. Missing Extension Check
# ================================================================

@app.route('/upload/no-extension', methods=['POST'])
def upload_no_extension():
    """VULNERABLE: No extension validation"""
    file = request.files['file']
    # VULNERABLE: No extension check
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


# ================================================================
# 3. Missing MIME Type Check
# ================================================================

@app.route('/upload/no-mime', methods=['POST'])
def upload_no_mime():
    """VULNERABLE: No MIME type validation"""
    file = request.files['file']
    # VULNERABLE: No MIME check
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


# ================================================================
# 4. Dangerous File Extensions Allowed
# ================================================================

@app.route('/upload/php', methods=['POST'])
def upload_php():
    """VULNERABLE: Allows PHP file upload"""
    file = request.files['file']
    # VULNERABLE: Allows .php files
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


@app.route('/upload/any-extension', methods=['POST'])
def upload_any_extension():
    """VULNERABLE: Allows any file extension"""
    file = request.files['file']
    # VULNERABLE: No extension restriction
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'


# ================================================================
# 5. Path Traversal in Upload
# ================================================================

@app.route('/upload/path-traversal', methods=['POST'])
def upload_path_traversal():
    """VULNERABLE: Path traversal in file upload"""
    filename = request.form.get('filename', 'file.txt')
    # VULNERABLE: Can use ../../../ to traverse
    file = request.files['file']
    file.save(f'uploads/{filename}')
    return 'File uploaded'


# ================================================================
# 6. Large File Upload (DoS)
# ================================================================

@app.route('/upload/large', methods=['POST'])
def upload_large():
    """VULNERABLE: No file size limit"""
    file = request.files['file']
    # VULNERABLE: No size limit
    file.save(f'uploads/{file.filename}')
    return 'File uploaded'
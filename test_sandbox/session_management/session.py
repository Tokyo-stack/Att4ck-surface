# 1. Insecure session cookie setting
response.set_cookie('session_id', token)

# 2. Sanitized session cookie setting
response.set_cookie('session_id', token, httponly=True, secure=True)

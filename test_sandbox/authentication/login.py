# 1. Insecure login SQL injection
def vuln_login(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

# 2. Sanitized login (parameterized query)
def safe_login(username, password):
    cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))

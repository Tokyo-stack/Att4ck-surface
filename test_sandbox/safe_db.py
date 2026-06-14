# Sanitized query using parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))

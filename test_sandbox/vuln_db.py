# Vulnerable query
query = "SELECT * FROM users WHERE username = '" + user_input + "'"
cursor.execute(query)

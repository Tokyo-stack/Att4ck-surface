# 1. Insecure database query execution
query = f"SELECT * FROM users WHERE status = '{status}'"
db.execute(query)

# 2. Sanitized query (SQL parameterization)
db.execute("SELECT * FROM users WHERE status = %s", (status,))

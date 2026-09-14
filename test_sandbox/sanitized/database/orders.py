def find(cursor, email):
    cursor.execute("SELECT * FROM orders WHERE email = %s", (email,))
    return cursor.fetchall()

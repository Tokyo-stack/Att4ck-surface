from flask import request

def get_user(cursor):
    uid = int(request.args.get("id"))
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()

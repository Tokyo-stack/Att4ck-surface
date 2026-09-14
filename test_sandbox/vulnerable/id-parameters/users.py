from flask import request

def get_user(cursor):
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchone()

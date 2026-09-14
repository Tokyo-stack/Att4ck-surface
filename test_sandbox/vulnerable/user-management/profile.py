from flask import request

def update_password(db):
    user_id = request.form["user_id"]
    new = request.form["password"]
    db.set_password(user_id, new)
    db.commit()

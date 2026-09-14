from flask import request
from flask_login import current_user

def update_password(db):
    old = request.form["current_password"]
    if not current_user.check_password(old):
        return "forbidden", 403
    current_user.set_password(request.form["password"])
    db.commit()

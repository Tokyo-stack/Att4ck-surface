from flask import request

def upload():
    f = request.files["file"]
    f.save("/var/www/uploads/" + f.filename)
    return "ok"

import os, uuid
from werkzeug.utils import secure_filename
from flask import request
ALLOWED_EXTENSIONS = {".png", ".jpg"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024

def upload():
    f = request.files["file"]
    name = secure_filename(f.filename)
    ext = os.path.splitext(name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return "rejected", 400
    f.save(os.path.join("/srv/uploads", str(uuid.uuid4()) + ext))
    return "ok"

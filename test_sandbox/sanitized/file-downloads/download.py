import os
from pathlib import Path
from flask import request, send_file, abort
BASE = Path("/var/data").resolve()

def download():
    name = request.args.get("file")
    target = (BASE / os.path.basename(name)).resolve()
    if not target.is_relative_to(BASE):
        abort(400)
    return send_file(target)

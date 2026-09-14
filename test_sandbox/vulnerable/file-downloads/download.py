from flask import request, send_file

def download():
    name = request.args.get("file")
    return send_file("/var/data/" + name)

import ipaddress, socket
from flask import request, abort
ALLOWED_HOSTS = {"api.partner.com"}

def check():
    host = request.args.get("host")
    if host not in ALLOWED_HOSTS:
        abort(400)
    ip = socket.gethostbyname(host)
    if ipaddress.ip_address(ip).is_private:
        abort(400)
    return ip

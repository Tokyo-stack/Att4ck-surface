import ipaddress, socket
from urllib.parse import urlparse
import requests
from flask import request, abort
ALLOWED_HOSTS = {"api.partner.com"}

def proxy():
    url = request.args.get("url")
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url, timeout=(3, 10)).text

from flask import request, redirect
from urllib.parse import urlparse

def go():
    nxt = request.args.get("next", "/")
    if urlparse(nxt).netloc or not nxt.startswith("/"):
        nxt = "/"
    return redirect(nxt)

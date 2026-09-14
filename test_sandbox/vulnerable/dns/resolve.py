import socket
from flask import request

def check():
    host = request.args.get("host")
    return socket.gethostbyname(host)

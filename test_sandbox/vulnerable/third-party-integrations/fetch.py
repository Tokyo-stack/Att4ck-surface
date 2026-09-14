import requests
from flask import request

def proxy():
    url = request.args.get("url")
    return requests.get(url).text

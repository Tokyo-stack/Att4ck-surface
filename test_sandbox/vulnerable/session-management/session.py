from flask import make_response

def login():
    resp = make_response("ok")
    resp.set_cookie("session", "abc123")
    return resp

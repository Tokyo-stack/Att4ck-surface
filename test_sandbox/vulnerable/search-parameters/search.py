from flask import request

def search():
    q = request.args.get("q")
    return "<div>Results for: " + q + "</div>"

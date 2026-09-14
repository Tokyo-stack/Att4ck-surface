from flask import request, redirect

def go():
    nxt = request.args.get("next")
    return redirect(nxt)

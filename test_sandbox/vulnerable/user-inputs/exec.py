from flask import request

def run():
    expr = request.args.get("expr")
    return eval(expr)

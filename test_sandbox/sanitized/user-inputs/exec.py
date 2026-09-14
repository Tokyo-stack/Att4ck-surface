import ast
from flask import request

def run():
    expr = request.args.get("expr")
    return ast.literal_eval(expr)

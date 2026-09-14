from flask import request

def callback(oauth_client):
    code = request.args.get("code")
    token = oauth_client.fetch_token(code=code)
    return login_with(token)

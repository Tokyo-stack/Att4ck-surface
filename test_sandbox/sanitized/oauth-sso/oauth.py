from flask import request, session, abort

def callback(oauth_client):
    if request.args.get("state") != session.pop("oauth_state", None):
        abort(400)
    token = oauth_client.fetch_token(code=request.args.get("code"))
    return login_with(token)

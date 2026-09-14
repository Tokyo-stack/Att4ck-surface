import secrets

def send_reset_link(client, user):
    token = secrets.token_urlsafe(32)  # single-use, expires in 15 min
    store_reset_token(user, token, expires_in=900)
    client.messages.create(to=user.verified_phone, body="Reset link: https://app/r/" + token)

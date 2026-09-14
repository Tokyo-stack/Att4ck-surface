def send_password(client, user):
    client.messages.create(
        to=user.phone,
        body="Your new password is: " + user.temp_password,
    )

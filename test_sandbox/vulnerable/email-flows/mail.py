from email.mime.text import MIMEText
from flask import request

def send(server):
    msg = MIMEText("hi")
    msg["Subject"] = request.form["subject"]
    msg["To"] = request.form["to"]
    server.send_message(msg)

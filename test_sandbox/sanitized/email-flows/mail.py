import smtplib, ssl
from email.mime.text import MIMEText
from flask import request
from email_validator import validate_email

def send():
    to = validate_email(request.form["to"]).email
    subject = request.form["subject"].replace("\r", "").replace("\n", " ")[:200]
    msg = MIMEText("hi")
    msg["Subject"] = subject
    msg["To"] = to
    with smtplib.SMTP("smtp.example.com", 587) as s:
        s.starttls(context=ssl.create_default_context())
        s.send_message(msg)

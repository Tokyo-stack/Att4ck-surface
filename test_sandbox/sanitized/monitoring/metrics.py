from flask import Flask
from .auth import basic_auth_required
app = Flask(__name__)

@app.route("/metrics")
@basic_auth_required
def metrics():
    return generate_latest()

from prometheus_client import make_wsgi_app
from flask import Flask
app = Flask(__name__)

@app.route("/metrics")
def metrics():
    return make_wsgi_app()

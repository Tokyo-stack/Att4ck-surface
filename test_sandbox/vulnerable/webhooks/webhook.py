from flask import request, Flask
app = Flask(__name__)

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    event = request.get_json()
    process(event)
    return "ok"

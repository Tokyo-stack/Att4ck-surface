import hmac, hashlib
from flask import request, Flask, abort
app = Flask(__name__)
SECRET = __import__("os").environ["STRIPE_WH_SECRET"].encode()

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    sig = request.headers.get("Stripe-Signature", "")
    expected = hmac.new(SECRET, request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(400)
    process(request.get_json())
    return "ok"

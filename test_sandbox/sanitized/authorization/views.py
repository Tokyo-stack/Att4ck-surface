from flask import Flask, request
from flask_login import login_required, current_user
app = Flask(__name__)

@app.route("/account/delete", methods=["POST"])
@login_required
def delete_account():
    db.delete(current_user.id)
    return "deleted"

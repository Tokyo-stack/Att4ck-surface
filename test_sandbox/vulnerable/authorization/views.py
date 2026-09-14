from flask import Flask, request
app = Flask(__name__)

@app.route("/account/delete", methods=["POST"])
def delete_account():
    user_id = request.form["user_id"]
    db.delete(user_id)
    return "deleted"

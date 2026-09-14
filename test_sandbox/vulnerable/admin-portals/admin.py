from flask import Flask
app = Flask(__name__)

@app.route("/admin/dashboard")
def admin_dashboard():
    return render_admin()

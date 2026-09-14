from flask import Flask
from .auth import admin_required
app = Flask(__name__)

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return render_admin()

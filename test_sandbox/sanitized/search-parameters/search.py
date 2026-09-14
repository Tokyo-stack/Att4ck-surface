from flask import request, render_template
import html

def search():
    q = request.args.get("q")
    return "<div>Results for: " + html.escape(q) + "</div>"

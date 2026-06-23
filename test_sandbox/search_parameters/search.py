"""
Search Parameter Vulnerabilities - search.py
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# ================================================================
# 1. Reflected XSS - q parameter
# ================================================================

@app.route('/search')
def search():
    """VULNERABLE: Reflected XSS via q parameter"""
    query = request.args.get('q', '')
    return render_template_string(f"<h1>Search Results: {query}</h1>")


@app.route('/find')
def find():
    """VULNERABLE: Reflected XSS via find parameter"""
    keyword = request.args.get('keyword', '')
    return f"<div>Searching for: {keyword}</div>"


@app.route('/query')
def query():
    """VULNERABLE: Reflected XSS via query parameter"""
    q = request.args.get('query', '')
    return f"<p>Query: {q}</p>"


# ================================================================
# 2. Reflected XSS - Multiple Parameters
# ================================================================

@app.route('/advanced-search')
def advanced_search():
    """VULNERABLE: Reflected XSS via multiple parameters"""
    q = request.args.get('q', '')
    filter = request.args.get('filter', '')
    sort = request.args.get('sort', '')
    return f"<div>Search: {q}, Filter: {filter}, Sort: {sort}</div>"


# ================================================================
# 3. Reflected XSS - Location Hash
# ================================================================

@app.route('/hash-search')
def hash_search():
    """VULNERABLE: Reflected XSS via location.hash"""
    return """
    <script>
        document.write(location.hash.substring(1));
    </script>
    """


# ================================================================
# 4. Reflected XSS - document.referrer
# ================================================================

@app.route('/referrer')
def referrer_search():
    """VULNERABLE: Reflected XSS via document.referrer"""
    return """
    <script>
        document.write(document.referrer);
    </script>
    """


# ================================================================
# 5. Reflected XSS - eval in search
# ================================================================

@app.route('/eval-search')
def eval_search():
    """VULNERABLE: eval with search parameter"""
    query = request.args.get('q', '')
    return f"""
    <script>
        eval('{query}');
    </script>
    """


# ================================================================
# 6. SQL Injection in Search
# ================================================================

@app.route('/sql-search')
def sql_search():
    """VULNERABLE: SQL Injection in search"""
    query = request.args.get('q', '')
    sql = f"SELECT * FROM items WHERE name LIKE '%{query}%'"
    return f"Query: {sql}"


# ================================================================
# 7. SSTI in Search
# ================================================================

@app.route('/ssti-search')
def ssti_search():
    """VULNERABLE: SSTI in search"""
    query = request.args.get('q', '')
    return render_template_string(f"<h1>Search: {query}</h1>")


# ================================================================
# 8. XSS via JSONP Callback
# ================================================================

@app.route('/jsonp')
def jsonp_callback():
    """VULNERABLE: XSS via JSONP callback"""
    callback = request.args.get('callback', '')
    return f"{callback}({{'data': 'test'}})"
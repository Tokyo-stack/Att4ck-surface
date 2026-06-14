# 1. Insecure reflected search parameter (XSS)
q = request.args.get('q')
print(f"Results for search: {q}")

# 2. Sanitized search parameter (HTML escape)
import html
q_safe = html.escape(request.args.get('q'))
print(f"Results for search: {q_safe}")

# 3. Insecure SSRF / Missing Timeout in search request
import requests
def fetch_external_search(url):
    # Missing timeout and lacks URL whitelisting
    response = requests.get(url)
    return response.text

# 4. Sanitized request (SSRF protection & Timeout)
def safe_fetch_external_search(url):
    if not url.startswith("https://trusted.api.com/"):
        raise ValueError("Untrusted destination domain")
    # Timeout parameter defined
    response = requests.get(url, timeout=5)
    return response.text

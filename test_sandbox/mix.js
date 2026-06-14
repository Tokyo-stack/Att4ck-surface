# Vulnerable XSS
element.innerHTML = req.query.search

# Hardcoded secret
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

# Sanitized XSS
element.textContent = req.query.search
# Sanitized XSS with DOMPurify
element.innerHTML = DOMPurify.sanitize(req.query.search)

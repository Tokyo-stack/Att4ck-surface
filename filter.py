import json

# Load findings
with open('output/findings.json', 'r') as f:
    findings = json.load(f)

# Filter for more likely real vulnerabilities
real_findings = []

for f in findings:
    file_name = f.get('file', '')
    
    # Skip hashed files (build artifacts)
    import re
    if re.search(r'[a-f0-9]{10,}\.js$', file_name):
        continue
    
    # Skip known library files
    if any(x in file_name for x in ['vendor', 'chunk', 'polyfill', 'runtime']):
        continue
    
    # Keep only suspicious patterns
    description = f.get('description', '')
    snippet = f.get('snippet', '')
    
    # More likely real vulnerabilities
    if 'userInput' in snippet or 'request.' in snippet:
        real_findings.append(f)
    
    # Network findings are more likely real
    if f.get('category') == 'NETWORK':
        real_findings.append(f)

# Save filtered results
with open('output/real_findings.json', 'w') as f:
    json.dump(real_findings, f, indent=2)

print(f"Filtered: {len(real_findings)} real findings out of {len(findings)}")
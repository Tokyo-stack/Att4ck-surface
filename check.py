import requests
import re
import json

# Download the suspicious files
files = [
    "101v8um-4sfpk.js",
    "2byz0zksszmry.js"
]

base_url = "https://flagforgectf.com/"

for file_name in files:
    print(f"\n{'='*60}")
    print(f"Checking: {file_name}")
    print('='*60)
    
    try:
        # Download file
        response = requests.get(base_url + file_name, timeout=10)
        content = response.text
        
        # Check for user input patterns
        user_input_patterns = [
            'location.search', 'location.hash', 'window.location',
            'document.URL', 'document.referrer',
            'request.', 'req.', 'params.', 'query.',
            'userInput', 'user_input', 'input',
            'getElementById', 'querySelector'
        ]
        
        print(f"File size: {len(content)} bytes")
        print(f"Lines: {len(content.splitlines())}")
        
        # Check for dangerous patterns
        dangerous_patterns = [
            (r'innerHTML\s*=\s*[^;]+', 'innerHTML assignment'),
            (r'eval\s*\(', 'eval call'),
            (r'Function\s*\(', 'Function constructor'),
            (r'setTimeout\s*\(\s*[\'"]', 'setTimeout with string'),
            (r'location\.href\s*=\s*', 'location assignment'),
        ]
        
        for pattern, desc in dangerous_patterns:
            matches = re.findall(pattern, content)
            if matches:
                print(f"⚠️  Found {desc}: {len(matches)} matches")
                # Show first match
                print(f"   Example: {matches[0][:100]}...")
        
        # Check specific line numbers
        lines_to_check = {
            '101v8um-4sfpk.js': [113],
            '2byz0zksszmry.js': [59, 5164, 6092, 6156]
        }
        
        lines = content.splitlines()
        for line_num in lines_to_check.get(file_name, []):
            if line_num <= len(lines):
                line_content = lines[line_num - 1]
                print(f"\n🔍 Line {line_num}:")
                # Show context (5 lines before and after)
                start = max(0, line_num - 6)
                end = min(len(lines), line_num + 5)
                for i in range(start, end):
                    prefix = ">>> " if i == line_num - 1 else "    "
                    print(f"{prefix}{i+1}: {lines[i][:100]}")

                # Check if this is in a known safe context
                safe_patterns = [
                    '__html', 'dangerouslySetInnerHTML',
                    'sanitize', 'escape', 'DOMPurify',
                    'textContent', 'innerText'
                ]
                is_safe = any(pattern in line_content.lower() for pattern in safe_patterns)
                if is_safe:
                    print("   ✅ Likely SAFE (contains sanitization)")
                else:
                    print("   ⚠️  POTENTIAL VULNERABILITY (no sanitization detected)")
                
    except Exception as e:
        print(f"Error: {e}")
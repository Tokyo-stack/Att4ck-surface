"""Debug script to trace why scanner finds zero results."""
import os
import re
from attack_surface.rules import RULES

target = os.path.abspath("test_sandbox")

# Test a specific known vulnerable file
test_file = os.path.join(target, "file_uploads", "upload.py")
with open(test_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"=== Testing {test_file} ===")
print(f"Lines in file: {len(lines)}")
for i, line in enumerate(lines, 1):
    print(f"  {i}: {line.rstrip()}")

print("\n=== Checking rules that match .py files ===")
# Find the file upload rule
for rule in RULES:
    if "file" in rule.name.lower() and "upload" in rule.name.lower():
        print(f"\nRule: {rule.name}")
        print(f"  Category: {rule.category}")
        print(f"  File exts: {rule.file_exts}")
        print(f"  Vuln patterns: {[p.pattern for p in rule.vuln_patterns]}")
        print(f"  Sanitizer patterns: {[p.pattern for p in rule.sanitizer_patterns]}")
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for p in rule.vuln_patterns:
                m = p.search(stripped)
                if m:
                    print(f"  VULN MATCH on line {i}: '{stripped}' matched '{p.pattern}'")

# Also test cookie rule against session.py
print("\n=== Testing session.py against cookie rule ===")
test_file2 = os.path.join(target, "session_management", "session.py")
with open(test_file2, "r", encoding="utf-8") as f:
    lines2 = f.readlines()

for rule in RULES:
    if "cookie" in rule.name.lower():
        print(f"Rule: {rule.name}")
        print(f"  Vuln patterns: {[p.pattern for p in rule.vuln_patterns]}")
        for i, line in enumerate(lines2, 1):
            stripped = line.strip()
            for p in rule.vuln_patterns:
                m = p.search(stripped)
                if m:
                    print(f"  VULN MATCH on line {i}: '{stripped}'")

# Test SQL injection rule
print("\n=== Testing vuln_db.py against SQL rules ===")
test_file3 = os.path.join(target, "vuln_db.py")
with open(test_file3, "r", encoding="utf-8") as f:
    lines3 = f.readlines()

for rule in RULES:
    if "sql" in rule.name.lower():
        print(f"Rule: {rule.name}")
        print(f"  Vuln patterns: {[p.pattern for p in rule.vuln_patterns]}")
        for i, line in enumerate(lines3, 1):
            stripped = line.strip()
            for p in rule.vuln_patterns:
                m = p.search(stripped)
                if m:
                    print(f"  VULN MATCH on line {i}: '{stripped}'")

# Test the XSS / innerHTML rule against mix.js
print("\n=== Testing mix.js against XSS/innerHTML rules ===")
test_file4 = os.path.join(target, "mix.js")
with open(test_file4, "r", encoding="utf-8") as f:
    lines4 = f.readlines()

for rule in RULES:
    if "dom" in rule.name.lower() or "innerHTML" in str([p.pattern for p in rule.vuln_patterns]):
        print(f"Rule: {rule.name} (ext={rule.file_exts})")
        print(f"  Vuln patterns: {[p.pattern for p in rule.vuln_patterns]}")
        for i, line in enumerate(lines4, 1):
            stripped = line.strip()
            for p in rule.vuln_patterns:
                m = p.search(stripped)
                if m:
                    print(f"  VULN MATCH on line {i}: '{stripped}'")

import os
import sys
from .rules import RULES
from .banner import (
    print_banner,
    COLOR_BLUE,
    COLOR_CYAN,
    COLOR_GREEN,
    COLOR_WARNING,
    COLOR_FAIL,
    COLOR_RESET,
    COLOR_BOLD
)

def scan_file(filepath):
    """
    Scans a single file against the defined rules.
    Returns a list of findings dicts.
    """
    findings = []
    _, ext = os.path.splitext(filepath)
    filename = os.path.basename(filepath)
    
    # Matching rules for this file type
    matching_rules = [r for r in RULES if ext in r.file_exts or filename in r.file_exts]
    if not matching_rules:
        return findings

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{COLOR_FAIL}[Error] Failed to read {filepath}: {e}{COLOR_RESET}")
        return findings

    # Check each rule
    for rule in matching_rules:
        rule_matched = False
        findings_for_rule = []
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            line_str = line.strip()
            
            # Check vulnerability pattern
            has_vuln = any(p.search(line_str) for p in rule.vuln_patterns)
            if has_vuln:
                rule_matched = True
                # Check context for sanitizers (same line, or 2 lines around it)
                has_sanitizer = False
                context_range = range(max(0, idx - 1), min(len(lines), idx + 2))
                for c_idx in context_range:
                    context_line = lines[c_idx].strip()
                    if any(s.search(context_line) for s in rule.sanitizer_patterns):
                        has_sanitizer = True
                        break
                
                findings_for_rule.append({
                    "line": line_num,
                    "code": line_str,
                    "sanitized": has_sanitizer
                })
        
        if rule_matched:
            # Group into sanitized vs unsanitized findings
            unsanitized_findings = [f for f in findings_for_rule if not f["sanitized"]]
            sanitized_findings = [f for f in findings_for_rule if f["sanitized"]]
            
            # If there are any unsanitized findings, report them
            if unsanitized_findings:
                for uf in unsanitized_findings:
                    findings.append({
                        "category": rule.category,
                        "name": rule.name,
                        "line": uf["line"],
                        "code": uf["code"],
                        "sanitized": False,
                        "message": f"{rule.name} possibility: {rule.vuln_desc}"
                    })
            # If all occurrences are sanitized, print the confirmation message
            else:
                for sf in sanitized_findings:
                    findings.append({
                        "category": rule.category,
                        "name": rule.name,
                        "line": sf["line"],
                        "code": sf["code"],
                        "sanitized": True,
                        "message": rule.safe_desc
                    })
                    
    return findings

def scan_directory(dirpath):
    """
    Recursively scans the directory and outputs formatted findings.
    """
    total_files = 0
    total_findings = 0
    unsanitized_count = 0
    
    print_banner()
    print(f"Target Directory: {dirpath}\n")

    # Group results by file
    for root, dirs, files in os.walk(dirpath):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__', '.idea', '.vscode')]
        
        for file in files:
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, dirpath)
            
            file_findings = scan_file(filepath)
            if file_findings:
                total_files += 1
                total_findings += len(file_findings)
                
                print(f"{COLOR_BLUE}{COLOR_BOLD}File: {relpath}{COLOR_RESET}")
                
                for f in file_findings:
                    if f["sanitized"]:
                        print(f"  [{COLOR_GREEN}SAFE{COLOR_RESET}] Line {f['line']}: {f['message']}")
                        print(f"         Code: {COLOR_GREEN}{f['code']}{COLOR_RESET}")
                    else:
                        unsanitized_count += 1
                        print(f"  [{COLOR_FAIL}VULN{COLOR_RESET}] Line {f['line']}: {f['message']}")
                        print(f"         Code: {COLOR_FAIL}{f['code']}{COLOR_RESET}")
                print()

    print(f"{COLOR_CYAN}{COLOR_BOLD}=== Scan Summary ==={COLOR_RESET}")
    print(f"Files with matches: {total_files}")
    print(f"Total findings:     {total_findings}")
    print(f"Unsanitized issues: {COLOR_FAIL if unsanitized_count > 0 else COLOR_GREEN}{unsanitized_count}{COLOR_RESET}")
    if unsanitized_count == 0 and total_findings > 0:
        print(f"{COLOR_GREEN}All identified attack surfaces have been properly sanitized.{COLOR_RESET}")

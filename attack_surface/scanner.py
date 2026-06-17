# attack_surface/scanner.py
import os
import concurrent.futures
from attack_surface.rules import RULES

def _process_single_file(args):
    file_path, rule, target_dir = args
    local_findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line_idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            vuln_detected = any(v_pattern.search(line) for v_pattern in rule.vuln_patterns)
            
            if vuln_detected:
                is_sanitized = any(s_pattern.search(line) for s_pattern in rule.sanitizer_patterns)
                
                if not is_sanitized:
                    start_win = max(0, line_idx - 2)
                    end_win = min(len(lines), line_idx + 1)
                    context_window = lines[start_win:end_win]
                    is_sanitized = any(
                        any(s_pattern.search(cl.strip()) for s_pattern in rule.sanitizer_patterns)
                        for cl in context_window
                    )

                # Determine explicit severity layers for tracking
                severity = "HIGH"
                if rule.category in ["authentication", "sessionManagement", "secretsConfig"]:
                    severity = "CRITICAL"
                elif rule.category in ["logging", "monitoring", "documentation"]:
                    severity = "LOW"

                local_findings.append({
                    "category": rule.category,
                    "name": rule.name,
                    "file": os.path.relpath(file_path, target_dir),
                    "line": line_idx,
                    "snippet": line[:100],
                    "status": "SANITIZED" if is_sanitized else "VULNERABLE",
                    "severity": severity,
                    "description": rule.safe_desc if is_sanitized else rule.vuln_desc
                })
    except Exception:
        pass
    return local_findings

class SurfaceScanner:
    def __init__(self, target_dir, rules_list=None):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = rules_list if rules_list is not None else RULES
        self.findings = []
        
        # Combined exclusions directly into class variables
        self.excluded_dirs = {
            'venv', '.venv', 'env', '.git', 'node_modules', 
            '__pycache__', '.pytest_cache', '.next', 'dist', 'build'
        }
        self.excluded_exts = {
            '.min.js', '.map', '.css', '.svg', '.png', '.jpg', '.jpeg', '.gif'
        }

    def scan(self):
        tasks = []
        for root, dirs, files in os.walk(self.target_dir):
            # In-place filtering modifications to skip build directories completely
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]
            
            for file in files:
                file_ext = os.path.splitext(file)[1].lower()
                file_path = os.path.join(root, file)
                
                # Check for two-part extensions like .min.js safely
                is_excluded_ext = any(file.lower().endswith(ext) for ext in self.excluded_exts)
                if is_excluded_ext:
                    continue  # Skip production bundles/media assets instantly

                for rule in self.rules:
                    if file_ext in rule.file_exts or (not rule.file_exts and file == "Dockerfile"):
                        tasks.append((file_path, rule, self.target_dir))

        if not tasks:
            return self.findings

        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(_process_single_file, tasks)
            for result_list in results:
                self.findings.extend(result_list)
        return self.findings

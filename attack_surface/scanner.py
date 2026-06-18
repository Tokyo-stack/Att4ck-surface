import os
import concurrent.futures
from attack_surface.rules import RULES
from attack_surface.risk_engine import get_risk


FALSE_POSITIVES = {
    "wp-admin/admin-ajax.php",
    "jquery.min.js",
    "bootstrap.min.js"
}


def _process_single_file(args):
    file_path, rule, target_dir = args
    local_findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line_idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # skip false positives
            if any(fp in line for fp in FALSE_POSITIVES):
                continue

            # detect vulnerability
            vuln_detected = any(
                pattern.search(line)
                for pattern in rule.vuln_patterns
            )

            if not vuln_detected:
                continue

            # context window
            start_win = max(0, line_idx - 5)
            end_win = min(len(lines), line_idx + 5)
            context_window = lines[start_win:end_win]

            is_sanitized = any(
                any(p.search(c.strip()) for p in rule.sanitizer_patterns)
                for c in context_window
            )

            severity, confidence = get_risk(rule.category)

            local_findings.append({
                "finding_id": f"AS-{rule.category}-{line_idx}",
                "cwe": rule.cwe,
                "category": rule.category,
                "name": rule.name,
                "file": os.path.relpath(file_path, target_dir),
                "line": line_idx,
                "snippet": line[:150],
                "status": "SANITIZED" if is_sanitized else "VULNERABLE",
                "severity": severity,
                "confidence": confidence,
                "description": rule.safe_desc if is_sanitized else rule.vuln_desc
            })

    except Exception as e:
        print(f"[SCAN ERROR] {file_path}: {e}")

    return local_findings


class SurfaceScanner:
    def __init__(self, target_dir, rules_list=None):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = rules_list if rules_list is not None else RULES
        self.findings = []

        self.excluded_dirs = {
            "venv", ".venv", "env", ".git", "node_modules",
            "__pycache__", ".pytest_cache", ".next", "dist", "build"
        }

        self.excluded_exts = {
            ".min.js", ".map", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif"
        }

    def scan(self):
        tasks = []

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]

            for file in files:
                file_path = os.path.join(root, file)

                if any(file.lower().endswith(ext) for ext in self.excluded_exts):
                    continue

                for rule in self.rules:
                    for ext in rule.file_exts:
                        if file.endswith(ext):
                            tasks.append((file_path, rule, self.target_dir))
                            break

        if not tasks:
            return self.findings

        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(_process_single_file, tasks)

        for r in results:
            self.findings.extend(r)

        return self.findings
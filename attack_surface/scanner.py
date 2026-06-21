"""
Scanner Module - Core scanning engine
"""

import os
import re
import json
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Optional

from attack_surface.rules import RULES
from attack_surface.risk_engine import get_risk


# False positives to ignore
FALSE_POSITIVES = {
    # Library files to ignore
    "jquery.min.js",
    "bootstrap.min.js",
    "react.min.js",
    "react-dom.min.js",
    "vue.min.js",
    "angular.min.js",
    "lodash.min.js",
    "underscore.min.js",
    "moment.min.js",
    "axios.min.js",
    "axios.js",
    "swiper.min.js",
    "slick.min.js",
    "owl.carousel.min.js",
    "chart.min.js",
    "d3.min.js",
    "three.min.js",
    
    # Framework files
    "vendor.js",
    "chunk-vendors.js",
    "chunk-common.js",
    "app.js",
    "main.js",
    "runtime.js",
    "polyfills.js",
    
    # CDN patterns
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    "googleapis.com",
    "gstatic.com",
    "facebook.net",
    "twitter.com",
    
    # Known safe patterns
    "console.log",
    "console.warn",
    "console.error",
    "// @license",
    "/*! ",
}


def safe_serializer(obj):
    """Custom JSON serializer for non-serializable objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, '__dict__'):
        return str(obj)
    return str(obj)


def _preprocess_javascript(content: str) -> str:
    """Preprocess JavaScript for better pattern matching"""
    # Add semicolons between statements
    content = re.sub(r'(;)(?=[^;])', r';\n', content)
    # Add newlines after braces
    content = re.sub(r'({)(?=[^{])', r'{\n', content)
    content = re.sub(r'(})(?=[^}])', r'}\n', content)
    # Add newlines after brackets
    content = re.sub(r'(\[)(?=[^\[])', r'[\n', content)
    content = re.sub(r'(\])(?=[^\]])', r']\n', content)
    return content


def _is_library_file(file_path: str, content: str) -> bool:
    """Check if file is a known library"""
    library_keywords = [
        'jQuery', 'React', 'Vue', 'Angular', 'lodash',
        'moment', 'axios', 'swiper', 'slick', 'chart.js',
        'd3', 'three', 'bootstrap', 'foundation'
    ]
    
    # Check file path for library indicators
    path_library_indicators = [
        'node_modules/',
        'bower_components/',
        'vendor/',
        'lib/',
        'assets/vendor/',
        'static/vendor/',
    ]
    
    for indicator in path_library_indicators:
        if indicator in file_path:
            return True
    
    # Check first few lines for library declarations
    lines = content.splitlines()[:20]
    header = '\n'.join(lines)
    
    for keyword in library_keywords:
        if keyword in header:
            return True
    
    # Check for hashed filenames (build artifacts)
    if re.search(r'[a-f0-9]{10,}\.js$', file_path):
        return True
    
    return False


def _should_skip_line(line: str) -> bool:
    """Check if a line should be skipped (false positive)"""
    # Skip comments
    if line.strip().startswith('//') or line.strip().startswith('/*'):
        return True
    
    # Skip common false positive patterns
    fp_patterns = [
        'console.log', 'console.warn', 'console.error',
        '// @ts-', '/* eslint-', '"use strict"',
        'typeof window', 'typeof document',
        'module.exports', 'exports.',
        'require(', 'import {', 'import ',
    ]
    
    for pattern in fp_patterns:
        if pattern in line:
            return True
    
    # Skip lines that are just braces or brackets
    if line.strip() in ['{', '}', '(', ')', '[', ']', ';']:
        return True
    
    return False


def _process_single_file(args):
    """Process a single file for vulnerabilities"""
    file_path, rule, target_dir = args
    local_findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.splitlines()

        # Skip empty files
        if not content.strip():
            return local_findings

        # Check if this is a library file
        if _is_library_file(file_path, content):
            # Still scan but with lower confidence
            pass

        # Pre-process minified JS
        if file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            content = _preprocess_javascript(content)
            lines = content.splitlines()

        for line_idx, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Skip lines that are false positives
            if _should_skip_line(line):
                continue

            # Check against false positives list
            if any(fp in line for fp in FALSE_POSITIVES):
                continue

            # Detect vulnerability
            vuln_detected = any(
                pattern.search(line)
                for pattern in rule.vuln_patterns
            )

            if not vuln_detected:
                continue

            # Get context window
            start_win = max(0, line_idx - 5)
            end_win = min(len(lines), line_idx + 5)
            context_window = lines[start_win:end_win]

            # Check for sanitization
            is_sanitized = any(
                any(p.search(c.strip()) for p in rule.sanitizer_patterns)
                for c in context_window
            )

            # Use rule's severity/confidence
            severity = rule.severity
            confidence = rule.confidence

            # Get risk info if available
            if hasattr(rule, 'category'):
                risk_info = get_risk(rule.category)
                if risk_info:
                    severity = risk_info[0]

            # If it's a library file, lower confidence
            if _is_library_file(file_path, content):
                confidence = min(confidence - 20, 50)

            local_findings.append({
                "finding_id": f"AS-{rule.category}-{line_idx}",
                "cwe": getattr(rule, 'cwe', 'N/A'),
                "category": getattr(rule, 'category', 'UNKNOWN'),
                "name": getattr(rule, 'name', 'Unnamed Rule'),
                "file": os.path.relpath(file_path, target_dir),
                "line": line_idx,
                "snippet": line[:200],
                "status": "VULNERABLE" if not is_sanitized else "SANITIZED",
                "severity": severity,
                "confidence": confidence,
                "description": getattr(rule, 'vuln_desc', '') if not is_sanitized else getattr(rule, 'safe_desc', ''),
                "timestamp": datetime.now().isoformat()
            })

    except Exception as e:
        print(f"[SCAN ERROR] {file_path}: {e}")

    return local_findings


class SurfaceScanner:
    """Main scanner class"""
    
    def __init__(self, target_dir: str, rules_list: Optional[List] = None):
        self.target_dir = os.path.abspath(target_dir)
        self.rules = rules_list if rules_list is not None else RULES
        self.findings = []

        self.excluded_dirs = {
            "venv", ".venv", "env", ".env", ".git", "node_modules",
            "__pycache__", ".pytest_cache", ".next", "dist", "build",
            "target", "out", "bin", "obj", "coverage", ".idea", ".vscode",
            "logs", "tmp", "temp", "backup", "backups", "cache"
        }

        self.excluded_exts = {
            ".min.js", ".map", ".css", ".svg", ".png", ".jpg", ".jpeg",
            ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".flv", ".wmv",
            ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2"
        }

        self.supported_exts = {
            ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm",
            ".json", ".yml", ".yaml", ".conf", ".config", ".env",
            ".xml", ".php", ".rb", ".go", ".rs", ".java", ".c", ".cpp",
            ".sh", ".bash", ".zsh", ".ps1", ".tf", ".sql", ".vue"
        }

    def scan(self) -> List[Dict]:
        """Perform the scan"""
        tasks = []
        file_count = 0

        # Collect all files to scan
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in self.excluded_dirs]

            for file in files:
                file_path = os.path.join(root, file)

                # Check if file should be scanned
                if not self._should_scan_file(file_path):
                    continue

                file_count += 1

                # Match rules to file
                for rule in self.rules:
                    if self._rule_matches_file(rule, file_path):
                        tasks.append((file_path, rule, self.target_dir))

        if not tasks:
            print(f"[INFO] No files to scan in {self.target_dir}")
            return self.findings

        print(f"[INFO] Scanning {file_count} files with {len(self.rules)} rules...")

        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(_process_single_file, tasks)

        for r in results:
            self.findings.extend(r)

        print(f"[INFO] Found {len(self.findings)} findings")
        return self.findings

    def _should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned"""
        # Skip known library paths
        lib_patterns = [
            'node_modules/',
            'bower_components/',
            'vendor/',
            'lib/',
            'assets/vendor/',
            'static/vendor/',
        ]
        
        for pattern in lib_patterns:
            if pattern in file_path:
                return False
        
        # Skip minified files
        if '.min.js' in file_path or '.min.css' in file_path:
            return False
        
        # Skip hashed filenames (build artifacts)
        if re.search(r'[a-f0-9]{10,}\.js$', file_path):
            return False
        
        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.supported_exts:
            return False
        
        # Check excluded extensions
        if any(file_path.lower().endswith(ext) for ext in self.excluded_exts):
            return False
        
        # Check file size (skip large files > 10MB)
        try:
            if os.path.getsize(file_path) > 10 * 1024 * 1024:
                return False
        except:
            return False
        
        return True

    def _rule_matches_file(self, rule, file_path: str) -> bool:
        """Check if rule applies to file"""
        ext = os.path.splitext(file_path)[1].lower()
        return any(file_path.endswith(fe) or ext == fe for fe in rule.file_exts)

    def export_findings(self, output_dir: str = "output") -> bool:
        """Export findings to JSON and SQLite"""
        import os
        import json
        import sqlite3
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Export to JSON
        json_path = os.path.join(output_dir, "findings.json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, default=safe_serializer, indent=2, ensure_ascii=False)
            print(f"[+] Exported {len(self.findings)} findings to {json_path}")
        except Exception as e:
            print(f"[!] Error exporting JSON: {e}")
            return False
        
        # Export to SQLite
        db_path = os.path.join(output_dir, "findings.db")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Drop old table if exists to fix schema
            cursor.execute("DROP TABLE IF EXISTS security_findings")
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT,
                    cwe TEXT,
                    category TEXT,
                    name TEXT,
                    file_path TEXT,
                    line_num INTEGER,
                    snippet TEXT,
                    status TEXT,
                    severity TEXT,
                    confidence INTEGER,
                    description TEXT,
                    timestamp TEXT
                )
            """)
            
            for f in self.findings:
                cursor.execute("""
                    INSERT INTO security_findings (
                        finding_id, cwe, category, name, file_path,
                        line_num, snippet, status, severity,
                        confidence, description, timestamp
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.get("finding_id"),
                    f.get("cwe"),
                    f.get("category"),
                    f.get("name"),
                    f.get("file"),
                    f.get("line"),
                    f.get("snippet"),
                    f.get("status"),
                    f.get("severity"),
                    f.get("confidence"),
                    f.get("description"),
                    f.get("timestamp"),
                ))
            
            conn.commit()
            conn.close()
            print(f"[+] Exported findings to {db_path}")
            return True
            
        except Exception as e:
            print(f"[!] Error exporting to SQLite: {e}")
            return False


# Keep backward compatibility
def export_results(results, output_dir):
    """Legacy function for compatibility"""
    scanner = SurfaceScanner(".")
    scanner.findings = results
    return scanner.export_findings(output_dir)
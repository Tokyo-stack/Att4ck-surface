"""
Exporter Module - Export findings to various formats
"""

import os
import json
import sqlite3
import csv
from datetime import datetime
from typing import List, Dict, Optional


def safe_serializer(obj):
    """Safe JSON serializer"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, '__dict__'):
        return str(obj)
    return str(obj)


def export_to_json(findings: List[Dict], output_dir: str = "output") -> str:
    """Export findings to JSON"""
    os.makedirs(output_dir, exist_ok=True)
    
    json_path = os.path.join(output_dir, "findings.json")
    
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, default=safe_serializer, indent=2, ensure_ascii=False)
        print(f"[+] Exported {len(findings)} findings to {json_path}")
        return json_path
    except Exception as e:
        print(f"[!] Error exporting to JSON: {e}")
        # Write empty array as fallback
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return json_path


def export_to_sqlite(findings: List[Dict], output_dir: str = "output") -> str:
    """Export findings to SQLite"""
    os.makedirs(output_dir, exist_ok=True)
    
    db_path = os.path.join(output_dir, "findings.db")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create table
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
                timestamp TEXT,
                risk_score INTEGER
            )
        """)
        
        # Clear old data
        cursor.execute("DELETE FROM security_findings")
        
        # Insert findings
        for f in findings:
            cursor.execute("""
                INSERT INTO security_findings (
                    finding_id, cwe, category, name, file_path,
                    line_num, snippet, status, severity,
                    confidence, description, timestamp, risk_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                f.get("risk_score", 0),
            ))
        
        conn.commit()
        conn.close()
        print(f"[+] Exported {len(findings)} findings to {db_path}")
        return db_path
        
    except Exception as e:
        print(f"[!] Error exporting to SQLite: {e}")
        return ""


def export_to_csv(findings: List[Dict], output_dir: str = "output") -> str:
    """Export findings to CSV"""
    os.makedirs(output_dir, exist_ok=True)
    
    csv_path = os.path.join(output_dir, "findings.csv")
    
    try:
        if not findings:
            with open(csv_path, "w", encoding="utf-8") as f:
                f.write("No findings found")
            return csv_path
        
        # Get all keys
        keys = ["finding_id", "category", "name", "file", "line", 
                "status", "severity", "confidence", "description", "cwe"]
        
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            
            for finding in findings:
                row = {k: finding.get(k, "") for k in keys}
                writer.writerow(row)
        
        print(f"[+] Exported {len(findings)} findings to {csv_path}")
        return csv_path
        
    except Exception as e:
        print(f"[!] Error exporting to CSV: {e}")
        return ""


def export_to_html(findings: List[Dict], output_dir: str = "output") -> str:
    """Export findings to HTML report"""
    os.makedirs(output_dir, exist_ok=True)
    
    html_path = os.path.join(output_dir, "report.html")
    
    try:
        # Build HTML content as a list of strings to avoid f-string issues
        html_lines = [
            '<!DOCTYPE html>',
            '<html>',
            '<head>',
            '    <meta charset="UTF-8">',
            '    <title>ATT4ck Surface Security Report</title>',
            '    <style>',
            '        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }',
            '        h1 { color: #333; }',
            '        .summary { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }',
            '        table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; }',
            '        th { background: #4CAF50; color: white; padding: 12px; text-align: left; }',
            '        td { padding: 10px; border-bottom: 1px solid #ddd; }',
            '        tr:hover { background: #f5f5f5; }',
            '        .critical { color: #ff0000; font-weight: bold; }',
            '        .high { color: #ff6b00; font-weight: bold; }',
            '        .medium { color: #ffa500; font-weight: bold; }',
            '        .low { color: #ffff00; font-weight: bold; }',
            '        .info { color: #808080; }',
            '        .timestamp { color: #666; font-size: 0.9em; }',
            '        .status-vulnerable { background: #ffebee; }',
            '        .status-sanitized { background: #e8f5e9; }',
            '    </style>',
            '</head>',
            '<body>',
            '    <h1>ATT4ck Surface Security Report</h1>',
            '    <div class="summary">',
            '        <h2>Scan Summary</h2>',
            f'        <p><strong>Total Findings:</strong> {len(findings)}</p>',
            f'        <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>',
            f'        <p><strong>Critical:</strong> {len([f for f in findings if f.get("severity") == "CRITICAL"])}</p>',
            f'        <p><strong>High:</strong> {len([f for f in findings if f.get("severity") == "HIGH"])}</p>',
            f'        <p><strong>Medium:</strong> {len([f for f in findings if f.get("severity") == "MEDIUM"])}</p>',
            f'        <p><strong>Low:</strong> {len([f for f in findings if f.get("severity") == "LOW"])}</p>',
            '    </div>',
            '    <h2>Detailed Findings</h2>',
            '    <table>',
            '        <thead>',
            '            <tr>',
            '                <th>Severity</th>',
            '                <th>Category</th>',
            '                <th>Name</th>',
            '                <th>File</th>',
            '                <th>Line</th>',
            '                <th>Status</th>',
            '            </tr>',
            '        </thead>',
            '        <tbody>'
        ]
        
        # Add each finding as a table row
        for f in findings:
            severity = f.get('severity', 'MEDIUM')
            severity_class = severity.lower()
            status = f.get('status', 'UNKNOWN')
            status_class = f"status-{status.lower()}"
            
            html_lines.append(f'''
            <tr class="{status_class}">
                <td><span class="{severity_class}">{severity}</span></td>
                <td>{f.get('category', 'N/A')}</td>
                <td>{f.get('name', 'N/A')}</td>
                <td>{f.get('file', 'N/A')}</td>
                <td>{f.get('line', 'N/A')}</td>
                <td>{status}</td>
            </tr>
            ''')
        
        # Close HTML
        html_lines.extend([
            '        </tbody>',
            '    </table>',
            '</body>',
            '</html>'
        ])
        
        # Join and write
        html_content = '\n'.join(html_lines)
        
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"[+] Exported HTML report to {html_path}")
        return html_path
        
    except Exception as e:
        print(f"[!] Error exporting to HTML: {e}")
        return ""


def export_results(findings: List[Dict], output_dir: str = "output") -> dict:
    """
    Export findings to all formats
    
    Args:
        findings: List of finding dictionaries
        output_dir: Output directory
        
    Returns:
        Dictionary with paths to exported files
    """
    results = {
        "json": export_to_json(findings, output_dir),
        "sqlite": export_to_sqlite(findings, output_dir),
        "csv": export_to_csv(findings, output_dir),
        "html": export_to_html(findings, output_dir),
    }
    
    return results
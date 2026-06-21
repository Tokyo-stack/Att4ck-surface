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
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ATT4ck Surface Security Report</
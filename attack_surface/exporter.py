# attack_surface/exporter.py
import json
import sqlite3
import os

def export_results(results, output_dir):
    """Generates clean JSON data dumps and queryable historical SQLite databases."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. Save Structured JSON Report
    json_path = os.path.join(output_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=4)

    # 2. Save Persistent SQLite File
    db_path = os.path.join(output_dir, "findings.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            name TEXT,
            file_path TEXT,
            line_num INTEGER,
            snippet TEXT,
            status TEXT,
            severity TEXT,
            description TEXT
        )
    """)
    
    # Empty old runs to ensure accurate current diff metrics
    cursor.execute("DELETE FROM security_findings")
    
    for f in results:
        cursor.execute("""
            INSERT INTO security_findings (category, name, file_path, line_num, snippet, status, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (f["category"], f["name"], f["file"], f["line"], f["snippet"], f["status"], f["severity"], f["description"]))
        
    conn.commit()
    conn.close()

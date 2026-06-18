import json
import sqlite3
import os


def export_results(results, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # JSON export
    json_path = os.path.join(output_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as f:
        print("TOTAL RESULTS:", len(results))
        json.dump(results, f, indent=4)

    # SQLite export
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
            confidence INTEGER,
            cwe TEXT,
            finding_id TEXT,
            description TEXT
        )
    """)

    cursor.execute("DELETE FROM security_findings")

    for f in results:
        cursor.execute("""
            INSERT INTO security_findings (
                category, name, file_path, line_num,
                snippet, status, severity,
                confidence, cwe, finding_id, description
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f.get("category"),
            f.get("name"),
            f.get("file"),
            f.get("line"),
            f.get("snippet"),
            f.get("status"),
            f.get("severity"),
            f.get("confidence"),
            f.get("cwe"),
            f.get("finding_id"),
            f.get("description"),
        ))

    conn.commit()
    conn.close()
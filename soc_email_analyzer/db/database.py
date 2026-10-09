import sqlite3
import json
import os
from datetime import datetime

class Database:
    def __init__(self, db_path="soc_analyzer.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create analyses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                risk_score INTEGER,
                severity TEXT,
                findings_json TEXT,
                raw_headers_json TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def save_analysis(self, subject, sender, risk_score, severity, findings, headers):
        """Saves an analysis record to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        timestamp = datetime.utcnow().isoformat()

        cursor.execute('''
            INSERT INTO analyses (timestamp, subject, sender, risk_score, severity, findings_json, raw_headers_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp,
            subject,
            sender,
            risk_score,
            severity,
            json.dumps(findings),
            json.dumps(headers)
        ))

        last_row_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return last_row_id

    def get_history(self, limit=50):
        """Retrieves recent analysis history."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, timestamp, subject, sender, risk_score, severity
            FROM analyses
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def get_analysis(self, analysis_id):
        """Retrieves a specific analysis record."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM analyses WHERE id = ?', (analysis_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            result = dict(row)
            result['findings'] = json.loads(result['findings_json']) if result.get('findings_json') else []
            result['headers'] = json.loads(result['raw_headers_json']) if result.get('raw_headers_json') else {}
            return result
        return None

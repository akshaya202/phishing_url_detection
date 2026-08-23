import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

try:
    from supabase import create_client
except Exception:  # pragma: no cover
    create_client = None

DB_PATH = Path(__file__).resolve().parent.parent / 'models' / 'app_data.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_ANON_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
SUPABASE_CLIENT = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY and create_client else None


class Database:
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self.init()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self):
        conn = self._connect()
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                email TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                url TEXT,
                prediction TEXT,
                confidence REAL,
                risk REAL,
                reason TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                reporter_id INTEGER,
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                verified_by INTEGER,
                verified_at TEXT
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                status TEXT DEFAULT 'verified',
                source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                verified_by INTEGER
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS model_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT UNIQUE,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1 REAL,
                confusion_matrix TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            '''
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (id, name, email, password, role) VALUES (1, 'System Admin', 'admin@college.edu', 'admin123', 'admin')"
        )
        conn.commit()
        conn.close()

    def create_user(self, name, email, password, role='user'):
        conn = self._connect()
        try:
            cursor = conn.execute(
                'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
                (name, email, password, role),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def get_user_by_email(self, email):
        conn = self._connect()
        row = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_id(self, user_id):
        conn = self._connect()
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def save_scan(self, user_id, url, prediction, confidence, risk, reason):
        conn = self._connect()
        conn.execute(
            'INSERT INTO scans (user_id, url, prediction, confidence, risk, reason) VALUES (?, ?, ?, ?, ?, ?)',
            (user_id, url, prediction, confidence, risk, reason),
        )
        conn.commit()
        conn.close()

    def get_user_scans(self, user_id):
        conn = self._connect()
        rows = conn.execute(
            'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 25',
            (user_id,),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def save_report(self, url, reporter_id):
        conn = self._connect()
        cursor = conn.execute(
            'INSERT INTO reports (url, reporter_id, status) VALUES (?, ?, ?)',
            (url, reporter_id, 'pending'),
        )
        conn.commit()
        conn.close()
        return cursor.lastrowid

    def get_reports(self):
        conn = self._connect()
        rows = conn.execute('SELECT * FROM reports ORDER BY created_at DESC').fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_report_status(self, report_id, status, verified_by):
        conn = self._connect()
        conn.execute(
            'UPDATE reports SET status = ?, verified_by = ?, verified_at = ? WHERE id = ?',
            (status, verified_by, datetime.utcnow().isoformat(timespec='seconds') + 'Z', report_id),
        )
        conn.commit()
        conn.close()

    def add_threat_intelligence(self, url, source, verified_by):
        conn = self._connect()
        conn.execute(
            'INSERT OR IGNORE INTO threat_intelligence (url, status, source, verified_by) VALUES (?, ?, ?, ?)',
            (url, 'verified', source, verified_by),
        )
        conn.commit()
        conn.close()

    def get_verified_reports(self):
        conn = self._connect()
        rows = conn.execute(
            'SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC',
            ('verified',),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def save_model_version(self, version, accuracy, precision, recall, f1, confusion_matrix):
        conn = self._connect()
        conn.execute(
            'INSERT OR REPLACE INTO model_versions (version, accuracy, precision, recall, f1, confusion_matrix) VALUES (?, ?, ?, ?, ?, ?)',
            (version, accuracy, precision, recall, f1, json.dumps(confusion_matrix)),
        )
        conn.commit()
        conn.close()

    def get_latest_model_version(self):
        conn = self._connect()
        row = conn.execute(
            'SELECT * FROM model_versions ORDER BY id DESC LIMIT 1',
        ).fetchone()
        conn.close()
        if not row:
            return None
        data = dict(row)
        data['confusion_matrix'] = json.loads(data['confusion_matrix']) if data.get('confusion_matrix') else [[0, 0], [0, 0]]
        return data

    def count_scan_distribution(self):
        conn = self._connect()
        rows = conn.execute(
            '''
            SELECT prediction, COUNT(*) as total
            FROM scans
            GROUP BY prediction
            '''
        ).fetchall()
        conn.close()
        result = {'legitimate': 0, 'phishing': 0, 'suspicious': 0}
        for row in rows:
            key = str(row['prediction']).lower()
            if key in result:
                result[key] = int(row['total'])
        return result

    def get_summary_stats(self):
        conn = self._connect()
        report_rows = conn.execute('SELECT status, COUNT(*) AS total FROM reports GROUP BY status').fetchall()
        daily_rows = conn.execute(
            '''
            SELECT date(created_at) AS day, COUNT(*) AS scans
            FROM scans
            GROUP BY date(created_at)
            ORDER BY day DESC
            LIMIT 7
            '''
        ).fetchall()
        conn.close()

        reports = {'total': 0, 'pending': 0, 'verified': 0, 'rejected': 0}
        for row in report_rows:
            status = str(row['status']).lower()
            reports['total'] += int(row['total'])
            if status in reports:
                reports[status] = int(row['total'])

        daily = [{'day': str(row['day'])[-5:], 'scans': int(row['scans'])} for row in reversed(daily_rows)]
        if not daily:
            daily = [{'day': 'today', 'scans': 0}]
        return reports, daily

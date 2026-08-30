import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

try:
    from supabase import create_client
except Exception:  # pragma: no cover
    create_client = None

DB_PATH = Path(__file__).resolve().parent.parent / 'models' / 'app_data.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_ANON_KEY')
SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')

# Use service role key for backend operations (server-side only)
SUPABASE_KEY = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY
SUPABASE_CLIENT = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY and create_client else None
USE_SUPABASE = SUPABASE_CLIENT is not None


class Database:
    def __init__(self, db_path: str = str(DB_PATH)):
        self.db_path = db_path
        self.use_supabase = USE_SUPABASE
        if not self.use_supabase:
            self.init_sqlite()
            self._ensure_scan_model_version()

    def _connect(self):
        """SQLite connection for fallback"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_scan_model_version(self):
        """Add model_version column for stored scan history when needed."""
        conn = self._connect()
        columns = conn.execute('PRAGMA table_info(scans)').fetchall()
        if not any(col['name'] == 'model_version' for col in columns):
            conn.execute('ALTER TABLE scans ADD COLUMN model_version TEXT')
        conn.commit()
        conn.close()

    def _ensure_report_metadata_columns(self):
        """Add optional metadata columns to existing reports table."""
        conn = self._connect()
        columns = conn.execute('PRAGMA table_info(reports)').fetchall()
        names = {col['name'] for col in columns}
        if 'reason' not in names:
            conn.execute('ALTER TABLE reports ADD COLUMN reason TEXT DEFAULT "Other"')
        if 'description' not in names:
            conn.execute('ALTER TABLE reports ADD COLUMN description TEXT DEFAULT ""')
        conn.commit()
        conn.close()

    def init_sqlite(self):
        """Initialize SQLite schema as fallback"""
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
                model_version TEXT,
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
                reason TEXT DEFAULT 'Other',
                description TEXT DEFAULT '',
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

    def init(self):
        """Initialize database (SQLite fallback only)"""
        if not self.use_supabase:
            self.init_sqlite()

    # ========================================================================
    # USER MANAGEMENT
    # ========================================================================

    def create_user(self, name, email, password, role='user'):
        """Create a new user in SQLite (for backward compatibility)"""
        if self.use_supabase:
            # For Supabase, use Supabase Auth instead
            return None
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

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('profiles').select('*').eq('email', email).execute()
                if response.data:
                    return response.data[0]
            except Exception as e:
                print(f"Error fetching user by email from Supabase: {e}")
            return None
        
        conn = self._connect()
        row = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_user_by_id(self, user_id) -> Optional[Dict]:
        """Get user by ID"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('profiles').select('*').eq('id', str(user_id)).execute()
                if response.data:
                    return response.data[0]
            except Exception as e:
                print(f"Error fetching user by ID from Supabase: {e}")
            return None
        
        conn = self._connect()
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_users(self) -> List[Dict]:
        """Get all users (admin only)"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('profiles').select('*').execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching all users from Supabase: {e}")
            return []
        return []

    def update_user_profile(self, user_id: str, full_name: str) -> Optional[Dict]:
        """Update user profile"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('profiles').update(
                    {'full_name': full_name}
                ).eq('id', str(user_id)).execute()
                return response.data[0] if response.data else None
            except Exception as e:
                print(f"Error updating user profile in Supabase: {e}")
            return None
        return None

    # ========================================================================
    # SCAN MANAGEMENT
    # ========================================================================

    def save_scan(self, user_id, url: str, prediction: str, confidence: float, 
                  risk: float, reason: str, **kwargs) -> Optional[str]:
        """Save a URL scan result"""
        if self.use_supabase:
            try:
                domain = kwargs.get('domain', '')
                severity = kwargs.get('severity', 'low')
                detection_reasons = kwargs.get('detection_reasons')
                extracted_features = kwargs.get('extracted_features')
                ssl_status = kwargs.get('ssl_status')
                domain_info = kwargs.get('domain_info')
                reputation_info = kwargs.get('reputation_info')
                is_phishing = prediction.lower() == 'phishing'

                response = SUPABASE_CLIENT.table('url_scans').insert({
                    'user_id': str(user_id),
                    'url': url,
                    'domain': domain,
                    'prediction': prediction.lower(),
                    'confidence': float(confidence),
                    'risk_score': float(risk),
                    'severity': severity,
                    'is_phishing': is_phishing,
                    'detection_reasons': detection_reasons,
                    'extracted_features': extracted_features,
                    'ssl_status': ssl_status,
                    'domain_info': domain_info,
                    'reputation_info': reputation_info,
                    'model_version': kwargs.get('model_version') or 'n/a',
                }).execute()
                
                if response.data:
                    return response.data[0].get('id')
            except Exception as e:
                print(f"Error saving scan to Supabase: {e}")
            return None

        # SQLite fallback
        conn = self._connect()
        conn.execute(
            'INSERT INTO scans (user_id, url, prediction, confidence, risk, reason, model_version) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (user_id, url, prediction, confidence, risk, reason, kwargs.get('model_version') or 'n/a'),
        )
        conn.commit()
        conn.close()
        return None

    def get_user_scans(self, user_id, limit: int = 25) -> List[Dict]:
        """Get user's scans"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('url_scans').select(
                    'id, user_id, url, domain, prediction, confidence, risk_score, severity, is_phishing, model_version, created_at'
                ).eq('user_id', str(user_id)).order('created_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching user scans from Supabase: {e}")
            return []

        conn = self._connect()
        rows = conn.execute(
            'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
            (user_id, limit),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_all_scans(self, limit: int = 100) -> List[Dict]:
        """Get all scans (admin only)"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('url_scans').select('*').order('created_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching all scans from Supabase: {e}")
            return []
        return []

    def get_scan_detail(self, scan_id: str) -> Optional[Dict]:
        """Get detailed scan information"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('url_scans').select('*').eq('id', scan_id).single().execute()
                return response.data if response.data else None
            except Exception as e:
                print(f"Error fetching scan detail from Supabase: {e}")
            return None
        return None

    # ========================================================================
    # THREAT INTELLIGENCE
    # ========================================================================

    def save_threat_intelligence(self, scan_id: str, source: str, threat_type: str, 
                                reputation: str, details: Optional[Dict] = None) -> Optional[str]:
        """Save threat intelligence for a scan"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('threat_intelligence').insert({
                    'scan_id': str(scan_id),
                    'source': source,
                    'threat_type': threat_type,
                    'reputation': reputation,
                    'details': details or {},
                }).execute()
                return response.data[0].get('id') if response.data else None
            except Exception as e:
                print(f"Error saving threat intelligence to Supabase: {e}")
            return None
        return None

    def get_threat_intelligence(self, scan_id: str) -> List[Dict]:
        """Get threat intelligence for a scan"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('threat_intelligence').select('*').eq('scan_id', scan_id).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching threat intelligence from Supabase: {e}")
            return []
        return []

    def get_all_threats(self, limit: int = 100) -> List[Dict]:
        """Get all threats (admin only)"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('threat_intelligence').select('*').order('checked_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching all threats from Supabase: {e}")
            return []
        return []

    # ========================================================================
    # ALERTS
    # ========================================================================

    def create_alert(self, user_id: str, scan_id: str, severity: str, message: str) -> Optional[str]:
        """Create an alert for high-risk scans"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('alerts').insert({
                    'user_id': str(user_id),
                    'scan_id': str(scan_id),
                    'severity': severity,
                    'message': message,
                    'status': 'unread',
                }).execute()
                return response.data[0].get('id') if response.data else None
            except Exception as e:
                print(f"Error creating alert in Supabase: {e}")
            return None
        return None

    def get_user_alerts(self, user_id: str, limit: int = 50) -> List[Dict]:
        """Get user's alerts"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('alerts').select('*').eq('user_id', str(user_id)).order('created_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching user alerts from Supabase: {e}")
            return []
        return []

    def get_all_alerts(self, limit: int = 100) -> List[Dict]:
        """Get all alerts (admin only)"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('alerts').select('*').order('created_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching all alerts from Supabase: {e}")
            return []
        return []

    def mark_alert_as_read(self, alert_id: str) -> Optional[Dict]:
        """Mark alert as read"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('alerts').update(
                    {'status': 'read'}
                ).eq('id', alert_id).execute()
                return response.data[0] if response.data else None
            except Exception as e:
                print(f"Error marking alert as read in Supabase: {e}")
            return None
        return None

    # ========================================================================
    # API LOGS
    # ========================================================================

    def log_api_call(self, user_id: Optional[str], endpoint: str, method: str, 
                    status_code: int, ip_address: Optional[str]) -> Optional[str]:
        """Log API call for audit trail"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('api_logs').insert({
                    'user_id': str(user_id) if user_id else None,
                    'endpoint': endpoint,
                    'method': method,
                    'status_code': status_code,
                    'ip_address': ip_address,
                }).execute()
                return response.data[0].get('id') if response.data else None
            except Exception as e:
                print(f"Error logging API call in Supabase: {e}")
            return None
        return None

    def get_api_logs(self, limit: int = 100) -> List[Dict]:
        """Get API logs (admin only)"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('api_logs').select('*').order('created_at', desc=True).limit(limit).execute()
                return response.data or []
            except Exception as e:
                print(f"Error fetching API logs from Supabase: {e}")
            return []
        return []

    # ========================================================================
    # REPORTS (Legacy)
    # ========================================================================

    def save_report(self, url, reporter_id, reason='Other', description=''):
        """Save URL report (legacy - SQLite only)"""
        if self.use_supabase:
            return None

        conn = self._connect()
        cursor = conn.execute(
            'INSERT INTO reports (url, reporter_id, reason, description, status) VALUES (?, ?, ?, ?, ?)',
            (url, reporter_id, reason or 'Other', description or '', 'pending'),
        )
        conn.commit()
        conn.close()
        return cursor.lastrowid

    def get_reports(self):
        """Get reports (legacy - SQLite only)"""
        if self.use_supabase:
            return []
        
        conn = self._connect()
        rows = conn.execute('SELECT * FROM reports ORDER BY created_at DESC').fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def update_report_status(self, report_id, status, verified_by):
        """Update report status (legacy - SQLite only)"""
        if self.use_supabase:
            return
        
        conn = self._connect()
        conn.execute(
            'UPDATE reports SET status = ?, verified_by = ?, verified_at = ? WHERE id = ?',
            (status, verified_by, datetime.utcnow().isoformat(timespec='seconds') + 'Z', report_id),
        )
        conn.commit()
        conn.close()

    def add_threat_intelligence(self, url, source, verified_by):
        """Add threat intelligence (legacy - SQLite only)"""
        if self.use_supabase:
            return
        
        conn = self._connect()
        conn.execute(
            'INSERT OR IGNORE INTO threat_intelligence (url, status, source, verified_by) VALUES (?, ?, ?, ?)',
            (url, 'verified', source, verified_by),
        )
        conn.commit()
        conn.close()

    def get_verified_reports(self):
        """Get verified reports (legacy - SQLite only)"""
        if self.use_supabase:
            return []
        
        conn = self._connect()
        rows = conn.execute(
            'SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC',
            ('verified',),
        ).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    # ========================================================================
    # MODEL VERSIONS
    # ========================================================================

    def save_model_version(self, version, accuracy, precision, recall, f1, confusion_matrix):
        """Save model version metrics"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('model_versions').insert({
                    'version': version,
                    'accuracy': float(accuracy),
                    'precision': float(precision),
                    'recall': float(recall),
                    'f1': float(f1),
                    'confusion_matrix': confusion_matrix if isinstance(confusion_matrix, dict) else json.loads(confusion_matrix),
                }).execute()
                return response.data[0].get('id') if response.data else None
            except Exception as e:
                print(f"Error saving model version to Supabase: {e}")
            return None

        conn = self._connect()
        conn.execute(
            'INSERT OR REPLACE INTO model_versions (version, accuracy, precision, recall, f1, confusion_matrix) VALUES (?, ?, ?, ?, ?, ?)',
            (version, accuracy, precision, recall, f1, json.dumps(confusion_matrix)),
        )
        conn.commit()
        conn.close()

    def get_latest_model_version(self):
        """Get latest model version"""
        if self.use_supabase:
            try:
                response = SUPABASE_CLIENT.table('model_versions').select('*').order('created_at', desc=True).limit(1).execute()
                if response.data:
                    return response.data[0]
            except Exception as e:
                print(f"Error fetching latest model version from Supabase: {e}")
            return None

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

    # ========================================================================
    # ANALYTICS & STATISTICS
    # ========================================================================

    def count_scan_distribution(self) -> Dict[str, int]:
        """Get scan distribution by prediction type"""
        if self.use_supabase:
            try:
                # Fetch all scans and count by prediction
                response = SUPABASE_CLIENT.table('url_scans').select('prediction').execute()
                scans = response.data or []
                result = {'legitimate': 0, 'phishing': 0, 'suspicious': 0}
                for scan in scans:
                    pred = scan['prediction'].lower()
                    if pred in result:
                        result[pred] += 1
                return result
            except Exception as e:
                print(f"Error getting scan distribution from Supabase: {e}")
            return {'legitimate': 0, 'phishing': 0, 'suspicious': 0}

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
        """Get summary statistics for dashboard"""
        if self.use_supabase:
            try:
                # Get scan counts by prediction
                scans = SUPABASE_CLIENT.table('url_scans').select('prediction, created_at').order('created_at', desc=True).execute()
                scan_data = scans.data or []

                # Count by prediction
                result = {'legitimate': 0, 'phishing': 0, 'suspicious': 0}
                daily_scans = {}
                
                for scan in scan_data:
                    pred = scan['prediction'].lower()
                    if pred in result:
                        result[pred] += 1
                    
                    # Group by date
                    date_str = scan['created_at'].split('T')[0]
                    daily_scans[date_str] = daily_scans.get(date_str, 0) + 1

                # Get alerts count
                alerts = SUPABASE_CLIENT.table('alerts').select('status').execute()
                alert_data = alerts.data or []
                alert_counts = {'total': len(alert_data), 'unread': 0, 'read': 0, 'verified': 0}
                for alert in alert_data:
                    if alert['status'] == 'unread':
                        alert_counts['unread'] += 1
                    elif alert['status'] == 'read':
                        alert_counts['read'] += 1

                # Convert daily stats to list format
                daily_list = [
                    {'day': day[-5:], 'scans': count}
                    for day, count in sorted(daily_scans.items())[-7:]
                ]
                if not daily_list:
                    daily_list = [{'day': 'today', 'scans': 0}]

                return alert_counts, daily_list
            except Exception as e:
                print(f"Error getting summary stats from Supabase: {e}")
            return {'total': 0, 'unread': 0, 'read': 0, 'verified': 0}, [{'day': 'today', 'scans': 0}]

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


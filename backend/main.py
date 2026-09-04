import os
import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import pandas as pd

try:
    from supabase import create_client
except ImportError:
    create_client = None

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.database import Database, SUPABASE_CLIENT, USE_SUPABASE
from ml.dataset_pipeline import load_all_datasets, split_training_and_external
from ml.phishing_model import DATASETS_DIR, bootstrap_initial_model, load_latest_model, predict_label_and_reason

app = FastAPI(title='Dynamic Phishing URL Detection System')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

security = HTTPBearer(auto_error=False)
SECRET_KEY = os.getenv('SECRET_KEY', 'college-phish-sense-secret')
ALGORITHM = 'HS256'

db = Database()


def _safe_url(url: str):
    trimmed = (url or '').strip()
    if not trimmed:
        raise HTTPException(status_code=400, detail='A URL is required.')
    parsed = urlparse(trimmed if trimmed.startswith(('http://', 'https://')) else f'https://{trimmed}')
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail='Please enter a valid URL.')
    return trimmed


def _get_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
        return parsed.netloc.lower()
    except:
        return ''


def _create_token(user):
    payload = {'sub': user['email'], 'role': user['role'], 'user_id': user['id']}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _decode_token(credentials: HTTPAuthorizationCredentials):
    if not credentials:
        raise HTTPException(status_code=401, detail='Authentication required.')
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail='Invalid or expired token.') from exc
    user = db.get_user_by_email(payload.get('sub'))
    if not user:
        raise HTTPException(status_code=401, detail='User not found.')
    return user


def _require_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = _decode_token(credentials)
    if user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail='Admin access required.')
    return user


def _require_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return _decode_token(credentials)


@app.on_event('startup')
def startup_event():
    try:
        model, metadata = load_latest_model()
        if model is None:
            model, metadata = bootstrap_initial_model()
            db.save_model_version(
                metadata['version'],
                metadata['accuracy'],
                metadata['precision'],
                metadata['recall'],
                metadata['f1'],
                metadata['confusion_matrix'],
            )
    except Exception:
        model, metadata = bootstrap_initial_model()
        db.save_model_version(
            metadata['version'],
            metadata['accuracy'],
            metadata['precision'],
            metadata['recall'],
            metadata['f1'],
            metadata['confusion_matrix'],
        )


@app.get('/')
def read_root():
    return {'message': 'Dynamic Phishing URL Detection System API is running.'}


@app.post('/api/auth/register')
def register_user(payload: dict):
    name = (payload.get('name') or '').strip()
    email = (payload.get('email') or '').strip().lower()
    password = str(payload.get('password') or '').strip()

    if not name or not email or not password:
        raise HTTPException(status_code=400, detail='Name, email and password are required.')

    if db.get_user_by_email(email):
        raise HTTPException(status_code=400, detail='Email already registered.')

    user_id = db.create_user(name, email, password, role='user')
    user = db.get_user_by_id(user_id)
    return {'token': _create_token(user), 'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}}


@app.post('/api/auth/login')
def login_user(payload: dict):
    email = (payload.get('email') or '').strip().lower()
    password = str(payload.get('password') or '').strip()
    user = db.get_user_by_email(email)
    if not user or user['password'] != password:
        raise HTTPException(status_code=401, detail='Invalid email or password.')
    return {'token': _create_token(user), 'user': {'id': user['id'], 'name': user['name'], 'email': user['email'], 'role': user['role']}}


@app.post('/api/scan')
def scan_url(payload: dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
    url = _safe_url(payload.get('url'))
    model, _ = load_latest_model()
    if model is None:
        model, _ = bootstrap_initial_model()

    label, probability, reason = predict_label_and_reason(model, url)
    risk_value = float(probability)
    user = _decode_token(credentials) if credentials else None

    # Save to database with complete data
    if user:
        from ml.phishing_model import _extract_features
        
        domain = _get_domain(url)
        features = _extract_features(url)
        
        # Determine severity based on risk
        severity = 'high' if risk_value >= 0.8 else ('medium' if risk_value >= 0.5 else 'low')
        
        scan_id = db.save_scan(
            user['id'], 
            url, 
            label, 
            float(probability), 
            risk_value, 
            reason,
            domain=domain,
            severity=severity,
            detection_reasons={'ml_classification': label, 'reason': reason},
            extracted_features={'feature_count': len(features), 'vector': features if isinstance(features, dict) else {}},
            model_version=_get_model_version(),
        )
        
        # Create alert if high risk
        if risk_value >= 0.7 and label.lower() == 'phishing':
            db.create_alert(
                user['id'],
                scan_id,
                'high',
                f'HIGH RISK: Phishing URL detected - {domain}'
            )

    return {
        'url': url,
        'prediction': label,
        'confidence': float(probability),
        'risk': risk_value,
        'reason': reason,
        'model_version': _get_model_version(),
    }


@app.get('/api/scans/history')
def get_history(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = _decode_token(credentials)
    return {'history': db.get_user_scans(user['id'])}


@app.post('/api/reports')
def submit_report(payload: dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = _decode_token(credentials)
    url = _safe_url(payload.get('url'))
    reason = str(payload.get('reason') or 'Other').strip() or 'Other'
    description = str(payload.get('description') or '').strip()
    report_id = db.save_report(url, user['id'], reason=reason, description=description)
    return {'id': report_id, 'status': 'pending', 'message': 'Your report has been submitted for admin verification.'}


@app.get('/api/admin/reports')
def list_reports(credentials: HTTPAuthorizationCredentials = Depends(security)):
    _require_admin(credentials)
    return {'reports': db.get_reports()}


@app.post('/api/admin/reports/{report_id}/decision')
def decide_report(report_id: int, payload: dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = _require_admin(credentials)
    status = (payload.get('status') or '').strip().lower()
    if status not in {'verified', 'rejected'}:
        raise HTTPException(status_code=400, detail='Status must be either verified or rejected.')

    report_rows = db.get_reports()
    report = next((item for item in report_rows if item['id'] == report_id), None)
    if not report:
        raise HTTPException(status_code=404, detail='Report not found.')

    db.update_report_status(report_id, status, user['id'])
    if status == 'verified':
        db.add_threat_intelligence(report['url'], 'crowdsourced', user['id'])

    return {'status': status, 'message': f'Report marked as {status}.'}


@app.get('/api/admin/summary')
def admin_summary(credentials: HTTPAuthorizationCredentials = Depends(security)):
    _require_admin(credentials)
    report_summary, daily = db.get_summary_stats()
    counts = db.count_scan_distribution()
    metadata = _get_latest_metadata()
    return {
        'counts': counts,
        'reports': report_summary,
        'dailyScans': daily,
        'model': {
            'accuracy': metadata['accuracy'] if metadata else 0,
            'precision': metadata['precision'] if metadata else 0,
            'recall': metadata['recall'] if metadata else 0,
            'f1': metadata['f1'] if metadata else 0,
        },
        'modelVersion': metadata['version'] if metadata else 'n/a',
    }


@app.get('/api/admin/metrics')
def admin_metrics(credentials: HTTPAuthorizationCredentials = Depends(security)):
    _require_admin(credentials)
    metadata = _get_latest_metadata()
    if not metadata:
        return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0, 'confusion_matrix': [[0, 0], [0, 0]]}
    return {**metadata}


# ============================================================================
# NEW SUPABASE-INTEGRATED ENDPOINTS
# ============================================================================

@app.get('/api/scan/{scan_id}')
def get_scan_detail(scan_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get detailed information about a specific scan"""
    user = _require_user(credentials)
    scan = db.get_scan_detail(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found.')
    
    # Check authorization
    if scan['user_id'] != user['id'] and user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Not authorized to view this scan.')
    
    # Get threat intelligence
    threats = db.get_threat_intelligence(scan_id)
    scan['threats'] = threats
    
    return {'scan': scan}


@app.get('/api/scans')
def get_scans(skip: int = 0, limit: int = 25, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get user's scans with pagination"""
    user = _require_user(credentials)
    scans = db.get_user_scans(user['id'], limit=limit)
    return {'scans': scans, 'total': len(scans)}


@app.get('/api/threats')
def get_threats(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get threat intelligence (user's or admin's)"""
    user = _require_user(credentials)
    
    if user['role'] == 'admin':
        threats = db.get_all_threats()
    else:
        # Get threats from user's scans
        scans = db.get_user_scans(user['id'], limit=100)
        threats = []
        for scan in scans:
            threats.extend(db.get_threat_intelligence(scan['id']))
    
    return {'threats': threats}


@app.get('/api/alerts')
def get_alerts(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get user's alerts"""
    user = _require_user(credentials)
    alerts = db.get_user_alerts(user['id'])
    return {'alerts': alerts}


@app.patch('/api/alerts/{alert_id}')
def update_alert(alert_id: str, payload: dict, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Mark alert as read"""
    user = _require_user(credentials)
    
    status = (payload.get('status') or '').strip().lower()
    if status not in {'read', 'unread'}:
        raise HTTPException(status_code=400, detail='Status must be "read" or "unread".')
    
    result = db.mark_alert_as_read(alert_id) if status == 'read' else None
    return {'alert': result, 'status': status}


@app.get('/api/analytics')
def get_analytics(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get analytics and statistics"""
    user = _require_user(credentials)
    
    if user['role'] == 'admin':
        # Admin gets system-wide stats
        scans = db.get_all_scans(limit=1000)
        alerts = db.get_all_alerts(limit=500)
    else:
        # User gets their own stats
        scans = db.get_user_scans(user['id'], limit=500)
        alerts = db.get_user_alerts(user['id'], limit=500)
    
    # Calculate statistics
    prediction_dist = {'safe': 0, 'suspicious': 0, 'phishing': 0}
    severity_dist = {'low': 0, 'medium': 0, 'high': 0}
    alert_dist = {'unread': 0, 'read': 0}
    
    for scan in scans:
        pred = scan['prediction'].lower() if scan.get('prediction') else 'safe'
        if pred in prediction_dist:
            prediction_dist[pred] += 1
        
        severity = scan.get('severity', 'low')
        if severity in severity_dist:
            severity_dist[severity] += 1
    
    for alert in alerts:
        status = alert.get('status', 'unread')
        if status in alert_dist:
            alert_dist[status] += 1
    
    return {
        'total_scans': len(scans),
        'total_alerts': len(alerts),
        'prediction_distribution': prediction_dist,
        'severity_distribution': severity_dist,
        'alert_distribution': alert_dist,
        'recent_scans': scans[:10],
    }


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@app.get('/api/admin/users')
def list_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get all users (admin only)"""
    _require_admin(credentials)
    users = db.get_all_users()
    return {'users': users}


@app.get('/api/admin/logs')
def get_logs(skip: int = 0, limit: int = 100, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get API logs (admin only)"""
    _require_admin(credentials)
    logs = db.get_api_logs(limit=limit)
    return {'logs': logs}


@app.get('/api/admin/scans')
def admin_get_scans(limit: int = 100, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get all scans (admin only)"""
    _require_admin(credentials)
    scans = db.get_all_scans(limit=limit)
    return {'scans': scans}


@app.get('/api/admin/threats')
def admin_get_threats(limit: int = 100, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get all threat intelligence (admin only)"""
    _require_admin(credentials)
    threats = db.get_all_threats(limit=limit)
    return {'threats': threats}


@app.get('/api/admin/alerts')
def admin_get_alerts(limit: int = 100, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get all alerts (admin only)"""
    _require_admin(credentials)
    alerts = db.get_all_alerts(limit=limit)
    return {'alerts': alerts}


@app.post('/api/admin/retrain')
def admin_retrain(credentials: HTTPAuthorizationCredentials = Depends(security)):
    _require_admin(credentials)
    combined, reports = load_all_datasets(DATASETS_DIR)
    training, external, reports = split_training_and_external(combined, reports)
    verified_reports = db.get_verified_reports()

    if verified_reports:
        verified_df = pd.DataFrame([
            {'url': item['url'], 'verdict': 1} for item in verified_reports
        ])
        training = pd.concat([training, verified_df], ignore_index=True)

    from ml.phishing_model import train_and_evaluate_model, get_next_model_version, save_model_version

    model, metrics = train_and_evaluate_model(training, external)
    metrics['dataset_reports'] = reports
    metrics['combined_records'] = int(len(combined))
    metrics['combined_class_distribution'] = {
        'legitimate': int((combined['verdict'] == 0).sum()),
        'phishing': int((combined['verdict'] == 1).sum()),
    }
    version = get_next_model_version()
    metadata = save_model_version(model, metrics, version)
    db.save_model_version(metadata['version'], metadata['accuracy'], metadata['precision'], metadata['recall'], metadata['f1'], metadata['confusion_matrix'])
    return {'message': f'Model retrained successfully as {metadata["version"]}.', 'version': metadata['version'], 'metrics': metadata}


def _get_latest_metadata():
    metadata_path = Path(__file__).resolve().parent.parent / 'models' / 'latest_model.json'
    if not metadata_path.exists():
        return None
    import json
    return json.loads(metadata_path.read_text())


def _get_model_version():
    metadata = _get_latest_metadata()
    return metadata['version'] if metadata else 'n/a'


if __name__ == '__main__':
    uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=True)

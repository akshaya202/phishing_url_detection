import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.database import Database
from ml.phishing_model import DATASET_PATH, bootstrap_initial_model, load_latest_model, predict_label_and_reason

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
        dataset = pd.read_csv(DATASET_PATH)
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

    if user:
        db.save_scan(user['id'], url, label, float(probability), risk_value, reason)

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
    report_id = db.save_report(url, user['id'])
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


@app.post('/api/admin/retrain')
def admin_retrain(credentials: HTTPAuthorizationCredentials = Depends(security)):
    _require_admin(credentials)
    dataset = pd.read_csv(DATASET_PATH)
    verified_reports = db.get_verified_reports()

    if verified_reports:
        verified_df = pd.DataFrame([
            {'url': item['url'], 'verdict': 1} for item in verified_reports
        ])
        combined = pd.concat([dataset, verified_df], ignore_index=True)
    else:
        combined = dataset.copy()

    from ml.phishing_model import train_and_evaluate_model, get_next_model_version, save_model_version

    model, metrics = train_and_evaluate_model(combined)
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

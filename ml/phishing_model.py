import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT_DIR / 'datasets' / 'phishing_dataset.csv'
MODELS_DIR = ROOT_DIR / 'models'
MODELS_DIR.mkdir(exist_ok=True)


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _extract_features(url: str):
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    hostname = parsed.hostname or ''

    dots = url.count('.')
    hyphens = url.count('-')
    underscores = url.count('_')
    special_chars = sum(ch.isalnum() is False for ch in url)
    digits = sum(ch.isdigit() for ch in url)
    at_sign = 1 if '@' in url else 0
    has_ip = 1 if hostname and hostname.replace('.', '').isdigit() else 0
    has_http = 1 if parsed.scheme in {'http', 'https'} else 0
    subdomains = len(hostname.split('.')) - 2 if hostname and '.' in hostname else 0
    path_len = len(path)
    query_len = len(query)
    suspicious_tld = 1 if hostname.endswith(('.tk', '.xyz', '.club', '.top', '.ga')) else 0
    sensitive_words = sum(word in url.lower() for word in ['login', 'verify', 'secure', 'bank', 'confirm', 'update', 'password', 'account'])
    tld_len = len(hostname.split('.')[-1]) if hostname and '.' in hostname else 0

    return [
        len(url),
        len(domain),
        path_len,
        query_len,
        dots,
        hyphens,
        underscores,
        at_sign,
        has_ip,
        has_http,
        subdomains,
        digits,
        suspicious_tld,
        special_chars,
        sensitive_words,
        tld_len,
    ]


def build_feature_matrix(df: pd.DataFrame):
    features = []
    labels = []
    for _, row in df.iterrows():
        url = str(row.get('url', '')).strip()
        if not url:
            continue
        features.append(_extract_features(url))
        labels.append(int(row.get('verdict', 0)))
    return np.asarray(features, dtype=float), np.asarray(labels, dtype=int)


def train_and_evaluate_model(df: pd.DataFrame):
    X, y = build_feature_matrix(df)
    if X.size == 0:
        raise ValueError('No valid URL rows were found in the dataset.')

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=250,
        random_state=42,
        class_weight='balanced',
        min_samples_leaf=2,
        max_depth=None,
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    metrics = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1': float(f1_score(y_test, y_pred, zero_division=0)),
        'confusion_matrix': confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist(),
    }
    return model, metrics


def get_next_model_version():
    files = sorted(MODELS_DIR.glob('model_v*.joblib'))
    if not files:
        return 'model_v1'
    numbers = []
    for path in files:
        try:
            numbers.append(int(str(path.name).split('v')[-1].split('.joblib')[0]))
        except ValueError:
            continue
    return f'model_v{max(numbers) + 1}' if numbers else 'model_v1'


def save_model_version(model, metrics, version):
    path = MODELS_DIR / f'{version}.joblib'
    joblib.dump(model, path)
    metadata = {
        'version': version,
        'created_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'accuracy': metrics['accuracy'],
        'precision': metrics['precision'],
        'recall': metrics['recall'],
        'f1': metrics['f1'],
        'confusion_matrix': metrics['confusion_matrix'],
    }
    (MODELS_DIR / 'latest_model.json').write_text(json.dumps(metadata, indent=2))
    return metadata


def load_latest_model():
    latest_meta = MODELS_DIR / 'latest_model.json'
    if not latest_meta.exists():
        return None, None

    metadata = json.loads(latest_meta.read_text())
    version = metadata.get('version')
    model_path = MODELS_DIR / f'{version}.joblib'
    if not model_path.exists():
        return None, None

    model = joblib.load(model_path)
    return model, metadata


def predict_probability(model, url: str):
    feature_vector = np.asarray([_extract_features(url)], dtype=float)
    probability = float(model.predict_proba(feature_vector)[0][1])
    return probability


def predict_label_and_reason(model, url: str):
    probability = predict_probability(model, url)
    if probability >= 0.80:
        label = 'Phishing'
    elif probability <= 0.45:
        label = 'Legitimate'
    else:
        label = 'Suspicious'

    if probability >= 0.80:
        reason = 'The URL shows strong phishing indicators such as suspicious domains, malicious keywords, or a high-risk structure.'
    elif probability <= 0.45:
        reason = 'The URL structure and indicators are consistent with a legitimate web destination.'
    else:
        reason = 'The URL is ambiguous and should be treated cautiously pending additional review.'
    return label, probability, reason


def bootstrap_initial_model():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f'Missing phishing dataset at {DATASET_PATH}')

    dataset = pd.read_csv(DATASET_PATH)
    dataset = dataset.dropna(subset=['url']).copy()
    if 'verdict' not in dataset.columns or 'url' not in dataset.columns:
        raise ValueError('Dataset must contain both url and verdict columns. Confirm the file schema before training.')

    model, metrics = train_and_evaluate_model(dataset)
    version = get_next_model_version()
    metadata = save_model_version(model, metrics, version)
    return model, metadata

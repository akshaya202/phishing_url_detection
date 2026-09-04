import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
from typing import Dict, Optional, Tuple

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

"""Feature extraction, model training, evaluation, and persistence."""

from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from ml.dataset_pipeline import (
    DATASETS_DIR,
    load_all_datasets,
    split_training_and_external,
)


FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'query_length', 'num_dots',
    'num_slashes', 'num_hyphens', 'num_underscores', 'num_digits',
    'num_special_characters', 'has_at_symbol', 'uses_ip_address',
    'uses_https', 'num_subdomains', 'suspicious_tld', 'suspicious_keywords',
    'url_shortener', 'tld_length',
]

SUSPICIOUS_KEYWORDS = (
    'login', 'verify', 'secure', 'bank', 'confirm', 'update', 'password',
    'account', 'signin', 'authenticate', 'validation', 'recover', 'unlock',
    'suspend', 'billing',
)

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'cutt.ly', 'shorturl.at',
}
MAX_TRAINING_ROWS = 120000


def _extract_features(url: str) -> Dict[str, float]:
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'https://{url}')
    domain = parsed.netloc.lower().split('@')[-1].split(':')[0]
    hostname = parsed.hostname or ''
    try:
        uses_ip = int(ipaddress.ip_address(hostname) is not None)
    except ValueError:
        uses_ip = 0
    labels = hostname.split('.') if hostname else []
    keyword_count = sum(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)
    tld = labels[-1] if len(labels) > 1 else ''
    return {
        'url_length': len(url),
        'domain_length': len(domain),
        'path_length': len(parsed.path),
        'query_length': len(parsed.query),
        'num_dots': url.count('.'),
        'num_slashes': url.count('/'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_digits': sum(character.isdigit() for character in url),
        'num_special_characters': sum(not character.isalnum() for character in url),
        'has_at_symbol': int('@' in url),
        'uses_ip_address': uses_ip,
        'uses_https': int(parsed.scheme == 'https'),
        'num_subdomains': max(len(labels) - 2, 0),
        'suspicious_tld': int(hostname.endswith(('.tk', '.xyz', '.club', '.top', '.ga', '.ml', '.cf'))),
        'suspicious_keywords': keyword_count,
        'url_shortener': int(hostname in SHORTENER_DOMAINS),
        'tld_length': len(tld),
    }


def build_feature_matrix(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    valid_rows = df[df['url'].notna() & df['verdict'].notna()]
    feature_rows = [_extract_features(str(url).strip()) for url in valid_rows['url']]
    features = np.asarray([[row[name] for name in FEATURE_NAMES] for row in feature_rows], dtype=float)
    labels = valid_rows['verdict'].astype(int).to_numpy()
    return features, labels


def _evaluate(model, X_test, y_test) -> Dict:
    predictions = model.predict(X_test)
    return {
        'accuracy': float(accuracy_score(y_test, predictions)),
        'precision': float(precision_score(y_test, predictions, zero_division=0)),
        'recall': float(recall_score(y_test, predictions, zero_division=0)),
        'f1': float(f1_score(y_test, predictions, zero_division=0)),
        'confusion_matrix': confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
    }


def _candidate_models() -> Dict[str, object]:
    candidates = {
        'random_forest': RandomForestClassifier(
            n_estimators=250, random_state=42, class_weight='balanced', min_samples_leaf=2
        ),
        'logistic_regression': make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        ),
        'svm': make_pipeline(
            StandardScaler(), SVC(probability=True, class_weight='balanced', random_state=42)
        ),
    }
    try:
        from xgboost import XGBClassifier
        candidates['xgboost'] = XGBClassifier(
            n_estimators=250, max_depth=6, learning_rate=0.08,
            subsample=0.9, colsample_bytree=0.9, eval_metric='logloss',
            random_state=42, n_jobs=2,
        )
    except ImportError:
        pass
    return candidates


def train_and_evaluate_model(df: pd.DataFrame, external_df: Optional[pd.DataFrame] = None):
    if len(df) > MAX_TRAINING_ROWS:
        # Keep model comparison tractable without changing the cleaned dataset report.
        samples = []
        for _, group in df.groupby('verdict'):
            samples.append(group.sample(n=min(len(group), MAX_TRAINING_ROWS // 2), random_state=42))
        df = pd.concat(samples, ignore_index=True)
    X, y = build_feature_matrix(df)
    if X.size == 0:
        raise ValueError('No valid URL rows were found in the datasets.')
    if len(np.unique(y)) < 2:
        raise ValueError('Training data must contain both legitimate and phishing labels.')
    if min(np.bincount(y)) < 2:
        raise ValueError('Each training class must contain at least two rows.')

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    comparisons = {}
    trained_models = {}
    for name, candidate in _candidate_models().items():
        candidate.fit(X_train, y_train)
        trained_models[name] = candidate
        comparisons[name] = _evaluate(candidate, X_test, y_test)

    best_name = max(comparisons, key=lambda name: (
        comparisons[name]['f1'], comparisons[name]['recall'], comparisons[name]['precision']
    ))
    best_model = trained_models[best_name]
    metrics = {
        **comparisons[best_name],
        'model_name': best_name,
        'model_comparison': comparisons,
        'feature_names': FEATURE_NAMES,
        'feature_config': {
            'url_normalization': 'strip whitespace and surrounding quotes; add https for parsing only',
            'label_encoding': {'0': 'Legitimate/Safe', '1': 'Phishing/Malicious'},
        },
        'training_records': int(len(y)),
    }
    if external_df is not None and not external_df.empty:
        external_X, external_y = build_feature_matrix(external_df)
        if len(np.unique(external_y)) >= 2:
            metrics['external_metrics'] = _evaluate(best_model, external_X, external_y)
            metrics['external_records'] = int(len(external_y))
            metrics['external_dataset'] = str(external_df['source'].iloc[0])
    return best_model, metrics


def get_next_model_version():
    files = sorted(MODELS_DIR.glob('model_v*.joblib'))
    numbers = []
    for path in files:
        try:
            numbers.append(int(path.stem.split('v')[-1]))
        except ValueError:
            continue
    return f'model_v{max(numbers) + 1}' if numbers else 'model_v1'


def save_model_version(model, metrics, version):
    path = MODELS_DIR / f'{version}.joblib'
    joblib.dump(model, path)
    metadata = {
        'version': version,
        'created_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        **{key: metrics[key] for key in ('accuracy', 'precision', 'recall', 'f1', 'confusion_matrix')},
        'model_name': metrics.get('model_name'),
        'model_comparison': metrics.get('model_comparison', {}),
        'feature_names': metrics.get('feature_names', FEATURE_NAMES),
        'feature_config': metrics.get('feature_config', {}),
        'external_metrics': metrics.get('external_metrics'),
        'external_records': metrics.get('external_records', 0),
        'external_dataset': metrics.get('external_dataset'),
        'dataset_reports': metrics.get('dataset_reports', []),
        'combined_records': metrics.get('combined_records', 0),
        'combined_class_distribution': metrics.get('combined_class_distribution', {}),
        'training_records': metrics.get('training_records', 0),
    }
    (MODELS_DIR / 'latest_model.json').write_text(json.dumps(metadata, indent=2))
    return metadata


def load_latest_model():
    latest_meta = MODELS_DIR / 'latest_model.json'
    if not latest_meta.exists():
        return None, None
    metadata = json.loads(latest_meta.read_text())
    model_path = MODELS_DIR / f"{metadata.get('version')}.joblib"
    if not model_path.exists():
        return None, None
    model = joblib.load(model_path)
    if getattr(model, 'n_features_in_', len(FEATURE_NAMES)) != len(FEATURE_NAMES):
        return None, None
    return model, metadata


def predict_probability(model, url: str):
    feature_values = _extract_features(url)
    feature_vector = np.asarray([[feature_values[name] for name in FEATURE_NAMES]], dtype=float)
    return float(model.predict_proba(feature_vector)[0][1])


def predict_label_and_reason(model, url: str):
    probability = predict_probability(model, url)
    if probability >= 0.80:
        label = 'Phishing'
        reason = 'The URL shows strong phishing indicators such as suspicious domains, malicious keywords, or a high-risk structure.'
    elif probability <= 0.45:
        label = 'Legitimate'
        reason = 'The URL structure and indicators are consistent with a legitimate web destination.'
    else:
        label = 'Suspicious'
        reason = 'The URL is ambiguous and should be treated cautiously pending additional review.'
    return label, probability, reason


def bootstrap_initial_model():
    combined, reports = load_all_datasets(DATASETS_DIR)
    training, external, reports = split_training_and_external(combined, reports)
    model, metrics = train_and_evaluate_model(training, external)
    metrics['dataset_reports'] = reports
    metrics['combined_records'] = int(len(combined))
    metrics['combined_class_distribution'] = {
        'legitimate': int((combined['verdict'] == 0).sum()),
        'phishing': int((combined['verdict'] == 1).sum()),
    }
    version = get_next_model_version()
    metadata = save_model_version(model, metrics, version)
    return model, metadata


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

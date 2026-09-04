"""Load, validate, normalize, and combine phishing URL CSV datasets."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import re

import pandas as pd


DATASETS_DIR = Path(__file__).resolve().parent.parent / 'datasets'

# Add a file entry here when a provider uses an unusual schema or label encoding.
# Numeric encodings are intentionally explicit so their meaning is never guessed.
DATASET_CONFIG: Dict[str, Dict[str, Any]] = {
    'phishing_dataset.csv': {
        'url_column': 'url',
        'label_column': 'verdict',
        'label_mapping': {0: 0, 1: 1},
    },
    'phishing_features.csv': {
        'url_column': 'url',
        'label_column': 'label',
        'label_mapping': {0: 0, 1: 1},
    },
    'phishing_site_urls.csv': {
        'url_column': 'URL',
        'label_column': 'Label',
        'label_mapping': {'good': 0, 'bad': 1},
    },
}

URL_COLUMN_ALIASES = {
    'url', 'urladdress', 'website', 'weburl', 'link', 'uri', 'domain',
}
LABEL_COLUMN_ALIASES = {
    'label', 'labels', 'verdict', 'class', 'classification', 'target',
    'result', 'status', 'type',
}
SAFE_LABELS = {'good', 'safe', 'legitimate', 'benign', '正常', 'legit'}
PHISHING_LABELS = {
    'bad', 'phishing', 'malicious', 'malware', 'fraud', 'unsafe',
    'suspicious', 'attack',
}


class DatasetSchemaError(ValueError):
    """Raised when a CSV cannot be safely converted to the standard schema."""


def _normalized_name(value: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', str(value).strip().lower())


def _find_column(columns, aliases: set, configured: Optional[str]) -> Optional[str]:
    if configured:
        if configured in columns:
            return configured
        configured_name = _normalized_name(configured)
        for column in columns:
            if _normalized_name(column) == configured_name:
                return column
        return None
    for column in columns:
        if _normalized_name(column) in aliases:
            return column
    return None


def _mapping_value(mapping: Dict[Any, int], value: Any) -> Optional[int]:
    if value in mapping:
        return int(mapping[value])
    text = str(value).strip().lower()
    if text in mapping:
        return int(mapping[text])
    for key, mapped in mapping.items():
        if str(key).strip().lower() == text:
            return int(mapped)
    return None


def _normalize_labels(values: pd.Series, mapping: Optional[Dict[Any, int]]) -> pd.Series:
    if mapping:
        normalized = values.map(lambda value: _mapping_value(mapping, value))
        if normalized.isna().any():
            unknown = sorted({str(value) for value in values[normalized.isna()].dropna()})
            raise DatasetSchemaError(f'Label mapping does not cover values: {unknown[:10]}')
        return normalized.astype(int)

    normalized = []
    unknown = set()
    for value in values:
        text = str(value).strip().lower()
        if text in SAFE_LABELS:
            normalized.append(0)
        elif text in PHISHING_LABELS:
            normalized.append(1)
        else:
            unknown.add(text)
            normalized.append(None)
    if unknown:
        raise DatasetSchemaError(
            'Unmapped label values found. Add an explicit label_mapping: '
            f'{sorted(unknown)[:10]}'
        )
    return pd.Series(normalized, index=values.index, dtype='int64')


def _clean_url(value: Any) -> str:
    if pd.isna(value):
        return ''
    return str(value).strip().strip('"\'').strip()


def _distribution(labels: pd.Series) -> Dict[str, int]:
    counts = labels.value_counts().to_dict()
    return {'legitimate': int(counts.get(0, 0)), 'phishing': int(counts.get(1, 0))}


def load_dataset(path: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Return standardized ``url/verdict/source`` rows and an inspection report."""
    report: Dict[str, Any] = {'file': path.name, 'status': 'rejected'}
    try:
        frame = pd.read_csv(path)
    except Exception as exc:
        report['reason'] = f'Could not read CSV: {exc}'
        return pd.DataFrame(), report

    config = DATASET_CONFIG.get(path.name, {})
    url_column = _find_column(frame.columns, URL_COLUMN_ALIASES, config.get('url_column'))
    label_column = _find_column(frame.columns, LABEL_COLUMN_ALIASES, config.get('label_column'))
    if not url_column or not label_column:
        missing = []
        if not url_column:
            missing.append('URL column')
        if not label_column:
            missing.append('label column')
        report['reason'] = f"Missing {', '.join(missing)}; columns found: {list(frame.columns)}"
        return pd.DataFrame(), report

    try:
        standardized = pd.DataFrame({
            'url': frame[url_column].map(_clean_url),
            'verdict': frame[label_column],
        })
        standardized = standardized[standardized['url'].ne('') & standardized['verdict'].notna()].copy()
        standardized['verdict'] = _normalize_labels(standardized['verdict'], config.get('label_mapping'))
    except DatasetSchemaError as exc:
        report['reason'] = str(exc)
        return pd.DataFrame(), report

    before = len(standardized)
    standardized['_url_key'] = standardized['url'].str.lower().str.rstrip('/')
    standardized = standardized.drop_duplicates('_url_key').drop(columns='_url_key')
    standardized['verdict'] = standardized['verdict'].astype(int)
    standardized['source'] = path.name
    report.update({
        'status': 'loaded',
        'url_column': url_column,
        'label_column': label_column,
        'records': len(standardized),
        'removed_missing': before - len(standardized),
        'class_distribution': _distribution(standardized['verdict']),
    })
    return standardized, report


def load_all_datasets(directory: Path = DATASETS_DIR) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """Load every CSV, returning usable rows and a report for every file."""
    frames: List[pd.DataFrame] = []
    reports: List[Dict[str, Any]] = []
    for path in sorted(directory.glob('*.csv')):
        frame, report = load_dataset(path)
        reports.append(report)
        if report['status'] == 'loaded':
            frames.append(frame)

    if not frames:
        reports.append({
            'file': '__combined__',
            'status': 'summary',
            'records': 0,
            'class_distribution': {'legitimate': 0, 'phishing': 0},
        })
        return pd.DataFrame(columns=['url', 'verdict', 'source']), reports

    combined = pd.concat(frames, ignore_index=True)
    combined['_url_key'] = combined['url'].str.lower().str.rstrip('/')
    combined = combined.drop_duplicates('_url_key').drop(columns='_url_key')
    reports.append({
        'file': '__combined__',
        'status': 'summary',
        'records': len(combined),
        'class_distribution': _distribution(combined['verdict']),
    })
    return combined, reports


def split_training_and_external(
    combined: pd.DataFrame,
    reports: List[Dict[str, Any]],
    training_dataset_count: int = 3,
) -> Tuple[pd.DataFrame, Optional[pd.DataFrame], List[Dict[str, Any]]]:
    """Use the first three usable datasets for training and the fourth externally."""
    usable = [report['file'] for report in reports if report['status'] == 'loaded']
    if len(usable) <= training_dataset_count:
        return combined, None, reports

    external_name = usable[training_dataset_count]
    external = combined[combined['source'] == external_name].copy()
    training = combined[combined['source'] != external_name].copy()
    return training, external, reports
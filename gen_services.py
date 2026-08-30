import textwrap

code = textwrap.dedent(r'''
"""
URL Analysis Services
Provides comprehensive URL scanning, SSL/TLS checks, domain reputation,
and explainable threat detection.
"""
import json
import socket
import ssl
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests

from backend.database import Database

db = Database()

SUSPICIOUS_TLDS = {'.tk', '.xyz', '.club', '.top', '.ga', '.ml', '.cf', '.gq', '.buzz', '.zip', '.review', '.country', '.kim', '.cricket', '.science', '.work', '.party', '.link', '.click'}
SENSITIVE_KEYWORDS = ['login', 'verify', 'secure', 'bank', 'confirm', 'update', 'password', 'account', 'signin', 'sign-in', 'authenticate', 'validation', 'recover', 'unlock', 'verifyaccount', 'verify-account', 'security', 'alert', 'warning', 'suspend', 'limited', 'expire', 'billing']
SAFE_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co'}


def _normalize_url(url):
    url = (url or '').strip()
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    return url


def check_https(url):
    is_https = url.startswith('https://')
    return {'available': is_https, 'status': 'secure' if is_https else 'insecure', 'message': 'HTTPS is enabled.' if is_https else 'URL uses HTTP instead of HTTPS.', 'passed': is_https}


def check_ssl_certificate(hostname, port=443, timeout=5.0):
    result = {'valid': False, 'issuer': None, 'subject': None, 'not_before': None, 'not_after': None, 'days_remaining': None, 'protocol': None, 'cipher': None, 'domain_match': False, 'error': None, 'passed': False}
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result['protocol'] = ssock.version()
                result['cipher'] = cipher[0] if cipher else None
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', ()))
                    result['subject'] = subject.get('commonName', '')
                    result['issuer'] = dict(x[0] for x in cert.get('issuer', ())).get('commonName', '')
                    result['not_before'] = cert.get('notBefore', '')
                    result['not_after'] = cert.get('notAfter', '')
                    for dfmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
                        try:
                            na = datetime.strptime(result['not_after'], dfmt)
                            nb = datetime.strptime(result['not_before'], dfmt)
                            result['days_remaining'] = (na - datetime.utcnow()).days
                            break
                        except ValueError:
                            continue
                    san_list = [x[1] for x in cert.get('subjectAltName', ()) if x[0] == 'DNS']
                    dl = hostname.lower()
                    matched = any((san.startswith('*.') and dl.endswith(san[1:].lower())) or san.lower() == dl for san in san_list) or result['subject'].lower() == dl
                    result['domain_match'] = matched
                    result['valid'] = True
                    result['passed'] = matched and (result['days_remaining'] is None or result['days_remaining'] > 0)
                    if not matched:
                        result['error'] = 'Certificate does not match the domain.'
                    elif result['days_remaining'] is not None and result['days_remaining'] <= 0:
                        result['error'] = 'Certificate has expired.'
                    elif result['days_remaining'] is not None and result['days_remaining'] <= 7:
                        result['error'] = f'Certificate expires in {result["days_remaining"]} days.'
    except ssl.SSLCertVerificationError as exc:
        result['error'] = f'SSL verification failed: {exc}'
    except ssl.SSLError as exc:
        result['error'] = f'SSL error: {exc}'
    except socket.timeout:
        result['error'] = 'Connection timed out.'
    except socket.gaierror:
        result['error'] = 'Could not resolve hostname.'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused.'
    except Exception as exc:
        result['error'] = f'Unexpected error: {exc}'
    return result
''').lstrip()

with open('backend/services.py', 'w', encoding='utf-8') as f:
    f.write(code)

print('Part 1 written.')

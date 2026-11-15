"""FastAPI v5: one API-key-protected RBAC+PIN bulk snapshot; Entra for PIN creation only."""
from __future__ import annotations
from urllib.parse import urlparse
import requests


class CloudAPIError(RuntimeError):
    pass


def _request(base_url: str, path: str, timeout_seconds: int, *,
             api_key: str | None = None, token: str | None = None,
             method: str = 'GET', payload: dict | None = None) -> dict:
    parsed = urlparse(base_url)
    if (parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise CloudAPIError('RBAC_API_BASE_URL must be a valid HTTPS URL without query or fragment')
    if (api_key is None) == (token is None):
        raise CloudAPIError('Exactly one credential type must be supplied')
    headers = {'Accept': 'application/json', 'Cache-Control': 'no-store'}
    if api_key is not None:
        headers['x-functions-key'] = api_key
    else:
        headers['Authorization'] = f'Bearer {token}'
    try:
        response = requests.request(method, base_url.rstrip('/') + path,
                                    headers=headers, json=payload, timeout=timeout_seconds,
                                    allow_redirects=False)
        if response.status_code >= 300:
            raise CloudAPIError(f'{path}: cloud returned HTTP {response.status_code}')
        body = response.json()
        if not isinstance(body, dict):
            raise CloudAPIError('Malformed cloud JSON response')
        return body
    except (requests.RequestException, ValueError) as exc:
        raise CloudAPIError(f'Cloud request failed ({type(exc).__name__})') from exc


def fetch_bulk_snapshot(base_url: str, api_key: str, timeout_seconds: int) -> dict:
    if not api_key or len(api_key) < 32:
        raise CloudAPIError('Set RBAC_API_KEY to the same 32+ character value as Azure App Service')
    return _request(base_url, '/rbac/snapshot', timeout_seconds, api_key=api_key)


def enroll_pin(base_url: str, token: str, pin: str, timeout_seconds: int) -> dict:
    return _request(base_url, '/pin/enroll', timeout_seconds, token=token, method='POST',
                    payload={'pin': pin, 'confirmPin': pin})

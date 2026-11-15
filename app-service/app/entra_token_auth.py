"""Validate Entra v2 access tokens scoped for this API, not Graph access tokens."""
from functools import lru_cache
from uuid import UUID
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException


@lru_cache(maxsize=8)
def _jwks_client(tenant: str) -> PyJWKClient:
    return PyJWKClient(
        f'https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys',
        cache_jwk_set=True, lifespan=3600, timeout=5,
    )


def validate_api_token(raw_token: str, *, tenant_id: str, api_client_id: str,
                       desktop_client_id: str, required_scope: str) -> str:
    """Return user OID; issuer/audience/signature/expiry/client/scope validated."""
    if not raw_token or len(raw_token) > 16000 or required_scope not in {'pin.enroll', 'pin.sync'}:
        raise HTTPException(401, 'Invalid access token')
    try:
        tenant_id = str(UUID(tenant_id))
        api_client_id = str(UUID(api_client_id))
        desktop_client_id = str(UUID(desktop_client_id))
        key = _jwks_client(tenant_id).get_signing_key_from_jwt(raw_token).key
        claims = jwt.decode(
            raw_token, key, algorithms=['RS256'],
            audience=[api_client_id, f'api://{api_client_id}'],
            issuer=f'https://login.microsoftonline.com/{tenant_id}/v2.0',
            options={'require': ['exp', 'iat', 'nbf', 'aud', 'iss', 'tid', 'oid']}, leeway=60,
        )
        if claims.get('ver') != '2.0' or str(claims.get('tid', '')).lower() != tenant_id:
            raise ValueError('Incorrect token version or tenant')
        if str(claims.get('azp', '')).lower() != desktop_client_id:
            raise ValueError('Unexpected calling application')
        if required_scope not in str(claims.get('scp', '')).split():
            raise ValueError('Missing delegated scope')
        return str(UUID(claims['oid'])).lower()
    except (jwt.PyJWTError, ValueError, KeyError, OSError) as exc:
        raise HTTPException(401, 'Invalid access token') from exc


# Backward-compatible symbol for existing imports; only enrollment scope.
def validate_enrollment_token(raw_token: str, *, tenant_id: str, api_client_id: str,
                              desktop_client_id: str) -> str:
    return validate_api_token(raw_token, tenant_id=tenant_id, api_client_id=api_client_id,
                              desktop_client_id=desktop_client_id, required_scope='pin.enroll')

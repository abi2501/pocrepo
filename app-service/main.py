"""Bulk RBAC + PIN snapshot: one shared-key download endpoint, no device ID.

PIN enrollment remains Entra-delegated so a shared read key cannot modify PINs.
"""
from datetime import datetime, timedelta, timezone
from typing import Any
import hmac
import logging

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.graph_reader import GraphReader, DirectoryReadError
from app.pin_repository import PinStore, PinAlreadyEnrolled
from app.pin_security import make_verifier
from app.policy_repository import RolePolicyStore, PolicyStoreError
from app.entra_token_auth import validate_api_token

LOG = logging.getLogger(__name__)
app = FastAPI(title='Edge RBAC + PIN Bulk Snapshot', version='6.0.0',
              description='One x-functions-key-protected download of all authorized users and PIN verifiers.')
key_header = APIKeyHeader(name='x-functions-key', auto_error=False)
bearer = HTTPBearer(auto_error=False)


class EnrollmentRequest(BaseModel):
    pin: str = Field(min_length=6, max_length=12)
    confirmPin: str = Field(min_length=6, max_length=12)


class PinVerifier(BaseModel):
    algorithm: str
    saltBase64: str
    verifierBase64: str
    pinVersion: int


class SnapshotUser(BaseModel):
    entraObjectId: str
    username: str
    displayName: str
    enabled: bool
    roles: list[str]
    customSecurityAttributes: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str]
    pinEnrolled: bool
    pin: PinVerifier | None


class BulkSnapshot(BaseModel):
    schemaVersion: int
    version: int
    generatedUtc: str
    validUntilUtc: str
    pinValidUntilUtc: str
    source: dict
    users: list[SnapshotUser]


def utc(dt):
    return dt.isoformat(timespec='seconds').replace('+00:00', 'Z')


def require_api_key(provided: str | None = Security(key_header),
                    settings: Settings = Depends(get_settings)):
    if not settings.api_key or len(settings.api_key) < 32:
        raise HTTPException(503, 'Shared API key is not configured')
    if not provided or not hmac.compare_digest(provided, settings.api_key):
        raise HTTPException(401, 'Invalid or missing API credential')


def get_graph_reader(settings: Settings = Depends(get_settings)):
    return GraphReader(settings)


def get_pin_store(settings: Settings = Depends(get_settings)):
    if not settings.pin_table_endpoint or not settings.pin_table_name:
        raise HTTPException(503, 'PIN storage is not configured')
    try:
        return PinStore(settings.pin_table_endpoint, settings.pin_table_name)
    except ValueError as exc:
        raise HTTPException(503, 'PIN storage is not configured') from exc


def get_policy_store(settings: Settings = Depends(get_settings)):
    if not settings.pin_table_endpoint or not settings.policy_table_name:
        raise HTTPException(503, 'Role policy storage is not configured')
    try:
        return RolePolicyStore(settings.pin_table_endpoint, settings.policy_table_name)
    except ValueError as exc:
        raise HTTPException(503, 'Role policy storage is not configured') from exc


def load_policies(store: RolePolicyStore):
    try:
        return store.get_active_policies()
    except Exception as exc:
        LOG.exception('Role policy read failed')
        raise HTTPException(503, 'Role policy storage unavailable or invalid') from exc


def require_enroll_user(creds: HTTPAuthorizationCredentials | None = Security(bearer),
                        settings: Settings = Depends(get_settings),
                        graph_reader: GraphReader = Depends(get_graph_reader),
                        policy_store: RolePolicyStore = Depends(get_policy_store)):
    if settings.missing_enroll():
        raise HTTPException(503, 'PIN enrollment is not configured')
    if not creds or creds.scheme.lower() != 'bearer':
        raise HTTPException(401, 'Bearer access token required for PIN enrollment')
    oid = validate_api_token(creds.credentials, tenant_id=settings.pin_api_tenant_id,
                             api_client_id=settings.pin_api_client_id,
                             desktop_client_id=settings.edge_public_client_id,
                             required_scope='pin.enroll')
    policies = load_policies(policy_store)
    try:
        user = next((u for u in graph_reader.list_direct_users(policies)
                     if u.get('enabled') and str(u.get('entraObjectId', '')).lower() == oid), None)
    except Exception as exc:
        LOG.exception('Directory lookup failed during enrollment')
        raise HTTPException(502, 'Directory synchronization failed') from exc
    if not user:
        raise HTTPException(403, 'User lacks eligible App Role assignment')
    return user


@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.get('/')
def home():
    return {'service': 'Edge RBAC + PIN Bulk Snapshot', 'documentation': '/docs'}


@app.get('/health')
def health():
    return {'status': 'ok'}


@app.get('/api/rbac/snapshot', response_model=BulkSnapshot, tags=['Bulk synchronization'],
         dependencies=[Depends(require_api_key)])
def bulk_snapshot(settings: Settings = Depends(get_settings),
                  graph_reader: GraphReader = Depends(get_graph_reader),
                  pin_store: PinStore = Depends(get_pin_store),
                  policy_store: RolePolicyStore = Depends(get_policy_store)):
    if settings.missing_snapshot():
        raise HTTPException(503, 'Snapshot service is not configured')
    policies = load_policies(policy_store)
    try:
        users = graph_reader.list_direct_users(policies)
    except (DirectoryReadError, Exception) as exc:
        LOG.exception('Microsoft Graph snapshot failed')
        raise HTTPException(502, 'Directory synchronization failed') from exc
    try:
        pin_records = pin_store.get_active_for_users([u['entraObjectId'] for u in users if u.get('enabled')])
    except Exception as exc:
        LOG.exception('PIN storage snapshot failed')
        raise HTTPException(503, 'PIN storage unavailable; refusing partial snapshot') from exc

    combined = []
    for user in users:
        record = pin_records.get(str(user['entraObjectId']).lower()) if user.get('enabled') else None
        combined.append({**user, 'pinEnrolled': record is not None, 'pin': record})
    now = datetime.now(timezone.utc)
    return {'schemaVersion': 4, 'version': int(now.timestamp()),
            'generatedUtc': utc(now),
            'validUntilUtc': utc(now + timedelta(hours=settings.cache_valid_hours)),
            'pinValidUntilUtc': utc(now + timedelta(hours=settings.pin_cache_valid_hours)),
            'source': {'assignmentMode': 'direct-users-only',
                       'servicePrincipalObjectId': settings.edge_app_sp_object_id},
            'users': combined}


@app.post('/api/pin/enroll', status_code=201, tags=['PIN enrollment'])
def enroll_pin(body: EnrollmentRequest,
               user: dict = Depends(require_enroll_user),
               store: PinStore = Depends(get_pin_store)):
    if body.pin != body.confirmPin:
        raise HTTPException(422, 'PIN confirmation does not match')
    try:
        verifier = make_verifier(body.pin)
        version = store.enroll_first_time(user['entraObjectId'], verifier)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except PinAlreadyEnrolled as exc:
        raise HTTPException(409, 'PIN already enrolled; controlled reset required') from exc
    except Exception as exc:
        LOG.exception('PIN enrollment storage failed')
        raise HTTPException(503, 'PIN storage unavailable') from exc
    return {'status': 'enrolled', 'pinVersion': version}

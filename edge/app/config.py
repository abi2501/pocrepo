"""Cross-platform configuration: shared-key bulk RBAC/PIN download, no RBAC device ID."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path


def _load_env():
    path = Path(os.environ.get('EDGE_ENV_FILE', str(Path(__file__).resolve().parents[1] / '.env')))
    if not path.is_file():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


_load_env()


@dataclass(frozen=True)
class Settings:
    # Only telemetry retains an IoT Hub device identifier, not used for RBAC or PIN sync.
    device_id: str
    telemetry_db_path: str
    auth_db_path: str
    sync_state_db_path: str
    iothub_connection_string: str
    telemetry_poll_seconds: int
    telemetry_batch_size: int
    telemetry_retry_max_seconds: int
    rbac_api_base_url: str
    rbac_http_timeout_seconds: int
    rbac_api_key: str
    entra_tenant_id: str
    edge_public_client_id: str
    pin_api_client_id: str
    offline_auth_max_failed: int
    offline_auth_lock_seconds: int
    log_level: str


def get_settings(require_cloud: bool = True) -> Settings:
    result = Settings(
        device_id=os.getenv('IOTHUB_TELEMETRY_DEVICE_ID', 'EDGE-TELEMETRY-001').strip(),
        telemetry_db_path=os.getenv('TELEMETRY_DB_PATH', './data/telemetry.db'),
        auth_db_path=os.getenv('AUTH_DB_PATH', './data/auth_cache.db'),
        sync_state_db_path=os.getenv('SYNC_STATE_DB_PATH', './data/sync_state.db'),
        iothub_connection_string=os.getenv('IOTHUB_DEVICE_CONNECTION_STRING', '').strip(),
        telemetry_poll_seconds=int(os.getenv('TELEMETRY_POLL_SECONDS', '5')),
        telemetry_batch_size=int(os.getenv('TELEMETRY_BATCH_SIZE', '100')),
        telemetry_retry_max_seconds=int(os.getenv('TELEMETRY_RETRY_MAX_SECONDS', '300')),
        rbac_api_base_url=os.getenv('RBAC_API_BASE_URL', '').strip().rstrip('/'),
        rbac_http_timeout_seconds=int(os.getenv('RBAC_HTTP_TIMEOUT_SECONDS', '20')),
        rbac_api_key=os.getenv('RBAC_API_KEY', '').strip(),
        entra_tenant_id=os.getenv('ENTRA_TENANT_ID', '').strip(),
        edge_public_client_id=os.getenv('EDGE_PUBLIC_CLIENT_ID', '').strip(),
        pin_api_client_id=os.getenv('PIN_API_CLIENT_ID', '').strip(),
        offline_auth_max_failed=int(os.getenv('OFFLINE_AUTH_MAX_FAILED', '5')),
        offline_auth_lock_seconds=int(os.getenv('OFFLINE_AUTH_LOCK_SECONDS', '300')),
        log_level=os.getenv('LOG_LEVEL', 'INFO').upper(),
    )
    if require_cloud and (not result.rbac_api_base_url or len(result.rbac_api_key) < 32):
        raise RuntimeError('Set RBAC_API_BASE_URL and RBAC_API_KEY (32+ characters) in .env')
    return result

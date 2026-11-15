"""Configuration for shared-key bulk read and Entra-authenticated self-enrollment."""
from dataclasses import dataclass
from functools import lru_cache
import os


@dataclass(frozen=True)
class Settings:
    tenant_id: str
    graph_client_id: str
    graph_client_secret: str
    edge_app_sp_object_id: str
    cache_valid_hours: int
    api_key: str
    pin_table_endpoint: str
    pin_table_name: str
    pin_api_client_id: str
    pin_api_tenant_id: str
    edge_public_client_id: str
    pin_cache_valid_hours: int = 24
    policy_table_name: str = "RolePermissionPolicies"

    @classmethod
    def from_env(cls):
        hours = int(os.getenv('RBAC_CACHE_VALID_HOURS', '168'))
        pin_hours = int(os.getenv('PIN_CACHE_VALID_HOURS', '24'))
        if not 1 <= hours <= 720 or not 1 <= pin_hours <= 168:
            raise ValueError('Cache validity hours out of range')
        tenant = os.getenv('ENTRA_TENANT_ID', '').strip()
        return cls(
            tenant_id=tenant,
            graph_client_id=os.getenv('GRAPH_CLIENT_ID', '').strip(),
            graph_client_secret=os.getenv('GRAPH_CLIENT_SECRET', '').strip(),
            edge_app_sp_object_id=os.getenv('EDGE_APP_SP_OBJECT_ID', '').strip(),
            cache_valid_hours=hours,
            api_key=os.getenv('RBAC_API_KEY', ''),
            pin_table_endpoint=os.getenv('PIN_TABLE_ENDPOINT', '').strip(),
            pin_table_name=os.getenv('PIN_TABLE_NAME', 'UserPinCredentials').strip(),
            pin_api_client_id=os.getenv('PIN_API_CLIENT_ID', '').strip(),
            pin_api_tenant_id=os.getenv('PIN_API_TENANT_ID', tenant).strip(),
            edge_public_client_id=os.getenv('EDGE_PUBLIC_CLIENT_ID', '').strip(),
            pin_cache_valid_hours=pin_hours,
            policy_table_name=os.getenv("POLICY_TABLE_NAME", "RolePermissionPolicies").strip(),
        )

    def missing_snapshot(self):
        required = {
            'ENTRA_TENANT_ID': self.tenant_id,
            'GRAPH_CLIENT_ID': self.graph_client_id,
            'GRAPH_CLIENT_SECRET': self.graph_client_secret,
            'EDGE_APP_SP_OBJECT_ID': self.edge_app_sp_object_id,
            'RBAC_API_KEY (minimum 32 characters)': self.api_key if len(self.api_key) >= 32 else '',
            'PIN_TABLE_ENDPOINT': self.pin_table_endpoint,
            'PIN_TABLE_NAME': self.pin_table_name,
            'POLICY_TABLE_NAME': self.policy_table_name,
        }
        return [key for key, val in required.items() if not val]

    def missing_enroll(self):
        return self.missing_snapshot() + [key for key, val in {
            'PIN_API_CLIENT_ID': self.pin_api_client_id,
            'PIN_API_TENANT_ID': self.pin_api_tenant_id,
            'EDGE_PUBLIC_CLIENT_ID': self.edge_public_client_id,
        }.items() if not val]


def get_settings():
    return Settings.from_env()

"""Load active role-to-function policies from Azure Table Storage.

Table: RolePermissionPolicies
PartitionKey=ROLE, RowKey=canonical Entra App Role value.
AllowedFunctions is a JSON-encoded array of function names.
Version and Enabled are required. No dynamic writes via the snapshot API.
"""
import json
import re

ROLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
FUNCTION_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class PolicyStoreError(RuntimeError):
    pass


class RolePolicyStore:
    def __init__(self, endpoint: str, table_name: str):
        if not endpoint.startswith("https://") or not endpoint.endswith(".table.core.windows.net"):
            raise ValueError("Invalid Azure Table endpoint")
        if not table_name:
            raise ValueError("Missing role-policy table name")
        from azure.identity import ManagedIdentityCredential
        from azure.data.tables import TableServiceClient
        service = TableServiceClient(endpoint=endpoint, credential=ManagedIdentityCredential())
        self.table = service.get_table_client(table_name)

    def get_active_policies(self) -> dict[str, frozenset[str]]:
        """Read and validate the COMPLETE active policy set; never silently default.

        Empty table is an error, avoiding accidental successful zero-permission
        snapshots during initial deployment. A disabled individual role can
        be represented explicitly by Enabled=False; its grants are empty.
        """
        try:
            rows = list(self.table.query_entities(query_filter="PartitionKey eq 'ROLE'"))
        except Exception as exc:
            raise PolicyStoreError("Cannot read role policy table") from exc
        if not rows:
            raise PolicyStoreError("Role policy table is empty")
        policies: dict[str, frozenset[str]] = {}
        for item in rows:
            role = item.get("RowKey")
            if not isinstance(role, str) or not ROLE_RE.fullmatch(role):
                raise PolicyStoreError("Invalid role name in policy table")
            enabled = item.get("Enabled")
            if not isinstance(enabled, bool):
                raise PolicyStoreError(f"Enabled must be Boolean for role {role}")
            version = item.get("PolicyVersion")
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise PolicyStoreError(f"PolicyVersion must be a positive integer for role {role}")
            data = item.get("AllowedFunctions")
            if not isinstance(data, str):
                raise PolicyStoreError(f"AllowedFunctions must be JSON text for role {role}")
            try:
                parsed = json.loads(data)
            except (ValueError, TypeError) as exc:
                raise PolicyStoreError(f"Invalid AllowedFunctions JSON for role {role}") from exc
            if (not isinstance(parsed, list) or
                any(not isinstance(v, str) or not FUNCTION_RE.fullmatch(v) for v in parsed) or
                len(parsed) != len(set(parsed))):
                raise PolicyStoreError(f"AllowedFunctions must be unique function strings for role {role}")
            if not enabled and parsed:
                # Explicitly disabled role is denied regardless of stale configured values.
                parsed = []
            if role in policies:
                raise PolicyStoreError("Duplicate policy role")
            policies[role] = frozenset(parsed)
        return policies

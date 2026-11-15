"""Policy evaluator. Role entitlements come exclusively from Azure Table Storage.

Entra App Role memberships establish role identity. The central table defines
which functions those roles allow; EdgeAccess.AllowedFunctions narrows access.
"""
from collections.abc import Mapping

LEGACY_ROLE_ALIASES = {"ServiceEnginner": "ServiceEngineer"}


def effective_permissions(role_names: list[str], assigned_functions: list[str],
                          role_policies: Mapping[str, frozenset[str]]) -> list[str]:
    allowed_by_roles: set[str] = set()
    for role in role_names:
        canonical = LEGACY_ROLE_ALIASES.get(role, role)
        allowed_by_roles.update(role_policies.get(canonical, frozenset()))
    return sorted(allowed_by_roles.intersection(assigned_functions))


def allowed_functions_from_profile(profile: dict) -> list[str]:
    """Read Entra's EdgeAccess.AllowedFunctions. Missing means no access.

    Do not hardcode the catalog of functions: centrally managed policies govern
    the allowed function set. Malformed values fail the whole snapshot.
    """
    attrs = profile.get("customSecurityAttributes")
    if attrs is None:
        return []
    if not isinstance(attrs, dict):
        raise ValueError("Invalid customSecurityAttributes type")
    edge = attrs.get("EdgeAccess")
    if edge is None:
        return []
    if not isinstance(edge, dict):
        raise ValueError("Invalid EdgeAccess attribute set")
    values = edge.get("AllowedFunctions")
    if values is None:
        return []
    if not isinstance(values, list) or any(not isinstance(v, str) or not v.strip() for v in values):
        raise ValueError("EdgeAccess.AllowedFunctions must be a list of non-empty strings")
    return sorted(set(values))

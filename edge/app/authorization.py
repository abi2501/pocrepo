"""Fail-closed authorization, independent of the UI (edge POC)."""

FUNCTIONS = (
    'view_status', 'start_operation', 'change_settings', 'service_tools', 'user_admin'
)


def permission_allowed(user: dict, function: str) -> bool:
    """Use only effective permissions delivered by the *v5* cloud snapshot.

    Never infer permissions from role strings on the edge: the cloud already
    applies the role intersection with Entra custom security attributes.
    """
    return bool(user.get('enabled')) and function in FUNCTIONS and function in user.get('permissions', [])

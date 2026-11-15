"""Shared, server-side-like authorization enforcement for GUI and CLI simulations."""
from .authorization import FUNCTIONS, permission_allowed
from . import db
from .util import parse_utc, utc_now


def run_simulated_action(path: str, username: str, function: str) -> tuple[bool,str]:
    """This POC NEVER operates real equipment. Every button is a simulation."""
    if function not in FUNCTIONS:
        raise ValueError('Unknown function')
    row=db.get_user_by_username(path,username)
    if row is None:
        return False,'Unknown user'
    user={'enabled':bool(row['enabled']),'permissions':db.get_permissions(path,row['entra_object_id'])}
    valid=parse_utc(row['valid_until_utc'])>utc_now()
    allowed=valid and permission_allowed(user,function)
    note='SIMULATED action authorized' if allowed else 'Denied (permission, account, or snapshot expired)'
    db.audit_action(path,row['entra_object_id'],username,function,allowed,note)
    return allowed,note

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import timedelta

from . import db
from .util import parse_utc, utc_now, utc_now_iso

ALGORITHM = "scrypt-n16384-r8-p1-dk32"


def _derive(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )


def verify_offline_secret(
    auth_db_path: str,
    username: str,
    secret: str,
    max_failed: int,
    lock_seconds: int,
) -> tuple[bool, str, list[str]]:
    user = db.get_user_by_username(auth_db_path, username)
    if user is None:
        db.audit_login(auth_db_path, None, username, "OFFLINE", False, "unknown user")
        return False, "Unknown user", []

    oid = user["entra_object_id"]
    if not bool(user["enabled"]):
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "user disabled")
        return False, "User is disabled in the most recent RBAC snapshot", []

    now = utc_now()
    if parse_utc(user["valid_until_utc"]) < now:
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "authorization cache expired")
        return False, "Cached authorization has expired; reconnect the device to refresh RBAC", []

    cred = db.get_offline_credential(auth_db_path, oid)
    if cred is None:
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "offline credential not enrolled")
        return False, "Offline credential has not been enrolled for this user", []

    # v5 cloud snapshot required; old local-only credentials are not trusted.
    if 'pin_version' not in cred.keys() or int(cred['pin_version']) < 1:
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "cloud PIN synchronization required")
        return False, "Cloud PIN synchronization required before offline login", []
    if (not cred['credential_valid_until_utc'] or
            parse_utc(cred['credential_valid_until_utc']) <= now):
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "PIN credential snapshot expired")
        return False, "Cloud PIN credential expired; sign in online to synchronize", []

    locked_until = cred["locked_until_utc"]
    if locked_until and parse_utc(locked_until) > now:
        db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "account temporarily locked")
        return False, f"Offline login is temporarily locked until {locked_until}", []

    salt = base64.b64decode(cred["salt_b64"])
    expected = base64.b64decode(cred["verifier_b64"])
    actual = _derive(secret, salt)

    if hmac.compare_digest(expected, actual):
        db.clear_login_failures(auth_db_path, oid)
        roles = db.get_roles(auth_db_path, oid)
        db.audit_login(auth_db_path, oid, username, "OFFLINE", True, "success")
        return True, "Login successful", roles

    failures = int(cred["failed_attempt_count"]) + 1
    lock_until_iso = None
    if failures >= max_failed:
        lock_until_iso = (now + timedelta(seconds=lock_seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")
        failures = 0
    db.update_login_failures(auth_db_path, oid, failures, lock_until_iso)
    db.audit_login(auth_db_path, oid, username, "OFFLINE", False, "invalid credential")
    if lock_until_iso:
        return False, f"Invalid credential; offline login locked until {lock_until_iso}", []
    return False, f"Invalid credential ({failures}/{max_failed} failed attempts)", []

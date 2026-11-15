"""Atomic, fail-closed importer for FastAPI v5 schemaVersion 4 bulk snapshots."""
from __future__ import annotations
import base64
import binascii
import json
from datetime import timedelta

from . import db
from .authorization import FUNCTIONS
from .security import ALGORITHM
from .util import parse_utc, utc_now, utc_now_iso


def _pin_fields(pin: dict | None, enrolled: bool):
    if type(enrolled) is not bool or enrolled != (pin is not None):
        raise ValueError('pinEnrolled and PIN record disagree')
    if pin is None:
        return None
    if not isinstance(pin, dict) or pin.get('algorithm') != ALGORITHM:
        raise ValueError('Unsupported PIN algorithm')
    salt, verifier, version = pin.get('saltBase64'), pin.get('verifierBase64'), pin.get('pinVersion')
    if not isinstance(salt, str) or not isinstance(verifier, str) or type(version) is not int or version < 1:
        raise ValueError('Malformed PIN verifier/version')
    try:
        if len(base64.b64decode(salt, validate=True)) != 16 or len(base64.b64decode(verifier, validate=True)) != 32:
            raise ValueError('Incorrect PIN salt/verifier size')
    except (binascii.Error, ValueError) as exc:
        raise ValueError('Invalid PIN verifier encoding') from exc
    return (ALGORITHM, salt, verifier, version)


def import_bulk_snapshot(path: str, snapshot: dict) -> dict:
    """Validate everything first, then commit whole snapshot. Never partially replace DB."""
    if not isinstance(snapshot, dict) or snapshot.get('schemaVersion') != 4:
        raise ValueError('Expected FastAPI v5 schemaVersion 4 snapshot')
    generated, auth_until, pin_until = (snapshot.get(k) for k in
                                          ('generatedUtc', 'validUntilUtc', 'pinValidUntilUtc'))
    now = utc_now()
    try:
        gen_dt, auth_dt, pin_dt = parse_utc(generated), parse_utc(auth_until), parse_utc(pin_until)
        version = snapshot.get('version')
        if type(version) is not int or version < 1:
            raise ValueError('Invalid snapshot version')
        if gen_dt > now + timedelta(minutes=5) or auth_dt <= now or pin_dt <= now:
            raise ValueError('Expired or future-dated bulk snapshot')
        if auth_dt <= gen_dt or pin_dt <= gen_dt:
            raise ValueError('Invalid snapshot time range')
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError('Invalid bulk snapshot timestamps/version') from exc
    entries = snapshot.get('users')
    if not isinstance(entries, list):
        raise ValueError('Bulk snapshot missing users array')
    parsed = []
    seen_oids, seen_names = set(), set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError('Invalid user entry')
        oid, username = item.get('entraObjectId'), item.get('username')
        if not isinstance(oid, str) or not oid.strip() or not isinstance(username, str) or not username.strip():
            raise ValueError('Missing Entra identity')
        oid, username = oid.lower(), username.strip()
        if oid in seen_oids or username.lower() in seen_names:
            raise ValueError('Duplicate user identity in bulk snapshot')
        seen_oids.add(oid)
        seen_names.add(username.lower())
        enabled = item.get('enabled')
        roles, permissions = item.get('roles'), item.get('permissions')
        if type(enabled) is not bool or not isinstance(roles, list) or not isinstance(permissions, list):
            raise ValueError('Malformed RBAC user record')
        if any(not isinstance(r, str) or not r.strip() for r in roles):
            raise ValueError('Invalid App Role')
        if any(not isinstance(p, str) or p not in FUNCTIONS for p in permissions):
            raise ValueError('Unknown effective permission')
        attributes = item.get('customSecurityAttributes', {})
        if not isinstance(attributes, dict):
            raise ValueError('customSecurityAttributes must be a JSON object')
        try:
            attributes_json = json.dumps(attributes, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError('Invalid customSecurityAttributes JSON') from exc
        if len(attributes_json.encode('utf-8')) > 65536:
            raise ValueError('Custom Security Attributes record too large')
        pin = _pin_fields(item.get('pin'), item.get('pinEnrolled'))
        if not enabled and pin is not None:
            raise ValueError('Disabled user cannot have an active PIN in snapshot')
        parsed.append((oid, username, str(item.get('displayName') or username), enabled,
                       sorted(set(roles)), sorted(set(permissions)), attributes_json, pin))

    db._ensure_v4_schema(path)
    with db.connect(path) as conn:
        try:
            conn.execute('BEGIN IMMEDIATE')
            state = conn.execute('SELECT generated_utc FROM auth_sync_state WHERE singleton_id=1').fetchone()
            if state and state[0] and gen_dt < parse_utc(state[0]):
                raise ValueError('Bulk snapshot rollback rejected')
            # Users absent from authoritative full snapshot must lose offline access.
            # Preserve audit history; remove stale roles and PIN verifiers.
            conn.execute("UPDATE users SET enabled=0, custom_attributes_json='{}'")
            conn.execute('DELETE FROM user_roles')
            conn.execute('DELETE FROM user_permissions')
            conn.execute('DELETE FROM offline_credentials WHERE entra_object_id NOT IN '
                         '(SELECT entra_object_id FROM users)')
            present_oids = []
            with_pin = 0
            for oid, username, display, enabled, roles, permissions, attributes_json, pin in parsed:
                present_oids.append(oid)
                conn.execute('''INSERT INTO users (entra_object_id,username,display_name,enabled,last_synced_utc,valid_until_utc,custom_attributes_json)
                    VALUES (?,?,?,?,?,?,?) ON CONFLICT(entra_object_id) DO UPDATE SET
                    username=excluded.username,display_name=excluded.display_name,enabled=excluded.enabled,
                    last_synced_utc=excluded.last_synced_utc,valid_until_utc=excluded.valid_until_utc,
                    custom_attributes_json=excluded.custom_attributes_json''',
                    (oid, username, display, int(enabled), generated, auth_until, attributes_json))
                for role in roles:
                    conn.execute('INSERT OR IGNORE INTO roles(role_name) VALUES (?)', (role,))
                    conn.execute('INSERT INTO user_roles(entra_object_id,role_name) VALUES (?,?)', (oid,role))
                for permission in permissions:
                    conn.execute('INSERT INTO user_permissions(entra_object_id,permission_name) VALUES (?,?)',
                                 (oid, permission))
                if not enabled or pin is None:
                    conn.execute('DELETE FROM offline_credentials WHERE entra_object_id=?', (oid,))
                    continue
                with_pin += 1
                algo, salt, verifier, pin_version = pin
                previous = conn.execute('''SELECT pin_version, salt_b64, verifier_b64
                    FROM offline_credentials WHERE entra_object_id=?''', (oid,)).fetchone()
                if previous:
                    old_version = int(previous['pin_version'])
                    if old_version > pin_version:
                        raise ValueError('PIN version rollback rejected')
                    if (old_version == pin_version and old_version > 0 and
                        (previous['salt_b64'] != salt or previous['verifier_b64'] != verifier)):
                        raise ValueError('PIN verifier changed without version increment')
                conn.execute('''INSERT INTO offline_credentials
                    (entra_object_id,algorithm,salt_b64,verifier_b64,created_utc,
                     failed_attempt_count,locked_until_utc,pin_version,credential_valid_until_utc)
                    VALUES (?,?,?,?,?,0,NULL,?,?) ON CONFLICT(entra_object_id) DO UPDATE SET
                    algorithm=excluded.algorithm,salt_b64=excluded.salt_b64,
                    verifier_b64=excluded.verifier_b64,created_utc=excluded.created_utc,
                    pin_version=excluded.pin_version,credential_valid_until_utc=excluded.credential_valid_until_utc,
                    failed_attempt_count=CASE WHEN offline_credentials.pin_version != excluded.pin_version
                      THEN 0 ELSE offline_credentials.failed_attempt_count END,
                    locked_until_utc=CASE WHEN offline_credentials.pin_version != excluded.pin_version
                      THEN NULL ELSE offline_credentials.locked_until_utc END''',
                    (oid, algo, salt, verifier, utc_now_iso(), pin_version, pin_until))
            # Delete records for users not in the new full list, including formerly active users.
            if present_oids:
                placeholders = ','.join('?' for _ in present_oids)
                conn.execute(f'DELETE FROM offline_credentials WHERE entra_object_id NOT IN ({placeholders})', present_oids)
            else:
                conn.execute('DELETE FROM offline_credentials')
            conn.execute('''UPDATE auth_sync_state SET snapshot_version=4, generated_utc=?,
                valid_until_utc=?, last_success_utc=?, last_error=NULL, updated_utc=?
                WHERE singleton_id=1''', (generated, auth_until, utc_now_iso(), utc_now_iso()))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {'users': len(parsed), 'withPin': with_pin, 'rbacExpiresUtc': auth_until,
            'pinExpiresUtc': pin_until}

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

from .util import utc_now_iso


def _ensure_parent(path: str) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def connect(path: str):
    _ensure_parent(path)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()


def init_telemetry_db(path: str) -> None:
    """Create the POC application telemetry DB. The sync agent later reads this DB read-only."""
    with connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )
        conn.commit()


def init_sync_state_db(path: str) -> None:
    with connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS telemetry_sync_state (
                source_name TEXT PRIMARY KEY,
                last_synced_id INTEGER NOT NULL DEFAULT 0,
                last_success_utc TEXT,
                last_error TEXT,
                updated_utc TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO telemetry_sync_state
                (source_name, last_synced_id, updated_utc)
            VALUES ('telemetry_events', 0, ?)
            """,
            (utc_now_iso(),),
        )
        conn.commit()


def connect_readonly(path: str):
    resolved = Path(path).expanduser().resolve()
    conn = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db(path: str) -> None:
    with connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                entra_object_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT,
                enabled INTEGER NOT NULL,
                last_synced_utc TEXT NOT NULL,
                valid_until_utc TEXT NOT NULL,
                custom_attributes_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS roles (
                role_name TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS user_permissions (
                entra_object_id TEXT NOT NULL,
                permission_name TEXT NOT NULL,
                PRIMARY KEY (entra_object_id, permission_name),
                FOREIGN KEY (entra_object_id) REFERENCES users(entra_object_id)
            );

            CREATE TABLE IF NOT EXISTS action_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time_utc TEXT NOT NULL,
                entra_object_id TEXT NOT NULL,
                username TEXT NOT NULL,
                action_name TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                note TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_roles (
                entra_object_id TEXT NOT NULL,
                role_name TEXT NOT NULL,
                PRIMARY KEY (entra_object_id, role_name),
                FOREIGN KEY (entra_object_id) REFERENCES users(entra_object_id),
                FOREIGN KEY (role_name) REFERENCES roles(role_name)
            );

            CREATE TABLE IF NOT EXISTS offline_credentials (
                entra_object_id TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL,
                salt_b64 TEXT NOT NULL,
                verifier_b64 TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                failed_attempt_count INTEGER NOT NULL DEFAULT 0,
                locked_until_utc TEXT,
                FOREIGN KEY (entra_object_id) REFERENCES users(entra_object_id)
            );

            CREATE TABLE IF NOT EXISTS auth_sync_state (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                snapshot_version INTEGER,
                generated_utc TEXT,
                valid_until_utc TEXT,
                last_success_utc TEXT,
                last_error TEXT,
                updated_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time_utc TEXT NOT NULL,
                entra_object_id TEXT,
                username TEXT NOT NULL,
                login_mode TEXT NOT NULL,
                success INTEGER NOT NULL,
                reason TEXT
            );
            """
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO auth_sync_state(singleton_id, updated_utc)
            VALUES (1, ?)
            """,
            (utc_now_iso(),),
        )
        conn.commit()


def add_telemetry(path: str, event_type: str, severity: str, payload: dict) -> int:
    init_telemetry_db(path)
    with connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO telemetry_events(event_time_utc, event_type, severity, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (utc_now_iso(), event_type, severity.upper(), json.dumps(payload, separators=(",", ":"))),
        )
        conn.commit()
        return int(cur.lastrowid)


def telemetry_checkpoint(path: str) -> int:
    init_sync_state_db(path)
    with connect(path) as conn:
        row = conn.execute(
            "SELECT last_synced_id FROM telemetry_sync_state WHERE source_name='telemetry_events'"
        ).fetchone()
        return int(row[0]) if row else 0


def pending_telemetry(path: str, after_id: int, limit: int) -> list[sqlite3.Row]:
    conn = connect_readonly(path)
    try:
        return conn.execute(
            """
            SELECT id, event_time_utc, event_type, severity, payload_json
            FROM telemetry_events
            WHERE id > ?
            ORDER BY id
            LIMIT ?
            """,
            (after_id, limit),
        ).fetchall()
    finally:
        conn.close()


def save_telemetry_checkpoint(path: str, record_id: int) -> None:
    now = utc_now_iso()
    with connect(path) as conn:
        conn.execute(
            """
            UPDATE telemetry_sync_state
            SET last_synced_id=?, last_success_utc=?, last_error=NULL, updated_utc=?
            WHERE source_name='telemetry_events'
            """,
            (record_id, now, now),
        )
        conn.commit()


def save_telemetry_error(path: str, message: str) -> None:
    now = utc_now_iso()
    with connect(path) as conn:
        conn.execute(
            """
            UPDATE telemetry_sync_state
            SET last_error=?, updated_utc=?
            WHERE source_name='telemetry_events'
            """,
            (message[:1000], now),
        )
        conn.commit()


def get_permissions(path: str, oid: str) -> list[str]:
    init_auth_db(path)
    with connect(path) as conn:
        rows=conn.execute('SELECT permission_name FROM user_permissions WHERE entra_object_id=? ORDER BY permission_name', (oid,)).fetchall()
        return [row[0] for row in rows]


def audit_action(path: str, oid: str, username: str, action: str, allowed: bool, note: str) -> None:
    init_auth_db(path)
    with connect(path) as conn:
        conn.execute('INSERT INTO action_audit(event_time_utc,entra_object_id,username,action_name,allowed,note) VALUES(?,?,?,?,?,?)',
                     (utc_now_iso(),oid,username,action,1 if allowed else 0,note[:300]))
        conn.commit()


def recent_actions(path: str, limit: int=20) -> list[dict]:
    init_auth_db(path)
    with connect(path) as conn:
        return [dict(row) for row in conn.execute('SELECT * FROM action_audit ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]


def save_rbac_error(path: str, message: str) -> None:
    init_auth_db(path)
    now = utc_now_iso()
    with connect(path) as conn:
        conn.execute(
            "UPDATE auth_sync_state SET last_error=?, updated_utc=? WHERE singleton_id=1",
            (message[:1000], now),
        )
        conn.commit()


def get_user_by_username(path: str, username: str):
    init_auth_db(path)
    with connect(path) as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE",
            (username,),
        ).fetchone()


def get_user_by_oid(path: str, oid: str):
    init_auth_db(path)
    with connect(path) as conn:
        return conn.execute("SELECT * FROM users WHERE entra_object_id=?", (oid,)).fetchone()


def get_roles(path: str, oid: str) -> list[str]:
    init_auth_db(path)
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT role_name FROM user_roles WHERE entra_object_id=? ORDER BY role_name",
            (oid,),
        ).fetchall()
        return [str(r[0]) for r in rows]


def list_users(path: str) -> list[dict]:
    _ensure_v4_schema(path)
    with connect(path) as conn:
        users = conn.execute(
            "SELECT entra_object_id, username, display_name, enabled, valid_until_utc, custom_attributes_json FROM users ORDER BY username"
        ).fetchall()
        result = []
        for user in users:
            result.append(
                {
                    "entraObjectId": user["entra_object_id"],
                    "username": user["username"],
                    "displayName": user["display_name"],
                    "enabled": bool(user["enabled"]),
                    "validUntilUtc": user["valid_until_utc"],
                    "customSecurityAttributes": json.loads(user["custom_attributes_json"] or "{}"),
                    "roles": get_roles(path, user["entra_object_id"]),
                    "permissions": get_permissions(path, user["entra_object_id"]),
                }
            )
        return result


def auth_sync_state(path: str) -> dict:
    init_auth_db(path)
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM auth_sync_state WHERE singleton_id=1").fetchone()
        return dict(row) if row else {}


def save_offline_credential(path: str, oid: str, algorithm: str, salt_b64: str, verifier_b64: str) -> None:
    init_auth_db(path)
    with connect(path) as conn:
        conn.execute(
            """
            INSERT INTO offline_credentials(
                entra_object_id, algorithm, salt_b64, verifier_b64, created_utc,
                failed_attempt_count, locked_until_utc
            ) VALUES (?, ?, ?, ?, ?, 0, NULL)
            ON CONFLICT(entra_object_id) DO UPDATE SET
                algorithm=excluded.algorithm,
                salt_b64=excluded.salt_b64,
                verifier_b64=excluded.verifier_b64,
                created_utc=excluded.created_utc,
                failed_attempt_count=0,
                locked_until_utc=NULL
            """,
            (oid, algorithm, salt_b64, verifier_b64, utc_now_iso()),
        )
        conn.commit()


def get_offline_credential(path: str, oid: str):
    init_auth_db(path)
    with connect(path) as conn:
        return conn.execute(
            "SELECT * FROM offline_credentials WHERE entra_object_id=?",
            (oid,),
        ).fetchone()


def update_login_failures(path: str, oid: str, count: int, locked_until_utc: str | None) -> None:
    with connect(path) as conn:
        conn.execute(
            """
            UPDATE offline_credentials
            SET failed_attempt_count=?, locked_until_utc=?
            WHERE entra_object_id=?
            """,
            (count, locked_until_utc, oid),
        )
        conn.commit()


def clear_login_failures(path: str, oid: str) -> None:
    update_login_failures(path, oid, 0, None)


def audit_login(path: str, oid: str | None, username: str, mode: str, success: bool, reason: str) -> None:
    init_auth_db(path)
    with connect(path) as conn:
        conn.execute(
            """
            INSERT INTO login_audit(event_time_utc, entra_object_id, username, login_mode, success, reason)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (utc_now_iso(), oid, username, mode, 1 if success else 0, reason[:500]),
        )
        conn.commit()

# Add versioned cloud PIN columns for FastAPI v5 bulk synchronization.
# Legacy local-only credentials are not valid for offline login.
def _ensure_v4_schema(path: str) -> None:
    init_auth_db(path)
    with connect(path) as conn:
        user_cols = {row['name'] for row in conn.execute('PRAGMA table_info(users)')}
        if 'custom_attributes_json' not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN custom_attributes_json TEXT NOT NULL DEFAULT '{}'")
        cols = {row['name'] for row in conn.execute('PRAGMA table_info(offline_credentials)')}
        if 'pin_version' not in cols:
            conn.execute('ALTER TABLE offline_credentials ADD COLUMN pin_version INTEGER NOT NULL DEFAULT 0')
        if 'credential_valid_until_utc' not in cols:
            conn.execute('ALTER TABLE offline_credentials ADD COLUMN credential_valid_until_utc TEXT')
        conn.commit()



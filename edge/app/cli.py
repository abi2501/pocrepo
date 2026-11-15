"""Cross-platform CLI for online per-user sync and local offline operation."""
from __future__ import annotations
import argparse
import getpass
import json
import json
import random
import time

from .config import get_settings
from . import db
from .security import verify_offline_secret
from .actions import run_simulated_action


def cmd_gui(_args):
    from .gui import start_gui
    start_gui()


def cmd_init(_args):
    s = get_settings(require_cloud=False)
    db.init_auth_db(s.auth_db_path)
    db.init_telemetry_db(s.telemetry_db_path)
    db.init_sync_state_db(s.sync_state_db_path)
    print('Initialized SQLite data files')


def cmd_sync(_args):
    """Download all directory users and their PIN verifiers with the shared API key."""
    s = get_settings(require_cloud=True)
    from .rbac_client import fetch_bulk_snapshot
    from .bulk_sync import import_bulk_snapshot
    snapshot = fetch_bulk_snapshot(s.rbac_api_base_url, s.rbac_api_key, s.rbac_http_timeout_seconds)
    result = import_bulk_snapshot(s.auth_db_path, snapshot)
    print(f"Synchronized {result['users']} users, including {result['withPin']} cloud PINs")
    print('RBAC cache expires:', result['rbacExpiresUtc'])
    print('PIN cache expires:', result['pinExpiresUtc'])


def cmd_enroll(args):
    """One-time user PIN enrollment. Bulk sync is required to obtain the new verifier."""
    s = get_settings(require_cloud=True)
    if not all((s.entra_tenant_id, s.edge_public_client_id, s.pin_api_client_id)):
        raise RuntimeError('Set ENTRA_TENANT_ID, EDGE_PUBLIC_CLIENT_ID and PIN_API_CLIENT_ID for PIN enrollment')
    from .entra_auth import interactive_browser_login, interactive_device_login
    from .rbac_client import enroll_pin
    if args.flow == 'device':
        def notify(details):
            print('DEVICE CODE:', details['user_code'])
            print('SIGN-IN URL:', details['verification_uri'])
        token, oid = interactive_device_login(s.entra_tenant_id, s.edge_public_client_id,
            s.pin_api_client_id, on_code=notify, return_identity=True)
    else:
        token, oid = interactive_browser_login(s.entra_tenant_id, s.edge_public_client_id,
            s.pin_api_client_id, return_identity=True)
    print('Signed-in Entra user ID:', oid)
    print('This creates a cloud PIN once; if it already exists, the server returns HTTP 409.')
    first = getpass.getpass('New 6–12 digit PIN: ')
    second = getpass.getpass('Confirm PIN: ')
    if first != second or not first.isascii() or not first.isdecimal() or not 6 <= len(first) <= 12:
        raise RuntimeError('PIN mismatch or invalid PIN; use 6–12 ASCII digits')
    enroll_pin(s.rbac_api_base_url, token, first, s.rbac_http_timeout_seconds)
    del first, second, token
    print('PIN enrolled. Refreshing all authorized users and PIN verifiers...')
    cmd_sync(args)


def cmd_users(_args):
    s = get_settings(require_cloud=False)
    records = db.list_users(s.auth_db_path)
    if not records:
        print('No users cached. Run sync while online first.')
    for u in records:
        print(f"{u['username']} | enabled={u['enabled']} | roles={','.join(u['roles'])} | "
              f"permissions={','.join(u['permissions'])} | auth expires={u['validUntilUtc']}")
        print('  customSecurityAttributes:', json.dumps(u['customSecurityAttributes'], ensure_ascii=False, sort_keys=True))


def cmd_login(args):
    s = get_settings(require_cloud=False)
    name = args.username or input('Cached username: ').strip()
    secret = getpass.getpass('PIN: ')
    ok, message, roles = verify_offline_secret(s.auth_db_path, name, secret,
        s.offline_auth_max_failed, s.offline_auth_lock_seconds)
    print(message)
    if ok:
        user = db.get_user_by_username(s.auth_db_path, name)
        print('Roles:', ', '.join(roles))
        print('Permissions:', ', '.join(db.get_permissions(s.auth_db_path, user['entra_object_id'])))


def cmd_action(args):
    s = get_settings(require_cloud=False)
    secret = getpass.getpass('PIN: ')
    ok, reason, _ = verify_offline_secret(s.auth_db_path, args.username, secret,
         s.offline_auth_max_failed, s.offline_auth_lock_seconds)
    if not ok:
        print('DENY: ' + reason)
        return
    allowed, note = run_simulated_action(s.auth_db_path, args.username, args.function)
    print(('ALLOW: ' if allowed else 'DENY: ') + note)


def cmd_status(_args):
    s = get_settings(require_cloud=False)
    db.init_auth_db(s.auth_db_path)
    print(json.dumps(db.auth_sync_state(s.auth_db_path), indent=2))


def cmd_generate(args):
    s = get_settings(require_cloud=False)
    for i in range(args.count):
        data = {'temperatureC': round(random.uniform(20, 70), 2),
                'pressureKPa': round(random.uniform(95, 115), 2),
                'machineState': random.choice(['IDLE', 'RUNNING'])}
        severity = 'WARNING' if data['temperatureC'] > 60 else 'INFO'
        row = db.add_telemetry(s.telemetry_db_path, 'measurement', severity, data)
        print(f'Telemetry event {row} created')
        if i < args.count - 1 and args.interval:
            time.sleep(args.interval)


def build_parser():
    parser = argparse.ArgumentParser(description='Edge RBAC v5 — bulk cloud RBAC+PIN sync and offline access')
    sub = parser.add_subparsers(dest='command', required=True)
    for name, fn in [('gui', cmd_gui), ('init', cmd_init), ('users', cmd_users),
                     ('status', cmd_status)]:
        p = sub.add_parser(name)
        p.set_defaults(func=fn)
    p = sub.add_parser('sync', help='Download all users + PIN verifiers using RBAC_API_KEY')
    p.set_defaults(func=cmd_sync)
    p = sub.add_parser('enroll', help='Entra sign-in for first-time cloud PIN creation; then bulk sync')
    p.add_argument('--flow', choices=['browser', 'device'], default='browser')
    p.set_defaults(func=cmd_enroll)
    p = sub.add_parser('login', help='Authenticate offline from local SQLite')
    p.add_argument('--username')
    p.set_defaults(func=cmd_login)
    p = sub.add_parser('action', help='Verify PIN and simulate a permitted action')
    p.add_argument('--username', required=True)
    p.add_argument('--function', choices=['view_status', 'start_operation', 'change_settings',
                                          'service_tools', 'user_admin'], required=True)
    p.set_defaults(func=cmd_action)
    p = sub.add_parser('generate', help='Generate simulated telemetry rows')
    p.add_argument('--count', type=int, default=1)
    p.add_argument('--interval', type=float, default=0)
    p.set_defaults(func=cmd_generate)
    return parser


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == '__main__':
    main()

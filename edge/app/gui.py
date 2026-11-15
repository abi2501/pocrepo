"""Windows/WSLg/Raspberry Pi GUI for shared-key bulk sync and Entra PIN enrollment.

All calls to Tkinter run on the GUI thread. Network tasks run on background threads.
"""
from __future__ import annotations
import queue
import json
import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from .config import get_settings
from . import db
from .security import verify_offline_secret
from .actions import run_simulated_action
from .authorization import FUNCTIONS


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = get_settings(require_cloud=False)
        self.path = self.settings.auth_db_path
        db.init_auth_db(self.path)
        self.events = queue.Queue()
        self.logged_username = None
        self.device_code_popup = None
        self.auth_in_progress = False
        self.root.title('Edge RBAC v5 — Bulk Cloud Sync / Offline Authorization')
        self.root.geometry('1040x670')
        self.root.minsize(950, 590)
        self.root.columnconfigure(0, weight=1)
        self.make_ui()
        self.root.after(90, self.process_events)

    def make_ui(self):
        ttk.Label(self.root, text='Bulk RBAC + PIN sync • shared API key • offline access',
                  font=('Arial', 14, 'bold')).grid(row=0, column=0, padx=15, pady=(14, 5), sticky='ew')
        ttk.Label(self.root, text='Local authorization cache: ' + self.path,
                  wraplength=850).grid(row=1, column=0, sticky='w', padx=15)
        controls = ttk.Frame(self.root)
        controls.grid(row=2, column=0, sticky='ew', padx=15, pady=12)
        self.sync_button = ttk.Button(controls, text='Sync All Users + PINs',
                                      command=self.start_bulk_sync)
        self.sync_button.pack(side='left', padx=4)
        self.browser_button = ttk.Button(controls, text='Enroll New PIN — Browser',
                                         command=lambda: self.start_signin('browser'))
        self.browser_button.pack(side='left', padx=4)
        self.device_button = ttk.Button(controls, text='Enroll New PIN — Device Code',
                                        command=lambda: self.start_signin('device'))
        self.device_button.pack(side='left', padx=4)
        ttk.Button(controls, text='Refresh Cached Users', command=self.refresh_users).pack(side='left', padx=4)
        ttk.Button(controls, text='View User Attributes', command=self.show_user_attributes).pack(side='left', padx=4)
        ttk.Button(controls, text='Show Audit', command=self.show_audit).pack(side='left', padx=4)

        offline = ttk.LabelFrame(self.root, text='Offline Login — no internet required after cloud synchronization')
        offline.grid(row=3, column=0, sticky='ew', padx=15, pady=4)
        offline.columnconfigure(1, weight=1)
        ttk.Label(offline, text='User:').grid(row=0, column=0, padx=8, pady=8)
        self.user_combo = ttk.Combobox(offline, state='readonly', width=55)
        self.user_combo.grid(row=0, column=1, sticky='ew', pady=8)
        ttk.Label(offline, text='PIN:').grid(row=1, column=0, padx=8, pady=8)
        self.pin_login = ttk.Entry(offline, show='*')
        self.pin_login.grid(row=1, column=1, sticky='ew', pady=8)
        self.pin_login.bind('<Return>', lambda _event: self.login())
        ttk.Button(offline, text='Login Offline', command=self.login).grid(row=1, column=2, padx=8)
        ttk.Button(offline, text='Logout', command=self.logout).grid(row=0, column=2, padx=8)

        actions = ttk.LabelFrame(self.root, text='Simulated functions — checked against cached effective permissions')
        actions.grid(row=4, column=0, sticky='ew', padx=15, pady=7)
        self.action_buttons = {}
        for i, function in enumerate(FUNCTIONS):
            button = ttk.Button(actions, text=function.replace('_', ' ').title(),
                                command=lambda f=function: self.action(f))
            button.grid(row=i // 3, column=i % 3, sticky='ew', padx=9, pady=10)
            actions.columnconfigure(i % 3, weight=1)
            self.action_buttons[function] = button

        frame = ttk.LabelFrame(self.root, text='Status / events')
        frame.grid(row=5, column=0, sticky='nsew', padx=15, pady=6)
        self.root.rowconfigure(5, weight=1)
        self.log = tk.Text(frame, height=12, state='disabled', wrap='word')
        self.log.pack(fill='both', expand=True, padx=8, pady=8)
        self.refresh_users()
        self.set_buttons()
        self.log_message('Click Sync All Users + PINs to download everyone. Entra sign-in is only for NEW PIN enrollment.')

    def log_message(self, text):
        self.log.configure(state='normal')
        self.log.insert('end', str(text) + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def process_events(self):
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == 'log':
                self.log_message(payload)
            elif event == 'error':
                self.close_device_code_popup()
                self.auth_in_progress = False
                self._set_signin_buttons()
                messagebox.showerror('Operation failed', str(payload))
                self.log_message('ERROR: ' + str(payload))
            elif event == 'code':
                self.show_device_code_popup(payload)
            elif event == 'needs-pin':
                self.close_device_code_popup()
                self.show_pin_popup(payload)
            elif event == 'completed':
                self.close_device_code_popup()
                self.auth_in_progress = False
                self._set_signin_buttons()
                self.refresh_users()
                self.log_message(payload)
                messagebox.showinfo('Cloud synchronization complete', payload)
        self.root.after(90, self.process_events)

    def _set_signin_buttons(self):
        value = 'disabled' if self.auth_in_progress else 'normal'
        self.sync_button.configure(state=value)
        self.browser_button.configure(state=value)
        self.device_button.configure(state=value)

    def _run_thread(self, fn):
        def run():
            try:
                fn()
            except Exception as exc:
                self.events.put(('error', str(exc)))
        threading.Thread(target=run, daemon=True).start()

    def refresh_users(self):
        records = db.list_users(self.path)
        self.users = {u['username']: u for u in records if u['enabled']}
        self.user_combo['values'] = list(self.users)
        if self.user_combo.get() not in self.users:
            self.user_combo.set(next(iter(self.users), ''))
        if hasattr(self, 'log'):
            self.log_message(f'Locally cached authorized users: {len(self.users)}')

    def show_user_attributes(self):
        username = self.user_combo.get()
        user = self.users.get(username)
        if not user:
            messagebox.showinfo('Custom Security Attributes', 'Select a synchronized user first.')
            return
        attributes = user.get('customSecurityAttributes') or {}
        win = tk.Toplevel(self.root)
        win.title(f'Custom Security Attributes — {username}')
        win.geometry('720x500')
        win.transient(self.root)
        ttk.Label(win, text=f'Custom Security Attributes for {username}',
                  font=('Arial', 12, 'bold')).pack(anchor='w', padx=12, pady=(12, 5))
        view = tk.Text(win, wrap='none')
        view.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        view.insert('1.0', json.dumps(attributes, indent=2, ensure_ascii=False, sort_keys=True))
        view.configure(state='disabled')

    def _cloud_settings(self, require_enrollment: bool = False):
        s = self.settings
        if not s.rbac_api_base_url or len(s.rbac_api_key) < 32:
            raise RuntimeError('Configure RBAC_API_BASE_URL and RBAC_API_KEY (32+ characters) in .env')
        if require_enrollment and not all((s.entra_tenant_id, s.edge_public_client_id, s.pin_api_client_id)):
            raise RuntimeError('PIN enrollment also requires ENTRA_TENANT_ID, EDGE_PUBLIC_CLIENT_ID, PIN_API_CLIENT_ID')

    def start_bulk_sync(self):
        if self.auth_in_progress:
            return
        try:
            self._cloud_settings()
        except RuntimeError as exc:
            messagebox.showerror('Cloud settings missing', str(exc))
            return
        self.auth_in_progress = True
        self._set_signin_buttons()
        self.log_message('Downloading all users, permissions, and PIN verifiers from FastAPI v5...')
        self._run_thread(self._bulk_sync)

    def _bulk_sync(self):
        from .rbac_client import fetch_bulk_snapshot
        from .bulk_sync import import_bulk_snapshot
        s = self.settings
        snapshot = fetch_bulk_snapshot(s.rbac_api_base_url, s.rbac_api_key, s.rbac_http_timeout_seconds)
        result = import_bulk_snapshot(self.path, snapshot)
        self.events.put(('completed', f"Synchronized {result['users']} users and {result['withPin']} PIN verifiers. "
            f"PIN expires {result['pinExpiresUtc']}."))

    def start_signin(self, flow: str):
        if self.auth_in_progress:
            return
        try:
            self._cloud_settings(require_enrollment=True)
        except RuntimeError as exc:
            messagebox.showerror('Cloud settings missing', str(exc))
            return
        self.auth_in_progress = True
        self._set_signin_buttons()
        self.log_message('Starting Microsoft Entra ' + flow + ' login for first-time PIN enrollment...')
        self._run_thread(lambda: self._online_flow(flow))

    def _online_flow(self, flow):
        from .entra_auth import interactive_browser_login, interactive_device_login
        s = self.settings
        if flow == 'device':
            token, oid = interactive_device_login(s.entra_tenant_id, s.edge_public_client_id,
                s.pin_api_client_id, on_code=lambda d: self.events.put(('code', d)), return_identity=True)
        else:
            token, oid = interactive_browser_login(s.entra_tenant_id, s.edge_public_client_id,
                s.pin_api_client_id, on_open=lambda m: self.events.put(('log', m)), return_identity=True)
        # Check authoritative cloud state before showing the PIN popup, including
        # when this device has never synchronized before.
        from .rbac_client import fetch_bulk_snapshot
        from .bulk_sync import import_bulk_snapshot
        snap = fetch_bulk_snapshot(s.rbac_api_base_url, s.rbac_api_key, s.rbac_http_timeout_seconds)
        import_bulk_snapshot(self.path, snap)
        user = db.get_user_by_oid(self.path, oid)
        if not user or not user['enabled']:
            raise RuntimeError('Signed-in user is not authorized in the current bulk RBAC snapshot')
        name = user['username']
        credential = db.get_offline_credential(self.path, oid)
        if credential and credential['pin_version'] >= 1:
            self.events.put(('completed', f'{name}: a cloud PIN is already cached. Use Sync All Users + PINs to refresh.'))
        else:
            self.events.put(('needs-pin', {'token': token, 'user': {'username': name, 'entraObjectId': oid}}))

    def show_pin_popup(self, context):
        """First-time cloud enrollment; token lives only in popup closure, never SQLite."""
        popup = tk.Toplevel(self.root)
        popup.title('Create your cloud PIN — first-time enrollment')
        popup.geometry('465x250')
        popup.transient(self.root)
        popup.grab_set()
        ttk.Label(popup, text='Create a 6–12 digit PIN (saved centrally)',
                  font=('Arial', 11, 'bold')).pack(pady=(15, 7))
        ttk.Label(popup, text=context['user']['username']).pack()
        ttk.Label(popup, text='PIN:').pack()
        p1 = ttk.Entry(popup, show='*', width=30)
        p1.pack(pady=4)
        ttk.Label(popup, text='Confirm PIN:').pack()
        p2 = ttk.Entry(popup, show='*', width=30)
        p2.pack(pady=4)
        button_bar = ttk.Frame(popup)
        button_bar.pack(pady=12)

        def cancel():
            popup.destroy()
            self.auth_in_progress = False
            self._set_signin_buttons()
            self.log_message('PIN enrollment canceled; no new cloud credential was created.')

        def submit():
            pin = p1.get()
            if pin != p2.get():
                messagebox.showerror('Mismatch', 'PINs do not match', parent=popup)
                return
            if not pin.isascii() or not pin.isdecimal() or not 6 <= len(pin) <= 12:
                messagebox.showerror('Invalid PIN', 'Use 6–12 ASCII digits.', parent=popup)
                return
            p1.delete(0, 'end')
            p2.delete(0, 'end')
            popup.destroy()
            self._run_thread(lambda: self._save_cloud_pin(context, pin))

        ttk.Button(button_bar, text='Save PIN in Cloud', command=submit).pack(side='left', padx=8)
        ttk.Button(button_bar, text='Cancel', command=cancel).pack(side='left', padx=8)
        popup.protocol('WM_DELETE_WINDOW', cancel)
        p1.focus_set()

    def _save_cloud_pin(self, context, pin):
        from .rbac_client import enroll_pin
        s = self.settings
        token = context['token']
        enroll_pin(s.rbac_api_base_url, token, pin, s.rbac_http_timeout_seconds)
        token = None
        pin = None
        # PIN was committed in Azure; fetch the canonical verifier via shared-key snapshot.
        self._bulk_sync()

    def show_device_code_popup(self, details: dict):
        self.close_device_code_popup()
        popup = tk.Toplevel(self.root)
        self.device_code_popup = popup
        popup.title('Microsoft Entra — Device Code Sign-In')
        popup.geometry('555x325')
        popup.transient(self.root)
        popup.columnconfigure(0, weight=1)
        popup.protocol('WM_DELETE_WINDOW', self.close_device_code_popup)
        ttk.Label(popup, text='Complete sign-in in your browser',
                  font=('Arial', 13, 'bold')).grid(row=0, column=0, pady=(18, 6))
        ttk.Label(popup, text='Step 1 — Copy the one-time code:').grid(row=1, column=0, sticky='w', padx=20)
        row = ttk.Frame(popup)
        row.grid(row=2, column=0, sticky='ew', padx=20, pady=(5, 12))
        row.columnconfigure(0, weight=1)
        code = tk.StringVar(value=details['user_code'])
        entry = ttk.Entry(row, textvariable=code, state='readonly', font=('Consolas', 14), justify='center')
        entry.grid(row=0, column=0, sticky='ew', padx=(0, 8))
        def copy_code():
            popup.clipboard_clear()
            popup.clipboard_append(code.get())
            popup.update()
            status.configure(text='Code copied to clipboard')
        ttk.Button(row, text='Copy Code', command=copy_code).grid(row=0, column=1)
        ttk.Label(popup, text='Step 2 — Copy or open the sign-in URL:').grid(row=3, column=0, sticky='w', padx=20)
        url_row = ttk.Frame(popup)
        url_row.grid(row=4, column=0, sticky='ew', padx=20, pady=(5, 12))
        url_row.columnconfigure(0, weight=1)
        uri = str(details['verification_uri'])
        url = ttk.Entry(url_row)
        url.insert(0, uri)
        url.configure(state='readonly')
        url.grid(row=0, column=0, sticky='ew', padx=(0, 8))
        ttk.Button(url_row, text='Open URL', command=lambda: webbrowser.open(uri)).grid(row=0, column=1)
        ttk.Label(popup, text='Step 3 — Sign in; this window closes after enrollment.').grid(
            row=5, column=0, sticky='w', padx=20)
        status = ttk.Label(popup, text='Waiting for sign-in…')
        status.grid(row=6, column=0, sticky='w', padx=20, pady=10)
        ttk.Button(popup, text='Hide', command=self.close_device_code_popup).grid(row=7, column=0, pady=9)
        entry.focus_set()
        entry.selection_range(0, 'end')

    def close_device_code_popup(self):
        popup = self.device_code_popup
        self.device_code_popup = None
        if popup:
            try:
                if popup.winfo_exists():
                    popup.destroy()
            except tk.TclError:
                pass

    def login(self):
        name = self.user_combo.get()
        if name not in self.users:
            messagebox.showwarning('Select user', 'Select a cached user')
            return
        secret = self.pin_login.get()
        self.pin_login.delete(0, 'end')
        s = self.settings
        ok, message, _roles = verify_offline_secret(self.path, name, secret,
            s.offline_auth_max_failed, s.offline_auth_lock_seconds)
        self.logged_username = name if ok else None
        self.log_message(('LOGIN OK: ' if ok else 'LOGIN DENIED: ') + message)
        if ok:
            self.log_message('Effective permissions: ' + (', '.join(self.users[name]['permissions']) or '(none)'))
        self.set_buttons()

    def logout(self):
        self.logged_username = None
        self.pin_login.delete(0, 'end')
        self.set_buttons()

    def set_buttons(self):
        for button in self.action_buttons.values():
            button.configure(state='normal' if self.logged_username else 'disabled')

    def action(self, function):
        if not self.logged_username:
            messagebox.showwarning('Login required', 'Log in with your PIN first')
            return
        allowed, reason = run_simulated_action(self.path, self.logged_username, function)
        self.log_message(('ALLOW' if allowed else 'DENY') + ' | ' + function + ' | ' + reason)
        if allowed:
            messagebox.showinfo('SIMULATED ACTION', function + ' permitted. No physical equipment operated.')
        else:
            messagebox.showwarning('Access denied', function + ': ' + reason)

    def show_audit(self):
        for row in reversed(db.recent_actions(self.path)):
            self.log_message(f"{row['event_time_utc']} | {row['username']} | {row['action_name']} | "
                             f"{'ALLOW' if row['allowed'] else 'DENY'}")


def start_gui():
    root = tk.Tk()
    App(root)
    root.mainloop()

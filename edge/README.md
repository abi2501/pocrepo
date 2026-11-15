# Edge RBAC Simulator v5 — All-user RBAC + Cloud PIN bulk synchronization

Windows / WSL2 / Raspberry Pi Python simulator compatible with the **FastAPI v5 Bulk Snapshot** backend. No RBAC device registration or device ID. The five existing simulated machine functions, offline PIN login, MSAL browser/device-code PIN enrollment, local SQLite, and optional IoT telemetry are retained.

## Core architecture and security

- **One synchronized read endpoint:** `GET /api/rbac/snapshot` with `x-functions-key: <RBAC_API_KEY>`. It returns schemaVersion **4**, `users[]` containing all directly assigned Entra users, effective permissions, and their cloud PIN verifiers (or `pin: null`).
- **One separate write endpoint:** `POST /api/pin/enroll` with an **Entra delegated `pin.enroll` bearer token** for first-time PIN creation. The server checks the signed-in user and does not accept an arbitrary user ID for enrollment.
- **No** `/api/access/snapshot`, `/api/pin/sync`, `/api/device-access/{id}`, or `/api/device-credentials/{id}` requests. No `DEVICE_KEY_SHA256_JSON` or RBAC device IDs.
- **Offline login:** all cloud-enrolled users can log into this installation after **one bulk sync**, without individually signing into Entra here. Existing role and permission checks still apply.
- **Expiry:** both `validUntilUtc` (RBAC) and `pinValidUntilUtc` (PIN) must be unexpired. Under the provided FastAPI v5 backend, PIN cache life defaults to a maximum of 24 hours; a new bulk sync renews the expiry. Offline login does NOT need a network connection while both are valid.
- **Risk:** a stolen shared API key can obtain **every user's salted PIN verifier**. A stolen local SQLite file presents the same offline guessing risk for short numeric PINs. Use only in a controlled POC with a long random key, HTTPS, encrypted devices, OS file permissions, and a short cache TTL. Shared API key grants bulk read access; do not expose it to untrusted users.

## Azure configuration

1. Deploy **FastAPI v5 Bulk Snapshot**, not v4. Verify `GET /health` works and Swagger lists `GET /api/rbac/snapshot` and `POST /api/pin/enroll`.
2. App Service should retain `RBAC_API_KEY` (**at least 32 random characters**), Microsoft Graph configuration, `PIN_TABLE_ENDPOINT`/`PIN_TABLE_NAME`, managed identity Table Storage permissions, and Entra enrollment API settings.
3. In `EdgeRbacPinApi > Expose an API`, enable the delegated `pin.enroll` scope; give `EdgeDeviceApplication` delegated permission with admin consent. `pin.sync` is **not needed** for this simulator. Configuring `pin.sync` in Entra is harmless but unused.
4. `RBAC_API_KEY` on the simulator **must be exactly the same value** configured on Azure App Service. Do not put it in source code or Git.

## Windows setup

1. Extract this ZIP to a **new folder**, e.g. `C:\EdgeRBACv5`.
2. Install Python 3.11+ with Tkinter. From a terminal in that folder run:

   ```powershell
   py -3 -m pip install -r requirements-live-minimal.txt
   Copy-Item .env.example .env
   ```

   The `Copy-Item` command is for PowerShell; in Command Prompt use `copy .env.example .env` instead.
3. Edit `.env`, particularly `RBAC_API_BASE_URL`, `RBAC_API_KEY`, `ENTRA_TENANT_ID`, `EDGE_PUBLIC_CLIENT_ID`, and `PIN_API_CLIENT_ID`. **Do not use** placeholder secret values.
4. Double-click **Run_Live_Mode_Windows.bat** (or `py -3 -m app.cli gui`).
5. Click **Sync All Users + PINs**. This imports all authorized users and their enrolled PIN verifiers into `data/auth_cache.db`. It does not require Entra sign-in on this installation.
6. Select an enrolled user and enter their PIN to log in offline. Test each simulated action's effective permission.
7. If a user has **not** enrolled a PIN, use **Enroll New PIN — Browser** or **Enroll New PIN — Device Code**; that person must authenticate with Microsoft Entra, enter a 6–12 digit PIN once, then the simulator performs a fresh bulk sync automatically.

## WSL / Raspberry Pi setup

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-tk
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-live-minimal.txt
cp .env.example .env
# Edit .env: Azure API URL and shared key, plus Entra IDs for PIN enrollment.
python -m app.cli gui
```

GUI requires WSLg/X11 or a Linux desktop. The CLI runs headless.

## CLI workflow

```bash
python -m app.cli sync                                  # All users, all enrolled PINs (shared key)
python -m app.cli users                                 # List cached users/permissions, not PINs
python -m app.cli login --username operator01@YOURTENANT.onmicrosoft.com
python -m app.cli action --username operator01@YOURTENANT.onmicrosoft.com --function view_status
python -m app.cli enroll --flow browser                 # First-time cloud PIN creation (Entra auth)
python -m app.cli enroll --flow device                  # Alternative: Microsoft device code
python -m app.cli status                                # Show last bulk sync metadata
```

The background `app.sync_agent` is for **optional IoT telemetry only** and does **not** refresh PIN/RBAC data. To refresh automatically, schedule `python -m app.cli sync` using Windows Task Scheduler, systemd timers, or cron, protecting the local shared API key appropriately. Ensure a refresh cadence shorter than the PIN credential expiry and maintain a fail-closed policy on expiry.

## Data consistency and migration

- The importer validates the entire schemaVersion-4 response, exact scrypt format and encoding, timestamp validity, unique users, and known effective permissions before any change to SQLite. Writes occur in **one transaction**.
- Users absent from a subsequent full snapshot are disabled locally and their PIN verifiers deleted. Disabled or unenrolled users cannot log in.
- PIN version rollback and unexpected same-version hash changes are rejected. On refresh of an unchanged credential, offline PIN lockout counters remain in place.
- The package does **not** include a local SQLite database. Use a fresh directory for initial v5 testing; stale v4 local data cannot substitute for a successful bulk sync.
- Old simulator clients must be upgraded together with FastAPI v5. Never expose the bulk endpoint anonymously.

## Tests

Run `python -m pip install pytest` and `python -m pytest -q tests/test_v5_bulk.py`. Synthetic test data is created in isolated temporary SQLite databases. No Azure calls are made during unit tests. Live Azure/Entra and actual WSL/Raspberry Pi execution must still be verified on your systems.

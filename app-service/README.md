# Edge RBAC FastAPI v6 — Azure Table Storage role policies

This version is based on **FastAPI v5 with all Microsoft Entra Custom Security Attributes included in the snapshot**. It replaces hardcoded `ROLE_PERMISSIONS` with a role policy table while preserving the API key-protected bulk snapshot and Entra-authenticated PIN enrollment.

> **Deployment prerequisite:** Create and populate the `RolePermissionPolicies` Azure Table **before** deploying this ZIP. Missing or invalid table policies cause HTTP 503. Do not deploy over a working environment until you have a rollback copy.

## Architecture

1. Microsoft Entra stores **direct App Role assignments** for `EdgeDeviceApplication` and user-specific `EdgeAccess.AllowedFunctions` (plus any other custom security attributes).
2. `RolePermissionPolicies` (Azure Table Storage) defines allowed function names **for each App Role**.
3. FastAPI v6 reads all three sources: Microsoft Graph user assignments/attributes, role policy table, and `UserPinCredentials` table.
4. Effective permissions = union of all assigned role policy grants **intersected with** `EdgeAccess.AllowedFunctions`.
5. `GET /api/rbac/snapshot` (header `x-functions-key`) returns the original **schemaVersion 4** bulk JSON; new attribute sets are passed through unmodified, and `permissions` reflects the policy table. The v5.1 simulator should continue to import this JSON without modification.
6. `POST /api/pin/enroll` continues to require a valid user-scoped Microsoft Entra bearer token with `pin.enroll` and an eligible App Role.

## 1 — Create the role policy table (Azure Portal)

1. Open **Azure Portal → Storage accounts → your existing Storage Account → Storage browser → Tables**, or **Data storage → Tables** depending on your portal version.
2. Click **+ Table**. Create the table with the exact name `RolePermissionPolicies`.
3. Open the new table and click **Add entity** to create each row below.
4. All rows use `PartitionKey = ROLE` (uppercase). `RowKey` identifies the canonical App Role.

**Column types are important:** `Enabled` must be Boolean (not a string), `PolicyVersion` must be Int32/Int64 (not a string), and `AllowedFunctions` must be **String** containing a valid JSON array of function strings.

| PartitionKey (String) | RowKey (String) | Enabled (Boolean) | PolicyVersion (Integer) | AllowedFunctions (String; JSON array) |
|---|---|---|---|---|
| ROLE | Operator | true | 1 | `["view_status","start_operation"]` |
| ROLE | Supervisor | true | 1 | `["view_status","start_operation","change_settings"]` |
| ROLE | ServiceEngineer | true | 1 | `["view_status","change_settings","service_tools"]` |
| ROLE | DeviceAdmin | true | 1 | `["view_status","start_operation","change_settings","service_tools","user_admin"]` |

`ServiceEnginner` is the value currently assigned in the existing Entra app. FastAPI normalizes that typo to the canonical table `RowKey = ServiceEngineer`. **Do not create a separate `ServiceEnginner` row.**

You can also enter an empty array `[]` for a role with no grants, or set `Enabled=false` to deny all grants for that row. **Do not omit the `AllowedFunctions` property.** Role rows are read dynamically; unknown app roles (without a policy row) grant no actions.

### Table-based policy editing

To grant `change_settings` through the Operator role, edit the `Operator` row:

- `AllowedFunctions` = `["view_status","start_operation","change_settings"]`
- `PolicyVersion` = `2` (increment on each change)
- `Enabled` = `true`

The user must ALSO have `change_settings` in `EdgeAccess.AllowedFunctions`. Changing role policy alone cannot grant a function outside that user's attribute list. A **new bulk sync** is required to publish the updated effective permissions, and the simulator must sync again while online.

To add a *new function*, first ensure that Entra `EdgeAccess.AllowedFunctions` has that value defined in its attribute schema and assigned to the user; add it to the table policy as well. Backend redeployment is not required to recognize the new function name, but the simulator needs UI/action code to actually implement the new function.

## 2 — Managed identity permissions

The existing App Service system-assigned Managed Identity needs **Storage Table Data Reader** (or the existing broader **Storage Table Data Contributor**) for reading the `RolePermissionPolicies` table. If you granted `Storage Table Data Contributor` at the **Storage Account** scope for PIN enrollment, it already covers this table. If you granted access only at the `UserPinCredentials` table scope, grant **Storage Table Data Reader** on `RolePermissionPolicies` as well.

Portal path: **Storage Account → Access control (IAM) → Add role assignment → Storage Table Data Reader → Managed identity → select your App Service**.

An Entra Global Administrator is not automatically a subscription Owner. If Add role assignment is disabled, a user with Azure **Owner/User Access Administrator/Role Based Access Control Administrator** rights must grant the role. Do not leave temporary root-level access elevation enabled after setup.

## 3 — App Service environment variables

Keep all working v5 values. Add:

```ini
POLICY_TABLE_NAME=RolePermissionPolicies
```

The code uses `PIN_TABLE_ENDPOINT` for both tables, e.g.:

```ini
PIN_TABLE_ENDPOINT=https://YOURSTORAGEACCOUNT.table.core.windows.net
PIN_TABLE_NAME=UserPinCredentials
POLICY_TABLE_NAME=RolePermissionPolicies
```

No API key, Graph credentials, or Entra app registrations need to change. `POLICY_TABLE_NAME` defaults to `RolePermissionPolicies` but setting it explicitly is recommended.

## 4 — Deploy the updated App Service

1. **Back up** the current FastAPI v5 deployment package.
2. Verify the policy table has all intended rows and the managed identity can read it.
3. Upload `Edge_RBAC_FastAPI_v6_Table_Policies_Deploy.zip` through the App Service deployment method that works for your environment (ZIP/Oryx build or connected GitHub deployment).
4. Keep `SCM_DO_BUILD_DURING_DEPLOYMENT=true` and the existing startup command:

   ```bash
   gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 main:app
   ```

5. Open `https://YOUR-APP.azurewebsites.net/health` and expect HTTP 200.
6. Call `GET /api/rbac/snapshot` in Swagger with **x-functions-key**, not an Entra bearer token. Expect HTTP 200 and `schemaVersion: 4`.
7. Confirm every directly assigned user has `customSecurityAttributes`, `roles`, `permissions`, `pinEnrolled`, and `pin` (if enrolled).
8. Sync the existing simulator with **Sync All Users + PINs**; check offline login and permitted functions.

## 5 — Example

- Entra App Role: `Operator`
- `RolePermissionPolicies` Operator policy: `["view_status","start_operation"]`
- User's `EdgeAccess.AllowedFunctions`: `["change_settings"]`
- Result: `permissions: []` (**no intersection**).

If the Operator policy is changed to include `change_settings` with `PolicyVersion=2`, the next bulk snapshot contains `permissions: ["change_settings"]` for that user. No Python redeploy is required.

## 6 — Implementation details

- `app/policy_repository.py` **new**: Uses system-assigned managed identity to read the policy table, validates all rows, and returns an in-memory dictionary keyed by App Role.
- `app/permissions.py` **replaced**: No hardcoded `ROLE_PERMISSIONS`. Calculates union of role grants and intersection with user attributes. Preserves `ServiceEnginner` alias.
- `app/graph_reader.py` **changed**: Accepts an explicit policy dictionary per Graph read, still passes through all Custom Security Attributes.
- `app/config.py` **changed**: `POLICY_TABLE_NAME` setting and validation.
- `main.py` **changed**: Reads policy table on every bulk snapshot and during PIN enrollment's authorization check. Keeps the existing HTTP API and response structure. The policy table is read per-request, so no application restart is required after changing a policy.

### Security and behavior notes

- Fails closed: an unavailable or invalid policy table makes the snapshot return **HTTP 503**, not a partial 200. Empty policy table is also treated as a configuration error. A missing *individual role row* grants no functions for that role.
- JSON function names must match `^[a-z][a-z0-9_]{0,127}$`; `AllowedFunctions` must have unique strings. Every row requires `Enabled` (Boolean), `PolicyVersion` (positive integer), and an `AllowedFunctions` JSON string.
- `PolicyVersion` is metadata for manual change tracking; this POC **does not yet enforce optimistic policy version updates, approvals, audit records, or multi-row atomic publication**. Azure Table Storage is not a full-fledged policy engine; edits to different rows may be observed at different times. For production, consider staging + publishing a versioned whole-policy bundle.
- Unauthorized table edits could expand permissions; restrict Table Data Contributor rights to designated administrators and use Azure activity/diagnostic auditing.
- **The shared-key bulk endpoint still exports every user's salted PIN verifier.** This is an intentional POC constraint with offline brute-force risk if the key or database is stolen. Prefer hardware-backed device enrollment for production.
- Offline devices retain previously cached grants until the cache expires or they synchronize again. Policy changes do **not** immediately revoke offline access.
- Existing `schemaVersion: 4` is retained deliberately for the simulator v5.1.

## 7 — Tests

In the project root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

Expected: 19 tests passing locally. Live Azure permissions and table connectivity require deployment testing.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| HTTP 503 `Role policy storage unavailable or invalid` | Table missing, incorrect column types, empty table, missing IAM role, or malformed JSON | Inspect `RolePermissionPolicies`; verify Managed Identity `Storage Table Data Reader` or `Contributor`; inspect App Service logs |
| HTTP 502 `Directory synchronization failed` | Microsoft Graph token, consent, assigned users, or response issue | Check Graph app permissions, tenant/client secret, direct App Role assignment, and logs |
| User has attributes but `permissions: []` | No matching role policy or empty intersection | Check Entra `roles`, `EdgeAccess.AllowedFunctions`, and matching `RolePermissionPolicies` row |
| New custom attribute appears but grants no action | Only `EdgeAccess.AllowedFunctions` participates in the function intersection | Implement explicit authorization logic for new policy dimensions as needed |
| Azure Portal Add role assignment disabled | Insufficient Azure RBAC rights | Ask subscription Owner/role admin to assign managed identity role |
| Simulator shows old permissions | Cached snapshot | Trigger **Sync All Users + PINs** and verify cache validity |
| PIN enrollment 401 | Entra token not valid for PIN API | Check `pin.enroll`, audience, token version 2, tenant, and desktop client |


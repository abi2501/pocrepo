# Browser-only Azure App Service + GitHub Deployment Guide

This guide assumes you already created:
- A Microsoft Entra workforce tenant, four test users, four roles and direct assignments for `EdgeDeviceApplication`.
- An app registration `EdgeRbacReaderFunction` with Graph **Application** permissions `Application.Read.All` and `User.Read.All` and **Granted admin consent**.
- A client secret for `EdgeRbacReaderFunction`, and you copied the **VALUE** (not Secret ID).
- An Azure subscription on which you can create a **Linux Python Web App**.

**No local Azure CLI, PowerShell, or WSL commands are needed to create and deploy the web service.** GitHub Actions performs build and deployment remotely; local terminal usage is optional.

## A. Azure Portal: create the Linux Web App

1. Open https://portal.azure.com > **App Services** > **Create** > **Web App**.
2. Choose **Publish: Code**; **Runtime stack: Python 3.11**; **Operating system: Linux**.
3. Choose your existing Resource Group `rg-edge-poc`, or create it.
4. Enter a globally unique App Service name, e.g. `app-edge-rbac-poc-84721` (example only).
5. Select a supported region such as Central India if available.
6. Pick an App Service Plan and review actual pricing. Use **F1 Free** *only if* shown and allowed for your Linux plan; do not assume the trial account qualifies. F1 may be slow and will not support all paid features. Avoid scaling a POC to an expensive plan unintentionally.
7. Turn **public network access ON** so you can test the HTTPS endpoint; keep HTTPS-only enabled and use the API key for the protected RBAC endpoint.
8. Optional: enable App Service application logging and Application Insights, reviewing charges.
9. Review + create > Create > Go to resource.

**Do not create an Azure Function App.** The result must be an **App Service Web App** with Linux/Python runtime.

## B. Azure Portal: set the FastAPI startup command

For **Python 3.11**, FastAPI requires an explicit startup command.

App Service > **Settings > Configuration > General settings** (portal labels may move):

```
gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 main:app
```

Click **Save**. This references `main.py` and its `app = FastAPI(...)` variable.

## C. Azure Portal: set ALL 8 application settings

App Service > **Settings > Environment variables > App settings** (or **Configuration > Application settings**) > **Add**. Set:

| Setting | What exactly to paste |
|---|---|
| `ENTRA_TENANT_ID` | **Entra ID > Overview > Tenant ID** |
| `GRAPH_CLIENT_ID` | **App registrations > EdgeRbacReaderFunction > Overview > Application (client) ID** |
| `GRAPH_CLIENT_SECRET` | **EdgeRbacReaderFunction > Certificates & secrets > Client secrets > Value** |
| `EDGE_APP_SP_OBJECT_ID` | **Enterprise applications > EdgeDeviceApplication > Overview > Object ID** |
| `ALLOWED_DEVICE_IDS` | `WSL-POC-001` |
| `RBAC_CACHE_VALID_HOURS` | `168` |
| `RBAC_API_KEY` | A randomly generated, secret string **at least 32 characters** long; securely store it for your edge app/Postman |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` |

Click **Apply/Save**. Allow App Service to restart if prompted.

**Never** put `GRAPH_CLIENT_SECRET` or `RBAC_API_KEY` into GitHub files, GitHub Actions logs, email, or chat. Later use Azure Key Vault references for production. The app has a liveness endpoint (`/health`) even before Graph connectivity works; a 200 there only proves the web server is running.

## D. GitHub: upload the code as actual source files

Use your existing private GitHub repository, or create a dedicated private repository such as `central-rbac-appservice`.

1. Unzip the supplied package locally using your computer's file explorer.
2. In GitHub > repository > **Code > Add file > Upload files**, upload the **contents of the extracted folder** at the repository root. Preserve the `app/` and `tests/` directories.
3. Confirm that `main.py`, `requirements.txt` and `README.md` appear in the **repository root**, and `app/config.py`, `app/graph_reader.py` appear under `app/`.
4. Commit to `main` (or your chosen deployment branch).

**Do not upload the ZIP itself as one file.** Do not keep the FastAPI project nested under a second folder if using the portal-generated deployment workflow; it usually assumes the repository root. Your previously uploaded `azure/rbac_function/` folder may remain, but the new FastAPI code must be at the repository root for these instructions.

## E. Connect GitHub using Azure App Service Deployment Center (recommended)

1. Azure Portal > **App Services** > open your Python Web App.
2. Open **Deployment > Deployment Center**.
3. **Source: GitHub**; authorize Azure to access your GitHub account if asked.
4. Select your **Organization/User**, **Repository**, and **Branch: main**.
5. **Build provider: GitHub Actions**.
6. Choose the **User-assigned identity (OpenID Connect)** authentication option, if offered; this avoids placing publish profile passwords into GitHub. If Azure prompts for permission to create the deployment identity, approve or ask the Azure subscription administrator. This deployment identity is independent from `EdgeRbacReaderFunction`.
7. Review the generated workflow preview, if shown. Confirm `python` is selected and it packages the repository root. Click **Save**.
8. App Service creates a `.github/workflows/...yml` file in your repo and triggers a run.
9. GitHub > repository > **Actions** > open latest deployment run; verify each step is green.

If Deployment Center cannot generate a workflow due to subscription permissions, use the **optional** `deployment_templates/deploy-appservice-oidc.yml` as a template. Browser-only manual setup requires an Entra/GitHub OIDC federated identity with deployment permission and GitHub Actions secrets (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`). Copy the template into `.github/workflows/deploy-appservice.yml`, replace the App Service name, and configure federation first. **Do not install both active workflows**; they would deploy twice.

**Key check:** This is `azure/webapps-deploy` for App Service, **not** `Azure/functions-action` for a Function App.

## F. Verify deployment from GitHub and Azure Portal

1. GitHub > **Actions** > your workflow > most recent run; look for successful build and deploy.
2. Azure Portal > App Service > **Deployment Center > Logs** (if available) to inspect source deployment.
3. App Service > **Overview > Default domain** to open the site.
4. Visit: `https://YOUR-APP.azurewebsites.net/health`. Expected: HTTP 200 and `{ "status": "ok" }`.
5. Visit `https://YOUR-APP.azurewebsites.net/docs` to open FastAPI Swagger.
6. If you see the default Azure welcome page or 503, verify Startup Command, dependencies, deployment path, `SCM_DO_BUILD_DURING_DEPLOYMENT=true`, and App Service **Monitoring > Log stream**.

## G. Test the real Microsoft Graph RBAC snapshot

From Swagger UI:

1. Open `/docs`.
2. Click **Authorize** (padlock button); enter the exact **RBAC_API_KEY** configured in App Service. (Swagger sends the value as `x-functions-key`.)
3. Find `GET /api/device-access/{device_id}` and choose **Try it out**.
4. Set `device_id` = `WSL-POC-001`.
5. Click **Execute**.
6. HTTP 200 should contain four user objects if all four were assigned directly to enabled App Roles in **Enterprise applications > EdgeDeviceApplication > Users and groups**.

Or in Postman:

- Method: `GET`
- URL: `https://YOUR-APP.azurewebsites.net/api/device-access/WSL-POC-001`
- Header: `x-functions-key: YOUR-RBAC-API-KEY`
- Header: `Accept: application/json`

Expected example (abbreviated):

```json
{
  "schemaVersion": 1,
  "deviceId": "WSL-POC-001",
  "source": {
    "assignmentMode": "direct-users-only",
    "servicePrincipalObjectId": "<your enterprise object id>"
  },
  "users": [
    {"entraObjectId":"...", "username":"operator01@...", "displayName":"Edge Operator", "enabled":true, "roles":["Operator"]},
    {"entraObjectId":"...", "username":"supervisor01@...", "displayName":"Edge Supervisor", "enabled":true, "roles":["Supervisor"]}
  ]
}
```

The actual response also includes `version`, timestamps, and other assigned users.

## H. Test security and negative scenarios

| Test | Action | Expected result |
|---|---|---|
| Liveness | GET `/health` | 200 (does **not** test Graph) |
| No API key | GET protected endpoint with no header | 401 |
| Wrong API key | Supply wrong `x-functions-key` | 401 |
| Device not allowed | Use `WSL-POC-999` with correct key | 403 |
| Correct key/device | Normal request, correct Graph consent | 200 + assigned users |
| Missing config | Temporarily remove nonsecret required setting on disposable POC | 503 |
| Invalid Graph permission | Revoke consent in isolated test tenant | 502; no partial snapshot |
| Role change | Operator -> Supervisor in Enterprise applications, then query again | Updated role after propagation |
| Role removal | Remove assignment, query again | User absent after propagation |

## I. Connect the existing WSL/Raspberry Pi edge client

Your existing `.env` keys can remain the same. The endpoint now uses the App Service base URL:

```dotenv
EDGE_DEVICE_ID=WSL-POC-001
RBAC_API_BASE_URL=https://YOUR-APP.azurewebsites.net/api
RBAC_API_KEY=<same-value-as-App-Service-RBAC_API_KEY>
RBAC_SYNC_SECONDS=300
RBAC_HTTP_TIMEOUT_SECONDS=20
```

The edge client sends the existing `x-functions-key` HTTP header and calls `/device-access/WSL-POC-001` relative to `RBAC_API_BASE_URL`. The cloud service returns the same main snapshot schema. The original edge code may have additional configuration requirements (for example, an IoT Hub connection string); these are outside this replacement service.

## J. Troubleshooting table

| Symptom | Likely cause | Fix |
|---|---|---|
| Azure default welcome page | FastAPI not started | Verify Python 3.11/Linux, startup command `main:app`, root files, and logging |
| GitHub deployment green, site 503 | Package install or startup failed | Check `Monitoring > Log stream`; confirm Oryx build setting and requirements.txt |
| `401` | Missing/wrong `x-functions-key` | Swagger Authorize; confirm exactly same `RBAC_API_KEY` in App Service |
| `403` | Device not listed | Add `WSL-POC-001` to `ALLOWED_DEVICE_IDS` |
| `502` | Token acquisition/Graph read failure | Check app-only Graph consent, secret VALUE, tenant ID, service principal Object ID, App Service logs |
| `503` | Missing/weak setting | Fill all required environment settings; API key min 32 characters |
| `200` with `users: []` | Roles not directly assigned, wrong service principal, or role disabled | Enterprise applications > EdgeDeviceApplication > Users and groups; verify App Roles enabled and direct assignments |
| User not returned | Group assignment or replication delay | This POC ignores group assignments; use direct assignments and allow propagation |
| Deployment Center can't create identity | Subscription lacks managed identity/RBAC permission | Have subscription admin grant Website Contributor to a suitable identity or configure OIDC manually |
| GitHub workflow targets old Function App | Wrong deployment action/name | App Service must use `azure/webapps-deploy`, not Functions Action |

## K. Production hardening (not yet implemented)

- Replace Graph client secret with App Service managed identity and grant it Graph application permissions.
- Replace shared API key with App Service Authentication (Microsoft Entra) and authenticated per-device tokens or mTLS/API gateway.
- Introduce device-specific user entitlements, not a global user list per allowed device.
- Evaluate shorter offline cache expiry, anti-replay and signed snapshots, secure local PIN enrollment, audit logs, local file ownership, and service-layer permission enforcement.
- Define how disabled Entra accounts are handled (the current `enabled` field **does not** read Graph's `accountEnabled`). The POC revokes by removing App Role assignments.
- Store secrets in Key Vault and enable secure secret rotation.
- Use separate DEV/PROD App Registrations, identities, subscriptions, and access policies.

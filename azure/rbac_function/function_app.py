from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import azure.functions as func
import requests
from azure.identity import ClientSecretCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
logger = logging.getLogger("rbac-snapshot")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def env_required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing app setting: {name}")
    return value


def utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_token() -> str:
    credential = ClientSecretCredential(
        tenant_id=env_required("ENTRA_TENANT_ID"),
        client_id=env_required("GRAPH_CLIENT_ID"),
        client_secret=env_required("GRAPH_CLIENT_SECRET"),
    )
    return credential.get_token("https://graph.microsoft.com/.default").token


def graph_get(url: str, token: str) -> dict:
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def graph_all(url: str, token: str) -> list[dict]:
    output: list[dict] = []
    while url:
        page = graph_get(url, token)
        output.extend(page.get("value", []))
        url = page.get("@odata.nextLink")
    return output


def build_snapshot(device_id: str) -> dict:
    allowed = {x.strip() for x in os.getenv("ALLOWED_DEVICE_IDS", "").split(",") if x.strip()}
    if allowed and device_id not in allowed:
        raise PermissionError(f"Device {device_id!r} is not allowed by this POC API")

    sp_id = env_required("EDGE_APP_SP_OBJECT_ID")
    token = get_token()

    sp = graph_get(
        f"{GRAPH_BASE}/servicePrincipals/{sp_id}?$select=id,displayName,appRoles",
        token,
    )
    role_map = {
        role["id"]: role.get("value") or role.get("displayName")
        for role in sp.get("appRoles", [])
        if role.get("isEnabled", True)
    }

    assignments = graph_all(
        f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignedTo?"
        "$select=principalId,principalType,principalDisplayName,appRoleId",
        token,
    )

    # POC implementation intentionally supports direct USER assignments only.
    # Group-based role expansion can be added later with GroupMember.Read.All / appropriate directory permission.
    users_by_id: dict[str, dict] = {}
    for assignment in assignments:
        if assignment.get("principalType") != "User":
            continue
        role_id = assignment.get("appRoleId")
        if not role_id or role_id == ZERO_GUID or role_id not in role_map:
            continue

        oid = assignment["principalId"]
        entry = users_by_id.get(oid)
        if entry is None:
            user = graph_get(
                f"{GRAPH_BASE}/users/{oid}?$select=id,displayName,userPrincipalName,accountEnabled",
                token,
            )
            entry = {
                "entraObjectId": user["id"],
                "username": user.get("userPrincipalName") or user["id"],
                "displayName": user.get("displayName") or user.get("userPrincipalName") or user["id"],
                "enabled": bool(user.get("accountEnabled", True)),
                "roles": [],
            }
            users_by_id[oid] = entry
        entry["roles"].append(role_map[role_id])

    users = sorted(users_by_id.values(), key=lambda x: x["username"].lower())
    for user in users:
        user["roles"] = sorted(set(user["roles"]))

    now = datetime.now(timezone.utc)
    valid_hours = int(os.getenv("RBAC_CACHE_VALID_HOURS", "168"))
    # A monotonic-enough POC version. Production could store a durable central version/hash.
    version = int(time.time())

    return {
        "schemaVersion": 1,
        "version": version,
        "deviceId": device_id,
        "generatedUtc": utc_iso(now),
        "validUntilUtc": utc_iso(now + timedelta(hours=valid_hours)),
        "source": {
            "servicePrincipalObjectId": sp_id,
            "applicationDisplayName": sp.get("displayName"),
            "assignmentMode": "direct-users-only"
        },
        "users": users,
    }


@app.route(route="device-access/{device_id}", methods=["GET"])
def rbac_snapshot(req: func.HttpRequest) -> func.HttpResponse:
    device_id = req.route_params.get("device_id", "").strip()
    if not device_id:
        return func.HttpResponse("device_id is required", status_code=400)

    try:
        payload = build_snapshot(device_id)
        logger.info("Built RBAC snapshot for %s with %d users", device_id, len(payload["users"]))
        return func.HttpResponse(
            json.dumps(payload, separators=(",", ":")),
            status_code=200,
            mimetype="application/json",
        )
    except PermissionError as exc:
        logger.warning("Forbidden device %s: %s", device_id, exc)
        return func.HttpResponse(str(exc), status_code=403)
    except requests.HTTPError as exc:
        detail = exc.response.text[:1000] if exc.response is not None else str(exc)
        logger.exception("Microsoft Graph request failed")
        return func.HttpResponse(f"Microsoft Graph request failed: {detail}", status_code=502)
    except Exception as exc:
        logger.exception("RBAC snapshot failed")
        return func.HttpResponse(f"RBAC snapshot failed: {type(exc).__name__}: {exc}", status_code=500)

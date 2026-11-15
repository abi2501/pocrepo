"""MSAL browser/device-code sign-in to the protected EdgeRbacPinApi.

Used only for first-time cloud PIN enrollment. Routine v5 bulk synchronization uses x-functions-key.
"""

from __future__ import annotations


def _client(tenant_id: str, client_id: str):
    if not tenant_id or not client_id:
        raise RuntimeError(
            "ENTRA_TENANT_ID and EDGE_PUBLIC_CLIENT_ID must be configured"
        )
    import msal  # Only required when initiating an online Entra sign-in.

    return msal.PublicClientApplication(
        client_id=client_id, authority=f"https://login.microsoftonline.com/{tenant_id}"
    )


def _scopes(pin_api_client_id: str) -> list[str]:
    if not pin_api_client_id:
        raise RuntimeError("PIN_API_CLIENT_ID must be configured")
    return [f"api://{pin_api_client_id}/pin.enroll"]


def _access_token(result: dict, flow: str, *, return_identity: bool = False):
    if not isinstance(result, dict) or not result.get("access_token"):
        error = (
            result.get("error", "unknown_error")
            if isinstance(result, dict)
            else "invalid_response"
        )
        raise RuntimeError(f"Microsoft Entra {flow} login failed: {error}")
    if return_identity:
        claims = result.get("id_token_claims") or {}
        oid = claims.get("oid")
        if not isinstance(oid, str) or not oid:
            raise RuntimeError("Entra ID token does not contain an object ID")
        return result["access_token"], oid.lower()
    return result["access_token"]


def interactive_browser_login(
    tenant_id: str,
    client_id: str,
    pin_api_client_id: str,
    on_open=None,
    return_identity: bool = False,
):
    client = _client(tenant_id, client_id)
    if on_open:
        on_open("Opening your system browser for Microsoft Entra sign-in.")
    try:
        response = client.acquire_token_interactive(
            scopes=_scopes(pin_api_client_id), timeout=180, prompt="select_account"
        )
    except Exception as exc:
        raise RuntimeError(
            "Browser sign-in failed. Verify the http://localhost desktop redirect."
        ) from exc
    return _access_token(response, "browser", return_identity=return_identity)


def interactive_device_login(
    tenant_id: str,
    client_id: str,
    pin_api_client_id: str,
    on_code=None,
    return_identity: bool = False,
):
    client = _client(tenant_id, client_id)
    try:
        flow = client.initiate_device_flow(scopes=_scopes(pin_api_client_id))
    except Exception as exc:
        raise RuntimeError(
            "Could not initiate Microsoft Entra device-code sign-in"
        ) from exc
    if (
        not isinstance(flow, dict)
        or not flow.get("user_code")
        or not flow.get("device_code")
    ):
        raise RuntimeError("Microsoft Entra did not return a device code")
    url = flow.get("verification_uri") or flow.get("verification_url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise RuntimeError("Microsoft Entra did not return a valid verification URL")
    if on_code:
        on_code(
            {
                "user_code": flow["user_code"],
                "verification_uri": url,
                "expires_in": flow.get("expires_in"),
            }
        )
    try:
        result = client.acquire_token_by_device_flow(flow)
    except Exception as exc:
        raise RuntimeError("Device-code authentication failed") from exc
    return _access_token(result, "device-code", return_identity=return_identity)

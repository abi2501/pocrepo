"""Read direct user app roles plus user custom security attributes from Graph.

Scope: directly assigned users only. Does not expand groups, and `enabled`
is retained for compatibility rather than reflecting Graph accountEnabled.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
import logging
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Settings
from .permissions import allowed_functions_from_profile, effective_permissions

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOG = logging.getLogger(__name__)


class DirectoryReadError(RuntimeError):
    """Upstream directory could not provide a reliable snapshot."""


class GraphReader:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = requests.Session()
        retry = Retry(
            total=3, backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "POST"]),
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _access_token(self) -> str:
        url = f"https://login.microsoftonline.com/{self.settings.tenant_id}/oauth2/v2.0/token"
        try:
            response = self.session.post(url, data={
                "client_id": self.settings.graph_client_id,
                "client_secret": self.settings.graph_client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            }, timeout=20)
            response.raise_for_status()
            token = response.json().get("access_token")
            if not token:
                raise DirectoryReadError("Missing Graph access token")
            return token
        except (requests.RequestException, ValueError) as exc:
            LOG.warning("Microsoft Entra token request failed (%s)", type(exc).__name__)
            raise DirectoryReadError("Microsoft Entra token acquisition failed") from exc

    def _get_json(self, url: str, token: str, params: dict | None = None) -> dict:
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc.lower() != "graph.microsoft.com":
            raise DirectoryReadError("Unexpected Microsoft Graph URL")
        try:
            response = self.session.get(
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                params=params, timeout=25,
            )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise DirectoryReadError("Invalid Microsoft Graph response")
            return result
        except (requests.RequestException, ValueError) as exc:
            LOG.warning("Microsoft Graph request failed (%s)", type(exc).__name__)
            raise DirectoryReadError("Microsoft Graph read failed") from exc

    def _get_all_pages(self, url: str, token: str) -> list[dict]:
        items: list[dict] = []
        visited: set[str] = set()
        while url:
            if url in visited or len(visited) >= 1000:
                raise DirectoryReadError("Graph pagination cycle or limit exceeded")
            visited.add(url)
            page = self._get_json(url, token)
            chunk = page.get("value")
            if not isinstance(chunk, list):
                raise DirectoryReadError("Invalid Graph collection response")
            items.extend(chunk)
            url = page.get("@odata.nextLink")
            if url and not isinstance(url, str):
                raise DirectoryReadError("Invalid Graph nextLink")
        return items

    def list_direct_users(self, role_policies: Mapping[str, frozenset[str]]) -> list[dict]:
        token = self._access_token()
        sp_id = self.settings.edge_app_sp_object_id
        principal = self._get_json(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}", token,
            params={"$select": "id,appRoles"},
        )
        roles = {
            str(role["id"]).lower(): role["value"]
            for role in principal.get("appRoles", [])
            if role.get("isEnabled") and role.get("id") and role.get("value")
            and "User" in role.get("allowedMemberTypes", [])
        }
        assignments = self._get_all_pages(
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/appRoleAssignedTo", token
        )
        roles_by_user: dict[str, set[str]] = defaultdict(set)
        for assignment in assignments:
            if assignment.get("principalType") != "User":
                continue
            user_id = assignment.get("principalId")
            role = roles.get(str(assignment.get("appRoleId", "")).lower())
            if user_id and role:
                roles_by_user[str(user_id)].add(role)

        users: list[dict] = []
        for user_id, role_names in sorted(roles_by_user.items()):
            profile = self._get_json(
                f"{GRAPH_BASE}/users/{user_id}", token,
                params={"$select": "id,displayName,userPrincipalName,mail,customSecurityAttributes"},
            )
            if str(profile.get("id", "")).lower() != user_id.lower():
                raise DirectoryReadError("Unexpected Graph user identity")
            username = profile.get("userPrincipalName") or profile.get("mail")
            if not username:
                raise DirectoryReadError("Assigned user lacks a resolvable username")
            try:
                assigned_functions = allowed_functions_from_profile(profile)
            except ValueError as exc:
                raise DirectoryReadError("Invalid user authorization attributes") from exc
            # Include every custom security attribute set supplied by Microsoft Graph.
            # EdgeAccess.AllowedFunctions alone determines effective permissions;
            # arbitrary attributes are informational until explicitly mapped to policy.
            raw_attributes = profile.get("customSecurityAttributes")
            if raw_attributes is None:
                raw_attributes = {}
            if not isinstance(raw_attributes, dict):
                raise DirectoryReadError("Invalid custom security attributes response")
            raw_roles = sorted(role_names)
            users.append({
                "entraObjectId": user_id,
                "username": username,
                "displayName": profile.get("displayName") or username,
                "enabled": True,
                "roles": raw_roles,
                "customSecurityAttributes": raw_attributes,
                "permissions": effective_permissions(raw_roles, assigned_functions, role_policies),
            })
        users.sort(key=lambda x: x["username"].lower())
        return users

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from urllib.parse import quote

import requests


class IoTSender:
    """Send device-to-cloud telemetry to Azure IoT Hub over HTTPS.

    Drop-in replacement for the MQTT/WebSocket IoTSender used by sync_agent.py.
    The public async interface is intentionally unchanged.
    """

    API_VERSION = "2021-04-12"
    SAS_TTL_SECONDS = 3600
    HTTP_TIMEOUT_SECONDS = 30

    def __init__(self, connection_string: str):
        values = self._parse_connection_string(connection_string)
        try:
            self._host = values["HostName"]
            self._device_id = values["DeviceId"]
            self._device_key = values["SharedAccessKey"]
        except KeyError as exc:
            raise ValueError(
                "IOTHUB_DEVICE_CONNECTION_STRING must contain "
                "HostName, DeviceId and SharedAccessKey"
            ) from exc

        encoded_device_id = quote(self._device_id, safe="")
        self._resource_uri = f"{self._host}/devices/{self._device_id}"
        self._url = (
            f"https://{self._host}/devices/{encoded_device_id}/messages/events"
            f"?api-version={self.API_VERSION}"
        )

        self._session = requests.Session()
        self._sas_token = ""
        self._sas_expiry = 0

    @staticmethod
    def _parse_connection_string(connection_string: str) -> dict[str, str]:
        values: dict[str, str] = {}
        for part in connection_string.split(";"):
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            values[key.strip()] = value.strip()
        return values

    def _get_sas_token(self) -> str:
        # Refresh a little early so a token does not expire during a request.
        now = int(time.time())
        if self._sas_token and now < self._sas_expiry - 60:
            return self._sas_token

        expiry = now + self.SAS_TTL_SECONDS
        encoded_uri = quote(self._resource_uri, safe="").lower()
        string_to_sign = f"{encoded_uri}\n{expiry}".encode("utf-8")

        key = base64.b64decode(self._device_key)
        signature = base64.b64encode(
            hmac.new(key, string_to_sign, hashlib.sha256).digest()
        ).decode("utf-8")

        self._sas_token = (
            "SharedAccessSignature "
            f"sr={encoded_uri}&sig={quote(signature, safe='')}&se={expiry}"
        )
        self._sas_expiry = expiry
        return self._sas_token

    async def connect(self) -> None:
        # HTTPS does not require a persistent IoT connection.
        # requests.Session still reuses underlying HTTP/TLS connections when possible.
        return None

    def _send_sync(self, event_id: str, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )

        headers = {
            "Authorization": self._get_sas_token(),
            "Content-Type": "application/json",
            "Content-Encoding": "utf-8",
            # IoT Hub application property; useful for tracing/deduplication downstream.
            "iothub-app-eventId": event_id,
        }

        response = self._session.post(
            self._url,
            data=body,
            headers=headers,
            timeout=self.HTTP_TIMEOUT_SECONDS,
        )

        # IoT Hub Send Device Event returns 204 No Content on success.
        if response.status_code != 204:
            raise RuntimeError(
                f"IoT Hub HTTPS send failed: HTTP {response.status_code}: "
                f"{response.text[:500]}"
            )

    async def send_json(self, event_id: str, payload: dict) -> None:
        # Keep blocking requests off the asyncio event loop used by sync_agent.py.
        await asyncio.to_thread(self._send_sync, event_id, payload)

    async def reset(self) -> None:
        # Drop pooled connections and force a fresh SAS token after a transport error.
        self._session.close()
        self._session = requests.Session()
        self._sas_token = ""
        self._sas_expiry = 0

    async def close(self) -> None:
        self._session.close()

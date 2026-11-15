from __future__ import annotations

import json
from azure.iot.device import Message
from azure.iot.device.aio import IoTHubDeviceClient


class IoTSender:
    def __init__(self, connection_string: str):
        self._connection_string = connection_string
        self._client: IoTHubDeviceClient | None = None

    async def connect(self) -> None:
        if self._client is not None:
            return
        client = IoTHubDeviceClient.create_from_connection_string(
            self._connection_string,
            websockets=True,
        )
        await client.connect()
        self._client = client

    async def send_json(self, event_id: str, payload: dict) -> None:
        await self.connect()
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        message = Message(body)
        message.content_type = "application/json"
        message.content_encoding = "utf-8"
        message.message_id = event_id
        await self._client.send_message(message)

    async def reset(self) -> None:
        if self._client is not None:
            try:
                await self._client.shutdown()
            finally:
                self._client = None

    async def close(self) -> None:
        await self.reset()

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sqlite3

from .config import get_settings
from . import db


logger = logging.getLogger("edge-sync")


def build_event(device_id: str, row) -> dict:
    source_id = int(row["id"])
    return {
        "schemaVersion": 1,
        "eventId": f"{device_id}:telemetry_events:{source_id}",
        "deviceId": device_id,
        "sourceTable": "telemetry_events",
        "sourceRecordId": source_id,
        "eventTimeUtc": row["event_time_utc"],
        "eventType": row["event_type"],
        "severity": row["severity"],
        "payload": json.loads(row["payload_json"]),
    }


def delete_uploaded_telemetry(telemetry_db_path: str, record_id: int) -> None:
    """Delete exactly one telemetry row after IoT Hub has confirmed receipt.

    If deletion fails, the row is intentionally left in SQLite. It may be sent
    again on the next retry, which preserves at-least-once delivery. The stable
    EventId allows duplicates to be identified/deduplicated downstream.
    """
    conn = sqlite3.connect(telemetry_db_path, timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        cursor = conn.execute(
            "DELETE FROM telemetry_events WHERE id = ?",
            (record_id,),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            raise RuntimeError(
                f"Expected to delete telemetry row {record_id}, "
                f"but deleted {cursor.rowcount} row(s)"
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


async def telemetry_loop(stop_event: asyncio.Event) -> None:
    s = get_settings(require_cloud=False)
    from .iot_sender import IoTSender
    sender = IoTSender(s.iothub_connection_string)
    backoff = 5

    try:
        while not stop_event.is_set():
            try:
                # Every row still present in telemetry_events is pending upload.
                # after_id=0 means there is no checkpoint dependency anymore.
                rows = db.pending_telemetry(
                    s.telemetry_db_path,
                    after_id=0,
                    limit=s.telemetry_batch_size,
                )

                if not rows:
                    try:
                        await asyncio.wait_for(
                            stop_event.wait(),
                            timeout=s.telemetry_poll_seconds,
                        )
                    except asyncio.TimeoutError:
                        pass
                    continue

                logger.info("Uploading %d pending telemetry row(s)", len(rows))

                for row in rows:
                    record_id = int(row["id"])
                    event = build_event(s.device_id, row)

                    # send_json returns only after IoT Hub confirms success.
                    # For the HTTPS sender this means HTTP 204 No Content.
                    await sender.send_json(event["eventId"], event)

                    # Delete only after successful cloud acknowledgement.
                    delete_uploaded_telemetry(s.telemetry_db_path, record_id)
                    logger.info(
                        "Uploaded and deleted local telemetry row: %s",
                        event["eventId"],
                    )

                backoff = 5

            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Telemetry sync failed; unsent/local row remains for retry: %s",
                    message,
                )
                await sender.reset()

                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass

                backoff = min(backoff * 2, s.telemetry_retry_max_seconds)

    finally:
        await sender.close()


# Telemetry agent remains separate; bulk RBAC/PIN sync is initiated from GUI/CLI.

async def main_async() -> None:
    s = get_settings(require_cloud=False)
    logging.basicConfig(
        level=getattr(logging, s.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger.info("Starting edge sync agent for device %s", s.device_id)

    db.init_auth_db(s.auth_db_path)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            pass

    tasks = []
    logger.info("Bulk RBAC/PIN synchronization is initiated from GUI/CLI, not by telemetry agent")
    if s.iothub_connection_string:
        tasks.append(asyncio.create_task(telemetry_loop(stop_event), name="telemetry-sync"))
    else:
        logger.info("IoT Hub device connection string absent; telemetry upload disabled")

    await stop_event.wait()
    logger.info("Stopping edge sync agent")
    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()

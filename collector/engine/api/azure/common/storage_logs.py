"""Reader for Azure diagnostic logs delivered to a Storage account.

The analogue of the AWS S3 log reader: many Azure resource logs (flow logs, firewall, App
Gateway/WAF, Front Door) land as JSON blobs in a Storage container only when a diagnostic
setting / Network-Watcher flow log routes them there. This lists the blobs, downloads them,
parses the per-blob ``records`` array, and yields each record within the configured window.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from collector.clouds.azure.client_factory import _raise_typed_azure
from collector.lib.limits import UNLIMITED_OBJECTS, UNLIMITED_RECORDS, records_unlimited

# Flow-log container names are fixed by Azure.
FLOW_CONTAINER = {
    "nsg": "insights-logs-networksecuritygroupflowevent",
    "vnet": "insights-logs-flowlogflowevent",
}

MAX_BLOBS = UNLIMITED_OBJECTS
MAX_RECORDS = UNLIMITED_RECORDS


def read_log_records(
    container_client: Any,
    *,
    prefix: str | None = None,
    max_blobs: int = MAX_BLOBS,
    max_records: int = MAX_RECORDS,
) -> Iterator[dict[str, Any]]:
    """Yield each entry of the ``records`` array across every JSON blob under ``prefix``.

    Azure writes diagnostic logs as ``…/PT1H.json`` blobs whose body is ``{"records": [...]}``.
    Callers flatten those records into the unified shape themselves (formats differ per source).
    """
    try:
        blobs = container_client.list_blobs(name_starts_with=prefix)
        scanned = 0
        emitted = 0
        for blob in blobs:
            if not records_unlimited(max_blobs) and scanned >= max_blobs:
                return
            name = getattr(blob, "name", "") or ""
            if not name.endswith(".json"):
                continue
            scanned += 1
            data = container_client.download_blob(name).readall()
            try:
                payload = json.loads(data)
            except (ValueError, TypeError):
                continue
            for rec in payload.get("records") or []:
                if not records_unlimited(max_records) and emitted >= max_records:
                    return
                yield rec
                emitted += 1
    except Exception as exc:  # noqa: BLE001
        _raise_typed_azure(exc, "storage:read_log_records")

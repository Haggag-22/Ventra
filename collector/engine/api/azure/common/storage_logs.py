"""Reader for Azure diagnostic logs delivered to a Storage account.

The analogue of the AWS S3 log reader: many Azure resource logs (flow logs, firewall, App
Gateway/WAF, Front Door) land as JSON blobs in a Storage container only when a diagnostic
setting / Network-Watcher flow log routes them there. This lists the blobs, downloads them,
and yields each log record within the configured window.

Azure writes two body shapes into ``…/PT1H.json``:

* a single object ``{"records": [...]}`` (VNet flow logs), and
* one JSON object per line, or a single bare record object (resource diagnostic logs).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from collector.clouds.azure.client_factory import _raise_typed_azure
from collector.lib.limits import UNLIMITED_OBJECTS, UNLIMITED_RECORDS, records_unlimited
from collector.lib.scoping import blob_path_in_window

# Flow-log container names are fixed by Azure.
FLOW_CONTAINER = {
    "nsg": "insights-logs-networksecuritygroupflowevent",
    "vnet": "insights-logs-flowlogflowevent",
}

MAX_BLOBS = UNLIMITED_OBJECTS
MAX_RECORDS = UNLIMITED_RECORDS


def resource_id_prefixes(resource_id: str) -> list[str]:
    """Blob-name prefixes for one ARM resource.

    Most diagnostic categories uppercase the resource id in the blob path. Storage
    data-plane logs keep the id's original casing. Listing both finds either layout.
    """
    original = f"resourceId={resource_id}"
    upper = f"resourceId={resource_id.upper()}"
    if original == upper:
        return [original]
    return [original, upper]


def _iter_body_records(data: bytes) -> Iterator[dict[str, Any]]:
    """Yield log records from a records-wrapper, a bare object, or JSON lines."""
    text = data.decode("utf-8-sig")
    payload: Any = None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        for rec in payload["records"]:
            if isinstance(rec, dict):
                yield rec
        return
    if isinstance(payload, dict):
        yield payload
        return
    if isinstance(payload, list):
        for rec in payload:
            if isinstance(rec, dict):
                yield rec
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        nested = obj.get("records")
        if isinstance(nested, list):
            for rec in nested:
                if isinstance(rec, dict):
                    yield rec
            continue
        yield obj


def read_log_records(
    container_client: Any,
    *,
    prefix: str | None = None,
    prefixes: list[str] | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    max_blobs: int = MAX_BLOBS,
    max_records: int = MAX_RECORDS,
) -> Iterator[dict[str, Any]]:
    """Yield each log record from every JSON blob under the given prefix(es).

    ``prefixes`` lists every blob-name prefix to scan (used when Azure's path casing
    is not predictable). The same blob name is downloaded once.
    """
    wanted = list(prefixes) if prefixes else [prefix]
    try:
        scanned = 0
        emitted = 0
        seen: set[str] = set()
        for one_prefix in wanted:
            blobs = container_client.list_blobs(name_starts_with=one_prefix)
            for blob in blobs:
                if not records_unlimited(max_blobs) and scanned >= max_blobs:
                    return
                name = getattr(blob, "name", "") or ""
                if not name.endswith(".json") or name in seen:
                    continue
                if not blob_path_in_window(name, start, end):
                    continue
                seen.add(name)
                scanned += 1
                data = container_client.download_blob(name).readall()
                for rec in _iter_body_records(data):
                    if not records_unlimited(max_records) and emitted >= max_records:
                        return
                    yield rec
                    emitted += 1
    except Exception as exc:  # noqa: BLE001
        _raise_typed_azure(exc, "storage:read_log_records")

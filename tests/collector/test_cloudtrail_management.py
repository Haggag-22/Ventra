"""Management-event collection: trail S3 logs first, Event History only on failure."""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from collector.clouds.aws.client_factory import AccessDenied
from collector.engine.api.aws.control_plane.cloudtrail import CloudTrailCollector
from collector.lib.models import CollectionContext, TimeWindow

START = datetime(2026, 6, 11, 0, 0, 0, tzinfo=UTC)
END = datetime(2026, 6, 11, 23, 59, 59, tzinfo=UTC)


def _gz(payload: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(json.dumps(payload).encode("utf-8"))
    return buf.getvalue()


def _s3_trail(name: str = "main", bucket: str = "trail-bucket") -> dict[str, Any]:
    return {
        "Name": name,
        "TrailARN": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{name}",
        "S3BucketName": bucket,
        "S3KeyPrefix": "",
        "HomeRegion": "us-east-1",
        "IsMultiRegionTrail": False,
        "Status": {"IsLogging": True},
    }


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _S3:
    def __init__(self, objects: dict[str, bytes]) -> None:
        self._objects = objects

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        return {"Body": _Body(self._objects[Key])}


class _Cf:
    """Client-factory stub. ``s3_objects`` drives S3 reads; ``lookup`` drives Event History."""

    def __init__(
        self,
        *,
        s3_objects: dict[str, bytes] | None = None,
        deny_s3: bool = False,
        lookup: list[dict[str, Any]] | None = None,
    ) -> None:
        self._s3_objects = s3_objects or {}
        self._deny_s3 = deny_s3
        self._lookup = lookup or []

    def client(self, service: str, region: str) -> _S3:
        return _S3(self._s3_objects)

    def paginate(self, service, region, operation, result_key, **kwargs):  # noqa: ANN001
        if service == "s3":
            if self._deny_s3:
                raise AccessDenied("s3:ListBucket", "denied")
            prefix = kwargs.get("Prefix", "")
            for key in self._s3_objects:
                if key.startswith(prefix):
                    yield {"Key": key}
        elif service == "cloudtrail" and operation == "lookup_events":
            yield from self._lookup

    def call(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return {}


def _collector(tmp_path: Path) -> CloudTrailCollector:
    staging = tmp_path / "staging"
    staging.mkdir()
    ctx = CollectionContext(
        cloud="aws",
        account_id="123456789012",
        regions=["us-east-1"],
        time_window=TimeWindow(),
        staging=staging,
        case_id="CASE-TEST",
    )
    return CloudTrailCollector(ctx)


def _mgmt_object() -> tuple[str, bytes]:
    key = "AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/11/log.json.gz"
    payload = {
        "Records": [
            {
                "eventCategory": "Management",
                "eventID": "m1",
                "eventTime": "2026-06-11T12:00:00Z",
                "eventName": "ConsoleLogin",
            }
        ]
    }
    return key, _gz(payload)


def test_collects_from_trails_when_s3_readable(tmp_path: Path) -> None:
    key, body = _mgmt_object()
    cf = _Cf(s3_objects={key: body}, lookup=[{"EventId": "should-not-be-used"}])
    collector = _collector(tmp_path)
    gaps: list[Any] = []
    s3_by_bucket: dict[str, Any] = {}

    records, lookup_insight, collection = collector._collect_management_events(
        cf, {"trails": [_s3_trail()]}, gaps, START, END, s3_by_bucket
    )

    assert collection["mode"] == "trails"
    assert collection["trails_collected"] == 1
    assert collection["buckets"] == ["trail-bucket"]
    assert [r["eventID"] for r in records] == ["m1"]
    assert records[0]["_ventra_collect_source"] == "s3_logs"
    assert lookup_insight == []  # Event History not consulted
    assert collection["trails"][0]["status"] == "collected"


def test_falls_back_to_event_history_when_bucket_denied(tmp_path: Path) -> None:
    cf = _Cf(deny_s3=True, lookup=[{"EventId": "from-event-history"}])
    collector = _collector(tmp_path)
    gaps: list[Any] = []

    records, _lookup_insight, collection = collector._collect_management_events(
        cf, {"trails": [_s3_trail()]}, gaps, START, END, {}
    )

    assert collection["mode"] == "event_history"
    assert collection["fallback_reason"] == "access_denied"
    assert collection["trails"][0]["status"] == "denied"
    assert [r["EventId"] for r in records] == ["from-event-history"]


def test_uses_event_history_when_no_trail_logs_to_s3(tmp_path: Path) -> None:
    not_logging = _s3_trail()
    not_logging["Status"] = {"IsLogging": False}
    cf = _Cf(lookup=[{"EventId": "eh-1"}, {"EventId": "eh-2"}])
    collector = _collector(tmp_path)
    gaps: list[Any] = []

    records, _lookup_insight, collection = collector._collect_management_events(
        cf, {"trails": [not_logging]}, gaps, START, END, {}
    )

    assert collection["mode"] == "event_history"
    assert collection["fallback_reason"] == "no_s3_trail"
    assert collection["trails_total"] == 0
    assert len(records) == 2

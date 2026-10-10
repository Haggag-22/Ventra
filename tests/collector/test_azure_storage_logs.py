"""Azure diagnostic blobs: JSON lines, bare records, and mixed-case paths."""

from __future__ import annotations

import json
from pathlib import Path

from collector.engine.api.azure.common.storage_logs import read_log_records, resource_id_prefixes
from collector.engine.api.azure.workloads.aks_audit import AksAuditCollector
from collector.engine.api.azure.workloads.storage_access import StorageAccessCollector
from collector.lib.models import CollectionContext, SourceStatus, TimeWindow


class _Blob:
    def __init__(self, name: str) -> None:
        self.name = name


class _Download:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def readall(self) -> bytes:
        return self._data


class _PrefixContainer:
    def __init__(self, blobs: dict[str, bytes]) -> None:
        self.blobs = blobs
        self.downloads: list[str] = []

    def list_blobs(self, name_starts_with=None):
        for name in self.blobs:
            if name_starts_with and not name.startswith(name_starts_with):
                continue
            yield _Blob(name)

    def download_blob(self, name: str) -> _Download:
        self.downloads.append(name)
        return _Download(self.blobs[name])


def test_resource_id_prefixes_cover_both_casings() -> None:
    rid = "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/app"
    prefixes = resource_id_prefixes(rid)
    assert prefixes[0] == f"resourceId={rid}"
    assert prefixes[1] == f"resourceId={rid.upper()}"


def test_read_log_records_jsonl_bare_object_and_records_wrapper() -> None:
    jsonl = (
        json.dumps({"operationName": "GetBlob", "statusCode": 200})
        + "\n"
        + json.dumps({"operationName": "PutBlob", "statusCode": 201})
        + "\n"
    ).encode()
    bare = json.dumps({"operationName": "SecretGet", "category": "AuditEvent"}).encode()
    wrapped = json.dumps({"records": [{"operationName": "FlowLogFlowEvent"}]}).encode()
    container = _PrefixContainer(
        {
            "a/PT1H.json": jsonl,
            "b/PT1H.json": bare,
            "c/PT1H.json": wrapped,
        }
    )
    rows = list(read_log_records(container))
    assert [r["operationName"] for r in rows] == ["GetBlob", "PutBlob", "SecretGet", "FlowLogFlowEvent"]


def test_read_log_records_does_not_download_a_blob_twice() -> None:
    name = "resourceId=/SUBSCRIPTIONS/S/PT1H.json"
    container = _PrefixContainer({name: json.dumps({"records": [{"n": 1}]}).encode()})
    rows = list(
        read_log_records(
            container,
            prefixes=["resourceId=/SUBSCRIPTIONS/S", "resourceId=/SUBSCRIPTIONS"],
        )
    )
    assert rows == [{"n": 1}]
    assert container.downloads == [name]


def _ctx(tmp_path: Path, cf: object) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure",
        account_id="tenant-abc",
        regions=[],
        time_window=TimeWindow(),
        staging=staging,
        case_id="CASE-AZ",
        tenant_id="tenant-abc",
        subscription_ids=["sub-1"],
        client_factory=cf,
    )


def test_storage_access_reads_original_case_jsonl(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/app"
    blob = f"resourceId={rid}/blobServices/default/y=2026/m=10/d=04/h=07/m=00/PT1H.json"
    body = (
        json.dumps({"time": "2026-10-04T07:00:00Z", "operationName": "GetBlob", "category": "StorageRead"})
        + "\n"
    ).encode()

    class _Cf:
        def resources_of_type(self, subscription_id, resource_types):
            del subscription_id, resource_types
            return [
                {"id": rid, "name": "app", "type": "Microsoft.Storage/storageAccounts", "location": "eastus"}
            ]

        def diagnostic_settings(self, resource_id):
            if resource_id == f"{rid}/blobServices/default":
                return [
                    {
                        "storage_account_id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs",
                        "categories": ["StorageRead"],
                        "category_groups": [],
                    }
                ]
            return []

        def container_client(self, storage_id, container):
            del storage_id, container
            return _PrefixContainer({blob: body})

    result = StorageAccessCollector(_ctx(tmp_path, _Cf())).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.COLLECTED


def test_aks_audit_unwraps_jsonl_diagnostic_envelope(tmp_path: Path) -> None:
    rid = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1"
    blob = f"resourceId={rid.upper()}/y=2026/m=10/d=04/h=07/m=00/PT1H.json"
    audit = {
        "verb": "get",
        "stage": "ResponseComplete",
        "user": {"username": "admin"},
        "objectRef": {"resource": "pods"},
    }
    line = json.dumps({"category": "kube-audit", "properties": {"log": json.dumps(audit)}}) + "\n"

    class _Cf:
        def managed_clusters(self, subscription_id):
            del subscription_id
            return [{"id": rid, "name": "aks1", "location": "eastus", "properties": {}}]

        def diagnostic_settings(self, resource_id):
            del resource_id
            return [
                {
                    "storage_account_id": "sa1",
                    "categories": ["kube-audit"],
                    "category_groups": [],
                }
            ]

        def container_client(self, storage_id, container):
            del storage_id, container
            return _PrefixContainer({blob: line.encode()})

    result = AksAuditCollector(_ctx(tmp_path, _Cf())).collect()
    assert result.record_count == 1
    assert result.status == SourceStatus.COLLECTED
    import gzip

    payload = gzip.decompress(
        (tmp_path / "staging" / "sources" / "aks_audit" / "events.jsonl.gz").read_bytes()
    )
    row = json.loads(payload.splitlines()[0])
    assert row["verb"] == "get"
    assert row["_ventra_cluster"] == "aks1"

"""NSG flow logs — configuration discovery and recent flow records from storage."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from ...lib.base import Collector
from ...lib.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, AzureClientFactory
from ..common.serialize import to_dict
from .nsg_flow_parse import flatten_nsg_records

MAX_FLOW_RECORDS = 200_000


class NsgFlowCollector(Collector):
    name = "nsg_flow"
    priority = 1
    description = "NSG flow log configuration + recent flow records from storage."
    required_actions = (
        "Microsoft.Network/networkWatchers/read",
        "Microsoft.Network/networkWatchers/flowLogs/read",
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    )

    def collect(self) -> SourceResult:
        cf: AzureClientFactory = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        flow_configs: list[dict] = []
        records: list[dict] = []

        for region in self.ctx.regions:
            try:
                net = cf.network()
                for fl in net.flow_logs.list(region):
                    item = to_dict(fl)
                    item["_ventra_region"] = region
                    flow_configs.append(item)
            except AccessDenied as exc:
                gaps.append(("nsg_flow", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
            except Exception as exc:
                gaps.append(("nsg_flow", GapReason.COLLECTOR_ERROR, f"{region}: {exc}"))

        if not flow_configs:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[
                    (
                        "nsg_flow",
                        GapReason.LOGGING_NOT_CONFIGURED,
                        "No NSG flow logs configured in scope. "
                        "Exfiltration volume cannot be quantified for this window.",
                    )
                ],
                notes="No NSG flow logging configured — recorded as a gap.",
            )

        window = self.ctx.time_window
        end = window.until or datetime.now(UTC)
        start = window.since or (end - timedelta(days=14))

        for cfg in flow_configs:
            if len(records) >= MAX_FLOW_RECORDS:
                break
            try:
                chunk = self._read_flow_storage(cf, cfg, start, end, gaps)
                records.extend(chunk)
            except Exception as exc:
                gaps.append(("nsg_flow_storage", GapReason.COLLECTOR_ERROR, str(exc)))

        records = records[:MAX_FLOW_RECORDS]
        files = [self.write_json({"flow_logs": flow_configs}, "config.json")]
        if records:
            files.append(self.write_jsonl(records, "events.jsonl.gz"))
        self.write_meta({"source": self.name, "flow_logs": len(flow_configs), "records": len(records)})

        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED if records else SourceStatus.PARTIAL,
            files=files,
            record_count=len(records),
            gaps=gaps,
            notes=f"{len(records)} flow record(s) from {len(flow_configs)} flow log(s).",
        )

    def _read_flow_storage(
        self,
        cf: AzureClientFactory,
        cfg: dict[str, Any],
        start: datetime,
        end: datetime,
        gaps: list[tuple[str, GapReason, str]],
    ) -> list[dict]:
        props = cfg.get("properties") or cfg.get("Properties") or {}
        storage = props.get("storageId") or props.get("storage_id") or ""
        enabled = props.get("enabled", props.get("Enabled", True))
        if not enabled or not storage:
            return []

        # storageId: /subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/name
        account_name = storage.rsplit("/", 1)[-1]
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            gaps.append(("nsg_flow_storage", GapReason.COLLECTOR_ERROR, str(exc)))
            return []

        try:
            blob_service = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=cf._credential,
            )
        except Exception as exc:
            gaps.append(("nsg_flow_storage", GapReason.ACCESS_DENIED, str(exc)))
            return []

        container_name = "insights-logs-networksecuritygroupflowevent"
        container = blob_service.get_container_client(container_name)
        out: list[dict] = []
        try:
            for blob in container.list_blobs(name_starts_with=""):
                if blob.last_modified and blob.last_modified.replace(tzinfo=UTC) < start:
                    continue
                if blob.last_modified and blob.last_modified.replace(tzinfo=UTC) > end:
                    continue
                data = container.download_blob(blob.name).readall()
                try:
                    payload = json.loads(data.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, list):
                    out.extend(flatten_nsg_records(payload))
                elif isinstance(payload, dict):
                    out.extend(flatten_nsg_records([payload]))
                if len(out) >= MAX_FLOW_RECORDS:
                    break
        except Exception as exc:
            gaps.append(("nsg_flow_storage", GapReason.ACCESS_DENIED, str(exc)))
        for r in out:
            r["_ventra_region"] = cfg.get("_ventra_region", "")
        return out

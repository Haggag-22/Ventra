"""Google Cloud client factory — ADC auth, project discovery, logging, SCC, IAM, Compute."""

from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Any, Callable, Iterator

# GRPC_DNS_RESOLVER is forced to "native" in collector/__init__.py — it must be set before grpc
# is imported (which happens on the next lines), so it lives at the package root, not here.
from google.api_core import exceptions as gcp_exc
from google.auth import default as google_auth_default
from google.cloud import compute_v1
from google.cloud import logging_v2
from google.cloud import resourcemanager_v3
from google.cloud import securitycenter_v1 as scc_v1

# Cloud Logging reads (entries.list / sinks.list) count against the per-project AND per-user
# "Read requests per minute" quota — a GCP default of 60/min. Every logging collector shares one
# factory and they run serially, so a single shared limiter keeps the whole run under that
# ceiling, and a full page per request means a given volume costs the fewest reads.
_LOG_PAGE_SIZE = 1000
_LOG_READ_QPM_DEFAULT = 55  # headroom under the 60/min default; override with VENTRA_GCP_LOG_READ_QPM
_LOG_BACKOFF_CAP = 60.0  # a per-minute quota fully refills within 60s, so backoff need not exceed it
# A read-quota 429 is always transient (the per-minute quota refills), so retries are *patient*:
# as long as the scan keeps making progress it retries indefinitely, and a logging read is only
# abandoned after this many seconds of ZERO-progress 429s — long past a quota reset, which means the
# block is no longer a simple rate limit. Override with VENTRA_GCP_LOG_STALL_LIMIT_S.
_LOG_STALL_LIMIT_S_DEFAULT = 600.0


class GcpAccessDenied(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GcpServiceNotEnabled(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GcpRateLimited(Exception):
    """Cloud Logging read quota (429) stayed exhausted past the retry budget."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GcpUnreachable(Exception):
    """A GCP API endpoint could not be reached (DNS/transport/connectivity)."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _connectivity_message(host: str, exc: Exception) -> str:
    return (
        f"Could not reach the GCP API endpoint {host}. This is a network/DNS problem, not a "
        "permissions one — check that this machine has internet access, that any VPN or proxy "
        "allows *.googleapis.com, and that DNS is resolving. "
        f"Underlying error: {exc}"
    )


def _raise_if_unreachable(host: str, exc: Exception) -> None:
    """Re-raise transport/DNS failures as a clear GcpUnreachable; ignore everything else."""
    text = str(exc).lower()
    transport = isinstance(exc, (gcp_exc.RetryError, gcp_exc.ServiceUnavailable))
    if transport or "dns" in text or "failed to connect" in text or "unavailable" in text:
        raise GcpUnreachable(_connectivity_message(host, exc)) from exc


def _log_read_qpm() -> int:
    raw = os.environ.get("VENTRA_GCP_LOG_READ_QPM", "").strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if value > 0:
            return value
    return _LOG_READ_QPM_DEFAULT


def _log_stall_limit_s() -> float:
    raw = os.environ.get("VENTRA_GCP_LOG_STALL_LIMIT_S", "").strip()
    if raw:
        try:
            value = float(raw)
        except ValueError:
            value = 0.0
        if value > 0:
            return value
    return _LOG_STALL_LIMIT_S_DEFAULT


def _sleep_backoff(attempt: int) -> float:
    """Exponential backoff (2s, 4s, … capped at 60s) with jitter; returns the seconds slept."""
    delay = min(2.0**attempt, _LOG_BACKOFF_CAP) + random.uniform(0.0, 1.0)
    time.sleep(delay)
    return delay


class _RateLimiter:
    """Token bucket shared across logging reads to stay under the per-minute quota.

    ``acquire`` blocks just long enough to keep the sustained rate at ``per_minute`` requests;
    when tokens are available (the common case for small runs) it returns immediately.
    """

    def __init__(self, per_minute: int) -> None:
        self._capacity = float(max(1, per_minute))
        self._tokens = self._capacity
        self._refill_per_sec = self._capacity / 60.0
        self._updated = time.monotonic()
        self._lock = Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self._capacity, self._tokens + (now - self._updated) * self._refill_per_sec
            )
            self._updated = now
            if self._tokens < 1.0:
                time.sleep((1.0 - self._tokens) / self._refill_per_sec)
                self._tokens = 0.0
                self._updated = time.monotonic()
            else:
                self._tokens -= 1.0


@dataclass
class GcpIdentity:
    project_id: str
    principal: str
    organization_id: str = ""
    organization_name: str = ""


def _entry_project(entry: dict[str, Any], fallback: str) -> str:
    """Owning project of a log entry, from ``logName: projects/<id>/logs/…``."""
    log_name = str(entry.get("logName") or entry.get("log_name") or "")
    if log_name.startswith("projects/"):
        parts = log_name.split("/", 2)
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    return fallback


def _enum_name(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


def _mapping_to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "items"):
        try:
            return dict(value)
        except TypeError:
            pass
    try:
        from google.protobuf.json_format import MessageToDict

        if hasattr(value, "_pb"):
            return MessageToDict(value._pb, preserving_proto_field_name=False)
        return MessageToDict(value, preserving_proto_field_name=False)
    except Exception:
        pass
    try:
        return dict(value)
    except (TypeError, ValueError):
        return {}


def _entry_to_dict(entry: logging_v2.LogEntry) -> dict[str, Any]:
    if hasattr(entry, "to_api_repr"):
        try:
            api = entry.to_api_repr()
            if isinstance(api, dict):
                return api
        except Exception:
            pass
    payload = entry.payload
    if hasattr(payload, "items"):
        try:
            payload = dict(payload)
        except TypeError:
            payload = _mapping_to_dict(payload)
    elif payload is not None and not isinstance(payload, (dict, list, str, int, float, bool)):
        payload = _mapping_to_dict(payload) if hasattr(payload, "DESCRIPTOR") else str(payload)
    resource = entry.resource
    out: dict[str, Any] = {
        "logName": entry.log_name,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
        "severity": _enum_name(entry.severity),
        "insertId": entry.insert_id,
        "resource": {
            "type": resource.type if resource else "",
            "labels": _mapping_to_dict(resource.labels if resource else None),
        },
        "labels": _mapping_to_dict(entry.labels),
        "payload": payload,
    }
    if entry.proto_payload:
        out["protoPayload"] = _mapping_to_dict(entry.proto_payload) or {
            "_raw": str(entry.proto_payload)
        }
    if entry.text_payload:
        out["textPayload"] = entry.text_payload
    if entry.json_payload:
        out["jsonPayload"] = _mapping_to_dict(entry.json_payload)
    return out


class GcpClientFactory:
    """Thin wrapper around Google Cloud SDK clients with typed gap exceptions."""

    def __init__(
        self,
        *,
        project_id: str | None = None,
        credentials_path: str | None = None,
        service_account_info: dict[str, Any] | None = None,
    ) -> None:
        # cloud-platform.read-only is insufficient for IAM Admin and Compute APIs
        # (they return 401, not 403). IAM on the service account still enforces read-only.
        scopes = [
            "https://www.googleapis.com/auth/cloud-platform",
        ]
        if service_account_info:
            from google.oauth2 import service_account

            creds = service_account.Credentials.from_service_account_info(
                service_account_info, scopes=scopes
            )
            self._credentials = creds
            self._default_project = project_id or service_account_info.get("project_id") or ""
        elif credentials_path:
            from google.oauth2 import service_account

            creds = service_account.Credentials.from_service_account_file(
                credentials_path, scopes=scopes
            )
            self._credentials = creds
            self._default_project = project_id or creds.project_id or ""
        else:
            self._credentials, self._default_project = google_auth_default(scopes=scopes)
            if project_id:
                self._default_project = project_id

        self._logging_clients: dict[str, logging_v2.Client] = {}
        # Shared across every project/collector so the per-user logging read quota is respected
        # across the whole run, not just per project.
        self._log_throttle = _RateLimiter(_log_read_qpm())
        self._rm = resourcemanager_v3.ProjectsClient(credentials=self._credentials)
        self._scc = scc_v1.SecurityCenterClient(credentials=self._credentials)
        self._compute: dict[str, Any] = {}
        self._iam: Any = None

    @property
    def credentials(self) -> Any:
        """ADC credentials, for read-only helpers (strategy resolution) sharing this identity."""
        return self._credentials

    def _logging_client(self, project_id: str) -> logging_v2.Client:
        if project_id not in self._logging_clients:
            self._logging_clients[project_id] = logging_v2.Client(
                project=project_id, credentials=self._credentials
            )
        return self._logging_clients[project_id]

    def caller_identity(self) -> GcpIdentity:
        principal = "unknown"
        if self._credentials:
            if hasattr(self._credentials, "service_account_email"):
                principal = self._credentials.service_account_email or principal
            elif hasattr(self._credentials, "signer_email"):
                principal = self._credentials.signer_email or principal
        project = self._default_project or ""
        org_id = ""
        org_name = ""
        if project:
            try:
                proj = self._rm.get_project(name=f"projects/{project}")
                parent = proj.parent or ""
                if parent.startswith("organizations/"):
                    org_id = parent.split("/", 1)[1]
            except gcp_exc.PermissionDenied as exc:
                raise GcpAccessDenied(str(exc)) from exc
            except gcp_exc.NotFound:
                pass
            except gcp_exc.GoogleAPIError as exc:
                _raise_if_unreachable("cloudresourcemanager.googleapis.com", exc)
                raise
        return GcpIdentity(
            project_id=project,
            principal=principal,
            organization_id=org_id,
            organization_name=org_name,
        )

    def projects(self, *, explicit: list[str] | None = None) -> list[str]:
        if explicit:
            return explicit
        if self._default_project:
            return [self._default_project]
        ids: list[str] = []
        try:
            for proj in self._rm.search_projects(query="state:ACTIVE"):
                pid = proj.project_id
                if pid:
                    ids.append(pid)
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.GoogleAPIError as exc:
            _raise_if_unreachable("cloudresourcemanager.googleapis.com", exc)
            raise GcpServiceNotEnabled(str(exc)) from exc
        return sorted(set(ids))

    def project_details(self, project_ids: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for pid in project_ids:
            try:
                proj = self._rm.get_project(name=f"projects/{pid}")
                out.append(
                    {
                        "project_id": proj.project_id,
                        "name": proj.display_name,
                        "state": proj.state.name if proj.state else "",
                        "parent": proj.parent,
                        "create_time": proj.create_time.isoformat() if proj.create_time else "",
                    }
                )
            except gcp_exc.PermissionDenied:
                out.append({"project_id": pid, "error": "access_denied"})
            except gcp_exc.NotFound:
                out.append({"project_id": pid, "error": "not_found"})
        return out

    def _throttled_log_entries(
        self, client: logging_v2.Client, full_filter: str, remaining: int
    ) -> Iterator[Any]:
        """Yield entries, taking one token from the shared limiter per read request (page)."""
        self._log_throttle.acquire()
        since_token = 0
        for entry in client.list_entries(
            filter_=full_filter,
            order_by="timestamp desc",
            page_size=_LOG_PAGE_SIZE,
            max_results=remaining,
        ):
            yield entry
            since_token += 1
            if since_token >= _LOG_PAGE_SIZE:
                self._log_throttle.acquire()  # next page is another read request
                since_token = 0

    def list_log_entries(
        self,
        project_id: str,
        *,
        log_filter: str,
        start: datetime | None,
        end: datetime | None,
        max_records: int,
    ) -> Iterator[dict[str, Any]]:
        client = self._logging_client(project_id)
        emitted = 0
        # Resume bookkeeping: on a 429 mid-scan we re-issue the query with the window tightened to
        # the last second we saw (order is timestamp desc), skipping insert IDs already yielded in
        # that second so retries never duplicate evidence.
        boundary_second = ""
        boundary_ids: set[str] = set()
        attempt = 0
        stalled = 0.0  # seconds spent backing off since the scan last made progress
        stall_limit = _log_stall_limit_s()
        emitted_at_failure = -1
        ts_start = start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if start is not None else ""
        ts_end = end.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if end is not None else ""
        try:
            while emitted < max_records:
                if start is not None and end is not None:
                    time_clause = f'timestamp >= "{ts_start}" AND timestamp <= "{ts_end}"'
                elif start is not None:
                    time_clause = f'timestamp >= "{ts_start}"'
                elif end is not None:
                    time_clause = f'timestamp <= "{ts_end}"'
                else:
                    time_clause = ""
                full_filter = (
                    f"({log_filter}) AND {time_clause}" if log_filter and time_clause
                    else log_filter or time_clause
                )
                try:
                    for entry in self._throttled_log_entries(
                        client, full_filter, max_records - emitted
                    ):
                        record = _entry_to_dict(entry)
                        insert_id = str(record.get("insertId") or "")
                        second = str(record.get("timestamp") or "")[:19]
                        if second == boundary_second and insert_id and insert_id in boundary_ids:
                            continue  # already yielded in this second before the retry
                        yield record
                        emitted += 1
                        if second != boundary_second:
                            boundary_second = second
                            boundary_ids = set()
                        if insert_id:
                            boundary_ids.add(insert_id)
                        if emitted >= max_records:
                            return
                    return  # page generator drained — this project is complete
                except gcp_exc.ResourceExhausted as exc:
                    if emitted > emitted_at_failure:
                        attempt, stalled = 1, 0.0  # progress since the last 429 — reset patience
                    else:
                        attempt += 1
                    emitted_at_failure = emitted
                    if stalled >= stall_limit:
                        raise GcpRateLimited(
                            f"logging read quota stayed exhausted ~{stalled:.0f}s without progress: {exc}"
                        ) from exc
                    stalled += _sleep_backoff(attempt)
                    if boundary_second:
                        ts_end = f"{boundary_second}Z"
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc
        except gcp_exc.GoogleAPIError as exc:
            if "not enabled" in str(exc).lower() or "api has not been used" in str(exc).lower():
                raise GcpServiceNotEnabled(str(exc)) from exc
            raise

    def prime_shared_log_reads(self, plan: dict[str, dict[str, Any]], spool_dir: Any) -> None:
        """Install a shared-table read plan (see ``shared_log_read_groups``).

        When several serviceName/field views of one shared table run in the same export-backend
        collection, the table is read ONCE into a spool file and each view is filtered from
        that spool in memory instead of re-querying per service.
        """
        from pathlib import Path

        self._shared_read_plan = dict(plan or {})
        self._shared_read_dir = Path(spool_dir) if spool_dir is not None else None
        self._shared_read_spools: dict[tuple[str, str], dict[str, Any]] = {}

    def prime_export_bulk_reads(
        self,
        *,
        plans: list[Any],
        spool_dir: Any,
        spec: Any,
        window_for: Callable[[str], tuple[datetime | None, datetime | None]],
        artifact_parameters: dict[str, dict] | None = None,
        on_spool_start: Callable[[str], None] | None = None,
        on_spool_progress: Callable[[str, int], None] | None = None,
        on_spool_done: Callable[[str, int], None] | None = None,
        on_raw_log: Callable[[str, str], None] | None = None,
    ) -> None:
        """Pre-fill export spools in parallel for enterprise full-window collection."""
        from pathlib import Path

        from collector.engine.gcp_export_bulk import (
            fill_export_spools_parallel,
            iter_entries_for_export_plan,
        )

        self._export_spools = fill_export_spools_parallel(
            plans=plans,
            spool_dir=Path(spool_dir),
            iter_entries=lambda project_id, **kwargs: iter_entries_for_export_plan(
                self, project_id=project_id, **kwargs
            ),
            spec=spec,
            window_for=window_for,
            artifact_parameters=artifact_parameters,
            on_spool_start=on_spool_start,
            on_spool_progress=on_spool_progress,
            on_spool_done=on_spool_done,
            on_raw_log=on_raw_log,
        )

    def _shared_spool_replay(
        self,
        entry_plan: dict[str, Any],
        *,
        project_id: str,
        log_filter: str,
        start: datetime | None,
        end: datetime | None,
        max_records: int,
        spec: Any,
        project_scope: list[str] | None,
        stats: dict[str, Any] | None,
    ) -> Iterator[dict[str, Any]]:
        """Serve one subset view from the group's spool, filling the spool on first use."""
        import gzip
        import json as _json

        from collector.lib.limits import UNLIMITED_RECORDS, records_unlimited

        group = str(entry_plan["group"])
        key = (group, project_id or "-")
        export_spools = getattr(self, "_export_spools", {})
        if group in export_spools:
            from collector.engine.gcp_export_bulk import replay_export_spool

            yield from replay_export_spool(
                export_spools[group],
                log_filter=log_filter,
                max_records=max_records,
                stats=stats,
            )
            return
        spool = self._shared_read_spools.get(key)
        if spool is None:
            self._shared_read_dir.mkdir(parents=True, exist_ok=True)
            path = self._shared_read_dir / f"{group}-{len(self._shared_read_spools)}.jsonl.gz"
            fill_stats: dict[str, Any] = {}
            with gzip.open(path, "wt", encoding="utf-8") as out:
                for entry in self._iter_export_entries(
                    project_id,
                    collector=group,
                    log_filter=str(entry_plan["log_filter"]),
                    start=start,
                    end=end,
                    max_records=UNLIMITED_RECORDS,  # subset caps apply per view, not to the spool
                    spec=spec,
                    artifact_params=None,
                    project_scope=project_scope,
                    stats=fill_stats,
                ):
                    out.write(_json.dumps(entry, default=str) + "\n")
            spool = {"path": path, "stats": fill_stats}
            self._shared_read_spools[key] = spool

        if stats is not None:
            for k, v in spool["stats"].items():
                stats.setdefault(k, v)
        from collector.engine.gcp_log_filter_sql import replay_spool_with_fallback

        yield from replay_spool_with_fallback(
            spool["path"],
            log_filter,
            max_records=max_records,
            unlimited=records_unlimited(max_records),
        )

    def _iter_export_entries(
        self,
        project_id: str,
        *,
        collector: str,
        log_filter: str,
        start: datetime | None,
        end: datetime | None,
        max_records: int,
        spec: Any,
        artifact_params: dict[str, Any] | None,
        project_scope: list[str] | None,
        stats: dict[str, Any] | None,
    ) -> Iterator[dict[str, Any]]:
        from collector.engine.gcp_log_backend import (
            gcs_reads_all_prefixes,
            resolve_gcs_prefix_candidates,
        )
        from collector.engine.gcp_log_export import (
            GcpExportAccessDenied,
            GcpExportError,
            GcpExportNotFound,
            GcpExportRateLimited,
            iter_gcs_log_entries,
        )

        try:
            yield from iter_gcs_log_entries(
                credentials=self._credentials,
                bucket_name=spec.gcs_bucket,
                prefixes=resolve_gcs_prefix_candidates(collector, spec, artifact_params),
                log_filter=log_filter,
                start=start,
                end=end,
                max_records=max_records,
                read_all_prefixes=gcs_reads_all_prefixes(collector),
                project_scope=project_scope,
                stats=stats,
            )
        except GcpExportAccessDenied as exc:
            raise GcpAccessDenied(exc.message) from exc
        except GcpExportRateLimited as exc:
            raise GcpRateLimited(exc.message) from exc
        except GcpExportNotFound as exc:
            raise GcpServiceNotEnabled(exc.message) from exc
        except GcpExportError as exc:
            raise GcpServiceNotEnabled(exc.message) from exc

    def list_log_entries_for_backend(
        self,
        project_id: str,
        *,
        collector: str,
        log_filter: str,
        start: datetime | None,
        end: datetime | None,
        max_records: int,
        gcp_log_backend: dict[str, Any],
        artifact_params: dict[str, Any] | None = None,
        project_scope: list[str] | None = None,
        stats: dict[str, Any] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Read log rows via Logging API or GCS archive."""
        from collector.engine.gcp_log_backend import GcpLogBackendSpec

        spec = GcpLogBackendSpec.from_acquisition_dict(gcp_log_backend)
        if spec.uses_gcs():
            export_spools = getattr(self, "_export_spools", {})
            if collector in export_spools:
                from collector.engine.gcp_export_bulk import replay_export_spool

                yield from replay_export_spool(
                    export_spools[collector],
                    log_filter=log_filter,
                    max_records=max_records,
                    stats=stats,
                )
                return
            shared = getattr(self, "_shared_read_plan", {}).get(collector)
            if shared is not None and getattr(self, "_shared_read_dir", None) is not None:
                yield from self._shared_spool_replay(
                    shared,
                    project_id=project_id,
                    log_filter=log_filter,
                    start=start,
                    end=end,
                    max_records=max_records,
                    spec=spec,
                    project_scope=project_scope,
                    stats=stats,
                )
                return
            yield from self._iter_export_entries(
                project_id,
                collector=collector,
                log_filter=log_filter,
                start=start,
                end=end,
                max_records=max_records,
                spec=spec,
                artifact_params=artifact_params,
                project_scope=project_scope,
                stats=stats,
            )
            return
        yield from self.list_log_entries(
            project_id,
            log_filter=log_filter,
            start=start,
            end=end,
            max_records=max_records,
        )

    def iter_log_entries_all_projects(
        self,
        project_ids: list[str],
        *,
        collector: str,
        log_filter: str,
        start: datetime | None,
        end: datetime | None,
        max_records: int,
        gcp_log_backend: dict[str, Any],
        artifact_params: dict[str, Any] | None = None,
        stats: dict[str, Any] | None = None,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        """Yield ``(owning_project_id, entry)`` across every in-scope project.

        The Logging API is queried once per project. Export backends read each *distinct*
        dataset/bucket exactly once — a fully-qualified dataset or a bucket holds the rows
        for every project, so re-reading it per project would duplicate evidence. Rows are
        scoped to ``project_ids`` in the query/filter and attributed to their owning project
        from ``logName`` (falling back to the project the read ran under).
        """
        from collector.engine.gcp_log_backend import GcpLogBackendSpec

        spec = GcpLogBackendSpec.from_acquisition_dict(gcp_log_backend)
        projects = [p for p in project_ids if p and p.strip()]

        if spec.uses_gcs():
            anchor = projects[0] if projects else self._default_project
            read_groups: list[tuple[str, list[str]]] = [(anchor, projects)]
            for anchor_project, scope in read_groups:
                for entry in self.list_log_entries_for_backend(
                    anchor_project,
                    collector=collector,
                    log_filter=log_filter,
                    start=start,
                    end=end,
                    max_records=max_records,
                    gcp_log_backend=gcp_log_backend,
                    artifact_params=artifact_params,
                    project_scope=scope,
                    stats=stats,
                ):
                    yield _entry_project(entry, anchor_project), entry
            return

        for pid in projects:
            for entry in self.list_log_entries_for_backend(
                pid,
                collector=collector,
                log_filter=log_filter,
                start=start,
                end=end,
                max_records=max_records,
                gcp_log_backend=gcp_log_backend,
                artifact_params=artifact_params,
            ):
                yield pid, entry

    def scc_findings(
        self,
        *,
        organization_id: str,
        max_records: int,
    ) -> Iterator[dict[str, Any]]:
        if not organization_id:
            return
        parent = f"organizations/{organization_id}"
        try:
            count = 0
            for finding in self._scc.list_findings(request={"parent": f"{parent}/sources/-"}):
                f = finding.finding
                if not f:
                    continue
                try:
                    from google.protobuf.json_format import MessageToDict

                    yield MessageToDict(f._pb)  # type: ignore[attr-defined]
                except Exception:
                    yield {
                        "name": f.name,
                        "category": f.category,
                        "severity": _enum_name(f.severity),
                    }
                count += 1
                if count >= max_records:
                    break
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc

    def _iam_client(self) -> Any:
        if self._iam is None:
            from google.cloud import iam_admin_v1

            self._iam = iam_admin_v1.IAMClient(credentials=self._credentials)
        return self._iam

    @staticmethod
    def _iam_etag(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value or "")

    @staticmethod
    def _iam_policy_dict(policy: Any) -> dict[str, Any]:
        bindings: list[dict[str, Any]] = []
        for binding in policy.bindings:
            row: dict[str, Any] = {"role": binding.role, "members": list(binding.members)}
            if binding.condition and binding.condition.expression:
                row["condition"] = GcpClientFactory._proto_to_dict(binding.condition)
            bindings.append(row)
        return {
            "bindings": bindings,
            "etag": GcpClientFactory._iam_etag(policy.etag),
        }

    def iam_policy_snapshot(self, project_id: str) -> dict[str, Any]:
        try:
            policy = self._rm.get_iam_policy(request={"resource": f"projects/{project_id}"})
            out = self._iam_policy_dict(policy)
            out["project_id"] = project_id
            return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc

    def list_service_accounts(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._iam_client()
        out: list[dict[str, Any]] = []
        try:
            for sa in client.list_service_accounts(request={"name": f"projects/{project_id}"}):
                out.append(self._proto_to_dict(sa))
                if len(out) >= max_items:
                    return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return out

    def list_service_account_keys(self, service_account_name: str) -> list[dict[str, Any]]:
        client = self._iam_client()
        try:
            response = client.list_service_account_keys(request={"name": service_account_name})
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        keys: list[dict[str, Any]] = []
        for key in response.keys:
            keys.append(
                {
                    "name": key.name,
                    "keyAlgorithm": key.key_algorithm.name if key.key_algorithm else "",
                    "keyOrigin": key.key_origin.name if key.key_origin else "",
                    "keyType": key.key_type.name if key.key_type else "",
                    "validAfterTime": key.valid_after_time.isoformat()
                    if key.valid_after_time
                    else "",
                    "validBeforeTime": key.valid_before_time.isoformat()
                    if key.valid_before_time
                    else "",
                    "disabled": key.disabled,
                }
            )
        return keys

    def service_account_iam_policy(self, service_account_name: str) -> dict[str, Any]:
        client = self._iam_client()
        try:
            policy = client.get_iam_policy(request={"resource": service_account_name})
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return self._iam_policy_dict(policy)

    def list_project_custom_roles(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        client = self._iam_client()
        out: list[dict[str, Any]] = []
        try:
            for role in client.list_roles(request={"parent": f"projects/{project_id}"}):
                out.append(self._proto_to_dict(role))
                if len(out) >= max_items:
                    return out
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        return out

    # -- Compute Engine (read-only inventory / posture) -----------------------------------

    def _compute_client(self, name: str, factory: Callable[..., Any]) -> Any:
        if name not in self._compute:
            self._compute[name] = factory(credentials=self._credentials)
        return self._compute[name]

    @staticmethod
    def _proto_to_dict(msg: Any) -> dict[str, Any]:
        if msg is None:
            return {}
        if isinstance(msg, dict):
            return msg
        # proto-plus / google.cloud wrappers expose the underlying pb on ``_pb``.
        pb = getattr(msg, "_pb", None)
        try:
            from google.protobuf.json_format import MessageToDict

            target = pb if pb is not None else msg
            return MessageToDict(target, preserving_proto_field_name=True)
        except Exception:
            pass
        to_dict = getattr(msg, "to_dict", None)
        if callable(to_dict):
            try:
                return dict(to_dict())
            except Exception:
                pass
        try:
            return dict(msg)
        except Exception:
            return {"_raw": str(msg)}

    def _raise_compute(self, exc: Exception) -> None:
        if isinstance(exc, gcp_exc.PermissionDenied):
            raise GcpAccessDenied(str(exc)) from exc
        if isinstance(exc, gcp_exc.NotFound):
            raise GcpServiceNotEnabled(str(exc)) from exc
        msg = str(exc).lower()
        if "not enabled" in msg or "api has not been used" in msg or "service disabled" in msg:
            raise GcpServiceNotEnabled(str(exc)) from exc
        raise exc

    def _list_compute(
        self,
        *,
        client_name: str,
        client_factory: Callable[..., Any],
        list_method: str,
        request: Any,
        max_items: int,
    ) -> list[dict[str, Any]]:
        client = self._compute_client(client_name, client_factory)
        out: list[dict[str, Any]] = []
        try:
            for item in getattr(client, list_method)(request=request):
                out.append(self._proto_to_dict(item))
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_aggregated_instances(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._compute_client("instances", compute_v1.InstancesClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListInstancesRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for inst in scoped.instances or []:
                    row = self._proto_to_dict(inst)
                    zone = row.get("zone", "")
                    if zone:
                        row["_ventra_zone"] = zone.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_aggregated_disks(
        self, project_id: str, *, max_items: int = 500
    ) -> list[dict[str, Any]]:
        client = self._compute_client("disks", compute_v1.DisksClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListDisksRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for disk in scoped.disks or []:
                    row = self._proto_to_dict(disk)
                    zone = row.get("zone", "")
                    if zone:
                        row["_ventra_zone"] = zone.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_snapshots(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        client = self._compute_client("snapshots", compute_v1.SnapshotsClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.ListSnapshotsRequest(project=project_id)
            for snap in client.list(request=request):
                out.append(self._proto_to_dict(snap))
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_networks(self, project_id: str, *, max_items: int = 200) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="networks",
            client_factory=compute_v1.NetworksClient,
            list_method="list",
            request=compute_v1.ListNetworksRequest(project=project_id),
            max_items=max_items,
        )

    def compute_subnetworks(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        client = self._compute_client("subnetworks", compute_v1.SubnetworksClient)
        out: list[dict[str, Any]] = []
        try:
            request = compute_v1.AggregatedListSubnetworksRequest(project=project_id)
            for _scope, scoped in client.aggregated_list(request=request):
                for subnet in scoped.subnetworks or []:
                    row = self._proto_to_dict(subnet)
                    region = row.get("region", "")
                    if region:
                        row["_ventra_region"] = region.rsplit("/", 1)[-1]
                    out.append(row)
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_routes(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="routes",
            client_factory=compute_v1.RoutesClient,
            list_method="list",
            request=compute_v1.ListRoutesRequest(project=project_id),
            max_items=max_items,
        )

    def compute_firewalls(self, project_id: str, *, max_items: int = 500) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="firewalls",
            client_factory=compute_v1.FirewallsClient,
            list_method="list",
            request=compute_v1.ListFirewallsRequest(project=project_id),
            max_items=max_items,
        )

    def compute_packet_mirrorings(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        client = self._compute_client("packet_mirrorings", compute_v1.PacketMirroringsClient)
        regions_client = self._compute_client("regions", compute_v1.RegionsClient)
        out: list[dict[str, Any]] = []
        try:
            for region in regions_client.list(
                request=compute_v1.ListRegionsRequest(project=project_id)
            ):
                region_id = str(region.name or "").strip()
                if not region_id:
                    continue
                req = compute_v1.ListPacketMirroringsRequest(
                    project=project_id,
                    region=region_id,
                )
                for item in client.list(request=req):
                    out.append(self._proto_to_dict(item))
                    if len(out) >= max_items:
                        return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def compute_security_policies(
        self, project_id: str, *, max_items: int = 200
    ) -> list[dict[str, Any]]:
        return self._list_compute(
            client_name="security_policies",
            client_factory=compute_v1.SecurityPoliciesClient,
            list_method="list",
            request=compute_v1.ListSecurityPoliciesRequest(project=project_id),
            max_items=max_items,
        )

    def list_gke_clusters(self, project_id: str, *, max_items: int = 200) -> list[dict[str, Any]]:
        from google.cloud import container_v1

        client = self._compute_client("container", container_v1.ClusterManagerClient)
        out: list[dict[str, Any]] = []
        try:
            parent = f"projects/{project_id}/locations/-"
            response = client.list_clusters(request={"parent": parent})
            clusters = list(getattr(response, "clusters", None) or [])
            for cluster in clusters:
                row = self._proto_to_dict(cluster)
                if not row.get("location"):
                    name = str(row.get("name") or "")
                    if name.startswith("projects/"):
                        row["location"] = name.split("/")[3] if len(name.split("/")) > 3 else ""
                out.append(row)
                if len(out) >= max_items:
                    return out
        except Exception as exc:
            self._raise_compute(exc)
        return out

    def list_log_sinks(self, project_id: str, *, max_items: int | None = None) -> list[dict[str, Any]]:
        client = self._logging_client(project_id)
        out: list[dict[str, Any]] = []
        try:
            self._log_throttle.acquire()  # sinks.list also counts against the read quota
            for sink in client.list_sinks():
                out.append(
                    {
                        "name": sink.name,
                        "destination": sink.destination,
                        "filter": sink.filter,
                        "includeChildren": sink.include_children,
                    }
                )
                if max_items is not None and len(out) >= max_items:
                    break
        except gcp_exc.PermissionDenied as exc:
            raise GcpAccessDenied(str(exc)) from exc
        except gcp_exc.NotFound as exc:
            raise GcpServiceNotEnabled(str(exc)) from exc
        return out

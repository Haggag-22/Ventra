"""Orchestrates a GCP collection run end-to-end."""

from __future__ import annotations

import json
import platform
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from collector import __version__
from collector.clouds.gcp.client_factory import GcpClientFactory
from collector.engine.acquisition import artifact_refs_for_collectors
from collector.engine.gcp_collection_summary import (
    STATUS_COLLECTED,
    STATUS_NOT_COLLECTED,
    CollectorOutcome,
    build_collection_summary,
    write_collection_summary,
)
from collector.engine.gcp_log_backend import (
    GCP_LOGGING_COLLECTOR_IDS,
    GcpLogBackendSpec,
    deduplicate_gcp_selection,
    shared_log_read_groups,
)
from collector.engine.gcp_strategy_resolver import (
    STATUS_NOT_COLLECTED as RESOLVE_NOT_COLLECTED,
)
from collector.engine.gcp_strategy_resolver import (
    CollectorResolution,
    resolve_collection_strategy,
)
from collector.engine.registry import GCP_REGISTRY
from collector.engine.run_common import RunReporter, parse_window
from collector.lib.models import (
    ArtifactRef,
    CollectionContext,
    GapReason,
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    TimeWindow,
    utcnow_iso,
)
from collector.lib.packaging.packager import PackageResult

__all__ = ["GcpRunConfig", "run_gcp_collection", "parse_window"]

SCHEMA_VERSION = "1.0.0"


def _source_result_for_dedup(
    name: str, broad: str, outcome: CollectorOutcome, note: str
) -> SourceResult:
    if outcome.status == STATUS_COLLECTED:
        return SourceResult(
            name=name,
            status=SourceStatus.COLLECTED,
            record_count=None,
            notes=note,
        )
    reason = outcome.reason or note
    return SourceResult(
        name=name,
        status=SourceStatus.SKIPPED,
        notes=reason,
        gaps=[(name, GapReason.NOT_PRESENT, reason)],
    )


def _publish_dedup_collector(
    reporter: RunReporter,
    name: str,
    broad: str,
    broad_outcome: CollectorOutcome | None,
    *,
    manifest: Manifest,
    outcomes: dict[str, CollectorOutcome],
) -> CollectorOutcome:
    note = (
        f"Deduplicated: '{name}' is a filter view over '{broad}', which is also "
        "selected — collected once via that stream."
    )
    outcome = _deduplicated_outcome(name, broad, broad_outcome)
    outcomes[name] = outcome
    result = _source_result_for_dedup(name, broad, outcome, note)
    manifest.add_source_result(result)
    matrix = getattr(reporter, "matrix", None)
    row = matrix.rows.get(name) if matrix is not None else None
    if row is None or row.status in ("pending", "running"):
        reporter.start(name)
        reporter.finish(name, result)
    return outcome


@dataclass
class GcpRunConfig:
    case_id: str
    collectors: list[str]
    regions: list[str] | None
    project_id: str | None
    time_window: TimeWindow
    out_dir: Path
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None
    credentials_path: str | None = None
    gcp_service_account_json: str = ""
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict] = field(default_factory=dict)
    gcp_log_backend: dict[str, Any] = field(default_factory=dict)
    preflight_lines: list[str] = field(default_factory=list)
    plan_label: str = ""
    artifact_labels: dict[str, str] = field(default_factory=dict)
    artifact_severities: dict[str, str] = field(default_factory=dict)
    pipeline_steps: list[str] = field(default_factory=list)


def run_gcp_collection(
    cfg: GcpRunConfig, *, factory: GcpClientFactory | None = None
) -> PackageResult:
    started = utcnow_iso()
    if factory is None:
        raw = (cfg.gcp_service_account_json or "").strip()
        if raw:
            info = json.loads(raw)
            cf = GcpClientFactory(
                project_id=cfg.project_id or info.get("project_id") or None,
                service_account_info=info,
            )
        else:
            cf = GcpClientFactory(
                project_id=cfg.project_id,
                credentials_path=cfg.credentials_path,
            )
    else:
        cf = factory
    identity = cf.caller_identity()
    explicit = None
    if cfg.project_id:
        explicit = [p.strip() for p in cfg.project_id.split(",") if p.strip()]
    projects = cf.projects(explicit=explicit)

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(
        identity.project_id or identity.organization_id,
        projects,
        cfg.case_id,
        cfg.collectors,
        plan_label=cfg.plan_label,
        artifact_labels=cfg.artifact_labels,
        artifact_severities=cfg.artifact_severities,
        preflight_lines=cfg.preflight_lines,
        pipeline_steps=cfg.pipeline_steps,
    )

    with (
        tempfile.TemporaryDirectory(prefix="ventra-stage-") as tmp,
        tempfile.TemporaryDirectory(prefix="ventra-spool-") as spool_tmp,
    ):
        staging = Path(tmp)
        (staging / "sources").mkdir(parents=True, exist_ok=True)

        ctx = CollectionContext(
            cloud="gcp",
            account_id=identity.organization_id or identity.project_id,
            regions=cfg.regions or [],
            time_window=cfg.time_window,
            staging=staging,
            case_id=cfg.case_id,
            client_factory=cf,
            logger=reporter,
            max_records_per_source=cfg.max_records_per_source,
            artifact_parameters=cfg.artifact_parameters,
            gcp_log_backend=dict(cfg.gcp_log_backend or {}),
        )
        ctx.project_ids = projects

        manifest = Manifest(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            case_id=cfg.case_id,
            engagement_id=cfg.engagement_id,
            cloud="gcp",
            account_id=identity.organization_id or identity.project_id,
            partition="gcp",
            org_id=identity.organization_id,
            regions=cfg.regions or [],
            operator=Operator(
                principal_arn=f"gcp-sa:{identity.principal}",
                user_id=identity.project_id,
            ),
            started_at=started,
            completed_at="",
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=[],
            account_alias=identity.project_id,
            host_environment="local",
            host_os=platform.platform(),
            host_runtime=f"python {platform.python_version()}",
        )
        manifest.artifacts = cfg.artifact_refs or artifact_refs_for_collectors("gcp", cfg.collectors)

        backend_spec = GcpLogBackendSpec.from_acquisition_dict(cfg.gcp_log_backend or {})
        strategy = _strategy_for_mode(backend_spec.mode)
        target = _strategy_target(backend_spec)

        # Dedup rule: a serviceName/field view selected alongside its broad stream is a
        # filter over data the broad stream already collects — collect the stream once.
        dedup_map = deduplicate_gcp_selection(cfg.collectors)
        run_list = [c for c in cfg.collectors if c not in dedup_map]

        # Phase 1+2: discover what the chosen backend actually holds and validate each
        # selected collector before promising data. NOT_COLLECTED here is skipped with its
        # reason recorded — never silently fallen back from or silently returned empty.
        resolutions, discovery = _preflight_resolution(
            backend_spec, cf, run_list, projects, cfg.time_window, reporter
        )
        skipped_by_resolution = {
            cid: res for cid, res in resolutions.items() if res.status == RESOLVE_NOT_COLLECTED
        }

        active_logging = [
            c
            for c in run_list
            if c in GCP_LOGGING_COLLECTOR_IDS and c not in skipped_by_resolution
        ]
        shared_groups: dict[str, dict[str, Any]] = {}
        spool_plans: list[Any] = []
        defer_export: set[str] = set()
        cap = cfg.max_records_per_source
        full_window = cap is None or cap <= 0
        if backend_spec.mode == "gcs":
            shared_groups = shared_log_read_groups(active_logging)
            if shared_groups:
                cf.prime_shared_log_reads(shared_groups, spool_dir=spool_tmp)

            if full_window and active_logging:
                from collector.engine.gcp_export_bulk import build_export_spool_plans
                from collector.engine.gcp_strategy_resolver import COLLECTOR_MAP

                def _log_filter_for(collector_id: str) -> str:
                    cls = GCP_REGISTRY.get(collector_id)
                    if cls is not None and getattr(cls, "log_filter", ""):
                        return str(cls.log_filter)
                    return str((COLLECTOR_MAP.get(collector_id) or {}).get("log_filter") or "")

                spool_plans = build_export_spool_plans(
                    collectors=active_logging,
                    dedup_map=dedup_map,
                    shared_groups=shared_groups,
                    projects=projects,
                    log_filter_for=_log_filter_for,
                )
                if spool_plans:
                    defer_export = set(active_logging)

        collection_log: list[dict] = []
        outcomes: dict[str, CollectorOutcome] = {}

        def _process_collector(name: str) -> None:
            if reporter.should_cancel():
                reporter.abort_remaining()
                return
            cls = GCP_REGISTRY.get(name)
            if cls is None:
                manifest.add_source_result(
                    SourceResult(
                        name=name,
                        status=SourceStatus.SKIPPED,
                        notes=f"Unknown collector {name!r}.",
                    )
                )
                outcomes[name] = CollectorOutcome(
                    collector=name,
                    status=STATUS_NOT_COLLECTED,
                    strategy_used="none",
                    reason=f"Unknown collector {name!r}.",
                )
                return
            if name in dedup_map:
                broad = dedup_map[name]
                collection_log.append(
                    {"collector": name, "status": "deduplicated", "via": broad}
                )
                if broad in outcomes:
                    _publish_dedup_collector(
                        reporter,
                        name,
                        broad,
                        outcomes[broad],
                        manifest=manifest,
                        outcomes=outcomes,
                    )
                return
            if name in skipped_by_resolution:
                res = skipped_by_resolution[name]
                reason = res.reason or "Not collected for the chosen strategy."
                result = SourceResult(
                    name=name,
                    status=SourceStatus.SKIPPED,
                    gaps=[(name, GapReason.LOGGING_NOT_CONFIGURED, reason)],
                    notes=reason,
                )
                reporter.start(name)
                reporter.finish(name, result)
                manifest.add_source_result(result)
                collection_log.append(
                    {"collector": name, "status": "not_collected", "reason": reason}
                )
                outcomes[name] = CollectorOutcome(
                    collector=name,
                    status=STATUS_NOT_COLLECTED,
                    strategy_used="none",
                    reason=reason,
                    tables=list(res.tables),
                )
                return
            reporter.start(name)
            result = _run_one(cls, ctx, collection_log)
            reporter.finish(name, result)
            manifest.add_source_result(result)
            outcomes[name] = _outcome_from_result(name, result, resolutions.get(name), strategy)

        # Pass 1: inventory / API collectors — do not wait for GCS export spools.
        for name in cfg.collectors:
            if name in defer_export:
                continue
            _process_collector(name)
            if reporter.should_cancel():
                break

        # Pass 2: parallel export pre-read (enterprise fast path) with live progress.
        if spool_plans and not reporter.should_cancel():
            from collector.lib.params import logging_window

            reporter.raw_log(
                "export_bulk",
                f"Parallel GCS export read: {len(spool_plans)} collector group(s), "
                f"workers={min(len(spool_plans), 8)}.",
            )
            cf.prime_export_bulk_reads(
                plans=spool_plans,
                spool_dir=spool_tmp,
                spec=backend_spec,
                window_for=lambda cid: logging_window(ctx, cid),
                artifact_parameters=cfg.artifact_parameters,
                on_spool_start=lambda cid: reporter.raw_log(
                    cid, "spool fill started — reading GCS log export"
                ),
                on_spool_progress=lambda cid, n: reporter.raw_log(
                    cid, f"spool: {n:,} rows buffered from GCS export"
                ),
                on_spool_done=lambda cid, n: reporter.raw_log(
                    cid, f"spool ready — {n:,} rows on disk"
                ),
                on_raw_log=lambda cid, msg: reporter.raw_log(cid, msg),
            )

        # Pass 3: log collectors replay from spools.
        for name in cfg.collectors:
            if name not in defer_export:
                continue
            _process_collector(name)
            if reporter.should_cancel():
                break

        for name, broad in dedup_map.items():
            broad_outcome = outcomes.get(broad)
            if name not in outcomes:
                outcomes[name] = _deduplicated_outcome(name, broad, broad_outcome)
            matrix = getattr(reporter, "matrix", None)
            row = matrix.rows.get(name) if matrix is not None else None
            if row is not None and row.status in ("pending", "running"):
                _publish_dedup_collector(
                    reporter,
                    name,
                    broad,
                    broad_outcome,
                    manifest=manifest,
                    outcomes=outcomes,
                )

        summary = build_collection_summary(
            case_id=cfg.case_id,
            projects=projects,
            time_window=cfg.time_window,
            strategy=strategy,
            target=target,
            outcomes=[outcomes[c] for c in cfg.collectors if c in outcomes],
            discovery=discovery,
        )
        write_collection_summary(staging, summary)

        manifest.completed_at = utcnow_iso()
        manifest.write(staging / "manifest.json")
        (staging / "collection.log").write_text(json.dumps(collection_log, indent=2), encoding="utf-8")

        from ...run_finalize import finalize_and_seal_package

        return finalize_and_seal_package(
            reporter=reporter,
            staging=staging,
            out_dir=cfg.out_dir,
            case_id=cfg.case_id,
            account_id=identity.organization_id or identity.project_id or "",
            key_path=cfg.key_path,
        )


def _strategy_for_mode(mode: str) -> str:
    return "storage" if mode == "gcs" else "log_explorer"


def _strategy_target(spec: GcpLogBackendSpec) -> str:
    return spec.gcs_bucket if spec.uses_gcs() else ""


def _preflight_resolution(
    spec: GcpLogBackendSpec,
    cf: GcpClientFactory,
    run_list: list[str],
    projects: list[str],
    time_window: TimeWindow,
    reporter: RunReporter,
) -> tuple[dict[str, CollectorResolution], dict]:
    """Phases 1–2: resolve how each selected logging collector will actually be read.

    A missing dataset/bucket is an analyst configuration error and aborts the run; any
    other resolution failure is advisory — collection proceeds without pre-flight
    validation rather than blocking evidence capture.
    """
    from collector.engine.gcp_strategy_resolver import BucketNotFoundError

    logging_ids = [c for c in run_list if c in GCP_LOGGING_COLLECTOR_IDS]
    if not logging_ids:
        return {}, {}
    discovery: dict = {}
    try:
        resolutions = resolve_collection_strategy(
            logging_ids,
            _strategy_for_mode(spec.mode),
            _strategy_target(spec),
            projects[0] if projects else "",
            credentials=cf.credentials,
            since=time_window.since,
            until=time_window.until,
            project_scope=projects,
            gcs_sink_prefix=spec.gcs_prefix,
            discovery_out=discovery,
        )
    except BucketNotFoundError:
        raise
    except Exception as exc:  # noqa: BLE001 — validation must never block collection
        reporter.event(
            "strategy_resolver",
            f"Pre-flight resolution failed ({exc}); collecting without validation.",
        )
        return {}, {}
    return {r.collector_id: r for r in resolutions}, discovery


def _outcome_from_result(
    name: str,
    result: SourceResult,
    resolution: CollectorResolution | None,
    strategy: str,
) -> CollectorOutcome:
    collected = result.status in (SourceStatus.COLLECTED, SourceStatus.PARTIAL)
    if name in GCP_LOGGING_COLLECTOR_IDS:
        strategy_used = resolution.strategy_used if resolution else strategy
    else:
        strategy_used = "direct_api"
    reason = None
    if not collected:
        reason = result.gaps[0][2] if result.gaps else (result.notes or "No records collected.")
    return CollectorOutcome(
        collector=name,
        status=STATUS_COLLECTED if collected else STATUS_NOT_COLLECTED,
        strategy_used=strategy_used if collected else "none",
        records=result.record_count,
        reason=reason,
        tables=list(resolution.tables) if resolution else [],
        files=[f.path for f in result.files],
        validation_timed_out=bool(resolution and resolution.validation_timed_out),
    )


def _deduplicated_outcome(
    name: str, broad: str, broad_outcome: CollectorOutcome | None
) -> CollectorOutcome:
    """Summary entry for a subset view collected once via its broad stream."""
    if broad_outcome is None or broad_outcome.status != STATUS_COLLECTED:
        reason = (
            broad_outcome.reason
            if broad_outcome and broad_outcome.reason
            else f"Covered by '{broad}', which returned no rows."
        )
        return CollectorOutcome(
            collector=name,
            status=STATUS_NOT_COLLECTED,
            strategy_used="none",
            reason=reason,
            tables=list(broad_outcome.tables) if broad_outcome else [],
            collected_via=broad,
        )
    return CollectorOutcome(
        collector=name,
        status=STATUS_COLLECTED,
        strategy_used=broad_outcome.strategy_used,
        records=None,  # rows live in the broad stream's file; not re-counted per view
        tables=list(broad_outcome.tables),
        collected_via=broad,
        files=list(broad_outcome.files),
    )


def _run_one(cls: type, ctx: CollectionContext, log: list[dict]) -> SourceResult:
    name = cls.name
    try:
        collector = cls(ctx)
        result = collector.collect()
        log.append({"collector": name, "status": result.status.value, "records": result.record_count})
        return result
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        ctx.error_log(name).write_text(tb, encoding="utf-8")
        log.append({"collector": name, "status": "errored", "error": str(exc)})
        return SourceResult(
            name=name,
            status=SourceStatus.ERRORED,
            gaps=[(name, GapReason.COLLECTOR_ERROR, str(exc))],
            notes=str(exc),
            errors=[tb],
        )

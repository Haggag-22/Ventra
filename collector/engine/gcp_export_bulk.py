"""Parallel pre-read of GCP GCS export backends for enterprise collection runs."""

from __future__ import annotations

import concurrent.futures
import gzip
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from collector.engine.gcp_log_backend import (
    _SHARED_GROUP_FILTERS,
    GCP_SUBSET_OF,
    gcs_reads_all_prefixes,
    resolve_gcs_prefix_candidates,
)
from collector.engine.gcp_log_export import _export_parallel_workers
from collector.lib.limits import UNLIMITED_RECORDS

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExportSpoolPlan:
    collector: str
    log_filter: str
    anchor_project: str
    project_scope: list[str]


def build_export_spool_plans(
    *,
    collectors: list[str],
    dedup_map: dict[str, str],
    shared_groups: dict[str, dict[str, Any]],
    projects: list[str],
    log_filter_for: Callable[[str], str],
) -> list[ExportSpoolPlan]:
    anchor = projects[0] if projects else ""
    scope = list(projects)
    plans: list[ExportSpoolPlan] = []
    seen: set[str] = set()

    for collector in collectors:
        if collector in dedup_map:
            continue
        if collector in shared_groups:
            continue
        if collector in seen:
            continue
        seen.add(collector)
        plans.append(
            ExportSpoolPlan(
                collector=collector,
                log_filter=log_filter_for(collector),
                anchor_project=anchor,
                project_scope=scope,
            )
        )

    grouped: dict[str, list[str]] = {}
    for collector in collectors:
        if collector in dedup_map:
            continue
        entry = shared_groups.get(collector)
        if entry is None:
            continue
        broad = str(entry["group"])
        grouped.setdefault(broad, []).append(collector)

    for broad, members in grouped.items():
        if broad in seen:
            continue
        seen.add(broad)
        plans.append(
            ExportSpoolPlan(
                collector=broad,
                log_filter=str(_SHARED_GROUP_FILTERS.get(broad, log_filter_for(broad))),
                anchor_project=anchor,
                project_scope=scope,
            )
        )

    return plans


def fill_export_spools_parallel(
    *,
    plans: list[ExportSpoolPlan],
    spool_dir: Path,
    iter_entries: Callable[..., Iterator[dict[str, Any]]],
    spec: Any,
    window_for: Callable[[str], tuple[datetime | None, datetime | None]],
    artifact_parameters: dict[str, dict] | None = None,
    on_spool_start: Callable[[str], None] | None = None,
    on_spool_progress: Callable[[str, int], None] | None = None,
    on_spool_done: Callable[[str, int], None] | None = None,
    on_raw_log: Callable[[str, str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    if not plans:
        return {}

    spool_dir.mkdir(parents=True, exist_ok=True)
    workers = min(_export_parallel_workers(), len(plans))
    meta: dict[str, dict[str, Any]] = {}
    progress_every = 50_000

    def _fill(plan: ExportSpoolPlan) -> tuple[str, dict[str, Any]]:
        if on_spool_start is not None:
            on_spool_start(plan.collector)
        start, end = window_for(plan.collector)
        path = spool_dir / f"{plan.collector}.jsonl.gz"
        stats: dict[str, Any] = {}
        count = 0
        progress_cb = (lambda msg: on_raw_log(plan.collector, msg)) if on_raw_log is not None else None
        with gzip.open(path, "wt", encoding="utf-8") as out:
            for entry in iter_entries(
                plan.anchor_project,
                collector=plan.collector,
                log_filter=plan.log_filter,
                start=start,
                end=end,
                max_records=UNLIMITED_RECORDS,
                spec=spec,
                artifact_params=(artifact_parameters or {}).get(plan.collector),
                project_scope=plan.project_scope,
                stats=stats,
                on_progress=progress_cb,
            ):
                out.write(json.dumps(entry, default=str) + chr(10))
                count += 1
                if on_spool_progress is not None and count % progress_every == 0:
                    on_spool_progress(plan.collector, count)
        if on_spool_done is not None:
            on_spool_done(plan.collector, count)
        return plan.collector, {"path": path, "stats": stats, "rows": count}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_fill, plan) for plan in plans]
        for future in concurrent.futures.as_completed(futures):
            collector, spool_meta = future.result()
            meta[collector] = spool_meta

    return meta


def iter_entries_for_export_plan(
    cf: Any,
    *,
    project_id: str,
    collector: str,
    log_filter: str,
    start: datetime | None,
    end: datetime | None,
    max_records: int,
    spec: Any,
    artifact_params: dict[str, Any] | None,
    project_scope: list[str] | None,
    stats: dict[str, Any] | None,
    on_progress: Callable[[str], None] | None = None,
) -> Iterator[dict[str, Any]]:
    from collector.engine.gcp_log_export import iter_gcs_log_entries

    yield from iter_gcs_log_entries(
        credentials=cf.credentials,
        bucket_name=spec.gcs_bucket,
        prefixes=resolve_gcs_prefix_candidates(collector, spec, artifact_params),
        log_filter=log_filter,
        start=start,
        end=end,
        max_records=max_records,
        read_all_prefixes=gcs_reads_all_prefixes(collector),
        project_scope=project_scope,
        stats=stats,
        on_progress=on_progress,
    )


def replay_export_spool(
    spool_meta: dict[str, Any],
    *,
    log_filter: str,
    max_records: int,
    stats: dict[str, Any] | None = None,
) -> Iterator[dict[str, Any]]:
    from collector.engine.gcp_log_filter_sql import replay_spool_with_fallback
    from collector.lib.limits import records_unlimited

    if stats is not None:
        for key, value in spool_meta.get("stats", {}).items():
            if isinstance(value, dict):
                merged = stats.setdefault(key, {})
                if isinstance(merged, dict):
                    merged.update(value)
            elif isinstance(value, list):
                stats.setdefault(key, []).extend(value)
            elif isinstance(value, bool):
                stats[key] = value
            elif isinstance(value, (int, float)):
                # Sum numeric counters (e.g. excluded_unparseable_timestamp) so a window
                # exclusion counted at spool-fill time reaches the collector's read stats.
                stats[key] = (stats.get(key, 0) or 0) + value

    yield from replay_spool_with_fallback(
        spool_meta["path"],
        log_filter,
        max_records=max_records,
        unlimited=records_unlimited(max_records),
    )


def subset_collectors_for_broad(broad: str) -> frozenset[str]:
    return frozenset(k for k, v in GCP_SUBSET_OF.items() if v == broad)

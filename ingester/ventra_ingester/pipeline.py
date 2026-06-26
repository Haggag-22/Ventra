"""Ingest pipeline: verify -> parse -> normalize -> enrich -> load.

One entry point, :func:`ingest_package`, takes a sealed package and a case-store root and
produces a fully-built case directory the console can open. Verification failure on a source
hash blocks that source's load and is recorded in the integrity report; a hard signature/
hash failure marks the case red but still loads what verified so the analyst can triage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .enrichment import Enricher
from .evidence_extract import extract_package
from .loaders.casestore import CaseStore, SummaryAccumulator
from .normalizer.base import NormalizeContext, UnifiedEvent, has_normalizer, normalize_source
from .normalizer.inventory import (
    INVENTORY_SOURCES,
    iam_policy_state_events,
    iam_state_events,
    parse_credential_report,
)
from .package import EvidencePackage
from .verify import verify_package


@dataclass
class IngestResult:
    case_id: str
    case_dir: Path
    event_count: int
    integrity_overall: str
    sources_loaded: list[str] = field(default_factory=list)
    inventory_loaded: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def ingest_package(
    package_path: Path,
    case_store_root: Path,
    *,
    case_id_override: str | None = None,
    enricher: Enricher | None = None,
    reporter: Any = None,
) -> IngestResult:
    with EvidencePackage(package_path) as pkg:
        return _ingest_open_package(
            pkg,
            package_path,
            case_store_root,
            case_id_override=case_id_override,
            enricher=enricher,
            reporter=reporter,
        )


def _ingest_open_package(
    pkg: EvidencePackage,
    package_path: Path,
    case_store_root: Path,
    *,
    case_id_override: str | None = None,
    enricher: Enricher | None = None,
    reporter: Any = None,
) -> IngestResult:
    manifest = dict(pkg.manifest)
    if case_id_override:
        manifest["case_id"] = case_id_override
    case_id = manifest["case_id"]
    account_id = manifest.get("account_id", "")
    ctx = NormalizeContext(case_id=case_id, account_id=account_id)
    enricher = enricher or Enricher()
    _say(reporter, f"Opening package for case {case_id} ({account_id})")

    report = verify_package(pkg)
    _say(reporter, f"Integrity: {report.overall} (signature: {report.signature_method})")
    verified_paths = {c.arcname for c in report.checks if c.matched}

    store = CaseStore(case_store_root, case_id)
    store.reset()
    store.write_json("manifest.json", manifest)
    store.write_json("integrity.json", report.to_dict())
    if pkg.member_bytes("collection.log"):
        (store.case_dir / "collection.log").write_bytes(pkg.member_bytes("collection.log"))

    extract_package(package_path, store.case_dir / "evidence")

    sources_loaded: list[str] = []
    inventory_loaded: list[str] = []
    warnings: list[str] = []
    summary_acc = SummaryAccumulator()
    source_had_events: set[str] = set()

    by_source: dict[str, list] = {}
    for sf in pkg.source_files():
        if sf.kind == "events" and sf.arcname not in verified_paths and report.overall == "red":
            warnings.append(f"Skipped {sf.arcname}: failed integrity check.")
            continue
        by_source.setdefault(sf.name, []).append(sf)

    with store.open_events_writer() as writer:
        for source, files in by_source.items():
            if has_normalizer(source):
                for sf in files:
                    if sf.kind != "events":
                        continue
                    batch: list[dict] = []
                    for rec in pkg.read_records(sf.arcname):
                        batch.append(rec)
                        if len(batch) >= 5000:
                            for ev in normalize_source(source, batch, ctx):
                                ev = enricher.enrich(ev)
                                writer.write(ev)
                                summary_acc.add(ev)
                                source_had_events.add(source)
                            batch.clear()
                    if batch:
                        for ev in normalize_source(source, batch, ctx):
                            ev = enricher.enrich(ev)
                            writer.write(ev)
                            summary_acc.add(ev)
                            source_had_events.add(source)
                if source in source_had_events:
                    sources_loaded.append(source)
                    _say(reporter, f"  {source}: loaded")

            if source == "cloudtrail":
                snapshot = _load_cloudtrail_artifacts(pkg, files)
                if snapshot is not None:
                    store.write_inventory("cloudtrail", snapshot)
                    inventory_loaded.append("cloudtrail")

            if source in ("vpc_flow", "nsg_flow"):
                snapshot = _load_vpc_flow_inventory(pkg, files)
                if snapshot is not None:
                    store.write_inventory(source, snapshot)
                    inventory_loaded.append(source)

            if source in INVENTORY_SOURCES:
                snapshot = _load_inventory(pkg, files)
                if snapshot is not None:
                    store.write_inventory(source, snapshot)
                    inventory_loaded.append(source)
                    if source == "iam" and isinstance(snapshot, dict):
                        for ev in iam_state_events(snapshot, ctx):
                            ev = enricher.enrich(ev)
                            writer.write(ev)
                            summary_acc.add(ev)
                    if source == "iam_policy" and isinstance(snapshot, dict):
                        for ev in iam_policy_state_events(snapshot, ctx):
                            ev = enricher.enrich(ev)
                            writer.write(ev)
                            summary_acc.add(ev)

        count = writer.close()

    summary = summary_acc.finalize(manifest, report.to_dict())
    summary["sources_loaded"] = sorted(set(sources_loaded))
    summary["inventory_loaded"] = sorted(set(inventory_loaded))
    store.write_json("summary.json", summary)

    _say(reporter, f"Loaded {count} events into {store.case_dir}")
    return IngestResult(
        case_id=case_id,
        case_dir=store.case_dir,
        event_count=count,
        integrity_overall=report.overall,
        sources_loaded=sorted(set(sources_loaded)),
        inventory_loaded=sorted(set(inventory_loaded)),
        warnings=warnings,
    )


def _load_cloudtrail_artifacts(pkg: EvidencePackage, files) -> Any:
    """Persist CloudTrail config + collector meta for the console collection summary."""
    out: dict[str, Any] = {}
    for sf in files:
        if sf.kind == "config":
            out["config"] = pkg.read_json(sf.arcname)
        elif sf.kind == "meta":
            out["meta"] = pkg.read_json(sf.arcname)
    return out or None


def _load_vpc_flow_inventory(pkg: EvidencePackage, files) -> Any:
    """Persist VPC / flow-log config for the resource inventory panel (no flow records)."""
    out: dict[str, Any] = {}
    for sf in files:
        if sf.kind == "config":
            out["_config"] = pkg.read_json(sf.arcname)
        elif sf.kind == "meta":
            out["meta"] = pkg.read_json(sf.arcname)
    return out or None


def _load_inventory(pkg: EvidencePackage, files) -> Any:
    """Merge a source's snapshot/config/credential_report files into one inventory object."""
    out: dict[str, Any] = {}
    for sf in files:
        if sf.kind == "snapshot":
            data = pkg.read_json(sf.arcname)
            if isinstance(data, dict):
                out.update(data)
            else:
                out["items"] = data
        elif sf.kind == "config":
            out["_config"] = pkg.read_json(sf.arcname)
        elif sf.kind == "credential_report":
            raw = pkg.member_bytes(sf.arcname)
            if raw:
                out["credential_report"] = parse_credential_report(raw)
    return out or None


def _say(reporter: Any, msg: str) -> None:
    if reporter is not None:
        reporter(msg)

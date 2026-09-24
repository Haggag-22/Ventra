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
from .normalizer.base import NormalizeContext, has_normalizer, normalize_source
from .normalizer.inventory import (
    INVENTORY_SOURCES,
    K8S_INVENTORY_SOURCES,
    iam_policy_state_events,
    iam_state_events,
    k8s_posture_events,
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
    ctx = NormalizeContext(
        case_id=case_id,
        account_id=account_id,
        collected_at=str(manifest.get("completed_at") or manifest.get("started_at") or ""),
    )
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
        event_total = 0
        for source, files in by_source.items():
            if has_normalizer(source):
                _say(reporter, f"Loading {source}…")
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
                                event_total += 1
                            if event_total and event_total % 100_000 == 0:
                                _say(reporter, f"{event_total:,} events normalized…")
                            batch.clear()
                    if batch:
                        for ev in normalize_source(source, batch, ctx):
                            ev = enricher.enrich(ev)
                            writer.write(ev)
                            summary_acc.add(ev)
                            source_had_events.add(source)
                            event_total += 1
                        if event_total and event_total % 100_000 == 0:
                            _say(reporter, f"{event_total:,} events normalized…")
                if source in source_had_events:
                    sources_loaded.append(source)
                    _say(reporter, f"  {source}: loaded")

            if source == "cloudtrail":
                snapshot = _load_cloudtrail_artifacts(pkg, files)
                if snapshot is not None:
                    store.write_inventory("cloudtrail", snapshot)
                    inventory_loaded.append("cloudtrail")

            if source == "cloudwatch":
                snapshot = _load_cloudtrail_artifacts(pkg, files)  # config + meta shape
                if snapshot is not None:
                    store.write_inventory("cloudwatch", snapshot)
                    inventory_loaded.append("cloudwatch")

            if source in ("vpc_flow", "nsg_flow"):
                snapshot = _load_vpc_flow_inventory(pkg, files)
                if snapshot is not None:
                    store.write_inventory(source, snapshot)
                    inventory_loaded.append(source)

            if source in K8S_INVENTORY_SOURCES:
                snapshot = _load_k8s_inventory(pkg, files)
                if snapshot is not None:
                    store.write_inventory(source, snapshot)
                    inventory_loaded.append(source)
                    for ev in k8s_posture_events(source, snapshot, ctx):
                        ev = enricher.enrich(ev)
                        writer.write(ev)
                        summary_acc.add(ev)

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


def _load_k8s_inventory(pkg: EvidencePackage, files) -> Any:
    """Merge a Kubernetes source's JSON sidecars into one inventory object.

    Unlike the cloud snapshot sources, a Kubernetes collector writes several named documents
    (``config.json`` plus derived ones such as ``suspicious_pods.json``, ``pod_security.json``,
    ``images.json``). Each is kept under its own key so the console can render them without
    re-deriving anything; ``config.json`` keeps the ``_config`` name the panels already use.

    The object payloads themselves (``pods.jsonl.gz`` and friends) are normalized into the
    event store, but the Resource Inventory panel needs *rows*, so a compact index of each
    object is built here under ``objects.<kind>`` — identity, age and the risk-relevant
    fields only, never the full spec, which stays in the event store and raw evidence.
    """
    out: dict[str, Any] = {}
    objects: dict[str, list[dict[str, Any]]] = {}
    for sf in files:
        name = sf.arcname.rsplit("/", 1)[-1]
        if name.endswith(".json"):
            stem = name[: -len(".json")]
            data = pkg.read_json(sf.arcname)
            if data is None:
                continue
            if stem == "config":
                out["_config"] = data
            elif stem == "_meta":
                out["_meta"] = data
            else:
                out[stem] = data
        elif name.endswith(".jsonl.gz"):
            kind = name[: -len(".jsonl.gz")]
            rows = [
                _k8s_object_row(rec)
                for rec in pkg.read_records(sf.arcname)
                if isinstance(rec, dict) and rec.get("metadata")
            ]
            if rows:
                objects[kind] = rows
    if objects:
        out["objects"] = objects
    return out or None


def _k8s_object_row(rec: dict[str, Any]) -> dict[str, Any]:
    """One compact inventory row for a Kubernetes object."""
    meta = rec.get("metadata") or {}
    spec = rec.get("spec") or {}
    status = rec.get("status") or {}
    row: dict[str, Any] = {
        "name": str(meta.get("name") or ""),
        "namespace": str(meta.get("namespace") or ""),
        "created": str(meta.get("creation_timestamp") or meta.get("creationTimestamp") or ""),
        "kind": str(rec.get("_ventra_kind") or ""),
    }
    uid = meta.get("uid")
    if uid:
        row["uid"] = str(uid)
    # The verdicts the collector stamped on, so the panel can flag a row without re-deriving.
    if rec.get("_ventra_suspicious"):
        row["flags"] = ", ".join(str(f) for f in rec["_ventra_suspicious"])
    if rec.get("_ventra_grants"):
        row["grants"] = ", ".join(str(g) for g in rec["_ventra_grants"])
    if rec.get("_ventra_anonymous_subjects"):
        row["anonymous"] = ", ".join(str(a) for a in rec["_ventra_anonymous_subjects"])

    containers = [
        c
        for key in ("containers", "init_containers", "initContainers")
        for c in (spec.get(key) or [])
        if isinstance(c, dict)
    ]
    images = [str(c.get("image", "")) for c in containers if c.get("image")]
    if images:
        row["images"] = ", ".join(images)
    container_names = [str(c.get("name", "")) for c in containers if c.get("name")]
    if container_names:
        row["containers"] = ", ".join(container_names)
    for src, dest in (
        ("node_name", "node"),
        ("nodeName", "node"),
        ("service_account_name", "service_account"),
        ("serviceAccountName", "service_account"),
        ("schedule", "schedule"),
        ("replicas", "replicas"),
        ("storage_class_name", "storage_class"),
        ("storageClassName", "storage_class"),
        ("type", "service_type"),
        ("cluster_ip", "cluster_ip"),
        ("clusterIP", "cluster_ip"),
    ):
        if spec.get(src) is not None and dest not in row:
            row[dest] = spec[src]
    if spec.get("host_path") or spec.get("hostPath"):
        hp = spec.get("host_path") or spec.get("hostPath") or {}
        row["host_path"] = str(hp.get("path", ""))
    if rec.get("type"):
        row["type"] = str(rec["type"])
    phase = status.get("phase")
    if phase:
        row["phase"] = str(phase)
    for status_src, dest in (
        ("pod_ip", "pod_ip"),
        ("podIP", "pod_ip"),
        ("host_ip", "host_ip"),
        ("hostIP", "host_ip"),
    ):
        if status.get(status_src) and dest not in row:
            row[dest] = str(status[status_src])
    node_info = status.get("node_info") or status.get("nodeInfo") or {}
    if node_info:
        row["kubelet"] = str(node_info.get("kubelet_version") or node_info.get("kubeletVersion") or "")
        row["os"] = str(node_info.get("os_image") or node_info.get("osImage") or "")
    ref = rec.get("role_ref") or rec.get("roleRef") or {}
    if ref:
        row["role"] = f"{ref.get('kind', '')}/{ref.get('name', '')}".strip("/")
    subjects = [
        str(sub.get("name", ""))
        for sub in (rec.get("subjects") or [])
        if isinstance(sub, dict) and sub.get("name")
    ]
    if subjects:
        row["subjects"] = ", ".join(subjects)
    owners = [
        f"{o.get('kind', '')}/{o.get('name', '')}".strip("/")
        for o in (meta.get("owner_references") or meta.get("ownerReferences") or [])
        if isinstance(o, dict) and o.get("name")
    ]
    if owners:
        row["owners"] = ", ".join(owners)
    labels = meta.get("labels") or {}
    if isinstance(labels, dict) and labels:
        # Keep a short label map for the detail drawer; PSA still gets its own column.
        row["labels"] = {str(k): str(v) for k, v in list(labels.items())[:40]}
    psa = {k: v for k, v in labels.items() if str(k).startswith("pod-security.kubernetes.io/")}
    if psa:
        row["pod_security"] = ", ".join(f"{k.split('/')[-1]}={v}" for k, v in sorted(psa.items()))
    return row


def _say(reporter: Any, msg: str) -> None:
    if reporter is not None:
        reporter(msg)

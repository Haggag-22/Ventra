"""Orchestrates an on-prem Kubernetes collection run end-to-end.

Mirrors the cloud runners: builds the shared context (an API-plane client + a node-plane
accessor), runs every collector in volatility order, isolates failures so one error never
aborts the run, and assembles + signs the manifest before sealing the package.

A run can be API-plane-only (operator workstation with a kubeconfig, node paths absent → node
collectors degrade to gaps) or in-cluster (privileged DaemonSet/Job with the host filesystem
mounted at ``node_root``).
"""

from __future__ import annotations

import json
import os
import platform
import tempfile
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from collector import __version__
from collector.clouds.kubernetes.client_factory import KubernetesClientFactory
from collector.clouds.kubernetes.node import NodeAccess
from collector.engine.acquisition import artifact_refs_for_collectors
from collector.engine.api.kubernetes.common.preflight import probe_permissions
from collector.engine.registry import KUBERNETES_REGISTRY
from collector.engine.run_common import RunReporter, parse_window
from collector.lib.base import Collector
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

__all__ = ["KubernetesRunConfig", "run_kubernetes_collection", "parse_window"]

SCHEMA_VERSION = "1.0.0"


@dataclass
class KubernetesRunConfig:
    case_id: str
    collectors: list[str]
    time_window: TimeWindow
    out_dir: Path
    kubeconfig_content: str = ""
    kubeconfig_path: str = ""
    k8s_context: str = ""
    node_root: str = ""
    node_name: str = ""
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None
    artifact_refs: list[ArtifactRef] = field(default_factory=list)
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict] = field(default_factory=dict)
    plan_label: str = ""
    artifact_labels: dict[str, str] = field(default_factory=dict)
    artifact_severities: dict[str, str] = field(default_factory=dict)
    pipeline_steps: list[str] = field(default_factory=list)


def _detect_environment() -> str:
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "ec2"  # in-cluster pod; closest allowed manifest enum value
    return "local"


def run_kubernetes_collection(
    cfg: KubernetesRunConfig, *, factory: KubernetesClientFactory | None = None
) -> PackageResult:
    started = utcnow_iso()
    if factory is None:
        node_root = cfg.node_root or os.environ.get("VENTRA_NODE_ROOT", "/")
        factory = KubernetesClientFactory(
            kubeconfig_content=cfg.kubeconfig_content,
            kubeconfig_path=cfg.kubeconfig_path,
            context=cfg.k8s_context,
            node=NodeAccess(root=Path(node_root), node_name=cfg.node_name),
        )
    cf = factory

    identity = _identity(cf)
    cluster_id = identity.get("cluster_id", "on-prem-cluster")

    reporter = cfg.reporter or RunReporter()
    reporter.begin_run(
        cluster_id,
        [],
        cfg.case_id,
        cfg.collectors,
        plan_label=cfg.plan_label,
        artifact_labels=cfg.artifact_labels,
        artifact_severities=cfg.artifact_severities,
        pipeline_steps=cfg.pipeline_steps,
    )

    with tempfile.TemporaryDirectory(prefix="ventra-stage-") as tmp:
        staging = Path(tmp)
        (staging / "sources").mkdir(parents=True, exist_ok=True)

        ctx = CollectionContext(
            cloud="kubernetes",
            account_id=cluster_id,
            regions=[],
            time_window=cfg.time_window,
            staging=staging,
            case_id=cfg.case_id,
            client_factory=cf,
            logger=reporter,
            max_records_per_source=cfg.max_records_per_source,
            artifact_parameters=cfg.artifact_parameters,
        )

        # Verify our own RBAC before collecting; writes preflight.json, never blocks.
        _run_preflight(cf, cfg.collectors, staging, reporter)

        runtime = _runtime_summary(cf)
        manifest = Manifest(
            schema_version=SCHEMA_VERSION,
            tool_version=__version__,
            case_id=cfg.case_id,
            engagement_id=cfg.engagement_id,
            cloud="kubernetes",
            account_id=cluster_id,
            partition="kubernetes",
            regions=[],
            operator=Operator(
                principal_arn=identity.get("principal", "kubernetes:collector"),
                user_id=identity.get("username", ""),
            ),
            started_at=started,
            completed_at="",
            time_window=cfg.time_window,
            profile_name="all",
            profile_overrides=[],
            account_alias=identity.get("server_version", ""),
            host_environment=_detect_environment(),
            host_os=platform.platform(),
            host_runtime=f"python {platform.python_version()}; runtime={runtime}",
        )
        manifest.artifacts = cfg.artifact_refs or artifact_refs_for_collectors(
            "kubernetes", cfg.collectors
        )

        collection_log: list[dict] = []
        for name in cfg.collectors:
            if reporter.should_cancel():
                reporter.abort_remaining()
                break
            cls = KUBERNETES_REGISTRY.get(name)
            if cls is None:
                manifest.add_source_result(
                    SourceResult(
                        name=name,
                        status=SourceStatus.SKIPPED,
                        gaps=[(name, GapReason.OUT_OF_SCOPE, "Unknown collector for kubernetes.")],
                        notes="Unknown collector name.",
                    )
                )
                continue
            reporter.start(name)
            result = _run_one(cls, ctx)
            reporter.finish(name, result)
            manifest.add_source_result(result)
            collection_log.append(
                {
                    "ts": utcnow_iso(),
                    "collector": name,
                    "status": result.status.value,
                    "records": result.record_count,
                    "gaps": [g[0] for g in result.gaps],
                    "errors": result.errors,
                }
            )
            if result.errors:
                ctx.error_log(name).write_text("\n".join(result.errors), encoding="utf-8")

        manifest.completed_at = utcnow_iso()
        _write_collection_log(staging, collection_log)
        manifest.write(staging / "manifest.json")

        from ...run_finalize import finalize_and_seal_package

        return finalize_and_seal_package(
            reporter=reporter,
            staging=staging,
            out_dir=cfg.out_dir,
            case_id=cfg.case_id,
            account_id=cluster_id,
            key_path=cfg.key_path,
        )


def _run_preflight(
    cf: KubernetesClientFactory, collectors: list[str], staging: Path, reporter: RunReporter
) -> dict:
    """Probe our own RBAC before collecting and record the result as evidence.

    Required by the build spec: the operator should learn what this kubeconfig cannot reach
    up front. It never blocks — a denied verb still gets attempted and recorded as a gap by
    the collector that needs it.
    """
    declared: dict[str, tuple[str, ...]] = {}
    for name in collectors:
        cls = KUBERNETES_REGISTRY.get(name)
        if cls is None or getattr(cls, "plane", "") != "api":
            continue
        actions = tuple(getattr(cls, "required_actions", ()) or ())
        if actions:
            declared[name] = actions
    if not declared:
        return {"available": False, "note": "no API-plane collectors selected."}

    report = probe_permissions(cf, declared)
    (staging / "preflight.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    if report.get("denied"):
        reporter.event(
            "preflight",
            f"RBAC pre-flight: {len(report['denied'])} permission(s) denied — "
            f"{', '.join(report['denied'][:6])}. Those sources will report gaps.",
        )
    elif report.get("available"):
        reporter.event("preflight", f"RBAC pre-flight: all {report['checked']} permission(s) allowed.")
    return report


def _identity(cf: KubernetesClientFactory) -> dict:
    try:
        ident = cf.cluster_identity()
        return {
            "cluster_id": ident.cluster_id,
            "server_version": ident.server_version,
            "username": ident.username,
            "principal": f"kubernetes:{ident.username or ident.cluster_id}",
        }
    except Exception:  # noqa: BLE001 - API plane may be unavailable on a node-only run
        node = getattr(cf, "node", None)
        cid = node.hostname() if node is not None else ""
        return {"cluster_id": cid or "on-prem-cluster", "principal": "kubernetes:node-collector"}


def _runtime_summary(cf: KubernetesClientFactory) -> str:
    node = getattr(cf, "node", None)
    if node is None:
        return "unknown"
    try:
        info = node.runtime_info()
        return f"{info.runtime} {info.version}".strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _run_one(cls: type[Collector], ctx: CollectionContext) -> SourceResult:
    try:
        return cls(ctx).collect()
    except Exception as exc:  # noqa: BLE001 - isolation is intentional
        return SourceResult(
            name=cls.name,
            status=SourceStatus.ERRORED,
            gaps=[(cls.name, GapReason.COLLECTOR_ERROR, str(exc))],
            errors=[traceback.format_exc()],
            notes=f"Collector raised: {exc}",
        )


def _write_collection_log(staging: Path, entries: list[dict]) -> None:
    path = staging / "collection.log"
    with path.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, default=str) + "\n")

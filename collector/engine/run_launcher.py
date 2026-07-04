"""Programmatic collection launch without full CLI argument parsing."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..lib.models import AzureAuthOptions, TimeWindow
from .acquisition import (
    AcquisitionError,
    artifact_refs_for_collectors,
    augment_collectors,
    load_pack,
)
from .acquire_platform import collector_cloud_for_platform
from .gcp_log_backend import validate_gcp_log_backend_dict
from .gcp_log_export import check_bigquery_log_dataset
from .matrix_state import ARTIFACT_SEVERITY, DEFAULT_SEVERITY
from .run_common import RunReporter, parse_window


@dataclass
class RunLaunchRequest:
    cloud: str
    case_id: str
    artifacts: list[str] = field(default_factory=list)
    pack: str | None = None
    regions: list[str] | None = None
    since: str = ""
    until: str = ""
    project: str = ""
    subscription: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    aws_profile: str = ""
    max_records_per_source: int | None = None
    artifact_parameters: dict[str, dict[str, Any]] = field(default_factory=dict)
    gcp_log_backend: dict[str, Any] | None = None
    credentials_path: str | None = None
    out_dir: Path | None = None
    engagement_id: str = ""
    key_path: Path | None = None
    reporter: RunReporter | None = None
    artifacts_root: Path | None = None


def _artifact_index(cloud: str, artifacts_root: Path) -> dict[str, dict[str, Any]]:
    from .acquisition import _artifact_index as idx

    return idx(cloud, artifacts_root)


def _resolve_collectors(req: RunLaunchRequest) -> tuple[list[str], list[Any], str]:
    platform = req.cloud.strip().lower()
    collector_cloud = collector_cloud_for_platform(platform)
    artifacts_root = req.artifacts_root or Path("artifacts")

    names = list(req.artifacts or [])
    if req.pack:
        names = load_pack(req.pack, artifacts_root)
    if not names:
        raise ValueError("Select at least one artifact.")
    names = augment_collectors(collector_cloud, names)
    refs = artifact_refs_for_collectors(collector_cloud, names, artifacts_root)
    return names, refs, collector_cloud


def _matrix_meta(
    cloud: str, artifact_refs: list, artifacts_root: Path
) -> tuple[str, dict[str, str], dict[str, str]]:
    index = _artifact_index(cloud, artifacts_root)
    labels: dict[str, str] = {}
    sevs: dict[str, str] = {}
    for ref in artifact_refs:
        key = ref.collector
        art = index.get(key) or {}
        labels[key] = ref.name or art.get("name") or key
        raw = str(art.get("severity") or "").lower()
        sevs[key] = ARTIFACT_SEVERITY.get(raw) or DEFAULT_SEVERITY.get(key, "Medium")
    plan = f"{len(artifact_refs)} artifacts"
    return plan, labels, sevs


def _gcp_preflight(req: RunLaunchRequest, project: str | None) -> tuple[list[str], Any | None]:
    if not req.gcp_log_backend:
        return [], None
    from ..clouds.gcp.client_factory import GcpClientFactory
    from .gcp_log_backend import GcpLogBackendSpec

    backend = GcpLogBackendSpec.from_acquisition_dict(dict(req.gcp_log_backend))
    if not backend.uses_bigquery() or not backend.bigquery_dataset.strip():
        return [], None
    factory = GcpClientFactory(project_id=project, credentials_path=req.credentials_path)
    check = check_bigquery_log_dataset(
        credentials=factory._credentials,
        dataset=backend.bigquery_dataset,
        default_project=project or factory._default_project or "",
    )
    if check.found:
        suffix = f" ({check.table_count} tables)" if check.table_count else " (empty)"
        line = f"BigQuery dataset: found — {check.ref}{suffix}"
    else:
        line = f"BigQuery dataset: not found — {check.ref}"
        if check.message:
            line += f" — {check.message}"
    return [line], check


def launch_collection(req: RunLaunchRequest):
    """Run a cloud collection and return the sealed package result."""
    platform = req.cloud.strip().lower()
    collectors, artifact_refs, collector_cloud = _resolve_collectors(req)
    window: TimeWindow = parse_window(req.since or None, req.until or None)
    artifacts_root = req.artifacts_root or Path("artifacts")
    plan_label, artifact_labels, artifact_severities = _matrix_meta(
        collector_cloud, artifact_refs, artifacts_root
    )
    out_dir = req.out_dir or Path(tempfile.mkdtemp(prefix="ventra-run-"))

    if platform == "aws":
        from .api.aws.runner import AwsRunConfig, run_aws_collection

        cfg = AwsRunConfig(
            case_id=req.case_id,
            collectors=collectors,
            regions=req.regions,
            time_window=window,
            out_dir=out_dir,
            engagement_id=req.engagement_id,
            key_path=req.key_path,
            reporter=req.reporter,
            aws_profile=req.aws_profile,
            artifact_refs=artifact_refs,
            max_records_per_source=req.max_records_per_source,
            artifact_parameters=req.artifact_parameters,
            plan_label=plan_label,
            artifact_labels=artifact_labels,
            artifact_severities=artifact_severities,
        )
        return run_aws_collection(cfg)

    if platform in {"azure", "m365"}:
        from .api.azure.runner import AzureRunConfig, run_azure_collection

        cfg = AzureRunConfig(
            case_id=req.case_id,
            collectors=collectors,
            regions=req.regions,
            subscription_id=req.subscription or None,
            time_window=window,
            out_dir=out_dir,
            engagement_id=req.engagement_id,
            key_path=req.key_path,
            reporter=req.reporter,
            auth=AzureAuthOptions(
                tenant_id=req.azure_tenant_id,
                client_id=req.azure_client_id,
            ),
            artifact_refs=artifact_refs,
            max_records_per_source=req.max_records_per_source,
            artifact_parameters=req.artifact_parameters,
            plan_label=plan_label,
            artifact_labels=artifact_labels,
            artifact_severities=artifact_severities,
        )
        return run_azure_collection(cfg)

    if platform == "gcp":
        from .api.gcp.runner import GcpRunConfig, run_gcp_collection

        project = req.project or None
        preflight_lines, _ = _gcp_preflight(req, project)
        gcp_backend = (
            dict(validate_gcp_log_backend_dict(req.gcp_log_backend))
            if req.gcp_log_backend
            else {}
        )
        cfg = GcpRunConfig(
            case_id=req.case_id,
            collectors=collectors,
            regions=req.regions,
            project_id=project,
            time_window=window,
            out_dir=out_dir,
            engagement_id=req.engagement_id,
            key_path=req.key_path,
            reporter=req.reporter,
            credentials_path=req.credentials_path,
            artifact_refs=artifact_refs,
            max_records_per_source=req.max_records_per_source,
            artifact_parameters=req.artifact_parameters,
            gcp_log_backend=gcp_backend,
            preflight_lines=preflight_lines,
            plan_label=plan_label,
            artifact_labels=artifact_labels,
            artifact_severities=artifact_severities,
        )
        return run_gcp_collection(cfg)

    raise ValueError(f"Unsupported cloud: {req.cloud!r}")


def resolve_launch_from_pack(
    req: RunLaunchRequest,
) -> RunLaunchRequest:
    """Validate pack/artifact selection; raise AcquisitionError on bad input."""
    try:
        _resolve_collectors(req)
    except AcquisitionError as exc:
        raise ValueError(str(exc)) from exc
    return req

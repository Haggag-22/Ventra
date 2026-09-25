"""Run a downloaded Collection Kit offline via ``ventra run``."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from collector import __version__

from .format import (
    KitError,
    KitExpiredError,
    OpenKit,
    assert_kit_usable,
    format_iso,
    open_kit,
    utcnow,
)


@dataclass
class KitRunResult:
    case_id: str
    kit_id: str
    cloud: str
    out_dir: Path
    package_path: Path | None
    started_at: str
    completed_at: str
    local_user: str
    collectors: list[str] = field(default_factory=list)
    per_collector: list[dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error: str = ""


def _local_user() -> str:
    """The human operator — the sudo caller when the run was elevated, not ``root``."""
    from collector.lib.elevate import invoking_user

    return invoking_user()


def _elevated() -> bool:
    from collector.lib.elevate import is_elevated_run

    return is_elevated_run()


def _apply_aws_credentials(kit: OpenKit) -> dict[str, str]:
    rel = str(kit.manifest.raw.get("credential", {}).get("path") or "credentials/aws.json")
    # Prefer acquisition.yaml pointer when present.
    try:
        import yaml

        acq = yaml.safe_load(kit.acquisition_path.read_text(encoding="utf-8")) or {}
        rel = str(acq.get("aws_credentials") or rel)
    except Exception:
        pass
    path = kit.root / rel
    if not path.is_file():
        raise KitError(f"AWS credentials missing in kit: {rel}")
    data = json.loads(path.read_text(encoding="utf-8"))
    access = str(data.get("aws_access_key_id") or "").strip()
    secret = str(data.get("aws_secret_access_key") or "").strip()
    token = str(data.get("aws_session_token") or "").strip()
    if not access or not secret:
        raise KitError("AWS credentials in kit are incomplete.")
    os.environ["AWS_ACCESS_KEY_ID"] = access
    os.environ["AWS_SECRET_ACCESS_KEY"] = secret
    if token:
        os.environ["AWS_SESSION_TOKEN"] = token
    else:
        os.environ.pop("AWS_SESSION_TOKEN", None)
    # Prefer embedded keys over any ambient profile.
    os.environ.pop("AWS_PROFILE", None)
    return {
        "aws_access_key_id": access,
        "aws_secret_access_key": secret,
        "aws_session_token": token,
    }


def _apply_gcp_credentials(kit: OpenKit) -> dict[str, str]:
    import yaml

    acq = yaml.safe_load(kit.acquisition_path.read_text(encoding="utf-8")) or {}
    token_rel = str(acq.get("gcp_access_token") or "").strip()
    sa_rel = str(acq.get("gcp_credentials") or "credentials/gcp-sa.json").strip()
    out: dict[str, str] = {}
    if token_rel and (kit.root / token_rel).is_file():
        out["gcp_access_token_path"] = str(kit.root / token_rel)
    if (kit.root / sa_rel).is_file():
        sa_path = str(kit.root / sa_rel)
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = sa_path
        out["credentials_path"] = sa_path
    project = str(acq.get("project") or "").strip()
    if project:
        os.environ["GOOGLE_CLOUD_PROJECT"] = project.split(",")[0].strip()
        out["project"] = project
    return out


def _apply_azure_credentials(kit: OpenKit) -> dict[str, str]:
    import yaml

    acq = yaml.safe_load(kit.acquisition_path.read_text(encoding="utf-8")) or {}
    rel = str(acq.get("azure_credentials") or "credentials/azure.json").strip()
    path = kit.root / rel
    if not path.is_file():
        raise KitError(f"Azure credentials missing in kit: {rel}")
    data = json.loads(path.read_text(encoding="utf-8"))
    tenant = str(data.get("azure_tenant_id") or acq.get("azure_tenant_id") or "").strip()
    client = str(data.get("azure_client_id") or acq.get("azure_client_id") or "").strip()
    secret = str(data.get("azure_client_secret") or "").strip()
    cert_rel = str(
        data.get("azure_client_certificate_path") or acq.get("azure_client_certificate") or ""
    ).strip()
    if tenant:
        os.environ["AZURE_TENANT_ID"] = tenant
    if client:
        os.environ["AZURE_CLIENT_ID"] = client
    if secret:
        os.environ["AZURE_CLIENT_SECRET"] = secret
    cert_path = ""
    if cert_rel:
        cert_path = str(kit.root / cert_rel)
        os.environ["AZURE_CLIENT_CERTIFICATE_PATH"] = cert_path
    sub = str(acq.get("subscription") or "").strip()
    if sub:
        os.environ["AZURE_SUBSCRIPTION_ID"] = sub.split(",")[0].strip()
    return {
        "tenant_id": tenant,
        "client_id": client,
        "client_secret": secret,
        "client_certificate_path": cert_path,
        "subscription": sub,
    }


def _apply_kubernetes_credentials(kit: OpenKit) -> dict[str, str]:
    import yaml

    acq = yaml.safe_load(kit.acquisition_path.read_text(encoding="utf-8")) or {}
    rel = str(acq.get("kubeconfig") or "credentials/kubeconfig.yaml").strip()
    path = kit.root / rel
    if not path.is_file():
        raise KitError(f"Kubernetes kubeconfig missing in kit: {rel}")
    os.environ["KUBECONFIG"] = str(path)
    return {
        "kubeconfig": str(path),
        "context": str(acq.get("k8s_context") or "").strip(),
        "node_root": str(acq.get("node_root") or "/").strip() or "/",
    }


def _write_custody(staging_or_out: Path, payload: dict[str, Any]) -> Path:
    path = staging_or_out / "cli_run.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _print_summary(result: KitRunResult) -> None:
    print()
    print("─" * 60)
    print("Ventra kit run complete" if result.success else "Ventra kit run failed")
    print("─" * 60)
    print(f"  kit_id:     {result.kit_id}")
    print(f"  case_id:    {result.case_id}")
    print(f"  cloud:      {result.cloud}")
    print(f"  operator:   {result.local_user} @ {result.completed_at}")
    print(f"  started:    {result.started_at}")
    print(f"  completed:  {result.completed_at}")
    if result.per_collector:
        print("  collectors:")
        for row in result.per_collector:
            status = row.get("status", "?")
            name = row.get("collector", "?")
            records = row.get("records")
            extra = f"  records={records}" if records is not None else ""
            print(f"    [{status:<9}] {name}{extra}")
    elif result.collectors:
        print(f"  collectors: {', '.join(result.collectors)}")
    if result.package_path:
        print(f"  package:    {result.package_path}")
    print(f"  out:        {result.out_dir}")
    if result.error:
        print(f"  error:      {result.error}")
    print("─" * 60)


def run_kit_file(kit_path: Path, *, out_dir: Path | None = None) -> KitRunResult:
    """Load ``.kit``, refuse if expired, collect offline, write local package + custody."""
    started = utcnow()
    local_user = _local_user()
    out = (out_dir or Path("evidence")).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    try:
        kit = open_kit(kit_path)
    except KitError as exc:
        result = KitRunResult(
            case_id="",
            kit_id="",
            cloud="",
            out_dir=out,
            package_path=None,
            started_at=format_iso(started),
            completed_at=format_iso(utcnow()),
            local_user=local_user,
            success=False,
            error=str(exc),
        )
        _print_summary(result)
        return result

    with kit:
        try:
            assert_kit_usable(kit.manifest)
        except KitExpiredError as exc:
            result = KitRunResult(
                case_id=kit.manifest.case_id,
                kit_id=kit.manifest.kit_id,
                cloud=kit.manifest.cloud,
                out_dir=out,
                package_path=None,
                started_at=format_iso(started),
                completed_at=format_iso(utcnow()),
                local_user=local_user,
                collectors=list(kit.manifest.collectors),
                success=False,
                error=str(exc),
            )
            _print_summary(result)
            return result

        # Point artifact catalog at the kit copy when present.
        art_dir = kit.root / "artifacts"
        if art_dir.is_dir():
            os.environ["VENTRA_ARTIFACTS_ROOT"] = str(art_dir)

        cloud = kit.manifest.cloud
        aws_creds: dict[str, str] | None = None
        gcp_creds: dict[str, str] | None = None
        azure_creds: dict[str, str] | None = None
        k8s_creds: dict[str, str] | None = None
        try:
            if cloud == "aws":
                aws_creds = _apply_aws_credentials(kit)
            elif cloud == "gcp":
                gcp_creds = _apply_gcp_credentials(kit)
            elif cloud in ("azure", "m365"):
                azure_creds = _apply_azure_credentials(kit)
                cloud = "azure"
            elif cloud == "kubernetes":
                k8s_creds = _apply_kubernetes_credentials(kit)
            else:
                raise KitError(f"unsupported cloud in kit: {cloud!r}")
        except KitError as exc:
            result = KitRunResult(
                case_id=kit.manifest.case_id,
                kit_id=kit.manifest.kit_id,
                cloud=kit.manifest.cloud,
                out_dir=out,
                package_path=None,
                started_at=format_iso(started),
                completed_at=format_iso(utcnow()),
                local_user=local_user,
                collectors=list(kit.manifest.collectors),
                success=False,
                error=str(exc),
            )
            _print_summary(result)
            return result

        # Re-check expiry immediately before collection (no partial runs).
        try:
            assert_kit_usable(kit.manifest)
        except KitExpiredError as exc:
            result = KitRunResult(
                case_id=kit.manifest.case_id,
                kit_id=kit.manifest.kit_id,
                cloud=kit.manifest.cloud,
                out_dir=out,
                package_path=None,
                started_at=format_iso(started),
                completed_at=format_iso(utcnow()),
                local_user=local_user,
                collectors=list(kit.manifest.collectors),
                success=False,
                error=str(exc),
            )
            _print_summary(result)
            return result

        print(f"Running kit {kit.manifest.kit_name or kit.manifest.kit_id}")
        print(f"  case:    {kit.manifest.case_id}")
        print(f"  cloud:   {cloud}")
        print(f"  version: kit={kit.manifest.ventra_version}  cli={__version__}")
        print(f"  expires: {kit.manifest.expires_at}")
        print(f"  out:     {out}")
        print()

        custody = {
            "kit_id": kit.manifest.kit_id,
            "kit_name": kit.manifest.kit_name,
            "case_id": kit.manifest.case_id,
            "cloud": cloud,
            "collectors": list(kit.manifest.collectors),
            "started_at": format_iso(started),
            "local_user": local_user,
            "elevated_via_sudo": _elevated(),
            "host": os.uname().nodename if hasattr(os, "uname") else "",
            "ventra_cli_version": __version__,
            "kit_ventra_version": kit.manifest.ventra_version,
        }
        _write_custody(out, {**custody, "status": "running"})

        try:
            package, per_collector = _execute_collection(
                cloud=cloud,
                acquisition_path=kit.acquisition_path,
                out_dir=out,
                aws_creds=aws_creds if cloud == "aws" else None,
                gcp_creds=gcp_creds if cloud == "gcp" else None,
                azure_creds=azure_creds if cloud == "azure" else None,
                k8s_creds=k8s_creds if cloud == "kubernetes" else None,
            )
        except Exception as exc:  # noqa: BLE001
            completed = format_iso(utcnow())
            _write_custody(
                out,
                {**custody, "completed_at": completed, "status": "failed", "error": str(exc)},
            )
            result = KitRunResult(
                case_id=kit.manifest.case_id,
                kit_id=kit.manifest.kit_id,
                cloud=cloud,
                out_dir=out,
                package_path=None,
                started_at=format_iso(started),
                completed_at=completed,
                local_user=local_user,
                collectors=list(kit.manifest.collectors),
                success=False,
                error=str(exc),
            )
            _print_summary(result)
            return result

        completed = format_iso(utcnow())
        _write_custody(
            out,
            {
                **custody,
                "completed_at": completed,
                "status": "completed",
                "package": str(package.path) if package else "",
                "collectors_detail": per_collector,
            },
        )
        # Also drop custody next to the sealed package for import.
        if package and package.path:
            _write_custody(
                package.path.parent,
                {
                    **custody,
                    "completed_at": completed,
                    "status": "completed",
                    "package": str(package.path),
                    "collectors_detail": per_collector,
                },
            )

        result = KitRunResult(
            case_id=kit.manifest.case_id,
            kit_id=kit.manifest.kit_id,
            cloud=cloud,
            out_dir=out,
            package_path=Path(package.path) if package else None,
            started_at=format_iso(started),
            completed_at=completed,
            local_user=local_user,
            collectors=list(kit.manifest.collectors),
            per_collector=per_collector,
            success=True,
        )
        _print_summary(result)
        return result


def _execute_collection(
    *,
    cloud: str,
    acquisition_path: Path,
    out_dir: Path,
    aws_creds: dict[str, str] | None,
    gcp_creds: dict[str, str] | None,
    azure_creds: dict[str, str] | None,
    k8s_creds: dict[str, str] | None,
) -> tuple[Any, list[dict[str, Any]]]:
    """Run collectors using the same engine path as ``ventra collect --acquisition``."""
    from collector.cli import (
        _artifact_matrix_meta,
        _artifacts_root_from_args,
        _cli_reporter,
        _plan_collection,
        _regions_from_args,
        _window_from_args,
    )
    from collector.engine.acquisition import load_acquisition

    class _Args:
        acquisition = str(acquisition_path)
        collectors = ""
        pack = ""
        case = ""
        engagement = ""
        since = None
        until = None
        regions = ""
        out = str(out_dir)
        quiet = False
        json_output = False
        key = ""
        profile = ""
        project = ""
        credentials = ""
        subscription = ""
        tenant_id = ""
        client_id = ""
        client_secret = ""
        client_certificate = ""
        kubeconfig = ""
        context = ""
        node_root = ""
        transport = "local"
        no_ingest = True
        ingest = False

    args = _Args()
    spec = load_acquisition(acquisition_path)
    # Ensure case_id from kit acquisition is used.
    if not args.case and spec.case_id:
        args.case = spec.case_id

    if cloud == "aws":
        from collector.engine.api.aws.runner import AwsRunConfig, run_aws_collection
        from collector.engine.registry import AWS_COLLECTOR_ORDER, AWS_REGISTRY

        collectors, artifact_refs, case_override, eng_override, spec = _plan_collection(
            args, "aws", list(AWS_COLLECTOR_ORDER), AWS_REGISTRY
        )
        case_id = args.case or case_override
        reporter, _console = _cli_reporter(quiet=False, json_mode=False, cloud="aws")
        labels, sevs = _artifact_matrix_meta("aws", artifact_refs, _artifacts_root_from_args(args))
        cfg = AwsRunConfig(
            case_id=case_id,
            collectors=collectors,
            regions=_regions_from_args(args, spec),
            time_window=_window_from_args(args, spec),
            out_dir=out_dir,
            engagement_id=eng_override or "",
            reporter=reporter,
            aws_access_key_id=(aws_creds or {}).get("aws_access_key_id", ""),
            aws_secret_access_key=(aws_creds or {}).get("aws_secret_access_key", ""),
            aws_session_token=(aws_creds or {}).get("aws_session_token", ""),
            artifact_refs=artifact_refs,
            max_records_per_source=spec.max_records_per_source if spec else None,
            artifact_parameters=spec.artifact_parameters() if spec else {},
            plan_label=f"{len(collectors)} artifacts from kit",
            artifact_labels=labels,
            artifact_severities=sevs,
        )
        package = run_aws_collection(cfg)
        reporter.finalize()
        return package, _collector_rows_from_reporter(reporter, collectors)

    if cloud == "gcp":
        from collector.engine.api.gcp.runner import GcpRunConfig, run_gcp_collection
        from collector.engine.registry import GCP_COLLECTOR_ORDER, GCP_REGISTRY

        collectors, artifact_refs, case_override, eng_override, spec = _plan_collection(
            args, "gcp", list(GCP_COLLECTOR_ORDER), GCP_REGISTRY
        )
        case_id = args.case or case_override
        reporter, _console = _cli_reporter(quiet=False, json_mode=False, cloud="gcp")
        labels, sevs = _artifact_matrix_meta("gcp", artifact_refs, _artifacts_root_from_args(args))
        project = (gcp_creds or {}).get("project") or (spec.project if spec else "") or ""
        cred_path = (gcp_creds or {}).get("credentials_path") or ""
        cfg = GcpRunConfig(
            case_id=case_id,
            collectors=collectors,
            regions=_regions_from_args(args, spec),
            project_id=project or None,
            time_window=_window_from_args(args, spec),
            out_dir=out_dir,
            engagement_id=eng_override or "",
            reporter=reporter,
            credentials_path=cred_path or None,
            artifact_refs=artifact_refs,
            max_records_per_source=spec.max_records_per_source if spec else None,
            artifact_parameters=spec.artifact_parameters() if spec else {},
            plan_label=f"{len(collectors)} artifacts from kit",
            artifact_labels=labels,
            artifact_severities=sevs,
        )
        package = run_gcp_collection(cfg)
        reporter.finalize()
        return package, _collector_rows_from_reporter(reporter, collectors)

    if cloud == "azure":
        from collector.engine.api.azure.runner import AzureRunConfig, run_azure_collection
        from collector.engine.registry import AZURE_COLLECTOR_ORDER, AZURE_REGISTRY
        from collector.lib.models import AzureAuthOptions

        collectors, artifact_refs, case_override, eng_override, spec = _plan_collection(
            args, "azure", list(AZURE_COLLECTOR_ORDER), AZURE_REGISTRY
        )
        case_id = args.case or case_override
        reporter, _console = _cli_reporter(quiet=False, json_mode=False, cloud="azure")
        labels, sevs = _artifact_matrix_meta("azure", artifact_refs, _artifacts_root_from_args(args))
        ac = azure_creds or {}
        auth = AzureAuthOptions(
            tenant_id=ac.get("tenant_id", ""),
            client_id=ac.get("client_id", ""),
            client_secret=ac.get("client_secret", ""),
            client_certificate_path=ac.get("client_certificate_path", ""),
        )
        sub = ac.get("subscription") or (spec.subscription if spec else "") or None
        cfg = AzureRunConfig(
            case_id=case_id,
            collectors=collectors,
            regions=_regions_from_args(args, spec),
            subscription_id=sub,
            time_window=_window_from_args(args, spec),
            out_dir=out_dir,
            engagement_id=eng_override or "",
            reporter=reporter,
            auth=auth,
            artifact_refs=artifact_refs,
            max_records_per_source=spec.max_records_per_source if spec else None,
            artifact_parameters=spec.artifact_parameters() if spec else {},
            plan_label=f"{len(collectors)} artifacts from kit",
            artifact_labels=labels,
            artifact_severities=sevs,
        )
        package = run_azure_collection(cfg)
        reporter.finalize()
        return package, _collector_rows_from_reporter(reporter, collectors)

    if cloud == "kubernetes":
        from collector.engine.api.kubernetes.runner import (
            KubernetesRunConfig,
            run_kubernetes_collection,
        )
        from collector.engine.registry import KUBERNETES_COLLECTOR_ORDER, KUBERNETES_REGISTRY

        collectors, artifact_refs, case_override, eng_override, spec = _plan_collection(
            args, "kubernetes", list(KUBERNETES_COLLECTOR_ORDER), KUBERNETES_REGISTRY
        )
        case_id = args.case or case_override
        reporter, _console = _cli_reporter(quiet=False, json_mode=False, cloud="kubernetes")
        labels, sevs = _artifact_matrix_meta("kubernetes", artifact_refs, _artifacts_root_from_args(args))
        kc = k8s_creds or {}
        cfg = KubernetesRunConfig(
            case_id=case_id,
            collectors=collectors,
            time_window=_window_from_args(args, spec),
            out_dir=out_dir,
            engagement_id=eng_override or "",
            reporter=reporter,
            kubeconfig_path=kc.get("kubeconfig", ""),
            k8s_context=kc.get("context", ""),
            node_root=kc.get("node_root", "/"),
            artifact_refs=artifact_refs,
            max_records_per_source=spec.max_records_per_source if spec else None,
            artifact_parameters=spec.artifact_parameters() if spec else {},
            plan_label=f"{len(collectors)} artifacts from kit",
            artifact_labels=labels,
            artifact_severities=sevs,
        )
        package = run_kubernetes_collection(cfg)
        reporter.finalize()
        return package, _collector_rows_from_reporter(reporter, collectors)

    raise KitError(f"unsupported cloud: {cloud}")


def _collector_rows_from_reporter(reporter: Any, collectors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    matrix = getattr(reporter, "_matrix", None)
    matrix_rows = getattr(matrix, "rows", None) if matrix is not None else None
    if isinstance(matrix_rows, dict) and matrix_rows:
        for name in collectors:
            row = matrix_rows.get(name)
            if row is None:
                rows.append({"collector": name, "status": "unknown"})
                continue
            status = getattr(row, "status", None) or "unknown"
            records = getattr(row, "records", None)
            rows.append({"collector": name, "status": str(status), "records": records})
        return rows
    finished = getattr(matrix, "finished_csv_rows", None) if matrix is not None else None
    if isinstance(finished, list) and finished:
        by_check = {str(r.get("check") or "").lower(): r for r in finished if isinstance(r, dict)}
        for name in collectors:
            r = by_check.get(name.lower()) or by_check.get(name.upper())
            if not r:
                rows.append({"collector": name, "status": "unknown"})
                continue
            label = str(r.get("label") or "unknown").lower()
            status = "pass" if label == "pass" else ("fail" if label == "fail" else label)
            tag = r.get("tag")
            records = None
            if isinstance(tag, str) and tag not in {"-", ""}:
                try:
                    records = int(tag.replace(",", ""))
                except ValueError:
                    records = None
            rows.append({"collector": name, "status": status, "records": records})
        return rows
    for name in collectors:
        rows.append({"collector": name, "status": "ran"})
    return rows

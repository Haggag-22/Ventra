#!/usr/bin/env python3
"""Ventra acquisition kit — operator entrypoint.

Bootstraps a local venv, installs the bundled ventra wheel (with dependencies), and runs
``ventra collect`` against ``acquisition.yaml`` in this directory.

Usage (credentials are embedded from the Authentication connection chosen at download):
    python3 ventra.py
    python3 ventra.py --out ./evidence

Evidence is written next to this script by default (kit folder / evidence).
Pass ``--out NAME`` for a different folder beside ventra.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_OUT_NAME = "evidence"
_UV_INSTALL_URL = "https://astral.sh/uv/install.sh"


def _resolve_out_dir(raw: str) -> Path:
    """Put relative --out paths next to ventra.py (not whatever cwd the shell is in)."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _find_uv() -> str | None:
    found = shutil.which("uv")
    if found:
        return found
    for candidate in (
        Path.home() / ".local" / "bin" / "uv",
        Path.home() / ".cargo" / "bin" / "uv",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def _ensure_uv() -> str:
    existing = _find_uv()
    if existing:
        return existing
    if os.name == "nt":
        raise SystemExit(
            "error: uv is required. Install from https://docs.astral.sh/uv/getting-started/installation/"
        )
    print("Installing uv…", file=sys.stderr)
    subprocess.run(["sh", "-c", f"curl -LsSf {_UV_INSTALL_URL} | sh"], check=True)
    uv = _find_uv()
    if not uv:
        raise SystemExit("error: uv install finished but uv was not found. Add ~/.local/bin to PATH.")
    return uv


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _uv_pip_install(
    uv: str,
    python: Path,
    *specs: str,
    reinstall: bool = False,
    no_deps: bool = False,
) -> None:
    cmd = [uv, "pip", "install", "--python", str(python), "-q"]
    if reinstall:
        cmd.append("--reinstall")
    if no_deps:
        cmd.append("--no-deps")
    cmd.extend(specs)
    subprocess.check_call(cmd)


def _read_acquisition_field(name: str) -> str:
    acq = ROOT / "acquisition.yaml"
    if not acq.is_file():
        return ""
    pattern = re.compile(rf"^{re.escape(name)}:\s*(.+)$")
    for line in acq.read_text(encoding="utf-8").splitlines():
        m = pattern.match(line.strip())
        if m:
            return m.group(1).strip().strip("'\"")
    return ""


def _case_id_from_kit() -> str:
    case_id = _read_acquisition_field("case_id").strip()
    if case_id:
        return case_id
    raise SystemExit(
        "error: acquisition.yaml has no case_id — rebuild the kit from Acquire or set case_id in the yaml."
    )


def _cloud() -> str:
    return (os.environ.get("VENTRA_CLOUD") or _read_acquisition_field("cloud") or "aws").lower()


def _venv_dir() -> Path:
    return ROOT / ".venv"


def _acquisition_window_args() -> list[str]:
    extra: list[str] = []
    since = _read_acquisition_field("since").strip()
    until = _read_acquisition_field("until").strip()
    if since:
        extra.extend(["--since", since])
    if until:
        extra.extend(["--until", until])
    return extra


_GCP_EXPORT_REQUIREMENTS = (
    "google-cloud-bigquery>=3.20",
    "google-cloud-storage>=2.16",
    # DuckDB powers the fast SQL log-filter path; the collector falls back to pure Python if it
    # is missing, so this is a performance dependency rather than a hard requirement.
    "duckdb>=0.10",
)


def _install_gcp_export_requirements(uv: str, py: Path, cloud: str) -> None:
    """Kits built before export deps were pinned may omit these from requirements.txt."""
    if cloud != "gcp":
        return
    _uv_pip_install(uv, py, *_GCP_EXPORT_REQUIREMENTS)


def _ensure_ventra(cloud: str) -> Path:
    """Create venv with uv, install requirements + bundled wheel, return ventra executable."""
    uv = _ensure_uv()
    venv = _venv_dir()
    if not venv.exists():
        subprocess.check_call([uv, "venv", str(venv), "--python", sys.executable])

    py = _venv_python(venv)

    reqs = ROOT / "requirements.txt"
    if reqs.is_file():
        _uv_pip_install(uv, py, "-r", str(reqs))
        _install_gcp_export_requirements(uv, py, cloud)
    else:
        fallback = [
            "rich>=13.7",
            "zstandard>=0.22",
            "PyYAML>=6.0",
        ]
        if cloud == "aws":
            fallback[:0] = ["boto3>=1.34", "botocore>=1.34"]
        elif cloud == "azure":
            fallback[:0] = [
                "requests>=2.31",
                "azure-identity>=1.16",
                "azure-mgmt-resource>=23.0",
                "azure-mgmt-resource-subscriptions>=1.0.0b2",
                "azure-mgmt-monitor>=6.0",
                "azure-mgmt-network>=25.0",
                "azure-mgmt-security>=7.0",
                "azure-mgmt-authorization>=4.0",
                "azure-storage-blob>=12.19",
            ]
        elif cloud == "gcp":
            fallback[:0] = [
                "google-api-core>=2.19",
                "google-auth>=2.29",
                "google-cloud-logging>=3.10",
                "google-cloud-resource-manager>=1.12",
                "google-cloud-iam>=2.15",
                "google-cloud-securitycenter>=1.28",
                "google-cloud-compute>=1.19",
                "google-cloud-container>=2.45",
                "google-cloud-bigquery>=3.20",
                "google-cloud-storage>=2.16",
                "protobuf>=4.25",
                "duckdb>=0.10",
            ]
        elif cloud == "kubernetes":
            fallback[:0] = [
                "kubernetes>=29.0",
                "PyYAML>=6.0",
            ]
        _uv_pip_install(uv, py, *fallback)

    wheels = sorted((ROOT / "dist").glob("ventra-*.whl"))
    if wheels:
        _uv_pip_install(uv, py, str(wheels[-1]), reinstall=True, no_deps=True)
    else:
        _uv_pip_install(uv, py, "ventra")

    ventra_bin = venv / "Scripts" / "ventra.exe" if os.name == "nt" else venv / "bin" / "ventra"
    if not ventra_bin.is_file():
        raise SystemExit("ventra install failed — ventra executable not found in .venv")
    return ventra_bin




def _kit_relative_path(raw: str) -> Path | None:
    value = (raw or "").strip()
    if not value:
        return None
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        return None
    return path


def _load_json_credentials(field: str) -> dict[str, str]:
    rel = _read_acquisition_field(field).strip()
    if not rel:
        return {}
    path = _kit_relative_path(rel)
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if v is not None and str(v).strip()}


def _apply_aws_env_from_kit() -> None:
    creds = _load_json_credentials("aws_credentials")
    if not creds:
        return
    for key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"):
        value = creds.get(key, "").strip()
        if value:
            os.environ[key.upper()] = value


def _azure_auth_extra_args() -> list[str]:
    """Pass SP tenant/client from acquisition.yaml or embedded credentials; secret stays in env only."""
    creds = _load_json_credentials("azure_credentials")
    extra: list[str] = []
    tenant = (
        creds.get("azure_tenant_id", "").strip()
        or _read_acquisition_field("azure_tenant_id").strip()
        or os.environ.get("AZURE_TENANT_ID", "").strip()
    )
    client = (
        creds.get("azure_client_id", "").strip()
        or _read_acquisition_field("azure_client_id").strip()
        or os.environ.get("AZURE_CLIENT_ID", "").strip()
    )
    if tenant:
        extra.extend(["--tenant-id", tenant])
    if client:
        extra.extend(["--client-id", client])
    secret = creds.get("azure_client_secret", "").strip() or os.environ.get("AZURE_CLIENT_SECRET", "").strip()
    if secret:
        extra.extend(["--client-secret", secret])
    cert_rel = (
        creds.get("azure_client_certificate_path", "").strip()
        or _read_acquisition_field("azure_client_certificate").strip()
        or os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH", "").strip()
    )
    if cert_rel:
        cert_path = _kit_relative_path(cert_rel) if not Path(cert_rel).is_absolute() else Path(cert_rel)
        if cert_path and cert_path.is_file():
            extra.extend(["--client-certificate", str(cert_path)])
        elif Path(cert_rel).expanduser().is_file():
            extra.extend(["--client-certificate", str(Path(cert_rel).expanduser())])
    return extra


def _embedded_gcp_credentials() -> str:
    rel = _read_acquisition_field("gcp_credentials").strip()
    if not rel:
        return ""
    path = _kit_relative_path(rel)
    if path is None or not path.is_file():
        return ""
    return str(path)


def _embedded_kubeconfig() -> str:
    rel = _read_acquisition_field("kubeconfig").strip()
    if not rel:
        return ""
    path = _kit_relative_path(rel)
    if path is None or not path.is_file():
        return ""
    return str(path)


def _apply_kubernetes_env_from_kit() -> None:
    """Point KUBECONFIG at the embedded file so the collector needs no flags."""
    kubeconfig = _embedded_kubeconfig()
    if kubeconfig:
        os.environ["KUBECONFIG"] = kubeconfig
    context = _read_acquisition_field("k8s_context").strip()
    if context and not os.environ.get("VENTRA_K8S_CONTEXT", "").strip():
        os.environ["VENTRA_K8S_CONTEXT"] = context
    node_root = (
        os.environ.get("VENTRA_NODE_ROOT", "").strip()
        or _read_acquisition_field("node_root").strip()
        or "/"
    )
    os.environ["VENTRA_NODE_ROOT"] = node_root
    if not os.environ.get("VENTRA_NODE_NAME", "").strip():
        # Best-effort; collectors also accept empty and record "unknown".
        try:
            import socket

            os.environ["VENTRA_NODE_NAME"] = socket.gethostname()
        except Exception:
            pass


def _cloud_extra_args(cloud: str, args: argparse.Namespace) -> list[str]:
    extra: list[str] = []
    if cloud == "aws":
        _apply_aws_env_from_kit()
        profile = (
            (args.profile or "").strip()
            or _read_acquisition_field("aws_profile").strip()
            or os.environ.get("AWS_PROFILE", "").strip()
        )
        if profile:
            extra.extend(["--profile", profile])
    elif cloud == "azure":
        sub = (
            (args.subscription or "").strip()
            or _read_acquisition_field("subscription").strip()
            or os.environ.get("AZURE_SUBSCRIPTION_ID", "").strip()
        )
        if sub:
            extra.extend(["--subscription", sub])
        extra.extend(_azure_auth_extra_args())
    elif cloud == "gcp":
        proj = (
            (args.project or "").strip()
            or _read_acquisition_field("project").strip()
            or os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
        )
        if proj:
            extra.extend(["--project", proj])
        creds = (
            (getattr(args, "credentials", "") or "").strip()
            or _embedded_gcp_credentials()
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        )
        if creds:
            extra.extend(["--credentials", creds])
    elif cloud == "kubernetes":
        _apply_kubernetes_env_from_kit()
        kubeconfig = _embedded_kubeconfig() or os.environ.get("KUBECONFIG", "").strip()
        if kubeconfig:
            extra.extend(["--kubeconfig", kubeconfig])
        context = (
            _read_acquisition_field("k8s_context").strip()
            or os.environ.get("VENTRA_K8S_CONTEXT", "").strip()
        )
        if context:
            extra.extend(["--context", context])
        node_root = os.environ.get("VENTRA_NODE_ROOT", "").strip() or "/"
        extra.extend(["--node-root", node_root])
        node_name = os.environ.get("VENTRA_NODE_NAME", "").strip()
        if node_name:
            extra.extend(["--node-name", node_name])
    return extra


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ventra.py",
        description="Run Ventra read-only collection from this acquisition kit.",
    )
    parser.add_argument(
        "--profile",
        metavar="NAME",
        help="AWS: named profile from ~/.aws/credentials (same as AWS_PROFILE)",
    )
    parser.add_argument(
        "--subscription",
        metavar="ID",
        help="Azure: subscription id(s), comma-separated (same as AZURE_SUBSCRIPTION_ID)",
    )
    parser.add_argument(
        "--project",
        metavar="ID",
        help="GCP: project id(s), comma-separated (acquisition.yaml, GOOGLE_CLOUD_PROJECT)",
    )
    parser.add_argument(
        "--credentials",
        metavar="PATH",
        help="GCP: path to service account JSON key (GOOGLE_APPLICATION_CREDENTIALS)",
    )
    parser.add_argument(
        "--run-id",
        metavar="ID",
        help="Console run id for live matrix relay (Cloud Shell mode)",
    )
    parser.add_argument(
        "--relay-url",
        metavar="URL",
        help="POST matrix events to this console URL (e.g. http://host:8000/api/runs/{id}/events)",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_OUT_NAME,
        metavar="DIR",
        help=(
            "Folder for the sealed evidence package, next to ventra.py "
            f"(default: {DEFAULT_OUT_NAME})"
        ),
    )
    args = parser.parse_args(argv)

    out_dir = _resolve_out_dir(args.out)

    cloud = _cloud()
    case_id = _case_id_from_kit()
    if cloud == "gcp":
        auth_method = _read_acquisition_field("auth_method").strip().lower()
        creds = (
            (args.credentials or "").strip()
            or _embedded_gcp_credentials()
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        )
        if auth_method != "adc" and not creds:
            raise SystemExit(
                "error: GCP collection requires a service account key in this kit.\n"
                "  Re-download the kit from Collection Kits with a GCP connection selected,\n"
                "  or: python3 ventra.py --credentials /path/to/key.json --out ./gcp-evidence"
            )
        if creds and not Path(creds).expanduser().is_file():
            raise SystemExit(f"error: credentials file not found: {creds}")
    elif cloud == "kubernetes":
        kubeconfig = _embedded_kubeconfig() or os.environ.get("KUBECONFIG", "").strip()
        if not kubeconfig or not Path(kubeconfig).expanduser().is_file():
            raise SystemExit(
                "error: Kubernetes kit is missing an embedded kubeconfig.\n"
                "  Re-download from Collection Kits with a Kubernetes Authentication connection selected."
            )

    run_id = (getattr(args, "run_id", "") or os.environ.get("VENTRA_RUN_ID", "")).strip()
    relay_url = (getattr(args, "relay_url", "") or os.environ.get("VENTRA_RELAY_URL", "")).strip()
    if run_id and relay_url:
        os.environ["VENTRA_RUN_ID"] = run_id
        os.environ["VENTRA_RELAY_URL"] = relay_url
        if "{run_id}" in relay_url or "{id}" in relay_url:
            relay_url = relay_url.format(run_id=run_id, id=run_id)
        os.environ["VENTRA_RELAY_URL"] = relay_url

    ventra_bin = _ensure_ventra(cloud)

    kit_artifacts = ROOT / "artifacts"
    if kit_artifacts.is_dir():
        os.environ["VENTRA_ARTIFACTS_ROOT"] = str(kit_artifacts)

    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(ventra_bin),
        "collect",
        cloud,
        "--acquisition",
        str(ROOT / "acquisition.yaml"),
        "--case",
        case_id,
        "--out",
        str(out_dir),
        *_acquisition_window_args(),
        *_cloud_extra_args(cloud, args),
    ]
    transport = _read_acquisition_field("transport").strip()
    if transport:
        cmd.extend(["--transport", transport])

    if os.name == "nt":
        return subprocess.call(cmd)
    os.execv(str(ventra_bin), cmd)
    return 0  # unreachable


if __name__ == "__main__":
    raise SystemExit(main())

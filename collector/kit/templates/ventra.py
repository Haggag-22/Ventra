#!/usr/bin/env python3
"""Ventra acquisition kit — operator entrypoint.

Bootstraps a local venv, installs the bundled ventra wheel (with dependencies), and runs
``ventra collect`` against ``acquisition.yaml`` in this directory.

Usage:
    python3 ventra.py --out ./ventra-evidence
    python3 ventra.py --profile my-aws-profile --out ./ventra-evidence
    python3 ventra.py --subscription <azure-sub-id> --out ./evidence
    python3 ventra.py --project my-gcp-project --credentials /path/to/sa-key.json --out ./evidence
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = "./ventra-evidence"


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


def _venv_paths() -> tuple[Path, Path, Path]:
    venv = ROOT / ".venv"
    if os.name == "nt":
        return venv, venv / "Scripts" / "python.exe", venv / "Scripts" / "pip.exe"
    return venv, venv / "bin" / "python", venv / "bin" / "pip"


def _ensure_ventra(cloud: str) -> Path:
    """Create venv, install requirements + bundled wheel, return path to ventra executable."""
    venv, _py, pip = _venv_paths()
    if not venv.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(venv)])

    subprocess.check_call([str(pip), "install", "-q", "--upgrade", "pip"])

    reqs = ROOT / "requirements.txt"
    if reqs.is_file():
        subprocess.check_call([str(pip), "install", "-q", "-r", str(reqs)])
    else:
        # Fallback when requirements.txt is missing — install only what this cloud needs.
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
                "google-cloud-securitycenter>=1.28",
                "protobuf>=4.25",
            ]
        subprocess.check_call([str(pip), "install", "-q", *fallback])

    wheels = sorted((ROOT / "dist").glob("ventra-*.whl"))
    if wheels:
        subprocess.check_call([str(pip), "install", "-q", str(wheels[-1])])
    else:
        extra = f"[{cloud}]" if cloud in ("azure", "gcp") else ""
        subprocess.check_call([str(pip), "install", "-q", f"ventra{extra}"])

    ventra_bin = venv / "Scripts" / "ventra.exe" if os.name == "nt" else venv / "bin" / "ventra"
    if not ventra_bin.is_file():
        raise SystemExit("ventra install failed — ventra executable not found in .venv")
    return ventra_bin




def _azure_auth_extra_args() -> list[str]:
    """Pass SP tenant/client from acquisition.yaml; secret stays in env only."""
    extra: list[str] = []
    tenant = _read_acquisition_field("azure_tenant_id").strip() or os.environ.get("AZURE_TENANT_ID", "").strip()
    client = _read_acquisition_field("azure_client_id").strip() or os.environ.get("AZURE_CLIENT_ID", "").strip()
    if tenant:
        extra.extend(["--tenant-id", tenant])
    if client:
        extra.extend(["--client-id", client])
    secret = os.environ.get("AZURE_CLIENT_SECRET", "").strip()
    if secret:
        extra.extend(["--client-secret", secret])
    cert = os.environ.get("AZURE_CLIENT_CERTIFICATE_PATH", "").strip()
    if cert:
        extra.extend(["--client-certificate", cert])
    return extra


def _cloud_extra_args(cloud: str, args: argparse.Namespace) -> list[str]:
    extra: list[str] = []
    if cloud == "aws":
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
            or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        )
        if creds:
            extra.extend(["--credentials", creds])
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
        "--out",
        default=DEFAULT_OUT,
        metavar="DIR",
        help=f"Output directory for the sealed evidence package (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    cloud = _cloud()
    case_id = _case_id_from_kit()
    ventra_bin = _ensure_ventra(cloud)

    kit_artifacts = ROOT / "artifacts"
    if kit_artifacts.is_dir():
        os.environ["VENTRA_ARTIFACTS_ROOT"] = str(kit_artifacts)

    cmd = [
        str(ventra_bin),
        "collect",
        cloud,
        "--acquisition",
        str(ROOT / "acquisition.yaml"),
        "--case",
        case_id,
        "--out",
        args.out,
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

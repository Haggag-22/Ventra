"""Build a Ventra Collection Kit (``.kit``) or legacy operator zip.

A ``.kit`` is a zip archive containing ``kit.json``, ``acquisition.yaml``, short-lived
credentials, selected artifacts, and IAM references. It is run with ``ventra run file.kit``
on any machine with Ventra installed — no re-authentication until the embedded credential
expires.

Legacy ``.zip`` kits also include a named entry script + optional wheel for hosts without
the Ventra CLI installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any

import yaml

from collector import __version__
from collector.engine.acquire_platform import collector_cloud_for_platform
from collector.engine.loader import load_artifacts_dir
from collector.kit.auth_embed import embed_connection_auth
from collector.kit.format import KIT_FORMAT, KIT_FORMAT_VERSION, format_iso, utcnow
from collector.kit.mint import kit_ttl_seconds

_KIT_ROOT = Path(__file__).resolve().parent
_TEMPLATES = _KIT_ROOT / "templates"
_REPO_ROOT = _KIT_ROOT.parents[1]

_KIT_BASE_REQUIREMENTS = [
    "rich>=13.7",
    "zstandard>=0.22",
    "PyYAML>=6.0",
]
_KIT_CLOUD_REQUIREMENTS: dict[str, list[str]] = {
    "aws": [
        "boto3>=1.34",
        "botocore>=1.34",
    ],
    "azure": [
        "requests>=2.31",
        "azure-identity>=1.16",
        "azure-mgmt-resource>=23.0",
        "azure-mgmt-resource-subscriptions>=1.0.0b2",
        "azure-mgmt-monitor>=6.0",
        "azure-mgmt-network>=25.0",
        "azure-mgmt-security>=7.0",
        "azure-mgmt-authorization>=4.0",
        "azure-storage-blob>=12.19",
    ],
    "gcp": [
        "google-cloud-logging>=3.10",
        "google-cloud-resource-manager>=1.12",
        "google-cloud-iam>=2.15",
        "google-cloud-securitycenter>=1.28",
        "google-cloud-compute>=1.19",
        "google-cloud-container>=2.45",
        "google-cloud-storage>=2.16",
        "google-auth>=2.29",
        "google-api-core>=2.19",
        "protobuf>=4.25",
    ],
    "kubernetes": [
        "kubernetes>=29.0",
        "PyYAML>=6.0",
    ],
}


_DEPLOYMENT_PROFILES = ("cloudshell", "workstation", "enterprise")

_PROFILE_TRADEOFFS: dict[str, str] = {
    "cloudshell": """profile: cloudshell

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: quick proof-of-access; client runs in {{CLOUD}} Cloud Shell with no local install.
- Collects all records in the configured since/until window unless max_records_per_source is set in acquisition.yaml.
- ~1 GB home disk and ~20 min idle timeout — very large pulls may fail on disk or session timeout; use EC2 or --stream-to s3:// for multi-GB handoff.
- Switch to workstation for long unattended runs or multi-TB S3 sources.
""",
    "workstation": """profile: workstation

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: responder jump host or local machine with CLI credentials; more disk/time than Cloud Shell.
- Collects the full since/until window unless max_records_per_source is set in acquisition.yaml.
- Local sleep/VPN drops can interrupt long runs; credentials live on the workstation during collection.
- Switch to Enterprise for multi-hour or very large pulls; switch to Cloud Shell if client cannot install locally.
""",
    "enterprise": """profile: enterprise

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: production IR engagements — complete collection within since/until and artifact parameters.
- Same default as other profiles: full window collection; use S3 transport for handoff.
- Run on EC2/VM with sufficient disk; not intended for Cloud Shell time/disk limits.
- Partial status means a real cloud gap (access denied, logging off), not Ventra truncation.
""",
}


def _safe_kit_slug(name: str, *, fallback: str = "ventra-kit") -> str:
    """Filesystem-safe slug from an Acquire kit display name."""
    import re

    raw = (name or "").strip()
    if not raw:
        return fallback
    slug = re.sub(r"[^\w.\-]+", "-", raw, flags=re.UNICODE)
    slug = re.sub(r"-{2,}", "-", slug).strip(".-")
    return slug[:80] or fallback


def build_kit(
    out_zip: Path,
    *,
    cloud: str,
    case_id: str,
    artifact_names: list[str],
    artifacts_root: Path | None = None,
    iam_policy_paths: list[Path] | None = None,
    since: str = "",
    until: str = "",
    regions: list[str] | None = None,
    project: str = "",
    subscription: str = "",
    azure_tenant_id: str = "",
    azure_client_id: str = "",
    aws_profile: str = "",
    max_records_per_source: int | None = None,
    artifact_parameters: dict[str, dict[str, Any]] | None = None,
    transport: str = "",
    gcp_log_backend: dict[str, Any] | None = None,
    bundle_wheel: bool = True,
    require_wheel: bool = False,
    deployment_profile: str = "cloudshell",
    connection: dict[str, Any] | None = None,
    kit_name: str = "",
) -> Path:
    """Generate an acquisition zip: acquisition.yaml + artifacts + narrowed IAM + entry script."""
    profile = deployment_profile.strip().lower() or "cloudshell"
    if profile not in _DEPLOYMENT_PROFILES:
        raise ValueError(f"unknown deployment profile: {deployment_profile!r}")
    collector_cloud = collector_cloud_for_platform(cloud)
    root = artifacts_root or Path("artifacts")
    staging = out_zip.with_suffix(".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    selected = _select_artifacts(root, cloud, artifact_names)
    if not selected:
        shutil.rmtree(staging)
        raise ValueError(f"no artifacts matched for cloud={cloud}: {artifact_names}")

    params_by_collector = artifact_parameters or {}
    display_name = (kit_name or "").strip() or f"ventra-{collector_cloud}"
    script_slug = _safe_kit_slug(display_name)
    acq: dict[str, Any] = {
        "case_id": case_id,
        "cloud": collector_cloud,
        "ventra_version": __version__,
        "deployment_profile": profile,
        "kit_name": display_name,
        "artifacts": [],
    }
    if since:
        acq["since"] = since
    if until:
        acq["until"] = until
    if regions:
        acq["regions"] = list(regions)
    if project:
        acq["project"] = project
    if subscription:
        acq["subscription"] = subscription
    if azure_tenant_id:
        acq["azure_tenant_id"] = azure_tenant_id
    if azure_client_id:
        acq["azure_client_id"] = azure_client_id
    if aws_profile:
        acq["aws_profile"] = aws_profile
    if max_records_per_source is not None:
        acq["max_records_per_source"] = max_records_per_source
    elif profile == "enterprise":
        acq["max_records_per_source"] = 0
    else:
        # Explicit unlimited — kits never inherit a triage cap unless the operator sets one.
        acq["max_records_per_source"] = 0
    transport_spec = (transport or "").strip()
    if transport_spec:
        acq["transport"] = transport_spec
    if collector_cloud == "gcp" and gcp_log_backend:
        acq["gcp_log_backend"] = dict(gcp_log_backend)

    if connection:
        cred_meta = embed_connection_auth(staging, connection, acq)
        # Connection scope wins when the kit template left fields empty.
        if not str(acq.get("project") or "").strip() and (connection.get("project") or "").strip():
            acq["project"] = str(connection.get("project") or "").strip()
        if not str(acq.get("subscription") or "").strip() and (connection.get("subscription") or "").strip():
            acq["subscription"] = str(connection.get("subscription") or "").strip()
    else:
        cred_meta = None

    for art in selected:
        collector = art["collector"]
        entry: dict[str, Any] = {
            "collector": collector,
            "name": art["name"],
            "version": str(art.get("version") or ""),
        }
        params = params_by_collector.get(collector) or {}
        if params:
            entry["parameters"] = dict(params)
        acq["artifacts"].append(entry)

    (staging / "acquisition.yaml").write_text(
        yaml.safe_dump(acq, sort_keys=False), encoding="utf-8"
    )

    art_dir = staging / "artifacts"
    art_dir.mkdir()
    for art in selected:
        src = Path(art.get("_path", ""))
        if src.is_file():
            shutil.copy2(src, art_dir / src.name)
        else:
            (art_dir / f"{art['collector']}.yaml").write_text(
                yaml.safe_dump({k: v for k, v in art.items() if not k.startswith("_")}, sort_keys=False),
                encoding="utf-8",
            )

    if iam_policy_paths:
        wanted_actions = {a for art in selected for a in art.get("required_actions", [])}
        if collector_cloud == "gcp" and gcp_log_backend:
            from collector.engine.gcp_log_backend import apply_gcp_log_backend_iam

            wanted_actions = apply_gcp_log_backend_iam(wanted_actions, gcp_log_backend)
        _write_iam(staging / "iam", iam_policy_paths, wanted_actions)

    kit_id = str(uuid.uuid4())
    created = utcnow()
    if cred_meta and cred_meta.get("expires_at"):
        expires_at = str(cred_meta["expires_at"])
    else:
        from datetime import timedelta

        expires_at = format_iso(created + timedelta(seconds=kit_ttl_seconds()))

    collectors = [str(a["collector"]) for a in acq.get("artifacts") or []]
    kit_manifest: dict[str, Any] = {
        "format": KIT_FORMAT,
        "format_version": KIT_FORMAT_VERSION,
        "kit_id": kit_id,
        "kit_name": display_name,
        "case_id": case_id,
        "cloud": collector_cloud,
        "ventra_version": __version__,
        "created_at": format_iso(created),
        "expires_at": expires_at,
        "collectors": collectors,
    }
    if cred_meta:
        kit_manifest["credential"] = cred_meta
    (staging / "kit.json").write_text(json.dumps(kit_manifest, indent=2) + "\n", encoding="utf-8")

    as_kit = out_zip.suffix.lower() == ".kit"
    if as_kit:
        _write_kit_cli_readme(
            staging,
            kit_name=display_name,
            kit_slug=script_slug,
            cloud=collector_cloud,
            expires_at=expires_at,
        )
        notes = _PROFILE_TRADEOFFS.get(profile, f"profile: {profile}\n")
        notes = notes.replace("{{CLOUD}}", collector_cloud.upper())
        (staging / "deployment-profile.txt").write_text(notes, encoding="utf-8")
    else:
        if bundle_wheel:
            _bundle_wheel(staging, required=require_wheel)

        _write_kit_requirements(staging, collector_cloud)
        entry_script = f"{script_slug}.py"
        entry_path = staging / entry_script
        shutil.copy2(_TEMPLATES / "ventra.py", entry_path)
        entry_path.chmod(0o755)
        run_sh = staging / "run.sh"
        run_sh.write_text(
            "#!/usr/bin/env bash\n"
            f"# Thin wrapper — prefer: python3 {entry_script} [options]\n"
            "set -euo pipefail\n"
            'ROOT="$(cd "$(dirname "$0")" && pwd)"\n'
            f'exec python3 "$ROOT/{entry_script}" "$@"\n',
            encoding="utf-8",
        )
        run_sh.chmod(0o755)
        _write_deployment_docs(
            staging,
            collector_cloud,
            profile,
            entry_script=entry_script,
            kit_name=display_name,
            kit_slug=script_slug,
        )

    if collector_cloud == "gcp" and gcp_log_backend:
        mode = str(gcp_log_backend.get("mode") or "logging_api")
        if mode == "gcs":
            src = _TEMPLATES / "gcp-log-setup-gcs.md"
            if src.is_file():
                shutil.copy2(src, staging / "SETUP-gcp-log-export-gcs.md")

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(staging).as_posix())
    shutil.rmtree(staging)
    return out_zip


def _write_kit_cli_readme(
    staging: Path,
    *,
    kit_name: str,
    kit_slug: str,
    cloud: str,
    expires_at: str,
) -> None:
    """Operator README for ``ventra run`` Collection Kits."""
    text = f"""# {kit_name}

Ventra Collection Kit (``.kit``) for **read-only** {cloud.upper()} evidence collection.

## Prerequisites

- Ventra CLI installed (`ventra --version`)
- Network access to the target cloud / cluster APIs
- This kit's embedded credential must not be expired (expires **{expires_at}**)

## Quick start

```bash
ventra run {kit_slug}.kit
ventra run {kit_slug}.kit --out ./evidence
```

No login prompts. No Ventra backend calls during the run. Authentication is already
baked into the kit until `{expires_at}`.

## After collection

```bash
# Import the sealed package into a case (case id is read from the package when omitted)
ventra import ./evidence
ventra import ./evidence --into CASE-YOUR-ID
```

Or use **Cases → Import package** in the console UI.

## Contents

| Path | Purpose |
|------|---------|
| `kit.json` | Kit id, case id, collectors, credential expiry, pinned Ventra version |
| `acquisition.yaml` | Collector config (scope, time window, regions / projects / …) |
| `credentials/` | Short-lived provider credential (do not share broadly) |
| `artifacts/` | Selected collector definitions |
| `iam/` | Read-only IAM / RBAC references for this kit |

## Chain of custody

`ventra run` writes `cli_run.json` next to the evidence package with: case id, kit id,
collectors, start/end time, and the local OS username of whoever executed the run.

## Security

- Treat this `.kit` file like a cloud key — it contains usable credentials until expiry.
- Do not grant admin / write roles “to make collection work”.
- Download a fresh kit from Acquire when the credential expires.
"""
    (staging / "README.md").write_text(text, encoding="utf-8")
    (staging / "README-operator.md").write_text(text, encoding="utf-8")


def _write_kit_requirements(staging: Path, cloud: str) -> None:
    """Pin runtime deps so ventra.py can bootstrap the kit venv offline."""
    cloud_key = cloud.lower()
    lines = list(_KIT_BASE_REQUIREMENTS)
    lines.extend(_KIT_CLOUD_REQUIREMENTS.get(cloud_key, []))
    # Preserve order while dropping duplicate pins (aws base + aws cloud both list boto3).
    seen: set[str] = set()
    deduped: list[str] = []
    for line in lines:
        key = line.split(">=")[0].split("==")[0].strip().lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(line)
    (staging / "requirements.txt").write_text("\n".join(deduped) + "\n", encoding="utf-8")


def _is_source_checkout() -> bool:
    """True when kit build runs from a Ventra dev clone (``ventra gui`` / ``make dev-setup``)."""
    return (_REPO_ROOT / "console" / "frontend" / "package.json").is_file()


def kit_wheel_source() -> str:
    """Where Acquire kits bundle the ventra wheel: ``local`` (dev clone) or ``pypi``."""
    return "local" if _is_source_checkout() else "pypi"


def _download_pypi_wheel(dist: Path, version: str) -> bool:
    """Download ``ventra==version`` wheel from PyPI into ``dist/``. Returns True on success."""
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                f"ventra=={version}",
                "--only-binary=:all:",
                "--no-deps",
                "-d",
                str(dist),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return any(dist.glob("ventra-*.whl"))


def _wheel_from_source_tree(dist: Path) -> bool:
    """Build a ventra wheel from the local source tree (dev / unreleased versions)."""
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(_REPO_ROOT), "-w", str(dist)],
            check=True,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return any(dist.glob("ventra-*.whl"))


def _bundle_wheel(staging: Path, *, required: bool = False) -> None:
    """Place a ventra wheel under ``dist/`` for offline bootstrap.

    From a source checkout (``ventra gui``), builds a fresh wheel from the working tree first so
    Acquire kits pick up unreleased changes. Otherwise downloads ``ventra==__version__`` from PyPI.
    """
    dist = staging / "dist"
    dist.mkdir()
    version = __version__

    if _is_source_checkout():
        bundled = _wheel_from_source_tree(dist) or _download_pypi_wheel(dist, version)
    else:
        bundled = _download_pypi_wheel(dist, version) or _wheel_from_source_tree(dist)

    if bundled:
        return

    if required:
        raise ValueError(
            f"Could not bundle ventra=={version} from "
            f"{'the local source tree or PyPI' if _is_source_checkout() else 'PyPI or the local source tree'}. "
            "Check network access or run Acquire from a Ventra source checkout."
        ) from None
    (staging / "INSTALL.md").write_text(
        "# Ventra install\n\n"
        "No bundled wheel was produced. From a machine with network access:\n\n"
        "```bash\n"
        "curl -LsSf https://astral.sh/uv/install.sh | sh\n"
        "uv tool install ventra\n"
        "# or from source: uv pip install -e /path/to/Ventra\n"
        "```\n",
        encoding="utf-8",
    )


def _write_deployment_docs(
    staging: Path,
    cloud: str,
    profile: str,
    *,
    entry_script: str = "ventra.py",
    kit_name: str = "",
    kit_slug: str = "ventra-kit",
) -> None:
    """Write README.md (+ operator alias) and profile-specific operator steps."""
    display = (kit_name or "").strip() or kit_slug
    kit_zip = f"{kit_slug}.zip"
    base = (_TEMPLATES / "README-operator.md").read_text(encoding="utf-8")
    profile_doc = _TEMPLATES / "deployment" / f"{profile}.md"
    if not profile_doc.is_file() and profile == "enterprise":
        profile_doc = _TEMPLATES / "deployment" / "ec2.md"
    if profile_doc.is_file():
        section = profile_doc.read_text(encoding="utf-8")
        section = section.replace("{{CLOUD}}", cloud.upper())
        base = base.rstrip() + "\n\n---\n\n" + section + "\n"
    for old, new in (
        ("{{KIT_NAME}}", display),
        ("{{KIT_SLUG}}", kit_slug),
        ("{{KIT_ZIP}}", kit_zip),
        ("{{ENTRY_SCRIPT}}", entry_script),
        ("ventra.py", entry_script),
    ):
        base = base.replace(old, new)
    (staging / "README.md").write_text(base, encoding="utf-8")
    # Keep the historical name so older operator docs / scripts still find it.
    (staging / "README-operator.md").write_text(base, encoding="utf-8")
    notes = _PROFILE_TRADEOFFS.get(profile, f"profile: {profile}\n")
    notes = notes.replace("{{CLOUD}}", cloud.upper())
    (staging / "deployment-profile.txt").write_text(notes, encoding="utf-8")
    ec2_script = _TEMPLATES / "ec2-bootstrap.sh"
    if profile in ("enterprise",) and ec2_script.is_file():
        shutil.copy2(ec2_script, staging / "ec2-bootstrap.sh")


def _select_artifacts(root: Path, cloud: str, artifact_names: list[str]) -> list[dict[str, Any]]:
    """Resolve requested collector keys / hierarchical names to artifact dicts, preserving order."""
    by_key: dict[str, dict[str, Any]] = {}
    for art in load_artifacts_dir(root, cloud=cloud):
        key = art.get("collector") or art.get("type")
        if key in artifact_names or art["name"] in artifact_names:
            by_key[key] = art

    ordered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for want in artifact_names:
        for key, art in by_key.items():
            if key in seen:
                continue
            if want == key or want == art["name"]:
                ordered.append(art)
                seen.add(key)
    for key, art in by_key.items():  # any matched-by-name not already added, stable
        if key not in seen:
            ordered.append(art)
            seen.add(key)
    return ordered


def _write_iam(iam_dir: Path, policy_paths: list[Path], wanted_actions: set[str]) -> None:
    """Copy each IAM policy into the kit, narrowed to the actions the selected artifacts need."""
    iam_dir.mkdir(parents=True, exist_ok=True)
    for p in policy_paths:
        if p.suffix != ".json":
            shutil.copy2(p, iam_dir / p.name)
            continue
        policy = json.loads(p.read_text(encoding="utf-8"))
        narrowed = _filter_policy(policy, wanted_actions)
        (iam_dir / p.name).write_text(json.dumps(narrowed, indent=2), encoding="utf-8")


def _filter_policy(policy: dict[str, Any], wanted: set[str]) -> dict[str, Any]:
    """Narrow an IAM policy to ``wanted`` actions. Falls back to the full policy if nothing matches.

    Handles the GCP custom-role shape (``permissions: [...]``) and the AWS/ARM statement shape
    (``Statement[].Action``). Unknown shapes are returned unchanged.
    """
    if not wanted:
        return policy

    if isinstance(policy.get("permissions"), list):
        kept = [a for a in policy["permissions"] if a in wanted]
        if not kept:
            return policy
        out = dict(policy)
        out["permissions"] = kept
        return out

    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if isinstance(statements, list):
        kept_stmts: list[dict[str, Any]] = []
        for stmt in statements:
            acts = stmt.get("Action", [])
            acts = [acts] if isinstance(acts, str) else list(acts)
            keep = [a for a in acts if a in wanted]
            if keep:
                new_stmt = dict(stmt)
                new_stmt["Action"] = keep
                kept_stmts.append(new_stmt)
        if not kept_stmts:
            return policy
        out = dict(policy)
        out["Statement"] = kept_stmts
        return out

    return policy

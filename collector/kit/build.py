"""Build a minimal operator acquisition zip from artifacts and templates.

The zip is what an IR lead hands to a client: an ``acquisition.yaml`` (full schema — the same
contract the engine's ``--acquisition`` flag consumes), the selected artifact YAMLs, a read-only
IAM policy narrowed to just the actions those artifacts need, a ``ventra.py`` entry point, and
(optionally) a bundled ``ventra`` wheel for offline bootstrap.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import yaml

from collector import __version__
from collector.engine.loader import load_artifacts_dir

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
        "azure-mgmt-monitor>=6.0",
        "azure-mgmt-network>=25.0",
        "azure-mgmt-security>=7.0",
        "azure-mgmt-authorization>=4.0",
        "azure-storage-blob>=12.19",
    ],
    "gcp": [
        "google-cloud-logging>=3.10",
        "google-cloud-resource-manager>=1.12",
        "google-cloud-securitycenter>=1.28",
        "google-auth>=2.29",
        "google-api-core>=2.19",
        "protobuf>=4.25",
    ],
}


_DEPLOYMENT_PROFILES = ("cloudshell", "workstation", "ec2", "enterprise")

_PROFILE_TRADEOFFS: dict[str, str] = {
    "cloudshell": """profile: cloudshell

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: quick proof-of-access; client runs in {{CLOUD}} Cloud Shell with no local install.
- Collects all records in the configured since/until window unless max_records_per_source is set in acquisition.yaml.
- ~1 GB home disk and ~20 min idle timeout — very large pulls may fail on disk or session timeout; use EC2 or --stream-to s3:// for multi-GB handoff.
- Switch to workstation or EC2 for long unattended runs or multi-TB S3 sources.
""",
    "workstation": """profile: workstation

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: responder jump host or local machine with CLI credentials; more disk/time than Cloud Shell.
- Collects the full since/until window unless max_records_per_source is set in acquisition.yaml.
- Local sleep/VPN drops can interrupt long runs; credentials live on the workstation during collection.
- Switch to EC2 for multi-hour or very large S3 pulls; switch to Cloud Shell if client cannot install locally.
""",
    "ec2": """profile: ec2

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: largest pulls, long unattended runs, complete collection within since/until.
- Requires VM + instance profile + secure copy-out; operational overhead vs Cloud Shell.
- Optional max_records_per_source in acquisition.yaml caps per-source volume for scoped triage only.
- Switch to Cloud Shell for quick proof-of-access; workstation when EC2 provisioning is not allowed.
""",
    "enterprise": """profile: enterprise

TRADEOFFS (summary — full detail in README-operator.md)
- Best for: production IR engagements — complete collection within since/until and artifact parameters.
- Same default as other profiles: full window collection; use S3 transport for handoff.
- Run on EC2/VM with sufficient disk; not intended for Cloud Shell time/disk limits.
- Partial status means a real cloud gap (access denied, logging off), not Ventra truncation.
""",
}


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
    max_records_per_source: int | None = None,
    artifact_parameters: dict[str, dict[str, Any]] | None = None,
    transport: str = "",
    bundle_wheel: bool = True,
    require_wheel: bool = False,
    deployment_profile: str = "cloudshell",
) -> Path:
    """Generate an acquisition zip: acquisition.yaml + artifacts + narrowed IAM + ventra.py."""
    profile = deployment_profile.strip().lower() or "cloudshell"
    if profile not in _DEPLOYMENT_PROFILES:
        raise ValueError(f"unknown deployment profile: {deployment_profile!r}")
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
    acq: dict[str, Any] = {
        "case_id": case_id,
        "cloud": cloud,
        "ventra_version": __version__,
        "deployment_profile": profile,
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
    if max_records_per_source is not None:
        acq["max_records_per_source"] = max_records_per_source
    elif profile == "enterprise":
        acq["max_records_per_source"] = 0
    transport_spec = (transport or "").strip()
    if transport_spec:
        acq["transport"] = transport_spec

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
        _write_iam(staging / "iam", iam_policy_paths, wanted_actions)

    if bundle_wheel:
        _bundle_wheel(staging, required=require_wheel)

    _write_kit_requirements(staging, cloud)
    shutil.copy2(_TEMPLATES / "ventra.py", staging / "ventra.py")
    shutil.copy2(_TEMPLATES / "run.sh", staging / "run.sh")
    _write_deployment_docs(staging, cloud, profile)

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(staging))
    shutil.rmtree(staging)
    return out_zip


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
        "python3 -m venv .venv && source .venv/bin/activate\n"
        f"pip install ventra=={version}\n"
        "# or from source: pip install -e /path/to/Ventra\n"
        "```\n",
        encoding="utf-8",
    )


def _write_deployment_docs(staging: Path, cloud: str, profile: str) -> None:
    """Append profile-specific operator steps and optional EC2 bootstrap script."""
    base = (_TEMPLATES / "README-operator.md").read_text(encoding="utf-8")
    profile_doc = _TEMPLATES / "deployment" / f"{profile}.md"
    if not profile_doc.is_file() and profile == "enterprise":
        profile_doc = _TEMPLATES / "deployment" / "ec2.md"
    if profile_doc.is_file():
        section = profile_doc.read_text(encoding="utf-8")
        section = section.replace("{{CLOUD}}", cloud.upper())
        base = base.rstrip() + "\n\n---\n\n" + section + "\n"
    (staging / "README-operator.md").write_text(base, encoding="utf-8")
    notes = _PROFILE_TRADEOFFS.get(profile, f"profile: {profile}\n")
    notes = notes.replace("{{CLOUD}}", cloud.upper())
    (staging / "deployment-profile.txt").write_text(notes, encoding="utf-8")
    ec2_script = _TEMPLATES / "ec2-bootstrap.sh"
    if profile in ("ec2", "enterprise") and ec2_script.is_file():
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

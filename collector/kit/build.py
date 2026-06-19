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
    "boto3>=1.34",
    "botocore>=1.34",
    "rich>=13.7",
    "zstandard>=0.22",
    "PyYAML>=6.0",
]
_KIT_CLOUD_REQUIREMENTS: dict[str, list[str]] = {
    "azure": [
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
    bundle_wheel: bool = True,
) -> Path:
    """Generate an acquisition zip: acquisition.yaml + artifacts + narrowed IAM + ventra.py."""
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
        _bundle_wheel(staging)

    _write_kit_requirements(staging, cloud)
    shutil.copy2(_TEMPLATES / "ventra.py", staging / "ventra.py")
    shutil.copy2(_TEMPLATES / "run.sh", staging / "run.sh")
    shutil.copy2(_TEMPLATES / "README-operator.md", staging / "README-operator.md")

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(staging))
    shutil.rmtree(staging)
    return out_zip


def _write_kit_requirements(staging: Path, cloud: str) -> None:
    """Pin runtime deps so ventra.py can bootstrap the kit venv offline."""
    lines = list(_KIT_BASE_REQUIREMENTS)
    lines.extend(_KIT_CLOUD_REQUIREMENTS.get(cloud.lower(), []))
    (staging / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bundle_wheel(staging: Path) -> None:
    """Best-effort: place a ventra wheel under ``dist/`` for run.sh bootstrap."""
    dist = staging / "dist"
    dist.mkdir()
    repo_dist = _REPO_ROOT / "dist"
    wheels = sorted(repo_dist.glob("ventra-*.whl")) if repo_dist.is_dir() else []
    if wheels:
        shutil.copy2(wheels[-1], dist / wheels[-1].name)
        return
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", str(_REPO_ROOT), "-w", str(dist)],
            check=True,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        (staging / "INSTALL.md").write_text(
            "# Ventra install\n\n"
            "No bundled wheel was produced. From a machine with network access:\n\n"
            "```bash\n"
            "python3 -m venv .venv && source .venv/bin/activate\n"
            "pip install ventra\n"
            "# or from source: pip install -e /path/to/Ventra\n"
            "```\n",
            encoding="utf-8",
        )


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

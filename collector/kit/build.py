"""Build a minimal operator acquisition zip from artifacts and templates."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import yaml

from collector.engine.loader import load_artifacts_dir

_KIT_ROOT = Path(__file__).resolve().parent
_TEMPLATES = _KIT_ROOT / "templates"


def build_kit(
    out_zip: Path,
    *,
    cloud: str,
    case_id: str,
    artifact_names: list[str],
    artifacts_root: Path | None = None,
    iam_policy_paths: list[Path] | None = None,
) -> Path:
    """Generate a minimal acquisition zip with acquisition.yaml, artifacts, IAM merge, run.sh."""
    root = artifacts_root or Path("artifacts")
    staging = out_zip.with_suffix(".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    selected: list[dict] = []
    for art in load_artifacts_dir(root, cloud=cloud):
        key = art.get("collector") or art.get("type")
        if key in artifact_names or art["name"] in artifact_names:
            selected.append(art)

    if not selected:
        raise ValueError(f"no artifacts matched for cloud={cloud}: {artifact_names}")

    acq = {
        "case_id": case_id,
        "cloud": cloud,
        "artifacts": [a["collector"] for a in selected],
        "artifact_names": [a["name"] for a in selected],
    }
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
        iam_dir = staging / "iam"
        iam_dir.mkdir()
        merged: list[dict] = []
        for p in iam_policy_paths:
            if p.suffix == ".json":
                merged.append(json.loads(p.read_text(encoding="utf-8")))
            else:
                shutil.copy2(p, iam_dir / p.name)
        if merged:
            (iam_dir / "merged-policy.json").write_text(
                json.dumps({"Version": "2012-10-17", "Statement": _merge_statements(merged)}),
                encoding="utf-8",
            )

    shutil.copy2(_TEMPLATES / "run.sh", staging / "run.sh")
    shutil.copy2(_TEMPLATES / "README-operator.md", staging / "README-operator.md")

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in staging.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(staging))
    shutil.rmtree(staging)
    return out_zip


def _merge_statements(policies: list[dict]) -> list[dict]:
    out: list[dict] = []
    for pol in policies:
        stmts = pol.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        out.extend(stmts)
    return out

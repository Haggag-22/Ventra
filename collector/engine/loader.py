"""Load and validate artifact YAML definitions from artifacts/."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REQUIRED = frozenset({"name", "cloud", "description", "version", "collector", "sources"})


class ArtifactValidationError(ValueError):
    pass


def load_artifact(path: Path) -> dict[str, Any]:
    """Load one artifact YAML file and validate required fields."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ArtifactValidationError(f"{path}: expected mapping at top level")
    missing = _REQUIRED - set(data)
    if missing:
        raise ArtifactValidationError(f"{path}: missing required fields: {sorted(missing)}")
    if "collector" not in data and "type" not in data:
        raise ArtifactValidationError(f"{path}: need collector or type")
    collector = data.get("collector") or data.get("type")
    if not collector:
        raise ArtifactValidationError(f"{path}: empty collector/type")
    data.setdefault("collector", collector)
    data.setdefault("aliases", [collector])
    if isinstance(data["aliases"], str):
        data["aliases"] = [data["aliases"]]
    return data


def load_artifacts_dir(root: Path, *, cloud: str | None = None) -> list[dict[str, Any]]:
    """Load all artifact YAML files under ``root`` (optionally filtered by cloud)."""
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for path in sorted(root.rglob("*.yaml")):
        if path.parent.name == "packs":
            continue
        art = load_artifact(path)
        if cloud and art.get("cloud", "").lower() != cloud.lower():
            continue
        art["_path"] = str(path)
        out.append(art)
    return out

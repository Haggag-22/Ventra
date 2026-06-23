"""Validate the artifact YAML catalog against the schema, the registry, and the read-only guard.

Powers ``ventra artifacts validate`` (and a CI gate). Returns a flat list of human-readable
error strings — empty means the catalog is healthy.

Checks performed:
  * every artifact YAML parses and carries the required fields (via :func:`load_artifact`);
  * the file matches ``schemas/artifact.schema.json`` (jsonschema when installed, else a
    focused built-in check so no extra dependency is required to gate CI);
  * each ``collector`` resolves in the engine registry for its cloud;
  * declared ``required_actions`` are read-only (the same guard as the collectors);
  * pack files reference only known collector keys;
  * (strict) every registered collector has a backing artifact YAML.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from ..lib.base import assert_readonly
from .acquisition import _pack_collector_keys
from .loader import ArtifactValidationError, load_artifact, load_artifacts_dir
from .registry import registry_for_cloud

_CLOUDS = ("aws", "azure", "gcp")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ALLOWED_KEYS = frozenset(
    {
        "name", "aliases", "cloud", "category", "description", "version", "collector",
        "type", "required_actions", "parameters", "sources", "severity", "estimated_volume",
        "implicit",
    }
)
_SEVERITY = frozenset({"critical", "extended", "optional"})
_VOLUME = frozenset({"low", "medium", "high"})


def _schema_path() -> Path:
    return Path(__file__).resolve().parents[2] / "schemas" / "artifact.schema.json"


def _check_schema_builtin(raw: dict[str, Any], rel: str) -> list[str]:
    """Focused schema check matching artifact.schema.json without requiring jsonschema."""
    errs: list[str] = []
    extra = set(raw) - _ALLOWED_KEYS
    if extra:
        errs.append(f"{rel}: unexpected field(s): {sorted(extra)}")
    cloud = raw.get("cloud")
    if cloud not in _CLOUDS:
        errs.append(f"{rel}: cloud must be one of {_CLOUDS}, got {cloud!r}")
    version = raw.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        errs.append(f"{rel}: version must match N.N.N, got {version!r}")
    sources = raw.get("sources")
    if not isinstance(sources, list) or not sources:
        errs.append(f"{rel}: sources must be a non-empty list")
    else:
        for i, src in enumerate(sources):
            if not isinstance(src, dict) or "type" not in src:
                errs.append(f"{rel}: sources[{i}] must be an object with a 'type'")
    if "severity" in raw and raw["severity"] not in _SEVERITY:
        errs.append(f"{rel}: severity must be one of {sorted(_SEVERITY)}")
    if "estimated_volume" in raw and raw["estimated_volume"] not in _VOLUME:
        errs.append(f"{rel}: estimated_volume must be one of {sorted(_VOLUME)}")
    return errs


def _check_schema(raw: dict[str, Any], rel: str) -> list[str]:
    try:
        import jsonschema  # type: ignore
    except Exception:
        return _check_schema_builtin(raw, rel)
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{rel}: {e.message}" for e in validator.iter_errors(raw)]


def validate_artifacts(
    artifacts_root: Path = Path("artifacts"), *, cloud: str | None = None, strict: bool = False
) -> list[str]:
    """Validate the artifact catalog. Returns a list of error strings (empty == clean)."""
    root = Path(artifacts_root)
    errors: list[str] = []
    clouds = [cloud.lower()] if cloud else list(_CLOUDS)

    for cl in clouds:
        try:
            reg = registry_for_cloud(cl)
        except ValueError as exc:
            errors.append(str(exc))
            continue

        seen_collectors: set[str] = set()
        cloud_dir = root / cl
        for path in sorted(cloud_dir.rglob("*.yaml")) if cloud_dir.is_dir() else []:
            rel = str(path.relative_to(root))
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                errors.append(f"{rel}: expected a mapping at the top level")
                continue
            errors.extend(_check_schema(raw, rel))
            try:
                art = load_artifact(path)
            except ArtifactValidationError as exc:
                errors.append(str(exc))
                continue

            collector = art["collector"]
            seen_collectors.add(collector)
            if reg.get(collector) is None:
                errors.append(f"{rel}: collector {collector!r} not in {cl} registry")
            bad = assert_readonly(art.get("required_actions", []))
            if bad:
                errors.append(f"{rel}: non-read-only required_actions: {', '.join(bad)}")

        if strict:
            for name in reg.all():
                if name not in seen_collectors:
                    errors.append(f"{cl}: registered collector {name!r} has no artifact YAML")

    errors.extend(_validate_packs(root, cloud))
    return errors


def _validate_packs(root: Path, cloud: str | None) -> list[str]:
    errors: list[str] = []
    packs = root / "packs"
    if not packs.is_dir():
        return errors
    for path in sorted(packs.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        pack_cloud = str(data.get("cloud") or "").lower()
        if cloud and pack_cloud != cloud.lower():
            continue
        rel = str(path.relative_to(root))
        if pack_cloud not in _CLOUDS:
            errors.append(f"{rel}: pack cloud must be one of {_CLOUDS}, got {pack_cloud!r}")
            continue
        reg = registry_for_cloud(pack_cloud)
        for key in _pack_collector_keys(data):
            if reg.get(key) is None:
                errors.append(f"{rel}: references unknown collector {key!r}")
    return errors


def diff_artifacts(artifacts_root: Path = Path("artifacts")) -> dict[str, dict[str, list[str]]]:
    """Report collectors with no YAML and YAML with no collector, per cloud (for ``artifacts diff``)."""
    root = Path(artifacts_root)
    out: dict[str, dict[str, list[str]]] = {}
    for cl in _CLOUDS:
        reg = registry_for_cloud(cl)
        registered = set(reg.all())
        in_yaml = {a["collector"] for a in load_artifacts_dir(root, cloud=cl)}
        out[cl] = {
            "missing_yaml": sorted(registered - in_yaml),
            "missing_registry": sorted(in_yaml - registered),
        }
    return out

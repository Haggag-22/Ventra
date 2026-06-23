"""Load acquisition specs and artifact packs; resolve them to collectors + provenance.

An *acquisition spec* (``acquisition.yaml``) is the operator-facing contract carried inside a
kit: it names a case, a cloud, and the artifacts to collect. A *pack* is a curated bundle of
collector keys under ``artifacts/packs/``. Both resolve, through the artifact YAML catalog and
the engine registry, to an ordered list of collector keys plus :class:`ArtifactRef` provenance
that the runner records in the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..lib.models import ArtifactRef
from .loader import load_artifacts_dir
from .registry import collector_order_for_cloud, registry_for_cloud

# Always merged into AWS plans — checks logging for sources without dedicated collectors.
_IMPLICIT_COLLECTORS: dict[str, list[str]] = {
    "aws": ["log_posture"],
}


class AcquisitionError(ValueError):
    """Raised when an acquisition spec or pack is malformed or references unknown collectors."""


@dataclass
class AcquisitionSpec:
    """Parsed ``acquisition.yaml`` — see :func:`load_acquisition`."""

    case_id: str
    cloud: str
    artifacts: list[ArtifactRef] = field(default_factory=list)
    pack: str = ""
    ventra_version: str = ""
    engagement_id: str = ""
    # Collection-wide filters carried in the kit so the client's run is fully specified.
    since: str = ""  # window start (YYYY-MM-DD or RFC3339)
    until: str = ""  # window end
    regions: list[str] = field(default_factory=list)
    project: str = ""  # GCP project id(s), comma-separated
    subscription: str = ""  # Azure subscription id(s)
    max_records_per_source: int | None = None  # None/0 = unlimited; positive = cap per source

    def artifact_parameters(self) -> dict[str, dict[str, Any]]:
        """Per-collector parameter values, keyed by collector — for CollectionContext."""
        return {a.collector: dict(a.parameters) for a in self.artifacts if a.collector and a.parameters}


def _ref_from_entry(entry: Any) -> ArtifactRef:
    """Build an ArtifactRef from one ``artifacts:`` entry (string short-form or full mapping)."""
    if isinstance(entry, str):
        return ArtifactRef(name="", version="", collector=entry.strip())
    if isinstance(entry, dict):
        collector = str(entry.get("collector") or entry.get("type") or "").strip()
        return ArtifactRef(
            name=str(entry.get("name") or "").strip(),
            version=str(entry.get("version") or "").strip(),
            collector=collector,
            parameters=dict(entry.get("parameters") or {}),
        )
    raise AcquisitionError(f"invalid artifact entry: {entry!r}")


def load_acquisition(path: Path) -> AcquisitionSpec:
    """Parse an ``acquisition.yaml`` file into an :class:`AcquisitionSpec`.

    Supports both the full mapping form (``- collector: …`` with optional name/version/parameters)
    and the legacy short form (``artifacts: [cloud_audit_admin, vpc_flow]``).
    """
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise AcquisitionError(f"{path}: expected a mapping at the top level")
    cloud = str(data.get("cloud") or "").strip().lower()
    if not cloud:
        raise AcquisitionError(f"{path}: 'cloud' is required")
    raw = data.get("artifacts") or []
    if not isinstance(raw, list):
        raise AcquisitionError(f"{path}: 'artifacts' must be a list")
    regions = data.get("regions") or []
    if isinstance(regions, str):
        regions = [r.strip() for r in regions.split(",") if r.strip()]
    cap = data.get("max_records_per_source")
    return AcquisitionSpec(
        case_id=str(data.get("case_id") or "").strip(),
        cloud=cloud,
        artifacts=[_ref_from_entry(e) for e in raw],
        pack=str(data.get("pack") or "").strip(),
        ventra_version=str(data.get("ventra_version") or "").strip(),
        engagement_id=str(data.get("engagement_id") or "").strip(),
        since=str(data.get("since") or "").strip(),
        until=str(data.get("until") or "").strip(),
        regions=[str(r).strip() for r in regions if str(r).strip()],
        project=str(data.get("project") or "").strip(),
        subscription=str(data.get("subscription") or "").strip(),
        max_records_per_source=int(cap) if cap is not None and str(cap) != "" else None,
    )


def _packs_dir(artifacts_root: Path) -> Path:
    return Path(artifacts_root) / "packs"


def _pack_path(name: str, artifacts_root: Path) -> Path | None:
    """Resolve a pack by file stem (``baseline-ir-gcp``) or its internal ``name:`` field."""
    packs = _packs_dir(artifacts_root)
    if not packs.is_dir():
        return None
    direct = packs / f"{name}.yaml"
    if direct.is_file():
        return direct
    for p in sorted(packs.glob("*.yaml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if p.stem == name or data.get("name") == name:
            return p
    return None


def _pack_collector_keys(data: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for entry in data.get("artifacts") or []:
        if isinstance(entry, str):
            keys.append(entry.strip())
        elif isinstance(entry, dict):
            key = entry.get("collector") or entry.get("type") or entry.get("name")
            if key:
                keys.append(str(key).strip())
    return keys


def load_pack(name: str, artifacts_root: Path = Path("artifacts")) -> list[str]:
    """Return the ordered collector keys listed in ``artifacts/packs/<name>.yaml``."""
    path = _pack_path(name, artifacts_root)
    if path is None:
        raise AcquisitionError(f"unknown pack: {name!r}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _pack_collector_keys(data)


def list_packs(cloud: str | None = None, artifacts_root: Path = Path("artifacts")) -> list[dict[str, Any]]:
    """List available packs (optionally filtered by cloud) for the CLI and the API."""
    packs = _packs_dir(artifacts_root)
    out: list[dict[str, Any]] = []
    if not packs.is_dir():
        return out
    for p in sorted(packs.glob("*.yaml")):
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if cloud and str(data.get("cloud") or "").lower() != cloud.lower():
            continue
        out.append(
            {
                "pack": p.stem,
                "name": data.get("name") or p.stem,
                "cloud": str(data.get("cloud") or ""),
                "description": str(data.get("description") or ""),
                "version": str(data.get("version") or ""),
                "artifacts": _pack_collector_keys(data),
            }
        )
    return out


def _artifact_index(cloud: str, artifacts_root: Path) -> dict[str, dict[str, Any]]:
    """Map every lookup key (collector, name, aliases) to its artifact dict for one cloud."""
    index: dict[str, dict[str, Any]] = {}
    for art in load_artifacts_dir(Path(artifacts_root), cloud=cloud):
        keys = {art.get("collector"), art.get("name"), *(art.get("aliases") or [])}
        for key in keys:
            if key:
                index.setdefault(key, art)
    return index


def _ref_for_key(
    key: str, index: dict[str, dict[str, Any]], parameters: dict[str, Any] | None = None
) -> ArtifactRef:
    art = index.get(key)
    return ArtifactRef(
        name=(art.get("name") if art else "") or key,
        version=(str(art.get("version")) if art else "") or "",
        collector=(art.get("collector") if art else "") or key,
        parameters=dict(parameters or {}),
    )


def artifact_refs_for_collectors(
    cloud: str, names: list[str], artifacts_root: Path = Path("artifacts")
) -> list[ArtifactRef]:
    """Build manifest provenance for a plain collector list by looking up the artifact YAML."""
    index = _artifact_index(cloud, artifacts_root)
    return [_ref_for_key(name, index) for name in names]


def _order_keys(cloud: str, keys: list[str]) -> list[str]:
    order = {n: i for i, n in enumerate(collector_order_for_cloud(cloud))}
    return sorted(keys, key=lambda n: order.get(n, len(order)))


def augment_collectors(cloud: str, names: list[str]) -> list[str]:
    """Append implicit collectors (e.g. AWS ``log_posture``) not shown in Acquire."""
    extra = _IMPLICIT_COLLECTORS.get(cloud, [])
    merged = list(names)
    seen = set(names)
    for key in extra:
        if key not in seen:
            merged.append(key)
            seen.add(key)
    return _order_keys(cloud, merged)


def resolve_collectors_from_acquisition(
    spec: AcquisitionSpec, artifacts_root: Path = Path("artifacts")
) -> tuple[list[str], list[ArtifactRef]]:
    """Merge pack + explicit artifacts, validate against the registry, return (names, refs).

    Explicit artifacts override pack entries for the same collector (so parameters/version set
    in the spec win). Collectors are returned in stable registry order.
    """
    cloud = spec.cloud
    reg = registry_for_cloud(cloud)  # raises ValueError on unsupported cloud
    index = _artifact_index(cloud, artifacts_root)

    ordered: list[str] = []
    refs_by_key: dict[str, ArtifactRef] = {}

    def _add(ref: ArtifactRef) -> None:
        art = index.get(ref.collector) or index.get(ref.name)
        collector_key = (art.get("collector") if art else "") or ref.collector or ref.name
        if not collector_key:
            raise AcquisitionError(f"artifact entry missing a collector/name: {ref!r}")
        merged = _ref_for_key(collector_key, index, ref.parameters)
        if ref.name:
            merged.name = ref.name
        if ref.version:
            merged.version = ref.version
        if collector_key not in refs_by_key:
            ordered.append(collector_key)
        refs_by_key[collector_key] = merged

    if spec.pack:
        for key in load_pack(spec.pack, artifacts_root):
            _add(ArtifactRef(name="", version="", collector=key))
    for ref in spec.artifacts:
        _add(ref)

    unknown = [k for k in ordered if reg.get(k) is None]
    if unknown:
        raise AcquisitionError(f"unknown collector(s) for {cloud}: {', '.join(sorted(unknown))}")

    names = augment_collectors(cloud, _order_keys(cloud, ordered))
    refs_by_key = {k: refs_by_key.get(k) or _ref_for_key(k, index) for k in names}
    return names, [refs_by_key[k] for k in names]

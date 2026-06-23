"""Execute artifact-backed acquisition — list collectors and delegate to cloud runners."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .loader import load_artifacts_dir
from .registry import collector_class_for, collector_order_for_cloud, registry_for_cloud


def list_collectors(cloud: str, *, artifacts_root: Path | None = None) -> list[str]:
    """Return collector names for a cloud (from artifacts if present, else registry order)."""
    cloud = cloud.lower()
    try:
        order = collector_order_for_cloud(cloud)
    except ValueError:
        order = []
    root = artifacts_root or Path("artifacts")
    arts = load_artifacts_dir(root, cloud=cloud)
    if arts:
        names = [a["collector"] for a in arts]
        order_index = {n: i for i, n in enumerate(order)}
        return sorted(names, key=lambda n: order_index.get(n, len(order)))
    return list(order)


def resolve_collectors(cloud: str, names: list[str] | None = None) -> list[type]:
    """Resolve collector registry keys to collector classes."""
    reg = registry_for_cloud(cloud)
    if not names:
        return [reg.get(n) for n in list_collectors(cloud) if reg.get(n)]
    out: list[type] = []
    for name in names:
        cls = reg.get(name) or collector_class_for(name)
        out.append(cls)
    return out


def run_collectors(
    cloud: str,
    ctx: Any,
    *,
    collector_names: list[str] | None = None,
) -> list[Any]:
    """Instantiate and run collectors for one cloud context.

    Full orchestration (manifest, packaging) remains in cloud runners; this helper
    runs individual collector classes for artifact-driven or test use.
    """
    results = []
    for cls in resolve_collectors(cloud, collector_names):
        collector = cls(ctx)
        results.append(collector.collect())
    return results

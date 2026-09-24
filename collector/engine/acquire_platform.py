"""Acquire UI platform keys — separate from engine ``cloud`` where M365 collectors use Azure."""

from __future__ import annotations

from pathlib import Path

M365_CATEGORY = "M365"

ACQUIRE_PLATFORMS = frozenset({"aws", "azure", "gcp", "kubernetes"})


def collector_cloud_for_platform(platform: str) -> str:
    """Map Acquire platform to the engine cloud used for collection and registry lookup."""
    return platform.strip().lower()


def artifact_matches_acquire_platform(art: dict, platform: str | None) -> bool:
    """Filter artifact YAML rows for Acquire tabs (M365 collectors are hidden for now)."""
    if not platform:
        return True
    p = platform.strip().lower()
    cat = (art.get("category") or "").strip()
    art_cloud = (art.get("cloud") or "").strip().lower()
    if cat == M365_CATEGORY or art.get("selectable") is False:
        return False
    return art_cloud == p


def iam_policy_paths_for_platform(
    platform: str,
    docs_iam_dir: Path,
    *,
    collector_names: list[str] | None = None,
) -> list[Path] | None:
    """Resolve IAM/RBAC policy files bundled into kits for an Acquire platform.

    Kubernetes ships a permissions JSON (for narrowing/preview) plus an applyable
    ClusterRole YAML. Cloud platforms use a single ``*-collector-readonly.json``.
    """
    del collector_names  # reserved for future per-collector policy selection
    p = platform.strip().lower()
    names = [f"{p}-collector-readonly.json"]
    if p == "kubernetes":
        names.append("kubernetes-collector-readonly.yaml")
    paths = [docs_iam_dir / name for name in names if (docs_iam_dir / name).is_file()]
    return paths or None

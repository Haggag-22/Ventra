"""Acquire UI platform keys — separate from engine ``cloud`` where M365 uses Azure collectors."""

from __future__ import annotations

from pathlib import Path

M365_PLATFORM = "m365"
M365_CATEGORY = "M365"

ACQUIRE_PLATFORMS = frozenset({"aws", "azure", "gcp", M365_PLATFORM})


def collector_cloud_for_platform(platform: str) -> str:
    """Map Acquire platform to the engine cloud used for collection and registry lookup."""
    p = platform.strip().lower()
    if p == M365_PLATFORM:
        return "azure"
    return p


def artifact_matches_acquire_platform(art: dict, platform: str | None) -> bool:
    """Filter artifact YAML rows for Acquire tabs (M365 is split out from Azure)."""
    if not platform:
        return True
    p = platform.strip().lower()
    cat = (art.get("category") or "").strip()
    art_cloud = (art.get("cloud") or "").strip().lower()
    if p == M365_PLATFORM:
        return cat == M365_CATEGORY
    if p == "azure":
        return art_cloud == "azure" and cat != M365_CATEGORY
    return art_cloud == p


def iam_policy_paths_for_platform(
    platform: str,
    docs_iam_dir: Path,
    *,
    collector_names: list[str] | None = None,
) -> list[Path] | None:
    """Resolve IAM policy files bundled into kits for an Acquire platform."""
    p = platform.strip().lower()
    names = set(collector_names or [])
    if p == M365_PLATFORM:
        paths: list[Path] = []
        graph = docs_iam_dir / "azure-collector-graph.json"
        m365 = docs_iam_dir / "azure-collector-m365.json"
        if graph.is_file():
            paths.append(graph)
        if m365.is_file() and "unified_audit_search" in names:
            paths.append(m365)
        return paths or None
    policy = docs_iam_dir / f"{p}-collector-readonly.json"
    if policy.is_file():
        return [policy]
    return None

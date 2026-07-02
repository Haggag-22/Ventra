"""Tests for Acquire platform filtering (M365 split from Azure)."""

from __future__ import annotations

from pathlib import Path

from collector.engine.acquire_platform import (
    artifact_matches_acquire_platform,
    collector_cloud_for_platform,
    iam_policy_paths_for_platform,
)
from collector.engine.loader import load_artifacts_dir

ARTIFACTS = Path("artifacts")
IAM = Path("docs/iam-policies")


def test_m365_platform_maps_to_azure_collector_cloud() -> None:
    assert collector_cloud_for_platform("m365") == "azure"
    assert collector_cloud_for_platform("azure") == "azure"


def test_load_artifacts_dir_splits_m365_from_azure() -> None:
    m365 = load_artifacts_dir(ARTIFACTS, cloud="m365")
    azure = load_artifacts_dir(ARTIFACTS, cloud="azure")
    m365_ids = {a["collector"] for a in m365}
    azure_ids = {a["collector"] for a in azure}
    assert m365_ids == {"unified_audit", "unified_audit_search"}
    assert "unified_audit" not in azure_ids
    assert "unified_audit_search" not in azure_ids
    assert "activity_log" in azure_ids


def test_iam_policy_paths_for_m365() -> None:
    paths = iam_policy_paths_for_platform("m365", IAM, collector_names=["unified_audit"])
    names = [p.name for p in paths or []]
    assert "azure-collector-graph.json" in names
    assert "azure-collector-m365.json" not in names

    paths_search = iam_policy_paths_for_platform(
        "m365", IAM, collector_names=["unified_audit_search"]
    )
    names_search = [p.name for p in paths_search or []]
    assert "azure-collector-graph.json" in names_search
    assert "azure-collector-m365.json" in names_search


def test_artifact_matches_acquire_platform() -> None:
    ual = {"cloud": "azure", "category": "M365"}
    act = {"cloud": "azure", "category": "ManagementPlane"}
    assert artifact_matches_acquire_platform(ual, "m365")
    assert not artifact_matches_acquire_platform(act, "m365")
    assert artifact_matches_acquire_platform(act, "azure")
    assert not artifact_matches_acquire_platform(ual, "azure")

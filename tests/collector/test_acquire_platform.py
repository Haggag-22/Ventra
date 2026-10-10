"""Tests for Acquire platform filtering."""

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


def test_azure_platform_maps_to_azure_collector_cloud() -> None:
    assert collector_cloud_for_platform("azure") == "azure"


def test_azure_artifacts_exclude_unified_audit() -> None:
    azure = load_artifacts_dir(ARTIFACTS, cloud="azure")
    azure_ids = {a["collector"] for a in azure}
    assert "unified_audit" not in azure_ids
    assert "entra_signin" in azure_ids
    assert "oauth_consent" in azure_ids
    assert "activity_log" in azure_ids


def test_iam_policy_paths_for_azure() -> None:
    paths = iam_policy_paths_for_platform("azure", IAM, collector_names=["activity_log"])
    names = [p.name for p in paths or []]
    assert names == ["azure-collector-readonly.json"]


def test_artifact_matches_acquire_platform() -> None:
    act = {"cloud": "azure", "category": "ManagementPlane"}
    hidden = {"cloud": "azure", "category": "Identity", "selectable": False}
    assert artifact_matches_acquire_platform(act, "azure")
    assert not artifact_matches_acquire_platform(hidden, "azure")
    assert not artifact_matches_acquire_platform(act, "aws")

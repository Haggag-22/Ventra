"""CloudWatch Logs collector registration and artifact wiring."""

from __future__ import annotations

from pathlib import Path

from collector.engine.loader import load_artifacts_dir
from collector.engine.registry import registry_for_cloud


def test_cloudwatch_registered_in_aws_registry() -> None:
    reg = registry_for_cloud("aws")
    assert "cloudwatch" in reg.names()
    assert reg.get("cloudwatch").name == "cloudwatch"


def test_cloudwatch_artifact_loads() -> None:
    arts = load_artifacts_dir(Path("artifacts"), cloud="aws")
    by_collector = {a["collector"]: a for a in arts}
    assert "cloudwatch" in by_collector
    art = by_collector["cloudwatch"]
    assert "log_group_names" in (art.get("parameters") or {})
    assert "logs:FilterLogEvents" in art["required_actions"]

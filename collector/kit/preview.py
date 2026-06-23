"""Preview IAM narrowing and kit metadata before building an acquisition zip."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from collector import __version__
from collector.engine.acquisition import augment_collectors
from collector.kit.build import _filter_policy, _select_artifacts


def preview_kit(
    *,
    cloud: str,
    artifact_names: list[str],
    artifacts_root: Path,
    iam_policy_paths: list[Path] | None = None,
    include_iam: bool = True,
) -> dict[str, Any]:
    """Return IAM action counts and artifact summary for the Acquire UI."""
    names = augment_collectors(cloud, list(artifact_names))
    selected = _select_artifacts(artifacts_root, cloud, names)
    if not selected:
        raise ValueError(f"no artifacts matched for cloud={cloud}: {artifact_names}")

    wanted: set[str] = set()
    for art in selected:
        for action in art.get("required_actions") or []:
            wanted.add(str(action))

    actions: set[str] = set()
    policy_files: list[str] = []
    iam_policies: dict[str, Any] = {}
    if include_iam and iam_policy_paths and wanted:
        for p in iam_policy_paths:
            if not p.is_file():
                continue
            policy_files.append(p.name)
            if p.suffix != ".json":
                continue
            policy = json.loads(p.read_text(encoding="utf-8"))
            narrowed = _filter_policy(policy, wanted)
            iam_policies[p.name] = narrowed
            actions.update(_extract_actions(narrowed))

    implicit = [n for n in names if n not in artifact_names]
    return {
        "ventra_version": __version__,
        "cloud": cloud,
        "artifact_count": len(selected),
        "collectors": [a.get("collector") for a in selected],
        "implicit_collectors": implicit,
        "iam_included": include_iam and bool(iam_policy_paths),
        "iam_policy_files": policy_files,
        "iam_action_count": len(actions) if actions else len(wanted),
        "iam_actions": sorted(actions) if actions else sorted(wanted),
        "iam_policies": iam_policies,
    }


def _extract_actions(policy: dict[str, Any]) -> set[str]:
    if isinstance(policy.get("permissions"), list):
        return {str(a) for a in policy["permissions"]}
    out: set[str] = set()
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if isinstance(statements, list):
        for stmt in statements:
            acts = stmt.get("Action", [])
            if isinstance(acts, str):
                out.add(acts)
            else:
                out.update(str(a) for a in acts)
    return out

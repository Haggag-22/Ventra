"""Static read-only guard.

Two modes:
  * ``python -m collector.tools.verify_readonly <policy.json>`` — check an IAM policy.
  * ``python -m collector.tools.verify_readonly --collectors`` — check that every
    registered collector's declared ``required_actions`` are read-only.

The ``readonly-guard`` CI job runs both. A non-zero exit means a mutating action slipped in.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..lib.base import assert_readonly


def check_policy(path: Path) -> list[str]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    actions: list[str] = []
    if "Actions" in policy and "Statement" not in policy:
        act = policy["Actions"]
        actions.extend([act] if isinstance(act, str) else act)
    else:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            act = stmt.get("Action", [])
            actions.extend([act] if isinstance(act, str) else act)
    return assert_readonly(actions)


def check_collectors() -> list[str]:
    from ..engine.registry import AWS_REGISTRY, AZURE_REGISTRY

    offenders: list[str] = []
    for name, cls in AWS_REGISTRY.all().items():
        bad = assert_readonly(cls.required_actions)
        offenders.extend(f"{name}:{a}" for a in bad)
    for name, cls in AZURE_REGISTRY.all().items():
        bad = assert_readonly(cls.required_actions)
        offenders.extend(f"{name}:{a}" for a in bad)
    return offenders


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv and argv[0] == "--collectors":
        offenders = check_collectors()
        scope = "registered collectors"
    elif argv:
        offenders = check_policy(Path(argv[0]))
        scope = argv[0]
    else:
        print("usage: verify_readonly <policy.json> | --collectors", file=sys.stderr)
        return 2

    if offenders:
        print(f"READ-ONLY VIOLATION in {scope}:", file=sys.stderr)
        for o in offenders:
            print(f"  - {o}", file=sys.stderr)
        return 1
    print(f"OK: {scope} contains only read-only actions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

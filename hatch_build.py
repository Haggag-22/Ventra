"""Hatch build hook — stage bundled data into the ``collector`` package of the wheel.

A pipx/uv/PyPI install has no repo checkout next to it, so the wheel carries its own copies of
the data trees that ``collector.paths`` looks up at runtime:

    artifacts/                  -> collector/_artifacts/
    schemas/                    -> collector/_schemas/
    docs/iam-policies/          -> collector/_iam_policies/
    console/frontend/out/       -> collector/_console_static/   (only when a static build exists)

Editable installs skip this: ``collector.paths`` falls back to the repo-relative paths.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# (source dir relative to the project root, destination inside the wheel, marker file that must
# exist for the tree to be staged — None means "stage whenever the directory exists").
_STAGED: tuple[tuple[str, str, str | None], ...] = (
    ("artifacts", "collector/_artifacts", None),
    ("schemas", "collector/_schemas", None),
    ("docs/iam-policies", "collector/_iam_policies", None),
    # Built by scripts/build-console-static.sh (the release workflow runs it before `uv build`).
    ("console/frontend/out", "collector/_console_static", "index.html"),
)

_JUNK_NAMES = frozenset({"__pycache__", ".DS_Store"})
# iCloud Drive / Finder conflict copies: "cli 2.py", "aws 2", "readonly 3.json".
_CONFLICT_COPY = re.compile(r" \d+(\.[^/]*)?$")


def _is_junk(rel: Path) -> bool:
    return any(part in _JUNK_NAMES or _CONFLICT_COPY.search(part) for part in rel.parts) or (
        rel.suffix == ".pyc"
    )


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name != "wheel" or version == "editable":
            return
        root = Path(self.root)
        force_include: dict[str, str] = build_data["force_include"]
        for src_rel, dst_rel, marker in _STAGED:
            src = root / src_rel
            if not src.is_dir() or (marker and not (src / marker).is_file()):
                continue
            for path in sorted(src.rglob("*")):
                rel = path.relative_to(src)
                if path.is_file() and not _is_junk(rel):
                    force_include[str(path)] = f"{dst_rel}/{rel.as_posix()}"

"""Setuptools hooks — copy artifact YAML into the wheel for uv/pip installs."""

from __future__ import annotations

import shutil
from pathlib import Path

from setuptools.command.build_py import build_py

_REPO_ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
_BUNDLED_NAME = "_artifacts"


class BuildPyWithArtifacts(build_py):
    """Stage ``artifacts/`` under ``collector/_artifacts`` in the built package."""

    def run(self) -> None:
        super().run()
        if not _REPO_ARTIFACTS.is_dir():
            return
        for base in self.build_lib, getattr(self, "build_base", None):
            if not base:
                continue
            dst = Path(base) / "collector" / _BUNDLED_NAME
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(_REPO_ARTIFACTS, dst)

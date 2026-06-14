"""CLI smoke tests."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from collector.cli import build_parser


def test_parser_has_collect_dev_gui() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])
    assert parser.parse_args(["collect", "aws", "--list-collectors"])
    assert parser.parse_args(["gui"])
    assert parser.parse_args(["dev"])  # alias of gui


def test_normalize_argv_preserves_global_flags() -> None:
    from collector.cli import _normalize_argv

    assert _normalize_argv(["--version"]) == ["--version"]
    assert _normalize_argv(["-h"]) == ["-h"]
    assert _normalize_argv(["collect", "aws"]) == ["collect", "aws"]
    assert _normalize_argv(["aws", "--case", "X"]) == ["collect", "aws", "--case", "X"]


def test_find_repo_root_from_cwd() -> None:
    from collector.devgui import find_repo_root

    root = find_repo_root()
    assert (root / "console/frontend/package.json").is_file()


def test_is_stale_detects_newer_pyproject(tmp_path: Path) -> None:
    from collector.devgui import _is_stale

    marker = tmp_path / "marker"
    source = tmp_path / "pyproject.toml"
    marker.touch()
    time.sleep(0.02)
    source.write_text("[project]\nname = 'x'\n")
    assert _is_stale(marker, source)
    assert not _is_stale(marker)

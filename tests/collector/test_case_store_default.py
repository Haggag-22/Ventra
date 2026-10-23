"""Default case store for ``ventra import`` / collect auto-ingest matches the console's.

A case imported from the CLI must land where ``ventra gui`` reads cases from, otherwise it
looks lost. The order is: ``--case-store`` > ``VENTRA_CASE_STORE`` > ``$VENTRA_HOME/cases`` >
the user data root (packaged installs) > ``./cases`` (source checkout).
"""

from __future__ import annotations

from pathlib import Path

import pytest

import collector.paths as paths
from collector.cli import main
from collector.lib.ingest import default_case_store


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("VENTRA_CASE_STORE", "VENTRA_HOME", "VENTRA_ROOT"):
        monkeypatch.delenv(name, raising=False)


def _as_packaged(monkeypatch: pytest.MonkeyPatch, data_root: Path) -> None:
    """Pretend this is a pipx/wheel install whose user data root is ``data_root``."""
    monkeypatch.setattr(paths, "bundled_console_static", lambda: None)
    monkeypatch.setattr(paths, "is_source_checkout", lambda: False)
    monkeypatch.setattr(paths, "user_data_root", lambda: data_root)


def _as_source_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "bundled_console_static", lambda: None)
    monkeypatch.setattr(paths, "is_source_checkout", lambda: True)


def test_ventra_case_store_env_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VENTRA_CASE_STORE", str(tmp_path / "explicit"))
    monkeypatch.setenv("VENTRA_HOME", str(tmp_path / "home"))
    assert default_case_store() == tmp_path / "explicit"


def test_ventra_home_used_over_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _as_source_checkout(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VENTRA_HOME", str(tmp_path / "home"))
    assert default_case_store() == (tmp_path / "home").resolve() / "cases"


def test_packaged_install_uses_user_data_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _as_packaged(monkeypatch, tmp_path / "data")
    monkeypatch.chdir(tmp_path)
    assert default_case_store() == tmp_path / "data" / "cases"


def test_source_checkout_uses_cwd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _as_source_checkout(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert default_case_store() == tmp_path.resolve() / "cases"


@pytest.mark.parametrize("layout", ["home", "packaged", "source"])
def test_matches_console_backend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, layout: str) -> None:
    from app.config import _default_data_root

    monkeypatch.chdir(tmp_path)
    if layout == "home":
        monkeypatch.setenv("VENTRA_HOME", str(tmp_path / "home"))
    elif layout == "packaged":
        _as_packaged(monkeypatch, tmp_path / "data")
    else:
        _as_source_checkout(monkeypatch)
    assert default_case_store() == _default_data_root() / "cases"


def _capture_import(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Stub the importer and record the case store ``ventra import`` passes it."""
    seen: dict = {}

    def fake_import(path, *, into_case_id=None, case_store=None):
        seen["case_store"] = case_store
        return {
            "case_id": "CASE-1",
            "package": str(path),
            "case_dir": str(case_store / "CASE-1"),
            "events": 0,
            "integrity": "ok",
        }

    monkeypatch.setattr("collector.kit.import_cmd.import_evidence", fake_import)
    return seen


def test_cli_import_defaults_to_ventra_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen = _capture_import(monkeypatch)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.chdir(run_dir)
    monkeypatch.setenv("VENTRA_HOME", str(tmp_path / "h"))

    assert main(["import", "pkg.tar.zst"]) == 0
    assert seen["case_store"] == (tmp_path / "h").resolve() / "cases"
    assert not (run_dir / "cases").exists()


def test_cli_import_case_store_flag_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen = _capture_import(monkeypatch)
    monkeypatch.setenv("VENTRA_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("VENTRA_CASE_STORE", str(tmp_path / "env-store"))

    assert main(["import", "pkg.tar.zst", "--case-store", str(tmp_path / "flag")]) == 0
    assert seen["case_store"] == tmp_path / "flag"

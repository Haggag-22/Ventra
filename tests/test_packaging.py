"""Packaging smoke tests — the installed layout works, independent of collection logic.

These guard the things that break a fresh ``uvx ventra`` / ``uv tool install ventra`` rather
than any collector behaviour: every module imports, every console script resolves, the CLI
dispatches, and bundled data (artifact catalog, schemas, IAM policies) is found from any cwd.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import subprocess
import sys
import tomllib
from pathlib import Path
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[1]
PACKAGES = ("collector", "ventra_ingester", "app")


def _pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def _all_modules() -> list[str]:
    names: list[str] = []
    for pkg in PACKAGES:
        mod = importlib.import_module(pkg)
        names.append(pkg)
        for info in pkgutil.walk_packages(mod.__path__, f"{pkg}."):
            # kit/templates holds files copied into kits, not importable package modules.
            if ".templates" not in info.name:
                names.append(info.name)
    return names


@pytest.mark.parametrize("module", _all_modules())
def test_every_module_imports(module: str) -> None:
    importlib.import_module(module)


@pytest.mark.parametrize("script", sorted(_pyproject()["project"]["scripts"].items()))
def test_console_scripts_resolve(script: tuple[str, str]) -> None:
    _name, target = script
    module, _, attr = target.partition(":")
    assert callable(getattr(importlib.import_module(module), attr))


def test_ventra_help_lists_subcommands(capsys: pytest.CaptureFixture[str]) -> None:
    from collector.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for sub in ("collect", "gui", "artifacts", "kit", "run", "import"):
        assert sub in out


def test_ventra_version_matches_distribution(capsys: pytest.CaptureFixture[str]) -> None:
    from collector import __version__
    from collector.cli import main

    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == f"ventra {__version__}"


def test_legacy_argv_dispatches_to_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ventra aws …`` is rewritten to ``ventra collect aws …`` and reaches the AWS runner."""
    from collector import cli

    with mock.patch.object(cli, "_run_aws", return_value=0) as run_aws:
        assert cli.main(["aws", "--case", "CASE-PKG-TEST", "--no-ingest"]) == 0
    args = run_aws.call_args.args[0]
    assert (args.command, args.cloud, args.case) == ("collect", "aws", "CASE-PKG-TEST")


def test_bundled_data_resolves_outside_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Catalog, schema and IAM lookups must not depend on the current working directory."""
    from collector import paths

    for var in ("VENTRA_ARTIFACTS_ROOT", "VENTRA_SCHEMAS_ROOT", "VENTRA_IAM_ROOT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)

    artifacts = paths.default_artifacts_root()
    assert (artifacts / "packs" / "baseline-ir-aws.yaml").is_file()
    assert paths.default_schema_path("artifact.schema.json").is_file()
    for cloud in ("aws", "azure", "gcp", "kubernetes"):
        assert paths.default_iam_policy(cloud) is not None


def test_list_packs_from_any_cwd(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from collector.cli import main

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert main(["collect", "aws", "--list-packs"]) == 0
    finally:
        os.chdir(cwd)
    assert "baseline-ir-aws" in capsys.readouterr().out


def test_python_dash_m_entry_point(tmp_path: Path) -> None:
    """``python -m collector`` works the same as the ``ventra`` script."""
    env = dict(os.environ)
    # Mirror conftest.py's sys.path setup so this works even when the editable .pth is skipped.
    roots = [str(REPO), str(REPO / "ingester"), str(REPO / "console" / "backend")]
    env["PYTHONPATH"] = os.pathsep.join([*roots, env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
    proc = subprocess.run(
        [sys.executable, "-m", "collector", "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "collect" in proc.stdout

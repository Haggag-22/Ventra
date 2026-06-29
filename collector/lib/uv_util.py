"""Bootstrap and invoke uv for Ventra installs (replaces pip in operator-facing paths)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

_UV_INSTALL_URL = "https://astral.sh/uv/install.sh"


def find_uv() -> str | None:
    found = shutil.which("uv")
    if found:
        return found
    for candidate in (
        Path.home() / ".local" / "bin" / "uv",
        Path.home() / ".cargo" / "bin" / "uv",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def ensure_uv(*, quiet: bool = False) -> str:
    """Return the uv executable, installing via the official script when missing."""
    existing = find_uv()
    if existing:
        return existing
    if os.name == "nt":
        raise SystemExit(
            "error: uv is required. Install from https://docs.astral.sh/uv/getting-started/installation/"
        )
    if not quiet:
        print("Installing uv…", file=sys.stderr)
    subprocess.run(["sh", "-c", f"curl -LsSf {_UV_INSTALL_URL} | sh"], check=True)
    uv = find_uv()
    if not uv:
        raise SystemExit(
            "error: uv install finished but uv was not found. Add ~/.local/bin to PATH and retry."
        )
    return uv


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def uv_venv(uv: str, venv_dir: Path, *, python: str | None = None) -> Path:
    cmd = [uv, "venv", str(venv_dir)]
    if python:
        cmd.extend(["--python", python])
    subprocess.check_call(cmd)
    return venv_python(venv_dir)


def uv_pip_install(
    uv: str,
    python: Path | str,
    *specs: str,
    quiet: bool = True,
    reinstall: bool = False,
    no_deps: bool = False,
) -> None:
    cmd = [uv, "pip", "install", "--python", str(python)]
    if quiet:
        cmd.append("-q")
    if reinstall:
        cmd.append("--reinstall")
    if no_deps:
        cmd.append("--no-deps")
    cmd.extend(specs)
    subprocess.check_call(cmd)

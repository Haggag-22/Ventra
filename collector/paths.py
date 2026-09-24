"""Shared path helpers for installs from source or from a pipx/PyPI wheel."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def package_dir() -> Path:
    """``collector/`` directory (source checkout or site-packages)."""
    return Path(__file__).resolve().parent


def bundled_artifacts_root() -> Path | None:
    p = package_dir() / "_artifacts"
    return p if p.is_dir() else None


def bundled_schemas_root() -> Path | None:
    p = package_dir() / "_schemas"
    return p if p.is_dir() else None


def bundled_iam_root() -> Path | None:
    p = package_dir() / "_iam_policies"
    return p if p.is_dir() else None


def bundled_console_static() -> Path | None:
    """Static console shipped inside the wheel (``collector/_console_static``)."""
    p = package_dir() / "_console_static"
    if p.is_dir() and (p / "index.html").is_file():
        return p
    env = os.environ.get("VENTRA_CONSOLE_STATIC", "").strip()
    if env:
        cand = Path(env).expanduser().resolve()
        if (cand / "index.html").is_file():
            return cand
    return None


def is_source_checkout() -> bool:
    """True when running from a git checkout that has the Next.js frontend source."""
    env = os.environ.get("VENTRA_ROOT", "").strip()
    if env and (Path(env).expanduser() / "console/frontend/package.json").is_file():
        return True
    here = package_dir()
    for candidate in (Path.cwd(), here, *here.parents):
        if (candidate / "console/frontend/package.json").is_file():
            return True
    return False


def default_artifacts_root() -> Path:
    env = os.environ.get("VENTRA_ARTIFACTS_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    bundled = bundled_artifacts_root()
    if bundled is not None:
        return bundled
    repo = package_dir().parents[0] / "artifacts"
    if repo.is_dir():
        return repo
    return Path("artifacts").resolve()


def default_schema_path(name: str = "artifact.schema.json") -> Path:
    env = os.environ.get("VENTRA_SCHEMAS_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve() / name
    bundled = bundled_schemas_root()
    if bundled is not None:
        return bundled / name
    repo = package_dir().parents[0] / "schemas" / name
    return repo


def default_iam_policy(cloud: str) -> Path | None:
    name = f"{cloud}-collector-readonly.json"
    env = os.environ.get("VENTRA_IAM_ROOT", "").strip()
    roots: list[Path] = []
    if env:
        roots.append(Path(env).expanduser())
    bundled = bundled_iam_root()
    if bundled is not None:
        roots.append(bundled)
    roots.append(package_dir().parents[0] / "docs" / "iam-policies")
    roots.append(Path("docs/iam-policies"))
    for root in roots:
        cand = root / name
        if cand.is_file():
            return cand
    return None


def user_data_root() -> Path:
    """Writable data root for packaged installs (cases, uploads, config)."""
    env = os.environ.get("VENTRA_HOME", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    if sys.platform == "darwin":
        return (Path.home() / "Library/Application Support/Ventra").resolve()
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return (Path(xdg).expanduser() / "ventra").resolve()
    return (Path.home() / ".ventra").resolve()

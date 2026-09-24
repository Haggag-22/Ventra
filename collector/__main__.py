"""Allow ``python -m collector dev`` from a fresh clone before ``pip install``."""

from __future__ import annotations

import os
import shutil
import sys

_MIN_PYTHON = (3, 11)


def _reexec_with_newer_python() -> None:
    """Re-run this module with Python 3.11+ when the default ``python3`` is too old."""
    if sys.version_info >= _MIN_PYTHON:
        return
    for cmd in ("python3.12", "python3.11", "python3"):
        path = shutil.which(cmd)
        if not path or os.path.realpath(path) == os.path.realpath(sys.executable):
            continue
        import subprocess

        ok = subprocess.run(
            [
                path,
                "-c",
                f"import sys; raise SystemExit(0 if sys.version_info >= {_MIN_PYTHON!r} else 1)",
            ],
            capture_output=True,
        ).returncode == 0
        if not ok:
            continue
        os.execv(path, [path, "-m", "collector", *sys.argv[1:]])

    print(
        "error: Ventra requires Python 3.11 or newer.\n"
        f"  Current: {sys.executable} ({sys.version.split()[0]})\n"
        "  Install:   brew install python@3.11\n"
        "  Then run:  python3.11 -m collector dev",
        file=sys.stderr,
    )
    raise SystemExit(1)


if __name__ == "__main__":
    _reexec_with_newer_python()
    from .cli import main

    raise SystemExit(main())

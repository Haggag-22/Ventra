"""Make the repo's own packages importable during tests.

Ventra ships three editable installs (``collector``, ``ventra_ingester``,
``ventra_console_backend``). Setuptools registers those through ``__editable__*.pth`` files,
and CPython **skips any ``.pth`` whose name begins with an underscore** ("Skipping hidden
.pth file", visible under ``python -v``). On such an interpreter every editable install in
the venv silently stops resolving, and `tests/ingester` / `tests/console` fail to import.

Putting the three source roots on ``sys.path`` here makes collection independent of how — or
whether — the packages were installed, for both ``uv run pytest`` and ``.venv/bin/pytest``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent

for _root in (_REPO, _REPO / "ingester", _REPO / "console" / "backend"):
    _path = str(_root)
    if _root.is_dir() and _path not in sys.path:
        sys.path.insert(0, _path)

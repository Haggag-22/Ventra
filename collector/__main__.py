"""Allow ``python -m collector dev`` from a fresh clone before ``pip install``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

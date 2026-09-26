"""Access token for the local analyst console.

The console API can read evidence, hold cloud credentials and start collections, so every
``/api`` request must prove it came from the person who launched it. The launcher opens the
browser at ``/api/session?token=…``, which trades the token for an HttpOnly cookie.

The token lives next to the saved connections (owner-only), so it survives restarts and a
bookmarked console keeps working. ``VENTRA_CONSOLE_TOKEN`` overrides it, e.g. for containers.
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

TOKEN_ENV = "VENTRA_CONSOLE_TOKEN"
TOKEN_FILE = "console-token"


def load_console_token(config_dir: Path) -> str:
    """Return the console token, creating an owner-only token file on first use."""
    env = os.environ.get(TOKEN_ENV, "").strip()
    if env:
        return env
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = config_dir / TOKEN_FILE
    try:
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_urlsafe(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process (the backend vs. its launcher) created it first; use theirs once
        # it has been written.
        for _ in range(50):
            token = path.read_text(encoding="utf-8").strip()
            if token:
                return token
            time.sleep(0.02)
        raise RuntimeError(f"console token file is empty: {path}") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    return token


def session_url(base_url: str, token: str, next_path: str = "/") -> str:
    """The link that signs a browser in to the console at ``base_url``."""
    from urllib.parse import urlencode

    return f"{base_url.rstrip('/')}/api/session?{urlencode({'token': token, 'next': next_path})}"

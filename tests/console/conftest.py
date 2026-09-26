"""Console API tests talk to the app directly; access control has its own tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _console_auth_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "console_auth", False)

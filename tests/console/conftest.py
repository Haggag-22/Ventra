"""Console API tests call the app as ``testserver``; the host check has its own tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _host_check_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "host_check", False)

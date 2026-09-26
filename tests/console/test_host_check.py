"""A web page using DNS rebinding must not reach the console API through 127.0.0.1."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "host_check", True)
    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_console_opens_without_any_login(client: TestClient) -> None:
    assert client.get("/api/cases").status_code == 200


@pytest.mark.parametrize("host", ["localhost:8081", "127.0.0.1:8000", "[::1]:8000", "LOCALHOST"])
def test_loopback_hosts_allowed(client: TestClient, host: str) -> None:
    assert client.get("/api/cases", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "192.168.1.20:8081"])
def test_foreign_hosts_rejected(client: TestClient, host: str) -> None:
    for method, path in (("GET", "/api/cases"), ("POST", "/api/runs"), ("GET", "/")):
        res = client.request(method, path, headers={"Host": host})
        assert res.status_code == 421, (method, path)


def test_forwarded_host_from_dev_proxy_is_checked(client: TestClient) -> None:
    """The Next.js dev proxy rewrites Host; the browser's host arrives in X-Forwarded-Host."""
    evil = client.get("/api/cases", headers={"X-Forwarded-Host": "evil.example:8081"})
    assert evil.status_code == 421
    ok = client.get("/api/cases", headers={"X-Forwarded-Host": "localhost:8081"})
    assert ok.status_code == 200


def test_extra_hosts_from_env(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENTRA_ALLOWED_HOSTS", "ventra.internal")
    assert client.get("/api/cases", headers={"Host": "ventra.internal"}).status_code == 200


def test_port_with_existing_listener_is_not_reused() -> None:
    """A server already answering on loopback (e.g. Apache on *:8080) makes the port busy."""
    from collector.devgui import _pick_port, _port_available

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert not _port_available(port)
        assert _pick_port(port) != port

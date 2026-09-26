"""The console API needs its token and an allowed Host, so neither local processes, the LAN
nor a DNS-rebinding web page can reach evidence, credentials or collection runs."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from collector.console_auth import load_console_token, session_url

TOKEN = "test-console-token-0123456789"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    import app.auth as auth

    monkeypatch.setattr(settings, "console_auth", True)
    monkeypatch.setenv("VENTRA_CONSOLE_TOKEN", TOKEN)
    monkeypatch.setattr(auth, "_token", None)
    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_api_without_token_is_locked(client: TestClient) -> None:
    for method, path in (
        ("GET", "/api/cases"),
        ("GET", "/api/config/connections"),
        ("POST", "/api/runs"),
        ("DELETE", "/api/cases/anything"),
    ):
        res = client.request(method, path)
        assert res.status_code == 401, (method, path)
        assert res.json()["auth_required"] is True


def test_health_stays_open_for_the_launcher(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize("bad", ["", "wrong", TOKEN + "x"])
def test_bad_tokens_rejected(client: TestClient, bad: str) -> None:
    res = client.get("/api/cases", headers={"Authorization": f"Bearer {bad}"})
    assert res.status_code == 401
    assert client.get("/api/session", params={"token": bad}).status_code == 401


def test_bearer_token_works(client: TestClient) -> None:
    res = client.get("/api/cases", headers={"Authorization": f"Bearer {TOKEN}"})
    assert res.status_code == 200


def test_session_link_sets_strict_httponly_cookie(client: TestClient) -> None:
    res = client.get("/api/session", params={"token": TOKEN, "next": "/cases"}, follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/cases"
    cookie = res.headers["set-cookie"].lower()
    assert "ventra_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    # The browser now carries the cookie on every API call.
    assert client.get("/api/cases").status_code == 200


@pytest.mark.parametrize("target", ["https://evil.example", "//evil.example", "/\\evil.example"])
def test_session_is_not_an_open_redirect(client: TestClient, target: str) -> None:
    res = client.get("/api/session", params={"token": TOKEN, "next": target}, follow_redirects=False)
    assert res.headers["location"] == "/"


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "192.168.1.20:8081"])
def test_dns_rebinding_hosts_rejected_even_with_token(client: TestClient, host: str) -> None:
    res = client.get("/api/cases", headers={"Host": host, "Authorization": f"Bearer {TOKEN}"})
    assert res.status_code == 421


@pytest.mark.parametrize("host", ["localhost:8081", "127.0.0.1:8000", "[::1]:8000"])
def test_loopback_hosts_allowed(client: TestClient, host: str) -> None:
    res = client.get("/api/cases", headers={"Host": host, "Authorization": f"Bearer {TOKEN}"})
    assert res.status_code == 200


def test_extra_hosts_from_env(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VENTRA_ALLOWED_HOSTS", "ventra.internal")
    res = client.get("/api/cases", headers={"Host": "ventra.internal", "Authorization": f"Bearer {TOKEN}"})
    assert res.status_code == 200


def test_token_file_is_created_owner_only_and_reused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VENTRA_CONSOLE_TOKEN", raising=False)
    first = load_console_token(tmp_path / "cfg")
    assert len(first) >= 32
    assert load_console_token(tmp_path / "cfg") == first  # stable across restarts
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "cfg" / "console-token").stat().st_mode) == 0o600


def test_session_url_encodes_token() -> None:
    url = session_url("http://127.0.0.1:8081/", "a+b/c", "/cases?x=1")
    assert url == "http://127.0.0.1:8081/api/session?token=a%2Bb%2Fc&next=%2Fcases%3Fx%3D1"


def test_forwarded_host_from_dev_proxy_is_checked(client: TestClient) -> None:
    """The Next.js dev proxy rewrites Host; the browser's host arrives in X-Forwarded-Host."""
    auth = {"Authorization": f"Bearer {TOKEN}"}
    evil = client.get("/api/cases", headers={**auth, "X-Forwarded-Host": "evil.example:8080"})
    assert evil.status_code == 421
    ok = client.get("/api/cases", headers={**auth, "X-Forwarded-Host": "localhost:8081"})
    assert ok.status_code == 200


def test_port_with_existing_listener_is_not_reused() -> None:
    """A server already answering on loopback (e.g. Apache on *:8080) makes the port busy."""
    import socket

    from collector.devgui import _pick_port, _port_available

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert not _port_available(port)
        assert _pick_port(port) != port

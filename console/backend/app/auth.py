"""Console access control: a per-install token and a Host allow-list.

The API reads evidence, stores cloud credentials and starts collections, and it runs on the
analyst's workstation. Binding to loopback is not enough on its own:

* any local process, or anyone on the LAN when a dev server binds all interfaces, could call it;
* a web page can reach it through DNS rebinding (its own hostname resolving to 127.0.0.1).

So every ``/api`` request needs the console token (HttpOnly cookie from ``/api/session``, or
``Authorization: Bearer`` for scripts), and every request must name an allowed ``Host``. The
``X-Ventra-Role`` RBAC header only shapes the UI after this check; it is not authentication.
"""

from __future__ import annotations

import hmac
import json
import os
from http.cookies import CookieError, SimpleCookie
from typing import Any

from collector.console_auth import load_console_token

from .config import settings

COOKIE = "ventra_session"
COOKIE_MAX_AGE = 30 * 24 * 3600
# Reachable without the token: the launcher's readiness probe and the sign-in exchange.
EXEMPT_PATHS = frozenset({"/api/health", "/api/session"})
DEFAULT_HOSTS = ("localhost", "127.0.0.1", "::1")

_token: str | None = None


def console_token() -> str:
    global _token
    if _token is None:
        _token = load_console_token(settings.config_dir)
    return _token


def token_matches(candidate: str | None) -> bool:
    return bool(candidate) and hmac.compare_digest(candidate.encode(), console_token().encode())


def allowed_hosts() -> set[str]:
    extra = os.environ.get("VENTRA_ALLOWED_HOSTS", "")
    return {*DEFAULT_HOSTS, *(h.strip().lower() for h in extra.split(",") if h.strip())}


def _hostname(host_header: str) -> str:
    """``[::1]:8000`` -> ``::1``, ``localhost:8081`` -> ``localhost``."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def safe_next(path: str | None) -> str:
    """Only same-site relative paths, so /api/session can't be used as an open redirect."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path


class ConsoleAuthMiddleware:
    """Pure ASGI (not BaseHTTPMiddleware) so streaming/SSE responses pass through untouched."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not settings.console_auth:
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        if not _hosts_allowed(headers):
            await _deny(send, 421, "Unknown host. Open the console via localhost or 127.0.0.1.")
            return
        path = scope.get("path", "")
        if path.startswith("/api/") and path not in EXEMPT_PATHS and not _authorized(headers):
            await _deny(
                send,
                401,
                "Console locked. Open the sign-in link printed by `ventra gui` "
                "(or run `ventra gui --print-link`).",
            )
            return
        await self.app(scope, receive, send)


def _hosts_allowed(headers: dict[str, str]) -> bool:
    """Check ``Host`` and, behind the Next.js dev proxy (which rewrites ``Host`` to the
    backend's own address), the browser's original host in ``X-Forwarded-Host``. Checking the
    forwarded header too can only refuse more requests, so it is safe to read unverified."""
    allowed = allowed_hosts()
    if _hostname(headers.get("host", "")) not in allowed:
        return False
    forwarded = headers.get("x-forwarded-host", "")
    return all(_hostname(h) in allowed for h in forwarded.split(",") if h.strip())


def _authorized(headers: dict[str, str]) -> bool:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and token_matches(auth[7:].strip()):
        return True
    try:
        jar = SimpleCookie(headers.get("cookie", ""))
    except CookieError:
        return False
    morsel = jar.get(COOKIE)
    return morsel is not None and token_matches(morsel.value)


async def _deny(send: Any, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail, "auth_required": status == 401}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})

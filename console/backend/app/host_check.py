"""Refuse requests that name a host other than this machine (DNS-rebinding protection).

The console has no login: it runs on the analyst's own workstation, on loopback only. But a web
page open in the same browser can still reach 127.0.0.1 by pointing its own hostname at it
(DNS rebinding) and then read evidence or saved-connection metadata, or start collections. Such
requests carry the attacker's hostname in ``Host``, so allowing only local names stops them
without the user noticing anything.
"""

from __future__ import annotations

import json
import os
from typing import Any

from .config import settings

DEFAULT_HOSTS = ("localhost", "127.0.0.1", "::1")


def allowed_hosts() -> set[str]:
    extra = os.environ.get("VENTRA_ALLOWED_HOSTS", "")
    return {*DEFAULT_HOSTS, *(h.strip().lower() for h in extra.split(",") if h.strip())}


def _hostname(host_header: str) -> str:
    """``[::1]:8000`` -> ``::1``, ``localhost:8081`` -> ``localhost``."""
    host = host_header.strip().lower()
    if host.startswith("["):
        return host[1 : host.find("]")] if "]" in host else ""
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def hosts_allowed(headers: dict[str, str]) -> bool:
    """Check ``Host`` and, behind the Next.js dev proxy (which rewrites ``Host`` to the
    backend's own address), the browser's original host in ``X-Forwarded-Host``. Checking the
    forwarded header too can only refuse more requests, so it is safe to read unverified."""
    allowed = allowed_hosts()
    if _hostname(headers.get("host", "")) not in allowed:
        return False
    forwarded = headers.get("x-forwarded-host", "")
    return all(_hostname(h) in allowed for h in forwarded.split(",") if h.strip())


class HostCheckMiddleware:
    """Pure ASGI (not BaseHTTPMiddleware) so streaming/SSE responses pass through untouched."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not settings.host_check:
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        if hosts_allowed(headers):
            await self.app(scope, receive, send)
            return
        body = json.dumps({"detail": "Unknown host. Open the console via localhost or 127.0.0.1."}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 421,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

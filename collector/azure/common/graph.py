"""Microsoft Graph read helpers (Entra ID sign-in and audit logs)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class GraphAccessDenied(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class GraphNotLicensed(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def graph_get_pages(
    token: str,
    path: str,
    *,
    params: dict[str, str] | None = None,
    max_records: int = 200_000,
) -> Iterator[dict[str, Any]]:
    """Paginate a Graph collection endpoint."""
    query = urllib.parse.urlencode(params or {})
    url = f"{GRAPH_BASE}{path}"
    if query:
        url = f"{url}?{query}"
    count = 0
    while url:
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            if exc.code in (401, 403):
                raise GraphAccessDenied(body or str(exc)) from exc
            if exc.code == 404:
                raise GraphNotLicensed(body or "Graph endpoint not available.") from exc
            raise
        for item in payload.get("value", []):
            yield item
            count += 1
            if count >= max_records:
                return
        url = payload.get("@odata.nextLink")

"""The packaged console serves real case/run/collector URLs from the static-export "_" shells."""

from __future__ import annotations

import pytest

from app.main import _rewrite_spa_path


@pytest.mark.parametrize(
    ("url", "shell"),
    [
        ("cases/CASE-2026-0042/cloudtrail/", "cases/_/cloudtrail/index.html"),
        ("cases/CASE-2026-0042", "cases/_/index.html"),
        ("runs/run-abc123/", "runs/_/index.html"),
        ("runs/new/", "runs/new/index.html"),
        ("docs/aws/collectors/cloudtrail/", "docs/aws/collectors/_/index.html"),
        ("", "index.html"),
    ],
)
def test_page_urls_map_to_placeholder_shells(url: str, shell: str) -> None:
    assert _rewrite_spa_path(url) == shell


@pytest.mark.parametrize(
    ("url", "payload"),
    [
        ("cases/CASE-2026-0042/identity/index.txt", "cases/_/identity/index.txt"),
        ("runs/run-abc123/index.txt", "runs/_/index.txt"),
        ("docs/gcp/collectors/vpc_flow/index.txt", "docs/gcp/collectors/_/index.txt"),
    ],
)
def test_rsc_payloads_map_to_the_shell_payload(url: str, payload: str) -> None:
    """Client-side navigation fetches ``index.txt``; serving HTML instead forces a full reload."""
    assert _rewrite_spa_path(url) == payload

"""OAuth consent collector and Entra normalizer."""

from __future__ import annotations

from pathlib import Path

from collector.engine.api.azure.identity.oauth_consent import OAuthConsentCollector
from collector.lib.models import CollectionContext, SourceStatus, TimeWindow
from ventra_ingester.normalizer.base import NormalizeContext
from ventra_ingester.normalizer.sources.azure_entra import normalize_oauth_consent

CTX = NormalizeContext(case_id="CASE-AZ", account_id="tenant-abc")


class _FakeCf:
    def __init__(self, *, graph=None) -> None:
        self._graph = graph or {}

    def graph_paginate(self, path, *, params=None, max_records=200_000):  # noqa: ANN001
        yield from self._graph.get(path, [])


def _ctx(tmp_path: Path, cf: _FakeCf) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    return CollectionContext(
        cloud="azure",
        account_id="tenant-abc",
        regions=[],
        time_window=TimeWindow(),
        staging=staging,
        case_id="CASE-AZ",
        tenant_id="tenant-abc",
        subscription_ids=[],
        client_factory=cf,
    )


def test_oauth_consent_collects(tmp_path: Path) -> None:
    cf = _FakeCf(
        graph={
            "oauth2PermissionGrants": [
                {
                    "clientId": "app-666",
                    "principalId": "u-1",
                    "consentType": "Principal",
                    "scope": "Directory.Read.All",
                    "resourceId": "graph",
                },
            ]
        }
    )
    result = OAuthConsentCollector(_ctx(tmp_path, cf)).collect()
    assert result.status == SourceStatus.COLLECTED
    assert result.record_count == 1


def test_normalize_oauth_grant_is_finding() -> None:
    rec = {
        "clientId": "app-666",
        "principalId": "u-1",
        "consentType": "Principal",
        "scope": "Directory.Read.All",
        "resourceId": "graph",
    }
    ev = next(iter(normalize_oauth_consent([rec], CTX)))
    assert ev.event_kind == "finding"
    assert "persistence" in ev.event_category
    assert "Directory.Read.All" in ev.message
    assert ev.ventra_source == "oauth_consent"
    assert ev.cloud_service == "entra"

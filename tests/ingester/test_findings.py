"""Tests for finding normalizers."""

from __future__ import annotations

from harbor_ingester.normalizer.base import NormalizeContext
from harbor_ingester.normalizer.sources.findings import (
    normalize_detective,
    normalize_macie,
    normalize_securityhub,
)


def test_securityhub_product_provider_from_product_name() -> None:
    ctx = NormalizeContext(case_id="c1", account_id="123")
    records = [
        {
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "Severity": {"Label": "HIGH"},
            "ProductName": "Macie",
            "Title": "Sensitive data",
            "Types": ["Software and Configuration Checks"],
        }
    ]
    ev = next(normalize_securityhub(records, ctx))
    assert ev.event_provider == "macie"
    assert ev.harbor_source == "securityhub"


def test_macie_finding_normalizer() -> None:
    ctx = NormalizeContext(case_id="c1", account_id="123")
    records = [
        {
            "updatedAt": "2026-01-02T00:00:00Z",
            "title": "S3 bucket is public",
            "type": "Policy:IAMUser/S3BucketPublic",
            "severity": {"description": "HIGH"},
            "region": "us-east-1",
        }
    ]
    ev = next(normalize_macie(records, ctx))
    assert ev.event_kind == "finding"
    assert ev.event_provider == "macie"
    assert ev.event_severity == "high"


def test_detective_investigation_normalizer() -> None:
    ctx = NormalizeContext(case_id="c1", account_id="123")
    records = [
        {
            "CreatedTime": "2026-01-03T00:00:00Z",
            "InvestigationId": "inv-1",
            "EntityArn": "arn:aws:iam::123:role/Admin",
            "EntityType": "IAMRole",
            "Severity": "HIGH",
            "_harbor_region": "us-east-1",
        }
    ]
    ev = next(normalize_detective(records, ctx))
    assert ev.event_kind == "finding"
    assert ev.event_provider == "detective"
    assert ev.event_severity == "high"

"""Manifest source entries must not stamp event counts onto config/meta sidecars."""

from __future__ import annotations

from collector.lib.models import (
    Manifest,
    Operator,
    SourceResult,
    SourceStatus,
    WrittenFile,
    _inherit_source_record_count,
)


def test_inherit_only_for_event_payloads() -> None:
    assert _inherit_source_record_count("sources/cloud_audit_admin/events.jsonl.gz")
    assert _inherit_source_record_count("sources/cloudtrail/events.jsonl.zst")
    assert not _inherit_source_record_count("sources/cloud_audit_admin/config.json")
    assert not _inherit_source_record_count("sources/cloud_audit_admin/_meta.json")


def test_add_source_result_does_not_double_count_sidecars() -> None:
    m = Manifest(
        schema_version="1",
        tool_version="0",
        case_id="CASE-TEST",
        cloud="gcp",
        account_id="proj",
        regions=[],
        operator=Operator(principal_arn="user:test"),
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:00Z",
        profile_name="demo",
        host_environment="test",
    )
    m.add_source_result(
        SourceResult(
            name="cloud_audit_admin",
            status=SourceStatus.COLLECTED,
            record_count=3_392_263,
            files=[
                WrittenFile(
                    path="sources/cloud_audit_admin/events.jsonl.gz",
                    sha256="a" * 64,
                    bytes=1000,
                ),
                WrittenFile(
                    path="sources/cloud_audit_admin/config.json",
                    sha256="b" * 64,
                    bytes=388,
                ),
                WrittenFile(
                    path="sources/cloud_audit_admin/_meta.json",
                    sha256="c" * 64,
                    bytes=345,
                ),
            ],
        )
    )
    by_path = {e["path"]: e for e in m.sources}
    assert by_path["sources/cloud_audit_admin/events.jsonl.gz"]["record_count"] == 3_392_263
    assert by_path["sources/cloud_audit_admin/config.json"]["record_count"] is None
    assert by_path["sources/cloud_audit_admin/_meta.json"]["record_count"] is None

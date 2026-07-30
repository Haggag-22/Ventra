"""CloudTrail collection_source parameter helpers."""

from __future__ import annotations

from collector.lib.scoping import (
    CLOUDTRAIL_SOURCE_BUCKET,
    CLOUDTRAIL_SOURCE_LOOKUP,
    CLOUDTRAIL_SOURCE_TRAIL,
    cloudtrail_collection_source,
    synthetic_cloudtrail_trails_from_buckets,
)


def test_cloudtrail_collection_source_defaults_to_trail() -> None:
    assert cloudtrail_collection_source({}) == CLOUDTRAIL_SOURCE_TRAIL


def test_cloudtrail_collection_source_normalizes_lookup() -> None:
    assert cloudtrail_collection_source({"collection_source": "lookup"}) == CLOUDTRAIL_SOURCE_LOOKUP
    assert (
        cloudtrail_collection_source({"collection_source": "lookup_events"})
        == CLOUDTRAIL_SOURCE_LOOKUP
    )


def test_cloudtrail_collection_source_normalizes_bucket() -> None:
    assert cloudtrail_collection_source({"collection_source": "s3"}) == CLOUDTRAIL_SOURCE_BUCKET
    assert cloudtrail_collection_source({"collection_source": "bucket"}) == CLOUDTRAIL_SOURCE_BUCKET


def test_synthetic_trails_from_bucket_params() -> None:
    trails = synthetic_cloudtrail_trails_from_buckets(
        {"s3_bucket_names": ["logs-a", "logs-b"], "s3_prefixes": ["prefix/"]},
        ["us-east-1"],
    )
    assert len(trails) == 2
    assert trails[0]["S3BucketName"] == "logs-a"
    assert trails[0]["S3KeyPrefix"] == "prefix/"
    assert trails[1]["S3BucketName"] == "logs-b"
    assert trails[1]["S3KeyPrefix"] == "prefix/"


def test_synthetic_trails_empty_without_buckets() -> None:
    assert synthetic_cloudtrail_trails_from_buckets({}, ["us-east-1"]) == []

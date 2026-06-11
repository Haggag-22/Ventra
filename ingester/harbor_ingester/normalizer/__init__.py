"""Normalization: map source records into the unified event schema.

Event-producing sources (cloudtrail, sts, guardduty, securityhub, vpc_flow, config) are
mapped to flat unified-event rows for ``events.parquet``. Inventory sources (iam, ec2, s3,
kms, secrets, account, waf, lambda) are kept as snapshots for the console's Resources and
Identity panels — see :mod:`harbor_ingester.normalizer.inventory`.
"""

from .base import UnifiedEvent, SOURCE_NORMALIZERS, normalize_source
from . import sources  # noqa: F401  (registers all source normalizers)

__all__ = ["UnifiedEvent", "SOURCE_NORMALIZERS", "normalize_source"]

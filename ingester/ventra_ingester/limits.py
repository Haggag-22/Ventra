"""Configurable size limits for ingest and package handling."""

from __future__ import annotations

import os

# Maximum decompressed tar bytes when buffering a package (default ~20 GB).
MAX_DECOMPRESS_BYTES = int(os.environ.get("VENTRA_MAX_DECOMPRESS_BYTES", str(20 * 1024**3)))

# Parquet row batch size during streaming ingest.
INGEST_BATCH_SIZE = int(os.environ.get("VENTRA_INGEST_BATCH_SIZE", "5000"))

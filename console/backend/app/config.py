"""Backend configuration. Everything is local and offline by design."""

from __future__ import annotations

import os
from pathlib import Path


class Settings:
    # Root of the case store the ingester writes to.
    case_store: Path = Path(os.environ.get("HARBOR_CASE_STORE", "./cases")).resolve()
    # Where uploaded packages are staged before ingest.
    upload_dir: Path = Path(os.environ.get("HARBOR_UPLOAD_DIR", "./.harbor-uploads")).resolve()
    # CORS origins for the frontend dev server.
    cors_origins: list[str] = os.environ.get(
        "HARBOR_CORS", "http://localhost:3000,http://localhost:8080"
    ).split(",")
    # Telemetry is OFF and not configurable to on. Stated explicitly for auditors.
    telemetry: bool = False


settings = Settings()
settings.upload_dir.mkdir(parents=True, exist_ok=True)

"""Backend configuration. Everything is local and offline by design."""

from __future__ import annotations

import os
from pathlib import Path


def _default_artifacts_root() -> Path:
    """Locate the artifact YAML catalog regardless of the backend's working directory.

    Honors ``VENTRA_ARTIFACTS_ROOT``; otherwise derives it from the installed ``collector``
    package (``<repo>/artifacts``), falling back to ``./artifacts``.
    """
    env = os.environ.get("VENTRA_ARTIFACTS_ROOT")
    if env:
        return Path(env).resolve()
    try:
        import collector

        cand = Path(collector.__file__).resolve().parents[1] / "artifacts"
        if cand.is_dir():
            return cand
    except Exception:
        pass
    return Path("artifacts").resolve()


class Settings:
    # Root of the case store the ingester writes to.
    case_store: Path = Path(os.environ.get("VENTRA_CASE_STORE", "./cases")).resolve()
    # Root of the artifact YAML catalog the Acquire tab and kit builder read.
    artifacts_root: Path = _default_artifacts_root()
    # Where uploaded packages are staged before ingest.
    upload_dir: Path = Path(os.environ.get("VENTRA_UPLOAD_DIR", "./.ventra-uploads")).resolve()
    # Hard cap on an uploaded evidence package, in MB. Streamed to disk; the request is
    # rejected once the limit is exceeded so a large upload can't exhaust memory or disk.
    max_upload_mb: int = int(os.environ.get("VENTRA_MAX_UPLOAD_MB", "4096"))
    # CORS origins for the frontend dev server.
    cors_origins: list[str] = os.environ.get(
        "VENTRA_CORS", "http://localhost:3000,http://localhost:8080"
    ).split(",")
    # Telemetry is OFF and not configurable to on. Stated explicitly for auditors.
    telemetry: bool = False


settings = Settings()
settings.upload_dir.mkdir(parents=True, exist_ok=True)

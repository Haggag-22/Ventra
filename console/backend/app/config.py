"""Backend configuration. Everything is local and offline by design."""

from __future__ import annotations

import os
from pathlib import Path


def _default_data_root() -> Path:
    env = os.environ.get("VENTRA_HOME", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    # Packaged / pipx installs: keep state under the user data dir, not cwd.
    try:
        from collector.paths import bundled_console_static, is_source_checkout, user_data_root

        if bundled_console_static() is not None or not is_source_checkout():
            return user_data_root()
    except Exception:
        pass
    return Path.cwd().resolve()


def _default_artifacts_root() -> Path:
    """Locate the artifact YAML catalog regardless of the backend's working directory."""
    env = os.environ.get("VENTRA_ARTIFACTS_ROOT")
    if env:
        return Path(env).resolve()
    try:
        from collector.paths import default_artifacts_root

        return default_artifacts_root()
    except Exception:
        pass
    return Path("artifacts").resolve()


_DATA = _default_data_root()


class Settings:
    # Root of the case store the ingester writes to.
    case_store: Path = Path(os.environ.get("VENTRA_CASE_STORE", str(_DATA / "cases"))).resolve()
    # Root of the artifact YAML catalog the Acquire tab and kit builder read.
    artifacts_root: Path = _default_artifacts_root()
    # Where uploaded packages are staged before ingest.
    upload_dir: Path = Path(os.environ.get("VENTRA_UPLOAD_DIR", str(_DATA / ".ventra-uploads"))).resolve()
    # Hard cap on an uploaded evidence package, in MB. Streamed to disk; the request is
    # rejected once the limit is exceeded so a large upload can't exhaust memory or disk.
    max_upload_mb: int = int(os.environ.get("VENTRA_MAX_UPLOAD_MB", "20480"))
    # CORS origins for the frontend dev server.
    cors_origins: list[str] = os.environ.get(
        "VENTRA_CORS", "http://localhost:3000,http://localhost:8080"
    ).split(",")
    # Require the console token on /api and an allowed Host header (see app.auth). Only turn
    # this off for tests or behind your own authenticating proxy.
    console_auth: bool = os.environ.get("VENTRA_CONSOLE_AUTH", "on").strip().lower() not in (
        "0",
        "off",
        "false",
        "no",
    )
    # Telemetry is OFF and not configurable to on. Stated explicitly for auditors.
    telemetry: bool = False
    # S3 prefix polled by Import from S3 in the console (s3://bucket/prefix/).
    ingest_s3_prefix: str = os.environ.get("VENTRA_INGEST_S3_PREFIX", "").strip()
    ingest_download_dir: Path = Path(
        os.environ.get("VENTRA_INGEST_DOWNLOAD_DIR", str(_DATA / ".ventra-ingest-watch"))
    ).resolve()
    _ingest_state = os.environ.get("VENTRA_INGEST_STATE_FILE", "").strip()
    ingest_state_file: Path | None = Path(_ingest_state).resolve() if _ingest_state else None
    # Saved connections and collection profiles for the Configuration section.
    config_dir: Path = Path(os.environ.get("VENTRA_CONFIG_DIR", str(_DATA / ".ventra-config"))).resolve()
    # File-backed collection run state (matrix + SSE events).
    runs_dir: Path = Path(os.environ.get("VENTRA_RUNS_DIR", str(_DATA / ".ventra-runs"))).resolve()
    # Optional SIEM drop zone: export writes NDJSON here for Logstash/Filebeat/forwarders.
    # Unset = download-only. Never holds SIEM credentials — shippers watch this path.
    _export_drop = os.environ.get("VENTRA_EXPORT_DROP_DIR", "").strip()
    export_drop_dir: Path | None = Path(_export_drop).resolve() if _export_drop else None


settings = Settings()
settings.upload_dir.mkdir(parents=True, exist_ok=True)
settings.config_dir.mkdir(parents=True, exist_ok=True)
settings.runs_dir.mkdir(parents=True, exist_ok=True)
settings.case_store.mkdir(parents=True, exist_ok=True)
if settings.export_drop_dir is not None:
    settings.export_drop_dir.mkdir(parents=True, exist_ok=True)

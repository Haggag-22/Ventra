"""Ventra Collection Kit (``.kit``) format — load, validate, and expiry checks."""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KIT_FORMAT = "ventra.kit"
KIT_FORMAT_VERSION = "1"
CREDENTIALS_META = "credentials/meta.json"


class KitError(Exception):
    """Invalid or unusable kit."""


class KitExpiredError(KitError):
    """Embedded provider credential (or kit TTL) has expired."""


def _parse_iso(value: str) -> datetime:
    raw = (value or "").strip()
    if not raw:
        raise KitError("missing timestamp")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _plural(n: int, unit: str) -> str:
    return f"{n} {unit}" if n == 1 else f"{n} {unit}s"


def human_duration(seconds: float) -> str:
    """Configured lifetimes in words: ``7 days``, ``36 hours``, ``1 hour``, ``15 minutes``."""
    total = max(0, int(seconds))
    if total >= 2 * 86400 and total % 86400 == 0:
        return _plural(total // 86400, "day")
    if total >= 3600:
        hours, rem = divmod(total, 3600)
        if rem < 60:
            return _plural(hours, "hour")
        return f"{hours}h {rem // 60}m"
    return _plural(max(1, total // 60), "minute")


def short_remaining(seconds: float) -> str:
    """Time left, compact: ``6d 23h``, ``11h 59m``, ``42m``, ``<1m``."""
    total = int(seconds)
    if total < 60:
        return "<1m"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


@dataclass
class KitCredentialMeta:
    provider: str
    kind: str
    expires_at: str
    path: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def expiry(self) -> datetime:
        return _parse_iso(self.expires_at)

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expiry()


@dataclass
class KitManifest:
    """Top-level ``kit.json`` for a Collection Kit."""

    kit_id: str
    case_id: str
    cloud: str
    ventra_version: str
    created_at: str
    expires_at: str
    kit_name: str = ""
    collectors: list[str] = field(default_factory=list)
    credential: KitCredentialMeta | None = None
    format: str = KIT_FORMAT
    format_version: str = KIT_FORMAT_VERSION
    raw: dict[str, Any] = field(default_factory=dict)

    def expiry(self) -> datetime:
        return _parse_iso(self.expires_at)

    def effective_expiry(self) -> datetime:
        """When the kit stops being runnable: the earlier of kit and credential expiry."""
        exp = self.expiry()
        if self.credential:
            exp = min(exp, self.credential.expiry())
        return exp

    @property
    def limited_by(self) -> str:
        """``kit``, ``credential``, ``static_secret``, or ``""`` for kits built before this was recorded."""
        if not self.credential:
            return "kit"
        return str(self.credential.details.get("limited_by") or "")

    @property
    def lifetime_note(self) -> str:
        if not self.credential:
            return ""
        return str(self.credential.details.get("lifetime_note") or "")

    @property
    def kit_ttl_seconds(self) -> int | None:
        raw = self.credential.details.get("kit_ttl_seconds") if self.credential else None
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.effective_expiry()


@dataclass
class OpenKit:
    """Extracted kit directory + parsed manifest (caller must close / cleanup)."""

    root: Path
    manifest: KitManifest
    _tmpdir: tempfile.TemporaryDirectory[str] | None = None

    @property
    def acquisition_path(self) -> Path:
        return self.root / "acquisition.yaml"

    @property
    def credentials_dir(self) -> Path:
        return self.root / "credentials"

    def close(self) -> None:
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def __enter__(self) -> OpenKit:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def load_kit_manifest(data: dict[str, Any]) -> KitManifest:
    if not isinstance(data, dict):
        raise KitError("kit.json must be a JSON object")
    fmt = str(data.get("format") or "").strip()
    if fmt and fmt != KIT_FORMAT:
        raise KitError(f"unsupported kit format {fmt!r} (expected {KIT_FORMAT!r})")
    required = ("kit_id", "case_id", "cloud", "ventra_version", "created_at", "expires_at")
    missing = [k for k in required if not str(data.get(k) or "").strip()]
    if missing:
        raise KitError(f"kit.json missing required fields: {', '.join(missing)}")

    cred_raw = data.get("credential")
    cred: KitCredentialMeta | None = None
    if isinstance(cred_raw, dict) and cred_raw:
        expires = str(cred_raw.get("expires_at") or data.get("expires_at") or "").strip()
        if not expires:
            raise KitError("credential.expires_at is required")
        cred = KitCredentialMeta(
            provider=str(cred_raw.get("provider") or data.get("cloud") or "").strip().lower(),
            kind=str(cred_raw.get("kind") or "embedded").strip(),
            expires_at=expires,
            path=str(cred_raw.get("path") or "").strip(),
            details={
                k: v for k, v in cred_raw.items() if k not in {"provider", "kind", "expires_at", "path"}
            },
        )

    collectors = data.get("collectors") or []
    if not isinstance(collectors, list):
        raise KitError("kit.json collectors must be a list")

    return KitManifest(
        kit_id=str(data["kit_id"]).strip(),
        case_id=str(data["case_id"]).strip(),
        cloud=str(data["cloud"]).strip().lower(),
        ventra_version=str(data["ventra_version"]).strip(),
        created_at=str(data["created_at"]).strip(),
        expires_at=str(data["expires_at"]).strip(),
        kit_name=str(data.get("kit_name") or "").strip(),
        collectors=[str(c).strip() for c in collectors if str(c).strip()],
        credential=cred,
        format=fmt or KIT_FORMAT,
        format_version=str(data.get("format_version") or KIT_FORMAT_VERSION),
        raw=dict(data),
    )


def read_kit_manifest(path: Path) -> KitManifest:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KitError(f"cannot read kit.json: {exc}") from exc
    return load_kit_manifest(data)


def assert_kit_usable(manifest: KitManifest, *, now: datetime | None = None) -> None:
    """Raise :class:`KitExpiredError` if the kit or embedded credential is past expiry."""
    now = now or utcnow()
    if not manifest.is_expired(now=now):
        return
    raise KitExpiredError(
        f"This kit expired at {manifest.effective_expiry():%Y-%m-%d %H:%M} UTC. "
        "Download a fresh kit from Acquire in the Ventra console."
    )


def open_kit(kit_path: Path) -> OpenKit:
    """Open a ``.kit`` archive (zip) or an already-extracted kit directory."""
    path = kit_path.expanduser().resolve()
    if not path.exists():
        raise KitError(f"kit not found: {path}")

    if path.is_dir():
        manifest_path = path / "kit.json"
        if not manifest_path.is_file():
            raise KitError(f"directory is not a Ventra kit (missing kit.json): {path}")
        manifest = read_kit_manifest(manifest_path)
        if not (path / "acquisition.yaml").is_file():
            raise KitError(f"kit missing acquisition.yaml: {path}")
        return OpenKit(root=path, manifest=manifest, _tmpdir=None)

    try:
        head = path.read_bytes()[:64]
    except PermissionError as exc:
        raise KitError(
            f"cannot read kit (macOS permission denied): {path}. "
            "Copy it into the Ventra folder (e.g. ~/Desktop/Ventra/) and run from there, "
            "or grant Full Disk Access to your terminal / Cursor."
        ) from exc
    except OSError as exc:
        raise KitError(f"cannot read kit: {path} ({exc})") from exc

    if not zipfile.is_zipfile(path):
        hint = ""
        if head.startswith(b"{") or head.startswith(b"["):
            hint = " File looks like JSON (a failed API response may have been saved)."
        elif head.startswith(b"<"):
            hint = " File looks like HTML (browser/error page), not a kit."
        elif not head.startswith(b"PK"):
            hint = f" Expected a ZIP kit (PK…); starts with {head[:16]!r}."
        raise KitError(f"not a Ventra kit archive: {path}.{hint}")

    tmp = tempfile.TemporaryDirectory(prefix="ventra-kit-run-")
    root = Path(tmp.name)
    try:
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(root)
        # Support a single top-level folder inside the zip.
        entries = [p for p in root.iterdir() if p.name != "__MACOSX"]
        if len(entries) == 1 and entries[0].is_dir() and (entries[0] / "kit.json").is_file():
            root = entries[0]
        manifest_path = root / "kit.json"
        if not manifest_path.is_file():
            raise KitError("kit archive missing kit.json")
        if not (root / "acquisition.yaml").is_file():
            raise KitError("kit archive missing acquisition.yaml")
        manifest = read_kit_manifest(manifest_path)
    except Exception:
        tmp.cleanup()
        raise
    return OpenKit(root=root, manifest=manifest, _tmpdir=tmp)


def write_kit_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def copy_tree_into_zip(staging: Path, out_kit: Path) -> Path:
    """Zip ``staging`` into ``out_kit`` (``.kit`` is a zip archive)."""
    out_kit.parent.mkdir(parents=True, exist_ok=True)
    if out_kit.exists():
        out_kit.unlink()
    with zipfile.ZipFile(out_kit, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(staging).as_posix())
    return out_kit


def ensure_empty_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path

"""File-backed configuration store for connections and collection profiles."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

# Connection fields that hold credentials. They stay on disk (the collectors need them) but
# never leave the backend: API responses carry only which ones are set.
SECRET_FIELDS = (
    "aws_secret_access_key",
    "aws_session_token",
    "azure_client_secret",
    "azure_client_certificate_content",
    "gcp_service_account_json",
    "kubeconfig_content",
)


def public_connection(conn: dict[str, Any]) -> dict[str, Any]:
    """A connection as the API returns it: secrets removed, ``stored_secrets`` lists what is set."""
    out = {k: v for k, v in conn.items() if k not in SECRET_FIELDS}
    out["stored_secrets"] = [k for k in SECRET_FIELDS if conn.get(k)]
    return out


class ConfigNotFound(Exception):
    pass


class ConfigStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.connections_path = self.root / "connections.json"
        self.profiles_path = self.root / "profiles.json"
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Owner-only access for the store (and files written by older versions)."""
        if os.name != "posix":
            return
        for path, mode in (
            (self.root, 0o700),
            (self.connections_path, 0o600),
            (self.profiles_path, 0o600),
        ):
            try:
                if path.exists() and (path.stat().st_mode & 0o777) != mode:
                    path.chmod(mode)
            except OSError:
                pass  # not ours to change (e.g. read-only mount); nothing more we can do

    def _read(self, path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, path: Path, items: list[dict[str, Any]]) -> None:
        """Write atomically, owner read/write only: the file holds cloud credentials."""
        tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(items, fh, indent=2)
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def list_connections(self) -> list[dict[str, Any]]:
        return self._read(self.connections_path)

    def get_connection(self, conn_id: str) -> dict[str, Any]:
        item = next((c for c in self.list_connections() if c.get("id") == conn_id), None)
        if item is None:
            raise ConfigNotFound(f"Connection not found: {conn_id}")
        return item

    def create_connection(self, data: dict[str, Any]) -> dict[str, Any]:
        from datetime import datetime, timezone

        items = self.list_connections()
        entry = {
            "id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        items.append(entry)
        self._write(self.connections_path, items)
        return entry

    def update_connection(self, conn_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        items = self.list_connections()
        for i, item in enumerate(items):
            if item.get("id") == conn_id:
                updated = {**item, **patch, "id": conn_id}
                items[i] = updated
                self._write(self.connections_path, items)
                return updated
        raise ConfigNotFound(f"Connection not found: {conn_id}")

    def delete_connection(self, conn_id: str) -> None:
        items = [c for c in self.list_connections() if c.get("id") != conn_id]
        if len(items) == len(self._read(self.connections_path)):
            raise ConfigNotFound(f"Connection not found: {conn_id}")
        self._write(self.connections_path, items)

    def list_profiles(self) -> list[dict[str, Any]]:
        return self._read(self.profiles_path)

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        item = next((p for p in self.list_profiles() if p.get("id") == profile_id), None)
        if item is None:
            raise ConfigNotFound(f"Profile not found: {profile_id}")
        return item

    def create_profile(self, data: dict[str, Any]) -> dict[str, Any]:
        items = self.list_profiles()
        entry = {"id": str(uuid.uuid4()), **data}
        items.append(entry)
        self._write(self.profiles_path, items)
        return entry

    def update_profile(self, profile_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        items = self.list_profiles()
        for i, item in enumerate(items):
            if item.get("id") == profile_id:
                updated = {**item, **patch, "id": profile_id}
                items[i] = updated
                self._write(self.profiles_path, items)
                return updated
        raise ConfigNotFound(f"Profile not found: {profile_id}")

    def delete_profile(self, profile_id: str) -> None:
        items = [p for p in self.list_profiles() if p.get("id") != profile_id]
        if len(items) == len(self._read(self.profiles_path)):
            raise ConfigNotFound(f"Profile not found: {profile_id}")
        self._write(self.profiles_path, items)


from .config import settings

config_store = ConfigStore(settings.config_dir)

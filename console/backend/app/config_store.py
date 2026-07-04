"""File-backed configuration store for connections and collection profiles."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any


class ConfigNotFound(Exception):
    pass


class ConfigStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.connections_path = self.root / "connections.json"
        self.profiles_path = self.root / "profiles.json"

    def _read(self, path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        return json.loads(path.read_text(encoding="utf-8"))

    def _write(self, path: Path, items: list[dict[str, Any]]) -> None:
        path.write_text(json.dumps(items, indent=2), encoding="utf-8")

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

"""Saved cloud credentials stay private: owner-only on disk and never returned by the API."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "console" / "backend"))

from app.config_store import SECRET_FIELDS, ConfigStore, public_connection  # noqa: E402
from app.main import app  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")

AWS = {
    "name": "prod",
    "platform": "aws",
    "auth_method": "credentials",
    "aws_access_key_id": "AKIAEXAMPLEEXAMPLE00",
    "aws_secret_access_key": "super-secret-value",
    "aws_session_token": "session-token-value",
}


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    import app.config_store as cs_mod
    import app.main as main_mod

    cs_mod.config_store = ConfigStore(tmp_path / "config")
    main_mod.config_store = cs_mod.config_store
    return TestClient(app)


def test_public_connection_strips_every_secret() -> None:
    conn = {"id": "1", **{f: "x" for f in SECRET_FIELDS}, "aws_access_key_id": "AKIA"}
    out = public_connection(conn)
    assert not set(SECRET_FIELDS) & set(out)
    assert out["stored_secrets"] == list(SECRET_FIELDS)
    assert out["aws_access_key_id"] == "AKIA"  # identifiers are not secrets


@posix_only
def test_store_files_are_owner_only(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "config")
    store.create_connection(dict(AWS))
    assert _mode(store.root) == 0o700
    assert _mode(store.connections_path) == 0o600
    assert not list(store.root.glob(".*.tmp"))  # atomic write leaves nothing behind


@posix_only
def test_existing_world_readable_store_is_tightened(tmp_path: Path) -> None:
    root = tmp_path / "config"
    root.mkdir(mode=0o755)
    legacy = root / "connections.json"
    legacy.write_text(json.dumps([{"id": "1", **AWS}]))
    legacy.chmod(0o644)

    ConfigStore(root)
    assert _mode(root) == 0o700
    assert _mode(legacy) == 0o600


def test_api_never_returns_secret_values(client: TestClient) -> None:
    created = client.post("/api/config/connections", json=AWS)
    assert created.status_code == 200, created.text
    conn_id = created.json()["id"]

    patched = client.patch(f"/api/config/connections/{conn_id}", json={"name": "renamed"})
    listed = client.get("/api/config/connections")

    for body in (created.json(), patched.json(), *listed.json()["connections"]):
        text = json.dumps(body)
        assert "super-secret-value" not in text
        assert "session-token-value" not in text
        assert body["stored_secrets"] == ["aws_secret_access_key", "aws_session_token"]


def test_edit_without_secret_keeps_stored_secret(client: TestClient) -> None:
    """The edit wizard omits secret fields it didn't change; the saved value must survive."""
    import app.config_store as cs_mod

    conn_id = client.post("/api/config/connections", json=AWS).json()["id"]
    client.patch(f"/api/config/connections/{conn_id}", json={"name": "renamed"})
    stored = cs_mod.config_store.get_connection(conn_id)
    assert stored["aws_secret_access_key"] == "super-secret-value"
    assert stored["name"] == "renamed"

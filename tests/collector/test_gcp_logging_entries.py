"""Tests for Cloud Logging entry serialization in the GCP client factory."""

from __future__ import annotations

from types import SimpleNamespace

from collector.clouds.gcp.client_factory import _entry_to_dict, _enum_name, _mapping_to_dict


def test_enum_name_accepts_string_or_enum() -> None:
    assert _enum_name("INFO") == "INFO"
    assert _enum_name(SimpleNamespace(name="WARNING")) == "WARNING"
    assert _enum_name(None) == ""


def test_mapping_to_dict_handles_none() -> None:
    assert _mapping_to_dict(None) == {}


def test_entry_to_dict_prefers_to_api_repr() -> None:
    entry = SimpleNamespace(
        to_api_repr=lambda: {
            "logName": "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
            "severity": "INFO",
            "protoPayload": {"methodName": "google.api.method"},
        }
    )
    out = _entry_to_dict(entry)
    assert out["logName"].endswith("activity")
    assert out["protoPayload"]["methodName"] == "google.api.method"


def test_entry_to_dict_string_severity_and_none_labels() -> None:
    entry = SimpleNamespace(
        log_name="projects/p/logs/cloudaudit.googleapis.com%2Factivity",
        timestamp=None,
        severity="INFO",
        insert_id="abc123",
        resource=SimpleNamespace(type="global", labels=None),
        labels=None,
        payload=None,
        proto_payload=None,
        text_payload="hello",
        json_payload=None,
    )
    out = _entry_to_dict(entry)
    assert out["severity"] == "INFO"
    assert out["resource"]["labels"] == {}
    assert out["labels"] == {}
    assert out["textPayload"] == "hello"


def test_entry_to_dict_json_payload_mapping() -> None:
    entry = SimpleNamespace(
        log_name="projects/p/logs/compute.googleapis.com%2Frequests",
        timestamp=None,
        severity=SimpleNamespace(name="DEFAULT"),
        insert_id="id1",
        resource=SimpleNamespace(type="http_load_balancer", labels={"url_map_name": "web"}),
        labels={"key": "value"},
        payload=None,
        proto_payload=None,
        text_payload=None,
        json_payload={"cacheLookup": True, "cacheHit": False},
    )
    out = _entry_to_dict(entry)
    assert out["jsonPayload"] == {"cacheLookup": True, "cacheHit": False}
    assert out["resource"]["labels"]["url_map_name"] == "web"

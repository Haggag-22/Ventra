"""GCP client connectivity handling: DNS resolver + clear unreachable errors."""

from __future__ import annotations

import os

import pytest
from collector.clouds.gcp.client_factory import (
    GcpUnreachable,
    _raise_if_unreachable,
)
from google.api_core import exceptions as gcp_exc


def test_grpc_dns_resolver_forced_native() -> None:
    # Importing the client factory forces the OS resolver so gRPC doesn't cancel DNS on
    # macOS/VPN. (setdefault, so an operator override is respected.)
    assert os.environ.get("GRPC_DNS_RESOLVER") == "native"


def test_retry_error_becomes_clear_unreachable() -> None:
    err = gcp_exc.RetryError(
        "Timeout of 60.0s exceeded, last exception: 503 ... DNS query cancelled", None
    )
    with pytest.raises(GcpUnreachable) as exc:
        _raise_if_unreachable("cloudresourcemanager.googleapis.com", err)
    msg = str(exc.value)
    assert "cloudresourcemanager.googleapis.com" in msg
    assert "network" in msg.lower() and "permission" in msg.lower()  # steers away from IAM


def test_service_unavailable_and_dns_text_wrapped() -> None:
    with pytest.raises(GcpUnreachable):
        _raise_if_unreachable("h", gcp_exc.ServiceUnavailable("backend unavailable"))
    with pytest.raises(GcpUnreachable):
        # a generic API error whose text mentions DNS is still treated as unreachable
        _raise_if_unreachable("h", gcp_exc.GoogleAPICallError("address lookup failed: dns"))


def test_non_transport_errors_pass_through() -> None:
    # Permission / not-found style failures must NOT be relabelled as connectivity issues.
    assert _raise_if_unreachable("h", gcp_exc.NotFound("no such project")) is None
    assert _raise_if_unreachable("h", gcp_exc.PermissionDenied("caller lacks role")) is None

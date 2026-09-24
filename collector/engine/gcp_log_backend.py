"""GCP log collection backend — how logging collectors read records.

Configured in ``acquisition.yaml`` as ``gcp_log_backend`` and chosen in the Acquire UI.
Ventra is read-only: ``setup_required`` means the *client admin* creates sinks/export
before collection; the collector never creates buckets or sinks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Collectors that pull rows via Cloud Logging API or GCS archive.
GCP_LOGGING_COLLECTOR_IDS: frozenset[str] = frozenset(
    {
        "cloud_audit_admin",
        "cloud_audit_system",
        "cloud_audit_data",
        "login_events",
        "vpc_flow",
        "firewall_logs",
        "cloud_nat",
        "load_balancer",
        "cloud_cdn",
        "api_gateway",
        "cloud_dns",
        "vm_logs",
        "cloud_functions",
        "storage_access",
        "bigquery_audit",
        "cloud_sql",
        "secret_manager",
        "cloud_monitoring",
        "cloud_armor",
        "gke_audit",
    }
)

_EXTRA_IAM_BY_MODE: dict[str, frozenset[str]] = {
    "logging_api": frozenset({"logging.logEntries.list"}),
    "gcs": frozenset(
        {
            "storage.buckets.get",
            "storage.objects.get",
            "storage.objects.list",
        }
    ),
}

_LOGGING_API_ONLY: frozenset[str] = frozenset(
    {
        "logging.logEntries.list",
        "logging.logs.list",
    }
)

_COLLECTOR_GCS_PREFIX_HINTS: dict[str, tuple[str, ...]] = {
    "cloud_audit_admin": ("cloudaudit.googleapis.com/activity/",),
    "cloud_audit_system": ("cloudaudit.googleapis.com/system_event/",),
    "cloud_audit_data": ("cloudaudit.googleapis.com/data_access/",),
    "login_events": ("cloudaudit.googleapis.com/data_access/",),
    "storage_access": ("cloudaudit.googleapis.com/data_access/",),
    "bigquery_audit": ("cloudaudit.googleapis.com/data_access/",),
    "secret_manager": ("cloudaudit.googleapis.com/data_access/",),
    "vpc_flow": (
        "compute.googleapis.com/vpc_flows/",
        "networkmanagement.googleapis.com/vpc_flows/",
    ),
    "firewall_logs": ("compute.googleapis.com/firewall/",),
    "cloud_nat": ("compute.googleapis.com/nat_flows/",),
    "load_balancer": ("requests/", "compute.googleapis.com/requests/"),
    "cloud_cdn": ("requests/", "compute.googleapis.com/requests/"),
    "cloud_armor": ("requests/", "compute.googleapis.com/requests/"),
    "api_gateway": ("apigateway.googleapis.com/requests/",),
    "cloud_dns": ("dns.googleapis.com/dns_queries/",),
    "vm_logs": (
        "syslog/",
        "auth/",
        "authlog/",
        "secure/",
        "messages/",
        "winevt.raw/",
        "windows_event_log/",
        "google_metadata_script_runner/",
    ),
    "gke_audit": ("container.googleapis.com/apiserver/",),
    "cloud_sql": ("cloudsql.googleapis.com/",),
    "cloud_monitoring": ("monitoring.googleapis.com/",),
    "cloud_functions": ("cloudfunctions.googleapis.com/cloud-functions/",),
}

_COLLECTOR_GCS_UNION: frozenset[str] = frozenset({"vpc_flow", "vm_logs", "cloud_sql"})

GCP_SUBSET_OF: dict[str, str] = {
    "login_events": "cloud_audit_data",
    "storage_access": "cloud_audit_data",
    "bigquery_audit": "cloud_audit_data",
    "secret_manager": "cloud_audit_data",
    "cloud_cdn": "load_balancer",
    "cloud_armor": "load_balancer",
}

_SHARED_GROUP_FILTERS: dict[str, str] = {
    "cloud_audit_data": 'logName:"cloudaudit.googleapis.com%2Fdata_access"',
    "load_balancer": 'resource.type="http_load_balancer" AND logName:"requests"',
}


def deduplicate_gcp_selection(selected: list[str]) -> dict[str, str]:
    chosen = set(selected)
    return {
        subset: broad
        for subset, broad in GCP_SUBSET_OF.items()
        if subset in chosen and broad in chosen
    }


def shared_log_read_groups(run_collectors: list[str]) -> dict[str, dict[str, Any]]:
    members: dict[str, list[str]] = {}
    for name in run_collectors:
        broad = GCP_SUBSET_OF.get(name)
        if broad is not None and broad not in run_collectors:
            members.setdefault(broad, []).append(name)
    out: dict[str, dict[str, Any]] = {}
    for broad, subs in members.items():
        if len(subs) < 2:
            continue
        for name in subs:
            out[name] = {
                "group": broad,
                "log_filter": _SHARED_GROUP_FILTERS[broad],
                "prefixes": list(_COLLECTOR_GCS_PREFIX_HINTS.get(broad, ())),
            }
    return out


def gcs_reads_all_prefixes(collector: str) -> bool:
    return collector in _COLLECTOR_GCS_UNION


def gcs_prefix_hints(collector: str) -> tuple[str, ...]:
    return _COLLECTOR_GCS_PREFIX_HINTS.get(collector, ())


@dataclass
class GcpLogBackendSpec:
    mode: str = "logging_api"
    gcs_bucket: str = ""
    gcs_prefix: str = ""
    gcs_setup_required: bool = False

    def uses_logging_api(self) -> bool:
        return self.mode == "logging_api"

    def uses_gcs(self) -> bool:
        return self.mode == "gcs"

    def to_acquisition_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode}
        if self.mode == "gcs":
            gcs: dict[str, Any] = {"setup_required": self.gcs_setup_required}
            if self.gcs_bucket.strip():
                gcs["bucket"] = self.gcs_bucket.strip()
            if self.gcs_prefix.strip():
                gcs["prefix"] = self.gcs_prefix.strip()
            out["gcs"] = gcs
        return out

    @classmethod
    def from_acquisition_dict(cls, raw: Any) -> GcpLogBackendSpec:
        if not raw or not isinstance(raw, dict):
            return cls()
        mode = str(raw.get("mode") or "logging_api").strip().lower()
        if mode == "bigquery":
            mode = "logging_api"
        if mode not in ("logging_api", "gcs"):
            mode = "logging_api"
        gcs = raw.get("gcs") if isinstance(raw.get("gcs"), dict) else {}
        return cls(
            mode=mode,
            gcs_bucket=str(gcs.get("bucket") or "").strip(),
            gcs_prefix=str(gcs.get("prefix") or "").strip(),
            gcs_setup_required=bool(gcs.get("setup_required")),
        )


def extra_iam_for_backend(spec: GcpLogBackendSpec | None) -> set[str]:
    if spec is None:
        return set()
    return set(_EXTRA_IAM_BY_MODE.get(spec.mode, frozenset()))


def iam_actions_for_mode(mode: str) -> list[str]:
    return sorted(_EXTRA_IAM_BY_MODE.get(mode, frozenset()))


def apply_gcp_log_backend_iam(wanted: set[str], raw: Any) -> set[str]:
    spec = GcpLogBackendSpec.from_acquisition_dict(raw)
    if spec.mode != "gcs":
        return wanted
    out = set(wanted) - _LOGGING_API_ONLY
    out.update(_EXTRA_IAM_BY_MODE["gcs"])
    return out


def cart_needs_gcp_log_backend(collector_names: list[str]) -> bool:
    return bool(GCP_LOGGING_COLLECTOR_IDS.intersection(collector_names))


def validate_gcp_log_backend_dict(raw: Any) -> dict[str, Any]:
    spec = GcpLogBackendSpec.from_acquisition_dict(raw)
    if spec.mode not in ("logging_api", "gcs"):
        raise ValueError(f"Unknown gcp_log_backend mode: {spec.mode!r}")
    if spec.mode == "gcs" and not spec.gcs_bucket:
        raise ValueError("Cloud Storage Archive requires gcp_log_backend.gcs.bucket.")
    return spec.to_acquisition_dict()


def resolve_gcs_prefix_candidates(
    collector: str,
    spec: GcpLogBackendSpec,
    artifact_params: dict[str, Any] | None = None,
) -> list[str]:
    params = artifact_params or {}
    explicit = str(params.get("gcs_prefix") or "").strip()
    base = explicit or spec.gcs_prefix.strip()
    base = f"{base.rstrip('/')}/" if base else ""
    hints = _COLLECTOR_GCS_PREFIX_HINTS.get(collector, ())
    if not hints:
        return [base]
    return [f"{base}{hint}" for hint in hints]


def uses_gcp_logging_api(raw: Any) -> bool:
    return GcpLogBackendSpec.from_acquisition_dict(raw).uses_logging_api()

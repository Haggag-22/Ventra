"""Case-store query layer.

Reads ``cases/<id>/`` produced by the ingester. Events are queried from ``events.parquet``
with DuckDB; summaries, integrity, manifest, and inventory are read from their JSON sidecars.
All event queries flow through :meth:`CaseStore.query_events` so filtering, faceting, and
pivoting share one safe, parameterized code path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb

from .config import settings

# Columns the frontend may filter/sort on. Anything not here is rejected — this is the
# allow-list that keeps the dynamic query construction injection-safe.
FILTERABLE = {
    "event_kind", "event_action", "event_outcome", "event_severity", "event_provider",
    "cloud_region", "cloud_service", "user_name", "user_arn", "user_type", "source_ip",
    "dest_ip", "resource_id", "resource_arn", "ventra_source", "ua_category", "source_country",
}
SORTABLE = {
    "timestamp", "event_severity", "event_action", "user_name", "source_ip",
    "dest_ip", "dest_port", "dest_bytes",
}

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

# CloudTrail ``eventCategory`` lives in the raw JSON payload; normalize to the labels the UI shows.
TRAIL_CATEGORY_SQL = (
    "CASE json_extract_string(raw, '$.eventCategory') "
    "WHEN 'NetworkActivity' THEN 'Network' "
    "WHEN 'Insight' THEN 'Insight' "
    "WHEN 'Data' THEN 'Data' "
    "ELSE 'Management' END"
)

# HTTP status embedded in access-log messages (`GET /path → 404 (resource)`).
HTTP_STATUS_SQL = "regexp_extract(message, '→ ([0-9]{3})', 1)"

# S3 server access logs + CloudTrail S3 object-level data events.
DATA_ACCESS_SCOPE = (
    "(ventra_source='s3_access' OR (ventra_source='cloudtrail' "
    "AND json_extract_string(raw, '$.eventCategory')='Data' "
    "AND json_extract_string(raw, '$.eventSource')='s3.amazonaws.com'))"
)

DATA_ACCESS_PRINCIPAL_SQL = "COALESCE(NULLIF(user_arn,''), NULLIF(user_name,''), '')"

# Classify a finding by what its raw payload represents (compliance control, vulnerability,
# threat detection, sensitive-data, etc.) so the Findings panel can column/filter on it. Mirrored
# client-side in ``lib/finding-class.ts`` for the table cell — keep the two in sync.
FINDING_CLASS_SQL = (
    "CASE "
    "WHEN ventra_source = 'inspector2' "
    "  OR json_extract_string(raw, '$.packageVulnerabilityDetails.vulnerabilityId') IS NOT NULL "
    "  THEN 'Vulnerability' "
    "WHEN json_extract_string(raw, '$.Compliance.SecurityControlId') IS NOT NULL "
    "  OR json_extract_string(raw, '$.Types[0]') LIKE 'Software and Configuration Checks/Industry and Regulatory Standards%' "
    "  THEN 'Compliance' "
    "WHEN ventra_source = 'macie' "
    "  OR json_extract_string(raw, '$.Types[0]') LIKE 'Sensitive Data Identifications%' "
    "  THEN 'Sensitive data' "
    "WHEN json_extract_string(raw, '$.Types[0]') LIKE 'Effects/Data Exposure%' "
    "  THEN 'Data exposure' "
    "WHEN ventra_source = 'guardduty' "
    "  OR json_extract_string(raw, '$.Type') IS NOT NULL "
    "  OR json_extract_string(raw, '$.Types[0]') LIKE 'TTPs%' "
    "  OR json_extract_string(raw, '$.Types[0]') LIKE 'Unusual Behaviors%' "
    "  OR json_extract_string(raw, '$.Types[0]') LIKE 'Effects%' "
    "  THEN 'Threat' "
    "WHEN ventra_source = 'defender' "
    "  OR json_extract_string(raw, '$.properties.alertType') IS NOT NULL "
    "  THEN 'Threat' "
    "WHEN json_extract_string(raw, '$.Types[0]') LIKE 'Software and Configuration Checks%' "
    "  THEN 'Configuration' "
    "ELSE 'Other' END"
)

NETWORK_SOURCES = "ventra_source IN ('vpc_flow', 'nsg_flow', 'vnet_flow', 'azure_firewall')"

# VPC / VNet scope on network events — collector tags, raw fields, or related_resource.
NETWORK_VPC_ID_SQL = (
    "COALESCE("
    "NULLIF(json_extract_string(raw, '$._ventra_vpc_id'), ''), "
    "NULLIF(json_extract_string(raw, '$.vpc_id'), ''), "
    "NULLIF(json_extract_string(raw, '$.' || 'vpc-id'), ''), "
    "NULLIF(CASE WHEN json_extract_string(raw, '$._ventra_flow_resource_id') LIKE 'vpc-%' "
    "  THEN json_extract_string(raw, '$._ventra_flow_resource_id') ELSE NULL END, ''), "
    "NULLIF(regexp_extract(related_resource, 'vpc-[a-z0-9]+', 0), '')"
    ")"
)

# Resource inventory roll-ups: (category title, item specs).
# Each spec maps an inventory JSON source + key to a human label. Keys may use
# dot paths; ``_config.*`` reads nested collector config (waf, vpc_flow).
_INVENTORY_RESOURCE_SPECS: list[tuple[str, list[dict[str, str]]]] = [
    (
        "Compute & storage",
        [
            {"id": "ec2_instances", "label": "EC2 instances", "source": "ec2", "key": "instances"},
            {"id": "ec2_volumes", "label": "EBS volumes", "source": "ec2", "key": "volumes"},
            {"id": "ec2_snapshots", "label": "EBS snapshots", "source": "ec2", "key": "snapshots"},
            {"id": "ec2_images", "label": "AMIs", "source": "ec2", "key": "images"},
            {"id": "ec2_launch_templates", "label": "Launch templates", "source": "ec2", "key": "launch_templates"},
            {"id": "lambda_functions", "label": "Lambda functions", "source": "lambda", "key": "functions"},
            {"id": "s3_buckets", "label": "S3 buckets", "source": "s3", "key": "buckets"},
        ],
    ),
    (
        "Network",
        [
            {"id": "vpc_count", "label": "VPCs", "source": "vpc_flow", "key": "_config.vpcs"},
            {"id": "vpc_flow_logs", "label": "VPC Flow Log configs", "source": "vpc_flow", "key": "_config.flow_logs"},
            {"id": "ec2_enis", "label": "Network interfaces", "source": "ec2", "key": "network_interfaces"},
            {"id": "ec2_security_groups", "label": "Security groups", "source": "ec2", "key": "security_groups"},
            {"id": "waf_acls", "label": "WAF Web ACLs", "source": "waf", "key": "_config.web_acls"},
        ],
    ),
    (
        "Identity & encryption",
        [
            {"id": "iam_users", "label": "IAM users", "source": "iam", "key": "users"},
            {"id": "iam_roles", "label": "IAM roles", "source": "iam", "key": "roles"},
            {"id": "iam_groups", "label": "IAM groups", "source": "iam", "key": "groups"},
            {"id": "iam_policies", "label": "Customer-managed policies", "source": "iam", "key": "policies"},
            {"id": "kms_keys", "label": "KMS keys", "source": "kms", "key": "keys"},
            {"id": "secrets", "label": "Secrets Manager secrets", "source": "secrets", "key": "secrets"},
        ],
    ),
]


def _inventory_resource_count(data: Any, key: str) -> int:
    node: Any = data
    for part in key.split("."):
        if not isinstance(node, dict):
            return 0
        node = node.get(part)
    if node is None:
        return 0
    if isinstance(node, list):
        return len(node)
    if isinstance(node, (int, float)):
        return int(node)
    return 0


def _flow_log_active(flow_log: dict[str, Any]) -> bool:
    status = flow_log.get("FlowLogStatus")
    if isinstance(status, str) and status.strip():
        return status.strip().upper() == "ACTIVE"
    enabled = flow_log.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    return True


def _vpc_ids_from_flow_config(config: dict[str, Any] | None) -> list[str]:
    """VPC IDs with an active flow-log config (inventory ``_config.flow_logs``)."""
    if not config:
        return []
    ids: set[str] = set()
    for fl in config.get("flow_logs") or []:
        if not isinstance(fl, dict) or not _flow_log_active(fl):
            continue
        rid = (fl.get("ResourceId") or fl.get("target") or "").strip()
        if rid.startswith("vpc-"):
            ids.add(rid)
    return sorted(ids)


def _vpc_name_from_inventory(vpc: dict[str, Any]) -> str:
    for tag in vpc.get("Tags") or []:
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            val = (tag.get("Value") or "").strip()
            if val:
                return val
    name = (vpc.get("Name") or "").strip()
    if name:
        return name
    cidr = (vpc.get("CidrBlock") or "").strip()
    if cidr:
        return cidr
    return (vpc.get("VpcId") or vpc.get("id") or "").strip()


def _vpc_names_from_config(config: dict[str, Any] | None) -> dict[str, str]:
    if not config:
        return {}
    names: dict[str, str] = {}
    for vpc in config.get("vpcs") or []:
        if not isinstance(vpc, dict):
            continue
        vid = (vpc.get("VpcId") or vpc.get("id") or "").strip()
        if vid:
            names[vid] = _vpc_name_from_inventory(vpc)
    return names


def network_vpc_filter_clause(
    vpc_ids: list[str], flow_log_vpc_ids: list[str] | None = None
) -> tuple[str, list[Any]]:
    """SQL for VPC-scoped network events.

    When the selected VPC is the only flow-log-enabled VPC in the case, untagged
    records (no ``_ventra_vpc_id``) are included — common when flow logs were
    ingested without per-record scope tags.
    """
    if not vpc_ids:
        return "", []
    sole = flow_log_vpc_ids[0] if flow_log_vpc_ids and len(flow_log_vpc_ids) == 1 else None
    parts: list[str] = []
    params: list[Any] = []
    for vid in vpc_ids:
        if sole and vid == sole:
            parts.append(f"(({NETWORK_VPC_ID_SQL}) = ? OR ({NETWORK_VPC_ID_SQL}) = '')")
        else:
            parts.append(f"({NETWORK_VPC_ID_SQL}) = ?")
        params.append(vid)
    if len(parts) == 1:
        return parts[0], params
    return "(" + " OR ".join(parts) + ")", params


@dataclass
class EventQuery:
    filters: dict[str, str] = field(default_factory=dict)
    q: str | None = None  # free-text across message/action/user/ip
    since: str | None = None
    until: str | None = None
    severities: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    trail_categories: list[str] = field(default_factory=list)
    finding_classes: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    related_ip: str | None = None
    related_user: str | None = None
    related_resource: str | None = None
    resources: list[str] = field(default_factory=list)
    http_status: list[str] = field(default_factory=list)
    outcomes: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    dest_ips: list[str] = field(default_factory=list)
    dest_ports: list[str] = field(default_factory=list)
    vpcs: list[str] = field(default_factory=list)
    data_access: bool = False
    sort: str = "timestamp"
    order: str = "asc"
    limit: int = 100
    offset: int = 0


class CaseNotFound(Exception):
    pass


class CaseStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or settings.case_store
        self._parquet_cols: dict[str, set[str]] = {}

    # -- discovery -----------------------------------------------------------------------

    def list_cases(self) -> list[dict[str, Any]]:
        out = []
        if not self.root.exists():
            return out
        for case_dir in sorted(self.root.iterdir()):
            summ = case_dir / "summary.json"
            if summ.is_file():
                try:
                    out.append(json.loads(summ.read_text()))
                except json.JSONDecodeError:
                    continue
        return out

    def case_dir(self, case_id: str) -> Path:
        d = self.root / case_id
        if not (d / "summary.json").is_file():
            raise CaseNotFound(case_id)
        return d

    def delete_case(self, case_id: str) -> None:
        """Remove a case directory and everything under it.

        Resolves the target and confirms it stays within the case store before deleting, so a
        crafted ``case_id`` can never escape the root even if upstream validation changes.
        """
        import shutil

        target = self.case_dir(case_id).resolve()
        root = self.root.resolve()
        if root not in target.parents:
            raise CaseNotFound(case_id)
        shutil.rmtree(target)

    def _events_path(self, case_id: str) -> str:
        return str(self.case_dir(case_id) / "events.parquet")

    # -- JSON sidecars -------------------------------------------------------------------

    def summary(self, case_id: str) -> dict:
        return json.loads((self.case_dir(case_id) / "summary.json").read_text())

    def integrity(self, case_id: str) -> dict:
        p = self.case_dir(case_id) / "integrity.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def manifest(self, case_id: str) -> dict:
        p = self.case_dir(case_id) / "manifest.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def inventory(self, case_id: str, source: str) -> Any:
        p = self.case_dir(case_id) / "inventory" / f"{source}.json"
        if not p.is_file():
            return None
        return json.loads(p.read_text())

    def inventory_sources(self, case_id: str) -> list[str]:
        inv = self.case_dir(case_id) / "inventory"
        if not inv.is_dir():
            return []
        return sorted(p.stem for p in inv.glob("*.json"))

    def inventory_summary(self, case_id: str) -> dict[str, Any]:
        """Aggregate point-in-time resource counts from inventory snapshots (no logs/events)."""
        sources = self.inventory_sources(case_id)
        loaded = {s: self.inventory(case_id, s) for s in sources}

        categories: list[dict[str, Any]] = []
        total = 0
        for cat_name, specs in _INVENTORY_RESOURCE_SPECS:
            items: list[dict[str, Any]] = []
            for spec in specs:
                data = loaded.get(spec["source"])
                count = _inventory_resource_count(data, spec["key"]) if data is not None else None
                if count is not None:
                    total += count
                items.append(
                    {
                        "id": spec["id"],
                        "label": spec["label"],
                        "source": spec["source"],
                        "key": spec["key"],
                        "count": count,
                        "collected": spec["source"] in sources,
                    }
                )
            categories.append({"name": cat_name, "items": items})

        return {
            "sources": sources,
            "categories": categories,
            "total_resources": total,
        }

    def collection_log(self, case_id: str) -> list[dict]:
        p = self.case_dir(case_id) / "collection.log"
        if not p.is_file():
            return []
        out = []
        for line in p.read_text().splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"raw": line})
        return out

    # -- event queries -------------------------------------------------------------------

    def _connect(self) -> duckdb.DuckDBPyConnection:
        con = duckdb.connect(database=":memory:")
        con.execute("SET threads TO 4")
        return con

    def _parquet_columns(self, con: duckdb.DuckDBPyConnection, path: str) -> set[str]:
        cached = self._parquet_cols.get(path)
        if cached is not None:
            return cached
        cols = {
            r[0]
            for r in con.execute("DESCRIBE SELECT * FROM read_parquet(?)", [path]).fetchall()
        }
        self._parquet_cols[path] = cols
        return cols

    def _events_table(self, con: duckdb.DuckDBPyConnection, path: str) -> str:
        """Read events.parquet, normalizing legacy ``harbor_source`` to ``ventra_source``."""
        cols = self._parquet_columns(con, path)
        has_v = "ventra_source" in cols
        has_h = "harbor_source" in cols
        if has_v and has_h:
            return (
                "(SELECT * EXCLUDE(ventra_source, harbor_source), "
                "COALESCE(NULLIF(ventra_source, ''), harbor_source) AS ventra_source "
                "FROM read_parquet(?))"
            )
        if has_v:
            return "read_parquet(?)"
        if has_h:
            return (
                "(SELECT * EXCLUDE(harbor_source), harbor_source AS ventra_source "
                "FROM read_parquet(?))"
            )
        return "(SELECT *, CAST('' AS VARCHAR) AS ventra_source FROM read_parquet(?))"

    def _vpc_flow_config(self, case_id: str) -> dict[str, Any] | None:
        inv = self.inventory(case_id, "vpc_flow") or {}
        config = inv.get("_config")
        return config if isinstance(config, dict) else None

    def _build_where(self, q: EventQuery, case_id: str | None = None) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, val in q.filters.items():
            if key in FILTERABLE and val:
                clauses.append(f"{key} = ?")
                params.append(val)
        if q.severities:
            placeholders = ",".join("?" for _ in q.severities)
            clauses.append(f"event_severity IN ({placeholders})")
            params.extend(q.severities)
        if q.sources:
            placeholders = ",".join("?" for _ in q.sources)
            clauses.append(f"ventra_source IN ({placeholders})")
            params.extend(q.sources)
        if q.actions:
            placeholders = ",".join("?" for _ in q.actions)
            clauses.append(f"event_action IN ({placeholders})")
            params.extend(q.actions)
        if q.regions:
            placeholders = ",".join("?" for _ in q.regions)
            clauses.append(f"cloud_region IN ({placeholders})")
            params.extend(q.regions)
        if q.services:
            placeholders = ",".join("?" for _ in q.services)
            clauses.append(f"cloud_service IN ({placeholders})")
            params.extend(q.services)
        if q.users:
            placeholders = ",".join("?" for _ in q.users)
            clauses.append(
                f"(user_name IN ({placeholders}) OR user_arn IN ({placeholders}))"
            )
            params.extend(q.users)
            params.extend(q.users)
        if q.categories:
            cat_clauses = []
            for c in q.categories:
                cat_clauses.append("event_category LIKE ?")
                params.append(f'%"{c}"%')
            clauses.append("(" + " OR ".join(cat_clauses) + ")")
        if q.trail_categories:
            placeholders = ",".join("?" for _ in q.trail_categories)
            clauses.append(f"({TRAIL_CATEGORY_SQL}) IN ({placeholders})")
            params.extend(q.trail_categories)
        if q.finding_classes:
            placeholders = ",".join("?" for _ in q.finding_classes)
            clauses.append(f"({FINDING_CLASS_SQL}) IN ({placeholders})")
            params.extend(q.finding_classes)
        if q.since:
            clauses.append("timestamp >= ?")
            params.append(q.since)
        if q.until:
            clauses.append("timestamp <= ?")
            params.append(q.until)
        if q.related_ip:
            clauses.append("related_ip LIKE ?")
            params.append(f'%"{q.related_ip}"%')
        if q.related_user:
            clauses.append("related_user LIKE ?")
            params.append(f'%{q.related_user}%')
        if q.related_resource:
            clauses.append("related_resource LIKE ?")
            params.append(f'%{q.related_resource}%')
        if q.resources:
            placeholders = ",".join("?" for _ in q.resources)
            clauses.append(f"resource_id IN ({placeholders})")
            params.extend(q.resources)
        if q.http_status:
            placeholders = ",".join("?" for _ in q.http_status)
            clauses.append(f"({HTTP_STATUS_SQL}) IN ({placeholders})")
            params.extend(q.http_status)
        if q.outcomes:
            placeholders = ",".join("?" for _ in q.outcomes)
            clauses.append(f"event_outcome IN ({placeholders})")
            params.extend(q.outcomes)
        if q.source_ips:
            placeholders = ",".join("?" for _ in q.source_ips)
            clauses.append(f"source_ip IN ({placeholders})")
            params.extend(q.source_ips)
        if q.dest_ips:
            placeholders = ",".join("?" for _ in q.dest_ips)
            clauses.append(f"dest_ip IN ({placeholders})")
            params.extend(q.dest_ips)
        if q.dest_ports:
            ports: list[int] = []
            for p in q.dest_ports:
                try:
                    ports.append(int(p))
                except ValueError:
                    continue
            if ports:
                placeholders = ",".join("?" for _ in ports)
                clauses.append(f"dest_port IN ({placeholders})")
                params.extend(ports)
        if q.vpcs:
            flow_vpcs = _vpc_ids_from_flow_config(
                self._vpc_flow_config(case_id) if case_id else None
            )
            vpc_clause, vpc_params = network_vpc_filter_clause(q.vpcs, flow_vpcs)
            if vpc_clause:
                clauses.append(vpc_clause)
                params.extend(vpc_params)
        if q.data_access:
            clauses.append(DATA_ACCESS_SCOPE)
        if q.q:
            like = f"%{q.q}%"
            clauses.append(
                "(message ILIKE ? OR event_action ILIKE ? OR user_name ILIKE ? "
                "OR source_ip ILIKE ? OR dest_ip ILIKE ? OR user_arn ILIKE ? OR resource_arn ILIKE ?)"
            )
            params.extend([like] * 7)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def query_events(self, case_id: str, q: EventQuery) -> dict[str, Any]:
        path = self._events_path(case_id)
        where, params = self._build_where(q, case_id)
        sort = q.sort if q.sort in SORTABLE else "timestamp"
        order = "DESC" if q.order.lower() == "desc" else "ASC"
        # Severity sorts by rank, not alphabetically.
        sort_expr = (
            "CASE event_severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 2 ELSE 1 END"
            if sort == "event_severity"
            else sort
        )
        con = self._connect()
        try:
            events = self._events_table(con, path)
            total = con.execute(
                f"SELECT count(*) FROM {events} {where}", [path, *params]
            ).fetchone()[0]
            rows = con.execute(
                f"SELECT * FROM {events} {where} "
                f"ORDER BY {sort_expr} {order}, timestamp ASC LIMIT ? OFFSET ?",
                [path, *params, q.limit, q.offset],
            )
            cols = [d[0] for d in rows.description]
            data = [dict(zip(cols, r)) for r in rows.fetchall()]
        finally:
            con.close()
        return {"total": total, "count": len(data), "offset": q.offset, "events": [
            _decode_row(r) for r in data
        ]}

    def facets(self, case_id: str, q: EventQuery) -> dict[str, Any]:
        """Aggregations for the filter rail, respecting the current filters."""
        path = self._events_path(case_id)
        where, params = self._build_where(q, case_id)
        con = self._connect()
        try:
            events = self._events_table(con, path)
            def agg(col: str) -> list[dict]:
                rows = con.execute(
                    f"SELECT {col} AS k, count(*) AS c FROM {events} {where} "
                    f"AND {col} <> '' GROUP BY 1 ORDER BY c DESC LIMIT 25"
                    if where
                    else f"SELECT {col} AS k, count(*) AS c FROM {events} "
                    f"WHERE {col} <> '' GROUP BY 1 ORDER BY c DESC LIMIT 25",
                    [path, *params],
                ).fetchall()
                return [{"value": r[0], "count": r[1]} for r in rows]

            return {
                "ventra_source": agg("ventra_source"),
                "event_severity": agg("event_severity"),
                "event_action": agg("event_action"),
                "event_outcome": agg("event_outcome"),
                "user_name": agg("user_name"),
                "source_ip": agg("source_ip"),
                "dest_ip": agg("dest_ip"),
                "dest_port": self._dest_port_facets(con, events, where, params, path),
                "cloud_region": agg("cloud_region"),
                "cloud_service": agg("cloud_service"),
                "ua_category": agg("ua_category"),
                "resource_id": agg("resource_id"),
                "http_status": self._http_status_facets(con, events, where, params, path),
                "principal": self._principal_facets(con, events, where, params, path)
                if q.data_access
                else [],
                "trail_category": self._trail_category_facets(con, events, where, params, path),
                "finding_class": self._finding_class_facets(con, events, where, params, path),
            }
        finally:
            con.close()

    def _dest_port_facets(
        self,
        con: duckdb.DuckDBPyConnection,
        events: str,
        where: str,
        params: list[Any],
        path: str,
    ) -> list[dict[str, Any]]:
        port_where = (
            f"{where} AND dest_port IS NOT NULL AND dest_port > 0"
            if where
            else " WHERE dest_port IS NOT NULL AND dest_port > 0"
        )
        rows = con.execute(
            f"SELECT cast(dest_port AS VARCHAR) AS k, count(*) AS c FROM {events}{port_where} "
            "GROUP BY 1 ORDER BY c DESC LIMIT 25",
            [path, *params],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def _http_status_facets(
        self,
        con: duckdb.DuckDBPyConnection,
        events: str,
        where: str,
        params: list[Any],
        path: str,
    ) -> list[dict[str, Any]]:
        """Aggregate HTTP status codes from access-log message text."""
        status_where = (
            f"{where} AND {HTTP_STATUS_SQL} <> ''"
            if where
            else f" WHERE {HTTP_STATUS_SQL} <> ''"
        )
        rows = con.execute(
            f"SELECT {HTTP_STATUS_SQL} AS k, count(*) AS c FROM {events}{status_where} "
            "GROUP BY 1 ORDER BY c DESC LIMIT 25",
            [path, *params],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def _principal_facets(
        self,
        con: duckdb.DuckDBPyConnection,
        events: str,
        where: str,
        params: list[Any],
        path: str,
    ) -> list[dict[str, Any]]:
        """Aggregate principals (ARN or username) for data-access filter dropdowns."""
        pr_where = (
            f"{where} AND {DATA_ACCESS_PRINCIPAL_SQL} <> ''"
            if where
            else f" WHERE {DATA_ACCESS_PRINCIPAL_SQL} <> ''"
        )
        rows = con.execute(
            f"SELECT {DATA_ACCESS_PRINCIPAL_SQL} AS k, count(*) AS c FROM {events}{pr_where} "
            "GROUP BY 1 ORDER BY c DESC LIMIT 25",
            [path, *params],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def _trail_category_facets(
        self,
        con: duckdb.DuckDBPyConnection,
        events: str,
        where: str,
        params: list[Any],
        path: str,
    ) -> list[dict[str, Any]]:
        """Aggregate CloudTrail Management / Data / Insight / Network counts from raw JSON."""
        ct_where = (
            f"{where} AND ventra_source = 'cloudtrail'"
            if where
            else " WHERE ventra_source = 'cloudtrail'"
        )
        rows = con.execute(
            f"SELECT {TRAIL_CATEGORY_SQL} AS k, count(*) AS c FROM {events}{ct_where} "
            "GROUP BY 1 ORDER BY c DESC",
            [path, *params],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def _finding_class_facets(
        self,
        con: duckdb.DuckDBPyConnection,
        events: str,
        where: str,
        params: list[Any],
        path: str,
    ) -> list[dict[str, Any]]:
        """Aggregate finding classes (Compliance / Vulnerability / Threat / ...) from raw JSON."""
        f_where = (
            f"{where} AND event_kind = 'finding'"
            if where
            else " WHERE event_kind = 'finding'"
        )
        rows = con.execute(
            f"SELECT {FINDING_CLASS_SQL} AS k, count(*) AS c FROM {events}{f_where} "
            "GROUP BY 1 ORDER BY c DESC",
            [path, *params],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def role_assumption_graph(self, case_id: str) -> dict[str, Any]:
        """Build the Identity panel's who-assumed-what graph from session/STS events."""
        path = self._events_path(case_id)
        con = self._connect()
        try:
            events = self._events_table(con, path)
            rows = con.execute(
                "SELECT user_arn, user_name, resource_arn, source_ip, count(*) c "
                f"FROM {events} WHERE event_action IN "
                "('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity') "
                "GROUP BY 1,2,3,4",
                [path],
            ).fetchall()
        finally:
            con.close()
        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        for user_arn, user_name, resource_arn, ip, c in rows:
            if user_arn:
                nodes.setdefault(user_arn, {"id": user_arn, "label": user_name or user_arn,
                                            "type": "principal"})
            if resource_arn:
                nodes.setdefault(resource_arn, {"id": resource_arn,
                                                "label": resource_arn.split("/")[-1],
                                                "type": "role"})
            if user_arn and resource_arn:
                edges.append({"source": user_arn, "target": resource_arn, "weight": c, "ip": ip})
        return {"nodes": list(nodes.values()), "edges": edges}

    def network_vpcs(self, case_id: str) -> dict[str, Any]:
        """VPCs with flow logging enabled — for the Network panel scope filter."""
        path = self._events_path(case_id)
        event_counts: dict[str, int] = {}
        con = self._connect()
        try:
            events = self._events_table(con, path)
            rows = con.execute(
                f"SELECT ({NETWORK_VPC_ID_SQL}) AS vpc_id, count(*) AS c FROM {events} "
                f"WHERE {NETWORK_SOURCES} AND ({NETWORK_VPC_ID_SQL}) <> '' "
                "GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
            event_counts = {r[0]: r[1] for r in rows if r[0]}
            untagged = con.execute(
                f"SELECT count(*) FROM {events} "
                f"WHERE {NETWORK_SOURCES} AND ({NETWORK_VPC_ID_SQL}) = ''",
                [path],
            ).fetchone()[0]
        finally:
            con.close()

        config = self._vpc_flow_config(case_id)
        flow_vpc_ids = _vpc_ids_from_flow_config(config)
        if len(flow_vpc_ids) == 1 and untagged:
            sole = flow_vpc_ids[0]
            event_counts[sole] = event_counts.get(sole, 0) + untagged
        vpc_names = _vpc_names_from_config(config)
        ordered = sorted(flow_vpc_ids, key=lambda vid: (-event_counts.get(vid, 0), vid))
        return {
            "vpcs": [
                {
                    "id": vid,
                    "name": vpc_names.get(vid) or vid,
                    "flows": event_counts.get(vid, 0),
                }
                for vid in ordered
            ]
        }

    def network_overview(self, case_id: str, vpc_id: str | None = None) -> dict[str, Any]:
        """VPC flow analysis: public egress (exfil), destination ports, talkers, rejects."""
        path = self._events_path(case_id)
        con = self._connect()
        base = NETWORK_SOURCES
        flow_vpc_ids = _vpc_ids_from_flow_config(self._vpc_flow_config(case_id))
        vpc_filter = ""
        vpc_params: list[Any] = []
        if vpc_id:
            vpc_clause, vpc_params = network_vpc_filter_clause([vpc_id], flow_vpc_ids)
            vpc_filter = f" AND {vpc_clause}"
        pub = _public_ip_sql("dest_ip")
        rej = "sum(CASE WHEN event_outcome='failure' THEN 1 ELSE 0 END)"
        query_params = [path, *vpc_params]
        try:
            events = self._events_table(con, path)
            case_flows = con.execute(
                f"SELECT count(*) FROM {events} WHERE {base}",
                [path],
            ).fetchone()[0]
            totals = con.execute(
                f"SELECT count(*) flows, "
                f"sum(CASE WHEN event_outcome='success' THEN 1 ELSE 0 END) accepted, "
                f"{rej} rejected, "
                f"sum(coalesce(dest_bytes,0)) bytes, "
                f"sum(CASE WHEN {pub} THEN coalesce(dest_bytes,0) ELSE 0 END) public_bytes, "
                f"count(DISTINCT CASE WHEN {pub} THEN dest_ip END) external_dests, "
                f"count(DISTINCT NULLIF(source_ip,'')) sources "
                f"FROM {events} WHERE {base}{vpc_filter}",
                query_params,
            ).fetchone()
            egress_public = con.execute(
                f"SELECT dest_ip, sum(coalesce(dest_bytes,0)) bytes, count(*) flows, "
                "count(DISTINCT dest_port) ports "
                f"FROM {events} WHERE {base} AND {pub}{vpc_filter} "
                "GROUP BY 1 ORDER BY bytes DESC LIMIT 15",
                query_params,
            ).fetchall()
            top_talkers = con.execute(
                "SELECT source_ip, sum(coalesce(dest_bytes,0)) bytes, count(*) flows "
                f"FROM {events} WHERE {base} AND source_ip<>''{vpc_filter} "
                "GROUP BY 1 ORDER BY bytes DESC LIMIT 15",
                query_params,
            ).fetchall()
            top_ports = con.execute(
                f"SELECT dest_port, count(*) flows, sum(coalesce(dest_bytes,0)) bytes, {rej} rejected "
                f"FROM {events} WHERE {base} AND dest_port IS NOT NULL AND dest_port > 0{vpc_filter} "
                "GROUP BY 1 ORDER BY flows DESC LIMIT 15",
                query_params,
            ).fetchall()
            rejected = con.execute(
                f"SELECT source_ip, dest_ip, dest_port, count(*) c FROM {events} "
                f"WHERE {base} AND event_outcome='failure'{vpc_filter} "
                "GROUP BY 1,2,3 ORDER BY c DESC LIMIT 15",
                query_params,
            ).fetchall()
            protocols = con.execute(
                "SELECT json_extract_string(raw,'$.protocol') proto, count(*) c "
                f"FROM {events} WHERE {base}{vpc_filter} GROUP BY 1 ORDER BY c DESC LIMIT 6",
                query_params,
            ).fetchall()
        finally:
            con.close()
        return {
            "case_totals": {"flows": case_flows or 0},
            "totals": {
                "flows": totals[0] or 0,
                "accepted": totals[1] or 0,
                "rejects": totals[2] or 0,
                "bytes": int(totals[3] or 0),
                "public_bytes": int(totals[4] or 0),
                "external_dests": totals[5] or 0,
                "sources": totals[6] or 0,
            },
            "egress_public": [
                {"dest_ip": r[0], "bytes": int(r[1] or 0), "flows": r[2], "ports": r[3]}
                for r in egress_public
            ],
            "top_talkers": [
                {"source_ip": r[0], "bytes": int(r[1] or 0), "flows": r[2]} for r in top_talkers
            ],
            "top_ports": [
                {"port": r[0], "flows": r[1], "bytes": int(r[2] or 0), "rejected": int(r[3] or 0)}
                for r in top_ports
            ],
            "rejected": [
                {"source_ip": r[0], "dest_ip": r[1], "dest_port": r[2], "count": r[3]}
                for r in rejected
            ],
            "protocols": [
                {"protocol": r[0] or "", "count": r[1]} for r in protocols if r[0]
            ],
        }

    def web_dns_overview(self, case_id: str) -> dict[str, Any]:
        """L7 edge (ELB/ALB + CloudFront), WAF, and DNS aggregations for the Web & DNS panel."""
        path = self._events_path(case_id)
        con = self._connect()
        edge = "ventra_source IN ('elb_alb', 'cloudfront')"
        fail = "sum(CASE WHEN event_outcome='failure' THEN 1 ELSE 0 END)"
        try:
            events = self._events_table(con, path)

            edge_totals = con.execute(
                f"SELECT count(*), count(DISTINCT NULLIF(source_ip,'')), {fail} "
                f"FROM {events} WHERE {edge}",
                [path],
            ).fetchone()
            edge_clients = con.execute(
                f"SELECT source_ip, count(*) c, {fail} fails, max(timestamp) last_seen "
                f"FROM {events} WHERE {edge} AND source_ip<>'' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 15",
                [path],
            ).fetchall()
            edge_methods = con.execute(
                f"SELECT event_action, count(*) c FROM {events} "
                f"WHERE {edge} AND event_action<>'' GROUP BY 1 ORDER BY c DESC LIMIT 10",
                [path],
            ).fetchall()
            edge_uas = con.execute(
                f"SELECT ua_original, count(*) c FROM {events} "
                f"WHERE {edge} AND ua_original<>'' GROUP BY 1 ORDER BY c DESC LIMIT 10",
                [path],
            ).fetchall()
            edge_by_source = con.execute(
                f"SELECT ventra_source, count(*) c FROM {events} WHERE {edge} "
                "GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
            edge_resources = con.execute(
                f"SELECT ventra_source, resource_id, count(*) c, {fail} fails "
                f"FROM {events} WHERE {edge} AND resource_id<>'' "
                "GROUP BY 1,2 ORDER BY c DESC LIMIT 15",
                [path],
            ).fetchall()
            status_expr = "regexp_extract(message, '→ ([0-9]+)', 1)"
            edge_status = con.execute(
                f"SELECT CASE "
                f"WHEN {status_expr} LIKE '2%' THEN '2xx' "
                f"WHEN {status_expr} LIKE '3%' THEN '3xx' "
                f"WHEN {status_expr} LIKE '4%' THEN '4xx' "
                f"WHEN {status_expr} LIKE '5%' THEN '5xx' ELSE 'other' END cls, count(*) c "
                f"FROM {events} WHERE {edge} AND {status_expr} <> '' GROUP BY 1 ORDER BY 1",
                [path],
            ).fetchall()
            edge_paths = con.execute(
                f"SELECT regexp_extract(message, '^\\S+ (.*) → ', 1) tgt, "
                f"count(*) c, {fail} fails "
                f"FROM {events} WHERE {edge} AND message LIKE '% → %' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 15",
                [path],
            ).fetchall()

            waf_totals = con.execute(
                f"SELECT count(*), {fail}, count(DISTINCT NULLIF(source_ip,'')) "
                f"FROM {events} WHERE ventra_source='waf'",
                [path],
            ).fetchone()
            waf_actions = con.execute(
                f"SELECT event_action, count(*) c FROM {events} "
                "WHERE ventra_source='waf' GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
            waf_ips = con.execute(
                f"SELECT source_ip, source_country, count(*) c, {fail} blocked "
                f"FROM {events} WHERE ventra_source='waf' AND source_ip<>'' "
                "GROUP BY 1,2 ORDER BY blocked DESC, c DESC LIMIT 15",
                [path],
            ).fetchall()

            dns_totals = con.execute(
                f"SELECT count(*), count(DISTINCT NULLIF(resource_id,'')), {fail} "
                f"FROM {events} WHERE ventra_source='route53_resolver'",
                [path],
            ).fetchone()
            dns_domains = con.execute(
                f"SELECT resource_id, count(*) c, {fail} fails, max(dest_ip) answer "
                f"FROM {events} WHERE ventra_source='route53_resolver' AND resource_id<>'' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 50",
                [path],
            ).fetchall()
            dns_qtypes = con.execute(
                "SELECT replace(event_action,'dns-query:','') qt, count(*) c "
                f"FROM {events} WHERE ventra_source='route53_resolver' AND event_action<>'' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 8",
                [path],
            ).fetchall()
        finally:
            con.close()

        return {
            "edge": {
                "totals": {
                    "requests": edge_totals[0] or 0,
                    "clients": edge_totals[1] or 0,
                    "failures": edge_totals[2] or 0,
                },
                "by_source": [{"source": r[0], "count": r[1]} for r in edge_by_source],
                "top_clients": [
                    {"source_ip": r[0], "requests": r[1], "failures": int(r[2] or 0),
                     "last_seen": r[3]}
                    for r in edge_clients
                ],
                "methods": [{"method": r[0], "count": r[1]} for r in edge_methods],
                "user_agents": [{"ua": r[0], "count": r[1]} for r in edge_uas],
                "top_resources": [
                    {"source": r[0], "resource_id": r[1], "count": r[2],
                     "failures": int(r[3] or 0)}
                    for r in edge_resources
                ],
                "status_classes": [{"cls": r[0], "count": r[1]} for r in edge_status],
                "top_paths": [
                    {"target": r[0], "count": r[1], "failures": int(r[2] or 0)}
                    for r in edge_paths
                    if r[0]
                ],
            },
            "waf": {
                "totals": {
                    "sampled": waf_totals[0] or 0,
                    "blocked": waf_totals[1] or 0,
                    "clients": waf_totals[2] or 0,
                },
                "actions": [{"action": r[0], "count": r[1]} for r in waf_actions],
                "top_ips": [
                    {"source_ip": r[0], "country": r[1], "count": r[2],
                     "blocked": int(r[3] or 0)}
                    for r in waf_ips
                ],
            },
            "dns": {
                "totals": {
                    "queries": dns_totals[0] or 0,
                    "domains": dns_totals[1] or 0,
                    "failures": dns_totals[2] or 0,
                },
                "top_domains": [
                    {"domain": r[0], "count": r[1], "failures": int(r[2] or 0),
                     "answer": r[3]}
                    for r in dns_domains
                ],
                "qtypes": [{"qtype": r[0] or "?", "count": r[1]} for r in dns_qtypes],
            },
        }

    def data_access_overview(self, case_id: str) -> dict[str, Any]:
        """S3 server-access logs + CloudTrail S3 data events — the 'what data was touched' view."""
        path = self._events_path(case_id)
        con = self._connect()
        # S3 server access logs OR CloudTrail S3 object-level (data) events.
        scope = DATA_ACCESS_SCOPE
        principal = DATA_ACCESS_PRINCIPAL_SQL
        fail = "sum(CASE WHEN event_outcome='failure' THEN 1 ELSE 0 END)"
        nbytes = "sum(coalesce(dest_bytes,0))"
        # Classify the access verb: exfil (read) vs ransomware/destruction (write/delete).
        op_class = (
            "CASE "
            "WHEN upper(event_action) LIKE '%DELETE%' THEN 'delete' "
            "WHEN upper(event_action) LIKE '%PUT%' OR upper(event_action) LIKE '%POST%' "
            "  OR upper(event_action) LIKE '%COPY%' OR upper(event_action) LIKE '%CREATE%' THEN 'write' "
            "WHEN upper(event_action) LIKE '%LIST%' THEN 'list' "
            "WHEN upper(event_action) LIKE '%GET%' OR upper(event_action) LIKE '%HEAD%' "
            "  OR upper(event_action) LIKE '%SELECT%' THEN 'read' "
            "ELSE 'other' END"
        )
        try:
            events = self._events_table(con, path)
            totals = con.execute(
                f"SELECT count(*), count(DISTINCT NULLIF(resource_id,'')), "
                f"count(DISTINCT NULLIF({principal},'')), {fail}, {nbytes}, "
                f"sum(CASE WHEN {op_class}='delete' THEN 1 ELSE 0 END), "
                f"sum(CASE WHEN {op_class}='write' THEN 1 ELSE 0 END) "
                f"FROM {events} WHERE {scope}",
                [path],
            ).fetchone()
            by_source = con.execute(
                f"SELECT ventra_source, count(*) c FROM {events} WHERE {scope} "
                "GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
            operations = con.execute(
                f"SELECT {op_class} op, count(*) c FROM {events} WHERE {scope} "
                "GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
            top_objects = con.execute(
                f"SELECT resource_id, count(*) c, {fail} fails, "
                f"count(DISTINCT NULLIF(source_ip,'')) ips, {nbytes} bytes "
                f"FROM {events} WHERE {scope} AND resource_id<>'' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 500",
                [path],
            ).fetchall()
            top_principals = con.execute(
                f"SELECT {principal} pr, count(*) c, {fail} fails, {nbytes} bytes "
                f"FROM {events} WHERE {scope} AND {principal}<>'' "
                "GROUP BY 1 ORDER BY c DESC LIMIT 200",
                [path],
            ).fetchall()
            top_ips = con.execute(
                f"SELECT source_ip, count(*) c, {fail} fails, {nbytes} bytes FROM {events} "
                f"WHERE {scope} AND source_ip<>'' GROUP BY 1 ORDER BY c DESC LIMIT 200",
                [path],
            ).fetchall()
        finally:
            con.close()
        return {
            "totals": {
                "events": totals[0] or 0,
                "objects": totals[1] or 0,
                "principals": totals[2] or 0,
                "failures": totals[3] or 0,
                "bytes_out": int(totals[4] or 0),
                "deletes": totals[5] or 0,
                "writes": totals[6] or 0,
            },
            "by_source": [{"source": r[0], "count": r[1]} for r in by_source],
            "operations": [{"op": r[0], "count": r[1]} for r in operations],
            "top_objects": [
                {"resource_id": r[0], "count": r[1], "failures": int(r[2] or 0), "ips": r[3],
                 "bytes": int(r[4] or 0)}
                for r in top_objects
            ],
            "top_principals": [
                {"principal": r[0], "count": r[1], "failures": int(r[2] or 0),
                 "bytes": int(r[3] or 0)}
                for r in top_principals
            ],
            "top_ips": [
                {"source_ip": r[0], "count": r[1], "failures": int(r[2] or 0),
                 "bytes": int(r[3] or 0)}
                for r in top_ips
            ],
        }

    def cloudtrail_collection(self, case_id: str) -> dict[str, Any]:
        """CloudTrail collection resources — trails, S3 buckets, and event counts by source."""
        inv = self.inventory(case_id, "cloudtrail") or {}
        config = inv.get("config") or {}
        meta = inv.get("meta") or {}
        summary = config.get("collection_summary") or meta.get("collection_summary") or {}
        trails = summary.get("trails") or [_trail_from_config(t) for t in config.get("trails", [])]
        live = self._cloudtrail_live_counts(case_id)

        lookup = summary.get("events", {}).get("lookup_api") or {}
        s3 = summary.get("events", {}).get("s3") or {}
        by_bucket = live.get("by_bucket") or s3.get("by_bucket") or []
        by_bucket = _merge_bucket_summaries(by_bucket, s3.get("by_bucket") or [])

        return {
            "trail_count": summary.get("trail_count", len(trails)),
            "trails": trails,
            "management_source": summary.get("management_source")
            or meta.get("management_source")
            or "",
            "management_collection": config.get("management_collection")
            or meta.get("management_collection")
            or {},
            "event_coverage": config.get("event_coverage") or meta.get("event_coverage") or {},
            "s3_collection": config.get("s3_collection") or meta.get("s3_collection") or {},
            "log_validation": config.get("log_validation") or meta.get("log_validation") or {},
            "events": {
                "lookup_api": {
                    "management": live.get("lookup_management") or lookup.get("management", 0),
                    "insight": live.get("lookup_insight") or lookup.get("insight", 0),
                    "total": live.get("lookup_total") or lookup.get("total", 0),
                },
                "s3": {
                    "total": live.get("s3_total") or s3.get("total", 0),
                    "management": s3.get("management", 0),
                    "data": s3.get("data", 0),
                    "insight": s3.get("insight", 0),
                    "network_activity": s3.get("network_activity", 0),
                    "by_bucket": by_bucket,
                },
            },
            "meta": meta,
        }

    def _cloudtrail_live_counts(self, case_id: str) -> dict[str, Any]:
        """Derive lookup vs S3 event counts from ingested events (falls back when meta is sparse)."""
        path = self._events_path(case_id)
        con = self._connect()
        try:
            events = self._events_table(con, path)
            lookup_total = con.execute(
                f"SELECT count(*) FROM {events} "
                "WHERE ventra_source = 'cloudtrail' AND ("
                "  json_extract_string(raw, '$._ventra_collect_source') = 'lookup_events' "
                "  OR (COALESCE(json_extract_string(raw, '$._ventra_log_key'), '') = '' "
                "      AND COALESCE(json_extract_string(raw, '$._ventra_s3_bucket'), '') = ''"
                "  ))",
                [path],
            ).fetchone()[0]
            s3_total = con.execute(
                f"SELECT count(*) FROM {events} "
                "WHERE ventra_source = 'cloudtrail' AND ("
                "  json_extract_string(raw, '$._ventra_collect_source') = 's3_logs' "
                "  OR COALESCE(json_extract_string(raw, '$._ventra_log_key'), '') <> '' "
                "  OR COALESCE(json_extract_string(raw, '$._ventra_s3_bucket'), '') <> ''"
                ")",
                [path],
            ).fetchone()[0]
            bucket_rows = con.execute(
                "SELECT COALESCE(NULLIF(json_extract_string(raw, '$._ventra_s3_bucket'), ''), "
                "'(unknown bucket)') AS bucket, count(*) AS c "
                f"FROM {events} "
                "WHERE ventra_source = 'cloudtrail' AND ("
                "  json_extract_string(raw, '$._ventra_collect_source') = 's3_logs' "
                "  OR COALESCE(json_extract_string(raw, '$._ventra_log_key'), '') <> '' "
                "  OR COALESCE(json_extract_string(raw, '$._ventra_s3_bucket'), '') <> ''"
                ") GROUP BY 1 ORDER BY c DESC",
                [path],
            ).fetchall()
        finally:
            con.close()

        by_bucket = [
            {"bucket": r[0], "events": {"total": int(r[1])}, "trail_arns": []}
            for r in bucket_rows
        ]
        return {
            "lookup_total": int(lookup_total or 0),
            "s3_total": int(s3_total or 0),
            "by_bucket": by_bucket,
        }


def _public_ip_sql(col: str) -> str:
    """SQL predicate: ``col`` is a routable public IPv4 (not RFC1918 / loopback / link-local)."""
    return (
        f"({col} <> '' "
        f"AND regexp_full_match({col}, '\\d+\\.\\d+\\.\\d+\\.\\d+') "
        f"AND {col} NOT LIKE '10.%' "
        f"AND {col} NOT LIKE '192.168.%' "
        f"AND {col} NOT LIKE '127.%' "
        f"AND {col} NOT LIKE '169.254.%' "
        f"AND NOT regexp_full_match({col}, '172\\.(1[6-9]|2[0-9]|3[01])\\..*'))"
    )


def _trail_from_config(trail: dict[str, Any]) -> dict[str, Any]:
    status = trail.get("Status") or {}
    return {
        "name": trail.get("Name", ""),
        "arn": trail.get("TrailARN", ""),
        "home_region": trail.get("HomeRegion", ""),
        "s3_bucket": trail.get("S3BucketName", ""),
        "s3_key_prefix": trail.get("S3KeyPrefix", ""),
        "is_logging": bool(status.get("IsLogging")),
        "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
        "is_organization": bool(trail.get("IsOrganizationTrail")),
        "log_file_validation": bool(trail.get("LogFileValidationEnabled")),
    }


def _merge_bucket_summaries(
    primary: list[dict[str, Any]], fallback: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Prefer live event totals but keep collector metadata (trail ARNs, category splits)."""
    by_name = {b.get("bucket"): dict(b) for b in fallback if b.get("bucket")}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in primary:
        bucket = row.get("bucket")
        if not bucket:
            continue
        seen.add(bucket)
        merged = dict(by_name.get(bucket, {}))
        merged["bucket"] = bucket
        live_total = (row.get("events") or {}).get("total")
        if live_total is not None:
            events = dict(merged.get("events") or {})
            events["total"] = live_total
            merged["events"] = events
        out.append(merged)
    for bucket, meta in by_name.items():
        if bucket not in seen:
            out.append(meta)
    return out


def _decode_row(row: dict[str, Any]) -> dict[str, Any]:
    """Turn the flat Parquet row back into the nested-ish shape the frontend expects."""
    for col in ("event_category", "related_ip", "related_user", "related_resource"):
        val = row.get(col)
        if isinstance(val, str) and val:
            try:
                row[col] = json.loads(val)
            except json.JSONDecodeError:
                row[col] = []
        else:
            row[col] = []
    raw = row.get("raw")
    if isinstance(raw, str) and raw:
        try:
            row["raw"] = json.loads(raw)
        except json.JSONDecodeError:
            pass
    return row


store = CaseStore()

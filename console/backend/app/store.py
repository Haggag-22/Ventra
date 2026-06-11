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
    "dest_ip", "resource_id", "resource_arn", "harbor_source", "ua_category", "source_country",
}
SORTABLE = {"timestamp", "event_severity", "event_action", "user_name", "source_ip"}

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class EventQuery:
    filters: dict[str, str] = field(default_factory=dict)
    q: str | None = None  # free-text across message/action/user/ip
    since: str | None = None
    until: str | None = None
    severities: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    related_ip: str | None = None
    related_user: str | None = None
    related_resource: str | None = None
    sort: str = "timestamp"
    order: str = "asc"
    limit: int = 100
    offset: int = 0


class CaseNotFound(Exception):
    pass


class CaseStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or settings.case_store

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

    def _build_where(self, q: EventQuery) -> tuple[str, list[Any]]:
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
            clauses.append(f"harbor_source IN ({placeholders})")
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
        if q.categories:
            cat_clauses = []
            for c in q.categories:
                cat_clauses.append("event_category LIKE ?")
                params.append(f'%"{c}"%')
            clauses.append("(" + " OR ".join(cat_clauses) + ")")
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
        if q.q:
            like = f"%{q.q}%"
            clauses.append(
                "(message ILIKE ? OR event_action ILIKE ? OR user_name ILIKE ? "
                "OR source_ip ILIKE ? OR user_arn ILIKE ? OR resource_arn ILIKE ?)"
            )
            params.extend([like] * 6)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def query_events(self, case_id: str, q: EventQuery) -> dict[str, Any]:
        path = self._events_path(case_id)
        where, params = self._build_where(q)
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
            total = con.execute(
                f"SELECT count(*) FROM read_parquet(?) {where}", [path, *params]
            ).fetchone()[0]
            rows = con.execute(
                f"SELECT * FROM read_parquet(?) {where} "
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
        where, params = self._build_where(q)
        con = self._connect()
        try:
            def agg(col: str) -> list[dict]:
                rows = con.execute(
                    f"SELECT {col} AS k, count(*) AS c FROM read_parquet(?) {where} "
                    f"AND {col} <> '' GROUP BY 1 ORDER BY c DESC LIMIT 25"
                    if where
                    else f"SELECT {col} AS k, count(*) AS c FROM read_parquet(?) "
                    f"WHERE {col} <> '' GROUP BY 1 ORDER BY c DESC LIMIT 25",
                    [path, *params],
                ).fetchall()
                return [{"value": r[0], "count": r[1]} for r in rows]

            return {
                "harbor_source": agg("harbor_source"),
                "event_severity": agg("event_severity"),
                "event_action": agg("event_action"),
                "user_name": agg("user_name"),
                "source_ip": agg("source_ip"),
                "cloud_region": agg("cloud_region"),
                "cloud_service": agg("cloud_service"),
                "ua_category": agg("ua_category"),
            }
        finally:
            con.close()

    def timeline_buckets(self, case_id: str, q: EventQuery, buckets: int = 80) -> dict[str, Any]:
        """Bucketed event counts over the case time span, split by severity, for the Timeline."""
        path = self._events_path(case_id)
        where, params = self._build_where(q)
        con = self._connect()
        try:
            span = con.execute(
                f"SELECT min(timestamp), max(timestamp) FROM read_parquet(?) {where} "
                f"{'AND' if where else 'WHERE'} timestamp <> ''",
                [path, *params],
            ).fetchone()
            tmin, tmax = span
            rows = con.execute(
                f"SELECT timestamp, event_severity, harbor_source FROM read_parquet(?) {where} "
                f"{'AND' if where else 'WHERE'} timestamp <> '' ORDER BY timestamp",
                [path, *params],
            ).fetchall()
        finally:
            con.close()
        return {"min": tmin, "max": tmax, "points": [
            {"t": r[0], "severity": r[1], "source": r[2]} for r in rows
        ]}

    def role_assumption_graph(self, case_id: str) -> dict[str, Any]:
        """Build the Identity panel's who-assumed-what graph from session/STS events."""
        path = self._events_path(case_id)
        con = self._connect()
        try:
            rows = con.execute(
                "SELECT user_arn, user_name, resource_arn, source_ip, count(*) c "
                "FROM read_parquet(?) WHERE harbor_source IN ('sts') OR event_action='AssumeRole' "
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

    def network_overview(self, case_id: str) -> dict[str, Any]:
        """Top talkers, rejected flows, and public egress for the Network panel."""
        path = self._events_path(case_id)
        con = self._connect()
        try:
            top_talkers = con.execute(
                "SELECT dest_ip, sum(coalesce(dest_bytes,0)) bytes, count(*) flows "
                "FROM read_parquet(?) WHERE harbor_source='vpc_flow' AND dest_ip<>'' "
                "GROUP BY 1 ORDER BY bytes DESC LIMIT 15",
                [path],
            ).fetchall()
            rejected = con.execute(
                "SELECT source_ip, dest_ip, dest_port, count(*) c FROM read_parquet(?) "
                "WHERE harbor_source='vpc_flow' AND event_outcome='failure' "
                "GROUP BY 1,2,3 ORDER BY c DESC LIMIT 15",
                [path],
            ).fetchall()
            totals = con.execute(
                "SELECT count(*) flows, sum(coalesce(dest_bytes,0)) bytes, "
                "sum(CASE WHEN event_outcome='failure' THEN 1 ELSE 0 END) rejects "
                "FROM read_parquet(?) WHERE harbor_source='vpc_flow'",
                [path],
            ).fetchone()
        finally:
            con.close()
        return {
            "totals": {"flows": totals[0] or 0, "bytes": totals[1] or 0, "rejects": totals[2] or 0},
            "top_talkers": [
                {"dest_ip": r[0], "bytes": int(r[1] or 0), "flows": r[2]} for r in top_talkers
            ],
            "rejected": [
                {"source_ip": r[0], "dest_ip": r[1], "dest_port": r[2], "count": r[3]}
                for r in rejected
            ],
        }


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

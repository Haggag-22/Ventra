"""ELB/ALB, CloudFront, and S3 server access-log normalizers → web/data events.

Collectors ship raw log lines (one record per line, plus delivery context); the parsing
lives here so formats stay independently versioned. Each parser is tolerant: a malformed
line is skipped, never fatal.
"""

from __future__ import annotations

import re
from typing import Any, Iterator
from urllib.parse import unquote_plus

from ..base import NormalizeContext, UnifiedEvent, register

# Tokenizer for quoted/space-delimited formats (ALB, S3 access): "..." | [...] | bare.
_TOKEN_RE = re.compile(r"\[[^\]]*\]|\"[^\"]*\"|\S+")

# ALB/NLB line type markers; Classic ELB lines start directly with the timestamp.
_ALB_TYPES = frozenset({"http", "https", "h2", "grpcs", "ws", "wss", "tls"})

# CloudFront standard log v1 field order, used when no #Fields header was captured.
_CLOUDFRONT_DEFAULT_FIELDS = (
    "date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status "
    "cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type "
    "x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for "
    "ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version fle-status "
    "fle-encrypted-fields c-port time-to-first-byte x-edge-detailed-result-type "
    "sc-content-type sc-content-len sc-range-start sc-range-end"
)


def _tokens(line: str) -> list[str]:
    return [t[1:-1] if t.startswith('"') else t for t in _TOKEN_RE.findall(line)]


def _dash(v: str) -> str:
    return "" if v in ("-", "-1") else v


def _ip(hostport: str) -> str:
    return _dash(hostport).rsplit(":", 1)[0] if _dash(hostport) else ""


def _status_outcome(status: str) -> str:
    try:
        return "failure" if int(status) >= 400 else "success"
    except ValueError:
        return "unknown"


# -- ELB / ALB -----------------------------------------------------------------------------


def parse_elb_line(line: str) -> dict[str, Any] | None:
    """Parse one ALB/NLB or Classic ELB access-log line into named fields."""
    t = _tokens(line)
    if len(t) < 12:
        return None
    if t[0] in _ALB_TYPES:  # ALB / NLB
        return {
            "kind": t[0],
            "time": t[1],
            "elb": t[2],
            "client_ip": _ip(t[3]),
            "target_ip": _ip(t[4]),
            "status": t[8],
            "received_bytes": _dash(t[10]),
            "sent_bytes": _dash(t[11]),
            "request": _dash(t[12]) if len(t) > 12 else "",
            "user_agent": _dash(t[13]) if len(t) > 13 else "",
        }
    # Classic ELB: timestamp first.
    if "T" not in t[0]:
        return None
    return {
        "kind": "classic",
        "time": t[0],
        "elb": t[1],
        "client_ip": _ip(t[2]),
        "target_ip": _ip(t[3]),
        "status": t[7],
        "received_bytes": _dash(t[9]),
        "sent_bytes": _dash(t[10]),
        "request": _dash(t[11]) if len(t) > 11 else "",
        "user_agent": _dash(t[12]) if len(t) > 12 else "",
    }


def _request_parts(request: str) -> tuple[str, str]:
    """('GET', 'https://host:443/path?x=1') from an ELB/S3 quoted request line."""
    parts = request.split(" ")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", request


@register("elb_alb")
def normalize_elb_alb(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        parsed = parse_elb_line(rec.get("line", ""))
        if parsed is None:
            continue
        method, url = _request_parts(parsed["request"])
        outcome = _status_outcome(parsed["status"])
        ip = parsed["client_ip"]
        lb = rec.get("_ventra_lb_name") or parsed["elb"]
        try:
            sent = int(parsed["sent_bytes"] or 0)
        except ValueError:
            sent = 0
        yield UnifiedEvent(
            timestamp=parsed["time"],
            event_kind="event",
            event_category=["network", "web"],
            event_action=method or parsed["kind"],
            event_outcome=outcome,
            event_severity="info",
            event_provider="elb",
            cloud_account=ctx.account_id,
            cloud_region=rec.get("_ventra_region", ""),
            cloud_service="elasticloadbalancing",
            source_ip=ip,
            dest_ip=parsed["target_ip"],
            dest_bytes=sent or None,
            ua_original=parsed["user_agent"],
            resource_type="load-balancer",
            resource_id=lb,
            related_ip=[i for i in (ip, parsed["target_ip"]) if i],
            message=f"{method or parsed['kind']} {url} → {parsed['status']} ({lb})",
            case_id=ctx.case_id,
            ventra_source="elb_alb",
            raw=rec,
        )


# -- CloudFront ----------------------------------------------------------------------------


def parse_cloudfront_line(line: str, fields: str = "") -> dict[str, str] | None:
    """Zip a tab-separated W3C line against its #Fields header."""
    names = (fields or _CLOUDFRONT_DEFAULT_FIELDS).split()
    values = line.split("\t")
    if len(values) < 2:
        return None
    return dict(zip(names, values))


@register("cloudfront")
def normalize_cloudfront(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        f = parse_cloudfront_line(rec.get("line", ""), rec.get("fields", ""))
        if f is None or not f.get("date"):
            continue
        status = f.get("sc-status", "")
        ip = _dash(f.get("c-ip", ""))
        method = f.get("cs-method", "")
        host = f.get("cs(Host)", "") or f.get("x-host-header", "")
        path = f.get("cs-uri-stem", "")
        ua = unquote_plus(f.get("cs(User-Agent)", "") or "")
        dist = rec.get("_ventra_distribution_id", "")
        yield UnifiedEvent(
            timestamp=f"{f['date']}T{f.get('time', '00:00:00')}Z",
            event_kind="event",
            event_category=["network", "web"],
            event_action=method,
            event_outcome=_status_outcome(status),
            event_severity="info",
            event_provider="cloudfront",
            cloud_account=ctx.account_id,
            cloud_region=f.get("x-edge-location", "global"),
            cloud_service="cloudfront",
            source_ip=ip,
            ua_original=_dash(ua),
            resource_type="distribution",
            resource_id=dist,
            related_ip=[ip] if ip else [],
            message=f"{method} {host}{path} → {status} ({dist})",
            case_id=ctx.case_id,
            ventra_source="cloudfront",
            raw=rec,
        )


# -- S3 server access logs -----------------------------------------------------------------

_S3_TIME_RE = re.compile(r"^\[(\d{2}/\w{3}/\d{4}):(\d{2}:\d{2}:\d{2})")

_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
    "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _s3_iso_time(bracketed: str) -> str:
    m = _S3_TIME_RE.match(bracketed)
    if not m:
        return ""
    day, mon, year = m.group(1).split("/")
    return f"{year}-{_MONTHS.get(mon, '01')}-{day}T{m.group(2)}Z"


def parse_s3_access_line(line: str) -> dict[str, Any] | None:
    """Parse one S3 server access-log line into named fields."""
    t = _tokens(line)
    if len(t) < 12:
        return None
    return {
        "bucket_owner": t[0],
        "bucket": t[1],
        "time": _s3_iso_time(t[2]),
        "remote_ip": _dash(t[3]),
        "requester": _dash(t[4]),
        "request_id": t[5],
        "operation": t[6],
        "key": _dash(t[7]),
        "request_uri": _dash(t[8]),
        "status": t[9],
        "error_code": _dash(t[10]),
        "bytes_sent": _dash(t[11]),
        "user_agent": _dash(t[16]) if len(t) > 16 else "",
    }


@register("s3_access")
def normalize_s3_access(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        p = parse_s3_access_line(rec.get("line", ""))
        if p is None or not p["time"]:
            continue
        ip = p["remote_ip"]
        requester = p["requester"]
        user = requester.split("/")[-1] if requester else ""
        obj = f"{p['bucket']}/{p['key']}" if p["key"] else p["bucket"]
        outcome = "failure" if p["error_code"] else _status_outcome(p["status"])
        try:
            sent = int(p["bytes_sent"] or 0)
        except ValueError:
            sent = 0
        yield UnifiedEvent(
            timestamp=p["time"],
            event_kind="event",
            event_category=["data"],
            event_action=p["operation"],
            event_outcome=outcome,
            event_severity="info",
            event_provider="s3_access",
            cloud_account=ctx.account_id,
            cloud_region=rec.get("_ventra_region", ""),
            cloud_service="s3",
            user_name=user,
            user_arn=requester if requester.startswith("arn:") else "",
            source_ip=ip,
            dest_bytes=sent or None,
            ua_original=p["user_agent"],
            resource_type="s3-object" if p["key"] else "s3-bucket",
            resource_id=obj,
            related_ip=[ip] if ip else [],
            related_user=[user] if user else [],
            message=f"{p['operation']} {obj} → {p['status']}"
            + (f" ({p['error_code']})" if p["error_code"] else ""),
            case_id=ctx.case_id,
            ventra_source="s3_access",
            raw=rec,
        )

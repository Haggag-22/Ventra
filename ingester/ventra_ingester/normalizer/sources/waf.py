"""WAF (WAFv2) sampled-request normalizer → web-protection events.

The collector ships ``GetSampledRequests`` results (last-3-hour sample per rule metric). Each
record is an AWS ``SampledRequest``: the HTTP request plus the rule action (ALLOW / BLOCK /
COUNT / CAPTCHA / CHALLENGE). Blocked requests are attack telemetry the analyst correlates
with ELB/ALB and CloudFront for the same client IP — so these live in the Web & DNS lens,
not in Security Findings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator

from ..base import NormalizeContext, UnifiedEvent, register

# Actions that represent the request being stopped / challenged rather than allowed through.
_BLOCKING_ACTIONS = frozenset({"BLOCK", "CAPTCHA", "CHALLENGE"})


def _iso_timestamp(value: Any) -> str:
    """Coerce the collector's timestamp (often ``2026-06-15 18:45:00+00:00``) to RFC 3339."""
    if not value:
        return ""
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return text


def _header(headers: list[dict], name: str) -> str:
    for h in headers or []:
        if str(h.get("Name", "")).lower() == name.lower():
            return str(h.get("Value", ""))
    return ""


def _acl_name(arn: str) -> str:
    """``arn:aws:wafv2:…:webacl/<name>/<id>`` → ``<name>``."""
    parts = (arn or "").split("/")
    return parts[-2] if len(parts) >= 2 else arn


@register("waf")
def normalize_waf(records: list[dict], ctx: NormalizeContext) -> Iterator[UnifiedEvent]:
    for rec in records:
        req = rec.get("Request") or {}
        action = str(rec.get("Action", "")).upper()
        method = str(req.get("Method", ""))
        uri = str(req.get("URI", ""))
        ip = str(req.get("ClientIP", ""))
        country = str(req.get("Country", ""))
        ua = _header(req.get("Headers") or [], "User-Agent")
        host = _header(req.get("Headers") or [], "Host")
        acl_arn = str(rec.get("_ventra_web_acl_arn", ""))
        acl = _acl_name(acl_arn)
        rule = str(rec.get("RuleNameWithinRuleGroup") or rec.get("_ventra_rule_metric") or "")
        blocked = action in _BLOCKING_ACTIONS

        yield UnifiedEvent(
            timestamp=_iso_timestamp(rec.get("Timestamp")),
            event_kind="event",
            event_category=["network", "web"],
            event_action=f"waf:{action.lower()}" if action else "waf",
            event_outcome="failure" if blocked else "success",
            event_severity="low" if blocked else "info",
            event_provider="waf",
            cloud_account=ctx.account_id,
            cloud_region=rec.get("_ventra_region", ""),
            cloud_service="wafv2",
            source_ip=ip,
            source_country=country,
            ua_original=ua,
            resource_type="web-acl",
            resource_id=acl,
            resource_arn=acl_arn,
            related_ip=[ip] if ip else [],
            related_resource=[r for r in (rule,) if r],
            message=(
                f"WAF {action or 'SAMPLE'} {method} {host}{uri} from {ip}"
                + (f" [{rule}]" if rule else "")
            ),
            case_id=ctx.case_id,
            ventra_source="waf",
            raw=rec,
        )

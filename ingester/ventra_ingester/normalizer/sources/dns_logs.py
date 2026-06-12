"""Route53 Resolver query-log normalizer → DNS network events.

Resolver records arrive as structured JSON from the collector (S3 vpcdnsquerylogs or
CloudWatch). NXDOMAIN bursts and lookups answered with external IPs are the C2 / DGA /
exfil signals the analyst pivots on.
"""

from __future__ import annotations

from typing import Iterator

from ..base import NormalizeContext, UnifiedEvent, register

_FAIL_RCODES = frozenset({"NXDOMAIN", "SERVFAIL", "REFUSED"})


@register("route53_resolver")
def normalize_route53_resolver(
    records: list[dict], ctx: NormalizeContext
) -> Iterator[UnifiedEvent]:
    for rec in records:
        qname = str(rec.get("query_name", "")).rstrip(".")
        if not qname:
            continue
        rcode = str(rec.get("rcode", ""))
        src = rec.get("srcaddr", "")
        answers = rec.get("answers") or []
        answer_ips = [
            a.get("Rdata", "") for a in answers if a.get("Type") in ("A", "AAAA")
        ]
        instance = (rec.get("srcids") or {}).get("instance", "")
        yield UnifiedEvent(
            timestamp=str(rec.get("query_timestamp", "")),
            event_kind="event",
            event_category=["network"],
            event_action=f"dns-query:{rec.get('query_type', '')}",
            event_outcome="failure" if rcode in _FAIL_RCODES else "success",
            event_severity="info",
            event_provider="route53_resolver",
            cloud_account=str(rec.get("account_id", ctx.account_id)),
            cloud_region=rec.get("region", rec.get("_ventra_region", "")),
            cloud_service="route53resolver",
            source_ip=src,
            dest_ip=answer_ips[0] if answer_ips else "",
            resource_type="dns-query",
            resource_id=qname,
            related_ip=[ip for ip in [src, *answer_ips] if ip],
            related_resource=[r for r in (instance, rec.get("vpc_id", "")) if r],
            message=f"{qname} ({rec.get('query_type', '')}) → {rcode}"
            + (f" [{instance}]" if instance else ""),
            case_id=ctx.case_id,
            ventra_source="route53_resolver",
            raw=rec,
        )

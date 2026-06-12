"""Enricher: geo/ASN, IP classification, and IOC tagging.

Offline-first. GeoIP/ASN lookups use a local MaxMind database only if one is supplied
(``--geoip <path>``); without it, country/ASN are left to whatever the source already
provided (e.g. GuardDuty includes them). IOC matches are written into ``related_*`` and a
dedicated ``ioc_match`` flag in raw-adjacent fields so the console can filter on them.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..normalizer.base import UnifiedEvent


@dataclass
class Enricher:
    iocs: set[str] = field(default_factory=set)
    _geo_reader: object | None = None
    _asn_reader: object | None = None

    @classmethod
    def build(cls, geoip_city: str | None = None, geoip_asn: str | None = None,
              iocs: set[str] | None = None) -> "Enricher":
        enr = cls(iocs=iocs or set())
        if geoip_city:
            try:
                import geoip2.database

                enr._geo_reader = geoip2.database.Reader(geoip_city)
            except Exception:  # pragma: no cover - optional
                enr._geo_reader = None
        if geoip_asn:
            try:
                import geoip2.database

                enr._asn_reader = geoip2.database.Reader(geoip_asn)
            except Exception:  # pragma: no cover
                enr._asn_reader = None
        return enr

    def enrich(self, ev: UnifiedEvent) -> UnifiedEvent:
        ip = ev.source_ip
        if ip and not ev.source_country:
            ev.source_country = self._country(ip)
        if ip and not ev.source_asn:
            ev.source_asn = self._asn(ip)
        # IOC tagging: any IP/user/resource present in the case IOC list.
        if self.iocs:
            hit = self.iocs.intersection(
                set(ev.related_ip) | set(ev.related_user) | set(ev.related_resource)
            )
            if hit:
                ev.event_severity = _bump(ev.event_severity)
                ev.message = f"[IOC] {ev.message}"
        return ev

    def _country(self, ip: str) -> str:
        if self._is_private(ip):
            return "PRIVATE"
        if self._geo_reader is not None:
            try:
                return self._geo_reader.city(ip).country.iso_code or ""  # type: ignore[attr-defined]
            except Exception:
                return ""
        return ""

    def _asn(self, ip: str) -> str:
        if self._is_private(ip):
            return ""
        if self._asn_reader is not None:
            try:
                resp = self._asn_reader.asn(ip)  # type: ignore[attr-defined]
                return f"AS{resp.autonomous_system_number} {resp.autonomous_system_organization}"
            except Exception:
                return ""
        return ""

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False


_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _bump(sev: str) -> str:
    try:
        i = _SEV_ORDER.index(sev)
    except ValueError:
        return "medium"
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]


def enrich_events(events, enricher: Enricher):
    for ev in events:
        yield enricher.enrich(ev)

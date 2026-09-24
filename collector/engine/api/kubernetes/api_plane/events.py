"""k8s_events — Kubernetes Events (the single most perishable artifact in the cluster).

The API server garbage-collects Events after ``--event-ttl`` (default **1h0m0s**). If the
incident is more than an hour old, this data is simply gone — so this collector runs first,
and it explicitly warns when the incident window predates the effective TTL rather than
silently returning a short list.

Both Event APIs are read — ``core/v1`` and ``events.k8s.io/v1``. They are two views over the
same storage, so records are de-duplicated by ``metadata.uid`` (the ``core/v1`` view wins,
because it carries the legacy fields most tooling parses) and each API's own count is
recorded. A denial on one API still leaves the other collectable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import scoped_window

from ..common.apiserver_flags import read_apiserver_flags
from ..common.distro import detect_distro

DEFAULT_EVENT_TTL = timedelta(hours=1)

# Reason substrings worth flagging for the analyst (case-insensitive contains match). Routine
# Normal-type reasons (Pulled/Pulling/Created/Started) are intentionally excluded — they fire
# on every healthy pod and would bury the signal. "Failed" covers FailedMount/FailedScheduling
# via substring match.
_FLAG_REASONS = (
    "Failed",
    "BackOff",
    "OOMKilling",
    "OOMKilled",
    "Evicted",
    "Killing",
    "Unhealthy",
    "NodeNotReady",
)


class EventsCollector(Collector):
    name = "k8s_events"
    priority = 1
    plane = "api"
    description = "Kubernetes Events across all namespaces (perishable; default TTL 1h)."
    required_actions = ("get events", "list events", "watch events")

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        # Only compare against a window the operator actually set — an unscoped run must not
        # spuriously claim retention loss.
        start, end = scoped_window(self.ctx, self.name, default_days=1)

        core_events, core_ok = self._list_api(cf, "core/v1", cf.list_events, gaps)
        modern_events, modern_ok = self._list_api(
            cf, "events.k8s.io/v1", getattr(cf, "list_events_v1", None), gaps
        )
        if not core_ok and not modern_ok:
            # Both Event APIs are unreadable: nothing to collect, but the gaps are recorded.
            self.write_meta({"source": self.name, "records": 0})
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps,
                notes="Neither core/v1 nor events.k8s.io/v1 Events could be listed — continuing.",
            )

        events, duplicates = _merge_events(core_events, modern_events)

        ttl, ttl_source = self._effective_ttl(cf)
        cutoff = datetime.now(UTC) - ttl
        if start is not None and start < cutoff:
            gaps.append(
                (
                    self.name,
                    GapReason.RETENTION_EXPIRED,
                    f"Incident window starts {start.isoformat()} but Events are garbage-collected "
                    f"after --event-ttl={_fmt(ttl)} ({ttl_source}); everything before "
                    f"{cutoff.isoformat()} is already gone from the API server. Use the "
                    f"apiserver audit log and node-plane sources for older activity.",
                )
            )

        flagged = 0
        for ev in events:
            reason = str(ev.get("reason", ""))
            if any(r.lower() in reason.lower() for r in _FLAG_REASONS):
                ev["_ventra_flag"] = reason
                flagged += 1
            ev["_ventra_cluster"] = self.ctx.account_id

        files = []
        if events:
            files.append(self.write_jsonl(events, "events.jsonl.gz"))
        files.append(
            self.write_json(
                {
                    "event_ttl": _fmt(ttl),
                    "event_ttl_source": ttl_source,
                    "collected": len(events),
                    "flagged": flagged,
                    "apis": {
                        "core/v1": {"readable": core_ok, "events": len(core_events)},
                        "events.k8s.io/v1": {"readable": modern_ok, "events": len(modern_events)},
                    },
                    "deduplicated": duplicates,
                    "window": {
                        "since": start.isoformat() if start else None,
                        "until": end.isoformat() if end else None,
                    },
                },
                "config.json",
            )
        )
        self.write_meta(
            {"source": self.name, "records": len(events), "flagged": flagged, "event_ttl": _fmt(ttl)}
        )

        if not events:
            # Nothing was obtained, whatever the reason — EMPTY, with the gaps saying why.
            # PARTIAL is reserved for "some records, but not all of them".
            status = SourceStatus.EMPTY
            if not gaps:
                gaps.append((self.name, GapReason.NOT_PRESENT, "No Events present in the cluster."))
        else:
            status = SourceStatus.PARTIAL if gaps else SourceStatus.COLLECTED
        return SourceResult(
            name=self.name,
            status=status,
            files=files,
            record_count=len(events),
            gaps=gaps,
            notes=f"{len(events)} event(s) ({len(core_events)} core/v1, "
            f"{len(modern_events)} events.k8s.io/v1, {duplicates} de-duplicated), "
            f"{flagged} flagged; TTL {_fmt(ttl)} ({ttl_source}).",
        )

    def _list_api(
        self,
        cf: Any,
        label: str,
        fn: Any,
        gaps: list[tuple[str, GapReason, str]],
    ) -> tuple[list[dict[str, Any]], bool]:
        """List one Event API. Returns ``(events, readable)``; a denial becomes a gap."""
        if fn is None:
            return [], False
        try:
            rows = fn() or []
        except KubeAccessDenied as exc:
            gaps.append((self.name, GapReason.ACCESS_DENIED, f"{label}: {exc.message}"))
            return [], False
        except KubeNotFound as exc:
            gaps.append((self.name, GapReason.NOT_PRESENT, f"{label}: {exc.message}"))
            return [], False
        except Exception as exc:  # noqa: BLE001 - one API failing must not lose the other
            gaps.append((self.name, GapReason.COLLECTOR_ERROR, f"{label}: {exc}"))
            return [], False
        for row in rows:
            row["_ventra_event_api"] = label
        return list(rows), True

    def _effective_ttl(self, cf: Any) -> tuple[timedelta, str]:
        """Read ``--event-ttl`` from whatever this distribution uses to declare it.

        kubeadm keeps it in the static pod manifest, k3s and RKE2 in their config or the
        server unit, microk8s in an args file. Reading all of them means the TTL is a
        measured value rather than an assumption on any distro where the node plane is
        available; without a node plane the documented 1h default is used and labelled as
        assumed, because claiming a measured TTL we did not read would be worse than
        admitting the uncertainty.
        """
        node = getattr(cf, "node", None)
        if node is not None:
            try:
                distro = detect_distro(node)
                resolved = read_apiserver_flags(node, distro, flags=("event-ttl",))
                raw = resolved.get("event-ttl")
                if raw:
                    parsed = _parse_duration(raw)
                    if parsed is not None:
                        origin = resolved.origins.get("event-ttl", "kube-apiserver flags")
                        return parsed, f"{origin} (--event-ttl={raw})"
                if resolved.determined:
                    return (
                        DEFAULT_EVENT_TTL,
                        f"default 1h0m0s (no --event-ttl set in {', '.join(resolved.evidence)})",
                    )
            except Exception:  # noqa: BLE001 - node access is best-effort here
                pass
        return DEFAULT_EVENT_TTL, "assumed default (1h0m0s); node plane unavailable to confirm"


def _merge_events(
    core: list[dict[str, Any]], modern: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    """Union both Event views, de-duplicating on ``metadata.uid`` (core/v1 wins).

    ``core/v1`` and ``events.k8s.io/v1`` are two representations of the same objects, so
    keeping both would double-count. Events without a uid (a hand-rolled fake, an older
    server) are always kept — dropping a real event is worse than one duplicate.
    """
    out = list(core)
    seen = {uid for uid in (_event_uid(e) for e in core) if uid}
    duplicates = 0
    for event in modern:
        uid = _event_uid(event)
        if uid and uid in seen:
            duplicates += 1
            continue
        if uid:
            seen.add(uid)
        out.append(event)
    return out, duplicates


def _event_uid(event: dict[str, Any]) -> str:
    meta = event.get("metadata") or {}
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("uid") or meta.get("UID") or "")


def _parse_duration(value: str) -> timedelta | None:
    """Parse a Go-style duration (e.g. ``1h0m0s``, ``30m``, ``2h``)."""
    units = {"h": 3600, "m": 60, "s": 1, "d": 86400, "w": 604800}
    total = 0
    num = ""
    seen = False
    for ch in value:
        if ch.isdigit():
            num += ch
        elif ch in units and num:
            total += int(num) * units[ch]
            num = ""
            seen = True
        else:
            return None
    return timedelta(seconds=total) if seen else None


def _fmt(td: timedelta) -> str:
    total = int(td.total_seconds())
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m}m{s}s"

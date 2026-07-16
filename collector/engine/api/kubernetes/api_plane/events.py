"""k8s_events — Kubernetes Events (the single most perishable artifact in the cluster).

The API server garbage-collects Events after ``--event-ttl`` (default **1h0m0s**). If the
incident is more than an hour old, this data is simply gone — so this collector runs first,
and it explicitly warns when the incident window predates the effective TTL rather than
silently returning a short list.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from collector.clouds.kubernetes.client_factory import KubeAccessDenied, KubeNotFound
from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import scoped_window

DEFAULT_EVENT_TTL = timedelta(hours=1)
_TTL_RE = re.compile(r"--event-ttl[= ]([0-9hlmsdw]+)")

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

        try:
            events = cf.list_events()
        except KubeAccessDenied as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.ACCESS_DENIED, exc.message)],
                notes="Denied 'list events' — continuing.",
            )
        except KubeNotFound as exc:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=[(self.name, GapReason.NOT_PRESENT, exc.message)],
            )

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
            status = SourceStatus.PARTIAL if gaps else SourceStatus.EMPTY
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
            notes=f"{len(events)} event(s), {flagged} flagged; TTL {_fmt(ttl)} ({ttl_source}).",
        )

    def _effective_ttl(self, cf: Any) -> tuple[timedelta, str]:
        """Read ``--event-ttl`` from the kube-apiserver static pod manifest via the node
        plane when available; otherwise assume the documented 1h default and say so."""
        node = getattr(cf, "node", None)
        manifest = "/etc/kubernetes/manifests/kube-apiserver.yaml"
        if node is not None:
            try:
                if node.exists(manifest):
                    text = node.read_text(manifest)
                    m = _TTL_RE.search(text)
                    if m:
                        parsed = _parse_duration(m.group(1))
                        if parsed is not None:
                            return parsed, f"kube-apiserver manifest (--event-ttl={m.group(1)})"
            except Exception:  # noqa: BLE001 - node access is best-effort here
                pass
        return DEFAULT_EVENT_TTL, "assumed default (1h0m0s); node plane unavailable to confirm"


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

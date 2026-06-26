"""Amazon Inspector (v2) collector.

Pulls vulnerability and network-reachability findings across regions, plus the account
enablement status. Inspector findings tell an IR team which CVEs were exposed on the
compromised workloads — the "how did they get in" lens. Whether Inspector is even enabled
is recorded as a gap when absent.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from collector.lib.base import Collector
from collector.lib.models import GapReason, SourceResult, SourceStatus
from collector.lib.params import effective_window
from collector.lib.scoping import filter_inspector_findings
from collector.clouds.aws.client_factory import AccessDenied, ServiceNotEnabled

from collector.lib.limits import records_unlimited


class Inspector2Collector(Collector):
    name = "inspector2"
    priority = 2
    description = "Inspector2 vulnerability / network-reachability findings + account status."
    required_actions = (
        "inspector2:ListFindings",
        "inspector2:BatchGetAccountStatus",
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        params = self.artifact_params()
        start, end = effective_window(self.ctx, self.name, default_days=90)
        findings: list[dict] = []
        status_by_region: list[dict] = []
        enabled_anywhere = False

        for region in self.ctx.regions:
            try:
                status = cf.call("inspector2", region, "batch_get_account_status")
            except AccessDenied as exc:
                gaps.append(("inspector2", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
                continue
            except (ServiceNotEnabled, ClientError):
                continue
            accounts = status.get("accounts") or []
            region_enabled = any(
                (a.get("state") or {}).get("status") == "ENABLED" for a in accounts
            )
            status_by_region.append({"region": region, "accounts": accounts})
            if not region_enabled:
                continue
            enabled_anywhere = True
            findings.extend(self._findings(cf, region, gaps, start, end))

        findings = filter_inspector_findings(findings, params)

        if not enabled_anywhere:
            return SourceResult(
                name=self.name,
                status=SourceStatus.EMPTY,
                gaps=gaps
                or [
                    (
                        "inspector2",
                        GapReason.SERVICE_NOT_ENABLED,
                        "Inspector2 not enabled in scope.",
                    )
                ],
                notes="Inspector2 not enabled — recorded as a gap.",
            )

        files = [self.write_json({"account_status": status_by_region, "artifact_parameters": params}, "config.json")]
        if findings:
            files.append(self.write_jsonl(findings, "events.jsonl.gz"))
        self.write_meta(
            {"source": self.name, "findings": len(findings), "regions": self.ctx.regions}
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED if findings else SourceStatus.EMPTY,
            files=files,
            record_count=len(findings),
            gaps=gaps,
            notes=f"{len(findings)} Inspector2 finding(s).",
        )

    def _findings(self, cf, region: str, gaps, start, end) -> list[dict]:
        out: list[dict] = []
        truncated = False
        cap = self.max_records()
        try:
            for f in cf.paginate("inspector2", region, "list_findings", "findings"):
                if not records_unlimited(cap) and len(out) >= cap:
                    truncated = True
                    break
                updated = f.get("updatedAt") or f.get("firstObservedAt")
                if updated:
                    try:
                        from datetime import datetime
                        ts = datetime.fromisoformat(str(updated).replace("Z", "+00:00"))
                        if ts < start or ts > end:
                            continue
                    except ValueError:
                        pass
                f["_ventra_region"] = region
                out.append(f)
        except AccessDenied as exc:
            gaps.append(("inspector2", GapReason.ACCESS_DENIED, f"{region}: {exc.message}"))
        except (ServiceNotEnabled, ClientError):
            pass
        if truncated:
            gaps.append(
                (
                    "inspector2",
                    GapReason.COLLECTOR_ERROR,
                    f"{region}: findings truncated at {cap:,}.",
                )
            )
        return out

"""Harbor ingester CLI: ``harbor-ingest`` and ``harbor-verify``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def _reporter():
    try:
        from rich.console import Console

        console = Console()
        return console.print
    except Exception:  # pragma: no cover
        return print


def ingest_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harbor-ingest", description="Ingest a Harbor evidence package.")
    p.add_argument("package", help="Path to the .tar.zst / .tar.gz evidence package.")
    p.add_argument("--case-store", default="./cases", help="Case store root (default: ./cases).")
    p.add_argument("--geoip-city", default=None, help="Optional MaxMind City DB for geo enrichment.")
    p.add_argument("--geoip-asn", default=None, help="Optional MaxMind ASN DB for ASN enrichment.")
    p.add_argument("--iocs", default=None, help="Optional file of IOCs (one IP/ARN/user per line).")
    p.add_argument("--version", action="version", version=f"harbor-ingester {__version__}")
    args = p.parse_args(argv)

    from .enrichment import Enricher
    from .pipeline import ingest_package

    iocs = set()
    if args.iocs:
        iocs = {
            line.strip()
            for line in Path(args.iocs).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    enricher = Enricher.build(args.geoip_city, args.geoip_asn, iocs)

    say = _reporter()
    try:
        result = ingest_package(
            Path(args.package), Path(args.case_store), enricher=enricher, reporter=say
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Ingest failed: {exc}", file=sys.stderr)
        return 1

    say(f"\n[bold green]Done.[/bold green] Case [bold]{result.case_id}[/bold] ready "
        f"({result.event_count} events, integrity={result.integrity_overall}).")
    say(f"  Event sources: {', '.join(result.sources_loaded) or '—'}")
    say(f"  Inventory:     {', '.join(result.inventory_loaded) or '—'}")
    for w in result.warnings:
        say(f"  [yellow]warning[/yellow] {w}")
    say(f"  Open the console and select case {result.case_id}.")
    return 0


def verify_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="harbor-verify", description="Verify package integrity only.")
    p.add_argument("package", help="Path to the evidence package.")
    p.add_argument("--key", default=None, help="Public key for cryptographic signature verify.")
    p.add_argument("--json", action="store_true", help="Emit the integrity report as JSON.")
    args = p.parse_args(argv)

    from .package import EvidencePackage
    from .verify import verify_package

    pkg = EvidencePackage(Path(args.package))
    report = verify_package(pkg)
    if args.json:
        import json

        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"Case:      {report.case_id}")
        print(f"Integrity: {report.overall.upper()}")
        print(f"Signature: {report.signature_method} (valid={report.signature_valid})")
        for c in report.checks:
            mark = "OK " if c.matched else "BAD"
            print(f"  [{mark}] {c.name:<14} {c.arcname}")
        for n in report.notes:
            print(f"  note: {n}")
    return 0 if report.overall != "red" else 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(ingest_main())

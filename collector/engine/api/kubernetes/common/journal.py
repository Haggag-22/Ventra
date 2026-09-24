"""Shared systemd-journal / log-file capture for node-plane collectors.

``journalctl -u <unit> -o json`` gives structured records on systemd nodes; on non-systemd
nodes (or when the journal is unavailable) we fall back to a plain log file. Everything here
is read-only.
"""

from __future__ import annotations

import json
from typing import Any


def collect_unit(node: Any, unit: str, *, fallback_files: tuple[str, ...] = ()) -> dict[str, Any]:
    """Return ``{records, source, available, note}`` for one systemd unit or its log fallback."""
    rc, out, err = node.run(["journalctl", "-u", unit, "-o", "json", "--no-pager"], timeout=180)
    if rc == 0 and out.strip():
        records = _parse_journal_json(out)
        return {
            "records": records,
            "source": f"journalctl -u {unit}",
            "available": True,
            "note": f"{len(records)} journal record(s) for {unit}.",
        }

    for host_path in fallback_files:
        if node.exists(host_path):
            try:
                text = node.read_text(host_path)
            except Exception:  # noqa: BLE001
                continue
            lines = [ln for ln in text.splitlines() if ln.strip()]
            return {
                "records": [{"MESSAGE": ln, "_ventra_log_file": host_path} for ln in lines],
                "source": host_path,
                "available": True,
                "note": f"{len(lines)} line(s) from {host_path} (non-systemd fallback).",
            }

    return {
        "records": [],
        "source": f"journalctl -u {unit}",
        "available": False,
        "note": err.strip() or f"neither journalctl nor a log file was available for {unit}.",
    }


def _parse_journal_json(out: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records

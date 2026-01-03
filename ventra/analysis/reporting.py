"""
Report generation for Ventra analysis.

Keeps it intentionally lightweight: summarize what was normalized/correlated,
and include (optional) AI enrichment output if available.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def _safe_load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _count_records(normalized_file: Path) -> int:
    data = _safe_load_json(normalized_file)
    if not data:
        return 0
    records = data.get("records", [])
    return len(records) if isinstance(records, list) else 0


def generate_report(
    *,
    case_dir: Path,
    normalized_dir: Path,
    correlated_dir: Path,
    ai_enrichment_path: Optional[Path],
    report_format: str = "text",
    output_path: Optional[Path] = None,
) -> Path:
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not output_path:
        ext = "json" if report_format == "json" else "txt"
        output_path = reports_dir / f"dfir_report.{ext}"

    # Collect summary stats
    normalized_files = sorted(normalized_dir.glob("*.json")) if normalized_dir.exists() else []
    normalized_counts = {p.name: _count_records(p) for p in normalized_files}
    total_normalized = sum(normalized_counts.values())

    correlated_files = sorted(correlated_dir.glob("*.json")) if correlated_dir.exists() else []
    correlated_artifacts = [p.name for p in correlated_files]

    ai_summary = None
    if ai_enrichment_path and ai_enrichment_path.exists():
        ai_data = _safe_load_json(ai_enrichment_path)
        if ai_data:
            ai_summary = {
                "provider": ai_data.get("provider"),
                "model": ai_data.get("model"),
                "count": ai_data.get("count"),
                "path": str(ai_enrichment_path),
            }

    generated_at = datetime.utcnow().isoformat() + "Z"

    if report_format == "json":
        payload: Dict[str, Any] = {
            "generated_at": generated_at,
            "case_dir": str(case_dir),
            "normalized": {
                "dir": str(normalized_dir),
                "total_records": total_normalized,
                "files": normalized_counts,
            },
            "correlated": {
                "dir": str(correlated_dir),
                "artifacts": correlated_artifacts,
            },
            "ai": ai_summary,
        }
        output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return output_path

    # text report
    lines = []
    lines.append("Ventra DFIR Report")
    lines.append("=" * 72)
    lines.append(f"Generated: {generated_at}")
    lines.append(f"Case Dir:  {case_dir}")
    lines.append("")

    lines.append("Normalization")
    lines.append("-" * 72)
    lines.append(f"Normalized Dir: {normalized_dir}")
    lines.append(f"Total Records:  {total_normalized:,}")
    if normalized_counts:
        for name in sorted(normalized_counts.keys()):
            lines.append(f"  - {name}: {normalized_counts[name]:,}")
    else:
        lines.append("  (no normalized files found)")
    lines.append("")

    lines.append("Correlation")
    lines.append("-" * 72)
    lines.append(f"Correlated Dir: {correlated_dir}")
    if correlated_artifacts:
        for name in correlated_artifacts:
            lines.append(f"  - {name}")
    else:
        lines.append("  (no correlated artifacts found)")
    lines.append("")

    lines.append("AI Enrichment")
    lines.append("-" * 72)
    if ai_summary:
        lines.append(f"Provider: {ai_summary.get('provider')}")
        lines.append(f"Model:    {ai_summary.get('model')}")
        lines.append(f"Count:    {ai_summary.get('count')}")
        lines.append(f"Path:     {ai_summary.get('path')}")
    else:
        lines.append("AI enrichment disabled or not configured.")
        lines.append("Tip: set VENTRA_AI_PROVIDER=openai and OPENAI_API_KEY, or pass --ai-provider openai.")

    lines.append("")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return output_path


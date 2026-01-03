"""
Analysis pipeline orchestrator.

This is the "one command" workflow users expect:
  1) Normalize collector outputs into a standard schema
  2) Correlate normalized records (timelines, relationships, patterns)
  3) Optionally enrich findings using AI
  4) Generate a report artifact under case/reports/
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Union

from ventra.normalization import run_pipeline as run_normalization_pipeline
from ventra.correlation import run_correlation_pipeline

from .reporting import generate_report
from .ai.enrich import enrich_findings


@dataclass
class AnalysisOutputs:
    case_dir: Path
    normalized_dir: Path
    correlated_dir: Path
    reports_dir: Path
    report_path: Optional[Path] = None
    ai_enrichment_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_dir": str(self.case_dir),
            "normalized_dir": str(self.normalized_dir),
            "correlated_dir": str(self.correlated_dir),
            "reports_dir": str(self.reports_dir),
            "report_path": str(self.report_path) if self.report_path else None,
            "ai_enrichment_path": str(self.ai_enrichment_path) if self.ai_enrichment_path else None,
        }


def run_analysis_pipeline(
    case_dir: Union[str, Path],
    *,
    output_subdir: str = "normalized",
    profile: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    ai_provider: str = "off",
    ai_model: str = "gpt-4o-mini",
    ai_max_findings: int = 25,
    report_format: str = "text",
    report_output: Optional[Union[str, Path]] = None,
) -> AnalysisOutputs:
    case_dir = Path(case_dir)
    if not case_dir.exists():
        raise ValueError(f"Case directory does not exist: {case_dir}")

    normalized_dir = case_dir / output_subdir
    correlated_dir = case_dir / "correlated"
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1) Normalize
    run_normalization_pipeline(
        case_dir=case_dir,
        targets=None,
        output_subdir=output_subdir,
        profile=profile,
        account_id=account_id,
        region=region,
    )

    # 2) Correlate
    run_correlation_pipeline(case_dir=case_dir)

    outputs = AnalysisOutputs(
        case_dir=case_dir,
        normalized_dir=normalized_dir,
        correlated_dir=correlated_dir,
        reports_dir=reports_dir,
    )

    # 3) AI enrichment (optional)
    if ai_provider and ai_provider != "off":
        ai_dir = case_dir / "ai"
        ai_dir.mkdir(parents=True, exist_ok=True)
        ai_out_path = ai_dir / "findings_enriched.json"

        enrichment = enrich_findings(
            normalized_dir=normalized_dir,
            correlated_dir=correlated_dir,
            provider=ai_provider,
            model=ai_model,
            max_findings=ai_max_findings,
        )
        payload = {
            "enriched_at": datetime.utcnow().isoformat() + "Z",
            "provider": ai_provider,
            "model": ai_model,
            "max_findings": ai_max_findings,
            "count": len(enrichment),
            "findings": enrichment,
        }
        ai_out_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        outputs.ai_enrichment_path = ai_out_path

    # 4) Report
    report_path = generate_report(
        case_dir=case_dir,
        normalized_dir=normalized_dir,
        correlated_dir=correlated_dir,
        ai_enrichment_path=outputs.ai_enrichment_path,
        report_format=report_format,
        output_path=Path(report_output) if report_output else None,
    )
    outputs.report_path = report_path
    return outputs


def run_from_args(args) -> Dict[str, Any]:
    """
    CLI adapter: expects `args.case_dir` and related flags.

    Returns a dict of output paths for pretty printing in CLI.
    """
    case_dir = getattr(args, "case_dir", None)
    if not case_dir:
        raise ValueError("case_dir is required to run analysis")

    outputs = run_analysis_pipeline(
        case_dir=case_dir,
        output_subdir=getattr(args, "output_subdir", "normalized"),
        profile=getattr(args, "profile", None),
        account_id=getattr(args, "account_id", None),
        region=getattr(args, "region", None),
        ai_provider=getattr(args, "ai_provider", "off"),
        ai_model=getattr(args, "ai_model", "gpt-4o-mini"),
        ai_max_findings=int(getattr(args, "ai_max_findings", 25) or 25),
        report_format=getattr(args, "format", "text"),
        report_output=getattr(args, "output", None),
    )
    return outputs.to_dict()


"""
Findings enrichment.

Consumes normalized GuardDuty and SecurityHub finding records and produces an
enriched list (triage summary, recommended actions, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .openai_client import chat_json


def _safe_load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_findings(normalized_dir: Path) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Return list of (source, record) where source is 'guardduty' or 'securityhub'.
    """
    findings: List[Tuple[str, Dict[str, Any]]] = []

    gd_path = normalized_dir / "guardduty.json"
    if gd_path.exists():
        data = _safe_load_json(gd_path)
        if data and isinstance(data.get("records"), list):
            for r in data["records"]:
                if isinstance(r, dict) and r.get("type") == "aws.guardduty.finding":
                    findings.append(("guardduty", r))

    sh_path = normalized_dir / "securityhub.json"
    if sh_path.exists():
        data = _safe_load_json(sh_path)
        if data and isinstance(data.get("records"), list):
            for r in data["records"]:
                if isinstance(r, dict) and r.get("type") == "aws.securityhub.finding":
                    findings.append(("securityhub", r))

    return findings


def _severity_score(source: str, record: Dict[str, Any]) -> float:
    meta = record.get("metadata") or {}
    if not isinstance(meta, dict):
        return 0.0

    if source == "guardduty":
        sev = meta.get("severity")
        try:
            return float(sev) if sev is not None else 0.0
        except Exception:
            return 0.0

    # securityhub: Severity dict; try Normalized (0-100) then Label
    sev = meta.get("severity") or {}
    if isinstance(sev, dict):
        norm = sev.get("Normalized")
        try:
            return float(norm) / 10.0  # scale into ~0-10
        except Exception:
            pass
        label = (sev.get("Label") or "").upper()
        return {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.0,
            "INFORMATIONAL": 1.0,
        }.get(label, 0.0)

    return 0.0


def _build_prompt(source: str, record: Dict[str, Any]) -> str:
    """
    Build a compact, provider-agnostic prompt input containing only the parts
    we want to send externally.
    """
    meta = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    payload: Dict[str, Any] = {
        "source": source,
        "id": record.get("id") or record.get("resource_id"),
        "account_id": record.get("account_id"),
        "region": record.get("region"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "title": meta.get("title"),
        "description": meta.get("description"),
        "severity": meta.get("severity"),
        "type": meta.get("type") if source == "guardduty" else meta.get("types"),
        "resources": meta.get("resources") if source == "securityhub" else meta.get("resource"),
        "remediation": meta.get("remediation") if source == "securityhub" else None,
        "workflow_status": meta.get("workflow_status") if source == "securityhub" else None,
        "compliance": meta.get("compliance") if source == "securityhub" else None,
    }
    return json.dumps(payload, indent=2, default=str)


def enrich_findings(
    *,
    normalized_dir: Path,
    correlated_dir: Path,
    provider: str,
    model: str,
    max_findings: int = 25,
) -> List[Dict[str, Any]]:
    """
    Enrich top findings (by severity) with AI.

    Returns a list of enriched finding objects. Does not write to disk.
    """
    all_findings = _load_findings(normalized_dir)
    if not all_findings:
        return []

    # Sort by severity (desc) and limit
    all_findings.sort(key=lambda sr: _severity_score(sr[0], sr[1]), reverse=True)
    selected = all_findings[: max(0, int(max_findings))]

    # Correlation context (lightweight; don't ship full event data to AI)
    corr_files = {}
    if correlated_dir.exists():
        for name in ["patterns.json", "timelines.json", "event_correlations_summary.json"]:
            p = correlated_dir / name
            if p.exists():
                data = _safe_load_json(p)
                if data:
                    corr_files[name] = data

    system_prompt = (
        "You are a cloud DFIR analyst. You will be given ONE AWS security finding "
        "(GuardDuty or Security Hub) plus optional correlation summary. "
        "Return ONLY valid JSON with the following keys:\n"
        "- summary (string)\n"
        "- why_it_matters (string)\n"
        "- confidence (number 0..1)\n"
        "- false_positive_notes (array of strings)\n"
        "- recommended_actions (array of {title, steps})\n"
        "- mitre (object with tactics, techniques arrays)\n"
        "- ioc (object with ips, arns, usernames arrays)\n\n"
        "Rules:\n"
        "- Be AWS-specific and actionable.\n"
        "- Do NOT invent IOCs or ARNs; only extract from provided input.\n"
        "- If uncertain, lower confidence and say what's missing."
    )

    enriched: List[Dict[str, Any]] = []
    for source, record in selected:
        finding_id = record.get("id") or record.get("resource_id")
        user_prompt = (
            "CORRELATION_SUMMARY:\n"
            f"{json.dumps(corr_files, indent=2, default=str)}\n\n"
            "INPUT_FINDING:\n"
            f"{_build_prompt(source, record)}"
        )

        if provider == "openai":
            ai = chat_json(model=model, system_prompt=system_prompt, user_prompt=user_prompt)
        else:
            raise ValueError(f"Unknown AI provider: {provider}")

        enriched.append(
            {
                "finding_id": finding_id,
                "source": source,
                "account_id": record.get("account_id"),
                "region": record.get("region"),
                "created_at": record.get("created_at"),
                "severity_score": _severity_score(source, record),
                "ai": ai,
            }
        )

    return enriched


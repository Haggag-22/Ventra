"""
AI helpers for Ventra analysis.

This package is intentionally minimal and optional. If AI is not configured,
Ventra analysis still completes (normalization + correlation + report).
"""

from .enrich import enrich_findings

__all__ = ["enrich_findings"]


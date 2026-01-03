"""
Analysis package.

Runs the end-to-end DFIR workflow on a case:
  normalize -> correlate -> (optional) AI enrich -> report
"""

from .pipeline import run_analysis_pipeline, run_from_args

__all__ = ["run_analysis_pipeline", "run_from_args"]


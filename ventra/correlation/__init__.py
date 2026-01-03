"""
Correlation module.

Correlates normalized events and resources to build relationships,
timelines, and identify patterns.
"""

from .pipeline import run_correlation_pipeline

__all__ = ["run_correlation_pipeline"]


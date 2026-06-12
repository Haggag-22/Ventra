"""Case-store loaders. Default: DuckDB-over-Parquet."""

from .casestore import CaseStore, build_summary

__all__ = ["CaseStore", "build_summary"]

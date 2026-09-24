"""Shared GCP collector helpers."""

from .logging_collector import GcpLoggingCollector, window_bounds

__all__ = ["GcpLoggingCollector", "window_bounds"]

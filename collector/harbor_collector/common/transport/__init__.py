"""Transport adapters for shipping a sealed package to the IR team."""

from .base import Transport, get_transport

__all__ = ["get_transport", "Transport"]

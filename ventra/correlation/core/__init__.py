"""
Correlation core module.

Provides base classes, context, and utilities for correlating normalized data.
"""

from .base import BaseCorrelator, CorrelationSummary
from .context import CorrelationContext
from .schema import CorrelationFields

__all__ = [
    "BaseCorrelator",
    "CorrelationSummary",
    "CorrelationContext",
    "CorrelationFields",
]


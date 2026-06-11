"""AWS collectors — the first supported cloud.

Importing this package registers every AWS collector with the shared registry via
``harbor_collector.aws.registry``.
"""

from . import registry  # noqa: F401  (import side effect: populates the registry)
from .registry import AWS_REGISTRY

__all__ = ["AWS_REGISTRY"]

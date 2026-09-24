"""Artifact engine — load YAML artifacts, resolve API modules, execute acquisition."""

from __future__ import annotations

from .executor import list_collectors, run_collectors
from .loader import load_artifact, load_artifacts_dir
from .registry import (
    artifact_type_for_collector,
    collector_class_for,
    collector_order_for_cloud,
    registry_for_cloud,
)

__all__ = [
    "AWS_REGISTRY",
    "AZURE_REGISTRY",
    "GCP_REGISTRY",
    "artifact_type_for_collector",
    "collector_class_for",
    "collector_order_for_cloud",
    "list_collectors",
    "load_artifact",
    "load_artifacts_dir",
    "registry_for_cloud",
    "run_collectors",
]


def __getattr__(name: str):
    if name in ("AWS_REGISTRY", "AZURE_REGISTRY", "GCP_REGISTRY"):
        from . import registry

        return getattr(registry, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

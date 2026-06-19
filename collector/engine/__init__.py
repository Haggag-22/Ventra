"""Artifact engine — load YAML artifacts, resolve API modules, execute acquisition."""

from .executor import list_collectors, run_collectors
from .loader import load_artifact, load_artifacts_dir
from .registry import (
    AWS_REGISTRY,
    AZURE_REGISTRY,
    GCP_REGISTRY,
    artifact_type_for_collector,
    collector_class_for,
    registry_for_cloud,
)

__all__ = [
    "AWS_REGISTRY",
    "AZURE_REGISTRY",
    "GCP_REGISTRY",
    "artifact_type_for_collector",
    "collector_class_for",
    "list_collectors",
    "load_artifact",
    "load_artifacts_dir",
    "registry_for_cloud",
    "run_collectors",
]

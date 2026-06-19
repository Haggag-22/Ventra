"""Thin entrypoint — delegates to cloud runners and engine listing."""

from __future__ import annotations

from collector.engine.api.aws.runner import AwsRunConfig, run_aws_collection
from collector.engine.api.azure.runner import AzureRunConfig, run_azure_collection
from collector.engine.executor import list_collectors
from collector.engine.api.gcp.runner import GcpRunConfig, run_gcp_collection

__all__ = [
    "AwsRunConfig",
    "AzureRunConfig",
    "GcpRunConfig",
    "list_collectors",
    "run_aws_collection",
    "run_azure_collection",
    "run_gcp_collection",
]

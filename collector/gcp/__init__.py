"""GCP collectors for Ventra.

Baseline sources aligned with the Google Cloud IR cheat sheet:

  Management Plane
    * cloud_audit_admin   — Admin Activity Logs
    * cloud_audit_system  — System Event Logs
    * cloud_audit_data    — Data Access Logs
    * login_events        — Login Audit Logs
    * workspace_audit     — Workspace Group Audit Logs

  Network
    * vpc_flow            — VPC Flow Logs
    * firewall_logs       — VPC Firewall Logs
    * load_balancer       — Cloud Load Balancer Logs

  Compute
    * vm_logs             — Compute Engine VM logs
    * cloud_functions     — Cloud Functions logs

  Application
    * api_gateway         — API Gateway logs

  Data
    * storage_access      — Storage Bucket access logs

  Cloud Services
    * scc_findings        — Security Command Center
    * cloud_monitoring    — Cloud Monitoring alerts

  Context
    * project             — project + organization context
    * iam_policy          — IAM policy bindings
"""

from .registry import COLLECTOR_ORDER, GCP_REGISTRY, all_collector_names

__all__ = ["GCP_REGISTRY", "COLLECTOR_ORDER", "all_collector_names"]

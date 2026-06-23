# Collector ↔ infrastructure mapping

## AWS (22) — `infrastructure/aws/`

account, cloudtrail, iam, vpc_flow, waf, guardduty, securityhub, config, detective, macie, inspector2, route53_resolver, cloudfront, elb_alb, lambda, s3, s3_access, ec2, secrets, kms, eks_audit, log_posture

## Azure (22) — `infrastructure/azure/`

**Terraform:** subscription, activity_log, log_analytics, diag_posture, resource_graph, defender, vnet_flow, nsg_flow, azure_firewall, app_gateway, front_door, dns, storage_access, key_vault, aks_audit

**Manual (tenant):** entra_signin, entra_audit, entra_directory, rbac, oauth_consent, unified_audit, unified_audit_search

## GCP (16) — `infrastructure/gcp/`

**Terraform:** project, iam_policy, cloud_audit_admin, cloud_audit_system, cloud_audit_data, login_events, vpc_flow, firewall_logs, load_balancer, storage_access, cloud_functions, api_gateway, cloud_monitoring, vm_logs

**Manual / optional:** workspace_audit (Workspace), scc_findings (org_id + enable_scc)

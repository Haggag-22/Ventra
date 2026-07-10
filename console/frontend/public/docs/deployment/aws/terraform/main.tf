terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "user_name" {
  type        = string
  default     = "ventra-collector"
  description = "IAM user name for Ventra authentication."
}

variable "create_access_key" {
  type        = bool
  default     = true
  description = "Create an access key pair for the IAM user."
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to IAM resources."
}

data "aws_iam_policy_document" "ventra_collector" {
  statement {
    sid    = "VentraIdentityAndAccountContext"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity",
      "iam:ListAccountAliases",
      "organizations:DescribeOrganization",
      "ec2:DescribeRegions",
      "account:GetContactInformation",
      "account:ListRegions",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraCloudTrail"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:GetTrail",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:GetInsightSelectors",
      "cloudtrail:ListTrails",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraVpcFlowAndNetwork"
    effect = "Allow"
    actions = [
      "ec2:DescribeFlowLogs",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeSnapshotAttribute",
      "ec2:DescribeImages",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeAddresses",
      "logs:FilterLogEvents",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraGuardDuty"
    effect = "Allow"
    actions = [
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
      "guardduty:GetFindingsStatistics",
      "guardduty:ListFilters",
      "guardduty:GetFilter",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraWAF"
    effect = "Allow"
    actions = [
      "wafv2:ListWebACLs",
      "wafv2:GetWebACL",
      "wafv2:GetLoggingConfiguration",
      "wafv2:ListLoggingConfigurations",
      "wafv2:GetSampledRequests",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraIAMSnapshot"
    effect = "Allow"
    actions = [
      "iam:GetAccountAuthorizationDetails",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:ListGroups",
      "iam:ListPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies",
      "iam:GetUserPolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:ListAttachedGroupPolicies",
      "iam:ListGroupPolicies",
      "iam:GetGroupPolicy",
      "iam:ListGroupsForUser",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRole",
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:ListMFADevices",
      "iam:GetAccountPasswordPolicy",
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraTier2ReadOnly"
    effect = "Allow"
    actions = [
      "config:DescribeConfigurationRecorders",
      "config:DescribeDeliveryChannels",
      "config:GetResourceConfigHistory",
      "config:DescribeComplianceByConfigRule",
      "securityhub:GetFindings",
      "securityhub:DescribeHub",
      "securityhub:GetEnabledStandards",
      "macie2:GetMacieSession",
      "macie2:ListFindings",
      "macie2:GetFindings",
      "detective:ListGraphs",
      "detective:ListInvestigations",
      "inspector2:ListFindings",
      "inspector2:BatchGetAccountStatus",
      "route53resolver:ListResolverQueryLogConfigs",
      "route53resolver:ListResolverQueryLogConfigAssociations",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "logs:DescribeLogGroups",
      "es:ListDomainNames",
      "es:DescribeDomain",
      "rds:DescribeDBInstances",
      "dynamodb:ListTables",
      "dynamodb:DescribeTable",
      "network-firewall:ListFirewalls",
      "network-firewall:DescribeLoggingConfiguration",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "elasticloadbalancing:DescribeListeners",
      "cloudfront:ListDistributions",
      "cloudfront:GetDistributionConfig",
      "apigateway:GET",
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:ListGrants",
      "secretsmanager:ListSecrets",
      "secretsmanager:DescribeSecret",
      "ssm:DescribeParameters",
      "ssm:GetParameterHistory",
      "lambda:ListFunctions",
      "lambda:GetFunction",
      "lambda:GetPolicy",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "s3:GetBucketLogging",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketObjectLockConfiguration",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "VentraReadLogObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::*-logs",
      "arn:aws:s3:::*-logs/*",
      "arn:aws:s3:::*cloudtrail*",
      "arn:aws:s3:::*cloudtrail*/*",
      "arn:aws:s3:::*flow-log*",
      "arn:aws:s3:::*flow-log*/*",
      "arn:aws:s3:::*access-log*",
      "arn:aws:s3:::*access-log*/*",
      "arn:aws:s3:::*lb-logs*",
      "arn:aws:s3:::*lb-logs*/*",
    ]
  }
}

resource "aws_iam_policy" "ventra_collector" {
  name        = "VentraCollectorReadOnly"
  description = "Read-only permissions for Ventra AWS forensic collectors."
  policy      = data.aws_iam_policy_document.ventra_collector.json
  tags        = var.tags
}

resource "aws_iam_user" "ventra_collector" {
  name = var.user_name
  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "ventra_collector" {
  user       = aws_iam_user.ventra_collector.name
  policy_arn = aws_iam_policy.ventra_collector.arn
}

resource "aws_iam_access_key" "ventra_collector" {
  count = var.create_access_key ? 1 : 0
  user  = aws_iam_user.ventra_collector.name
}

output "user_name" {
  value       = aws_iam_user.ventra_collector.name
  description = "IAM user for Ventra authentication."
}

output "policy_arn" {
  value       = aws_iam_policy.ventra_collector.arn
  description = "Managed policy ARN."
}

output "access_key_id" {
  value       = try(aws_iam_access_key.ventra_collector[0].id, null)
  description = "Access key ID for Ventra console credentials."
  sensitive   = false
}

output "secret_access_key" {
  value       = try(aws_iam_access_key.ventra_collector[0].secret, null)
  description = "Secret access key. Store securely."
  sensitive   = true
}

/** Read-only IAM actions Ventra needs for AWS connection test and collection. */

export type AwsPermissionGroup = {
  label: string;
  actions: string[];
};

/** Minimum action required to validate an AWS connection. */
export const AWS_AUTH_PERMISSION_GROUP: AwsPermissionGroup = {
  label: "Authentication",
  actions: ["sts:GetCallerIdentity"],
};

/** Grouped collector permissions — sourced from docs/iam-policies/aws-collector-permissions.txt */
export const AWS_COLLECTOR_PERMISSION_GROUPS: AwsPermissionGroup[] = [
  {
    label: "Account context",
    actions: [
      "sts:GetCallerIdentity",
      "iam:ListAccountAliases",
      "organizations:DescribeOrganization",
      "ec2:DescribeRegions",
    ],
  },
  {
    label: "IAM snapshot",
    actions: [
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
    ],
  },
  {
    label: "KMS",
    actions: ["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"],
  },
  {
    label: "Secrets Manager",
    actions: ["secretsmanager:ListSecrets", "secretsmanager:DescribeSecret"],
  },
  {
    label: "CloudTrail",
    actions: [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:GetInsightSelectors",
      "cloudtrail:LookupEvents",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "AWS Config",
    actions: [
      "config:DescribeConfigurationRecorders",
      "config:DescribeDeliveryChannels",
      "config:DescribeComplianceByConfigRule",
    ],
  },
  {
    label: "Log posture",
    actions: [
      "logs:DescribeLogGroups",
      "es:ListDomainNames",
      "es:DescribeDomain",
      "dynamodb:ListTables",
      "dynamodb:DescribeTable",
      "network-firewall:ListFirewalls",
      "network-firewall:DescribeLoggingConfiguration",
    ],
  },
  {
    label: "VPC flow logs",
    actions: [
      "ec2:DescribeFlowLogs",
      "ec2:DescribeVpcs",
      "logs:FilterLogEvents",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "ELB / ALB access logs",
    actions: [
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "CloudFront access logs",
    actions: [
      "cloudfront:ListDistributions",
      "cloudfront:GetDistributionConfig",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "Route 53 Resolver query logs",
    actions: [
      "route53resolver:ListResolverQueryLogConfigs",
      "route53resolver:ListResolverQueryLogConfigAssociations",
      "logs:FilterLogEvents",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "WAF",
    actions: [
      "wafv2:ListWebACLs",
      "wafv2:GetWebACL",
      "wafv2:GetLoggingConfiguration",
      "wafv2:GetSampledRequests",
    ],
  },
  {
    label: "API Gateway access logs",
    actions: ["apigateway:GET", "logs:FilterLogEvents"],
  },
  {
    label: "EC2 / EBS",
    actions: [
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceAttribute",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeSnapshotAttribute",
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeImages",
      "ec2:DescribeLaunchTemplates",
    ],
  },
  {
    label: "S3",
    actions: [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
      "s3:GetBucketLogging",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketObjectLockConfiguration",
    ],
  },
  {
    label: "S3 access logs",
    actions: [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLogging",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetObject",
    ],
  },
  {
    label: "Lambda",
    actions: ["lambda:ListFunctions", "lambda:GetFunction", "lambda:GetPolicy"],
  },
  {
    label: "Lambda logs",
    actions: ["lambda:ListFunctions", "logs:DescribeLogGroups", "logs:FilterLogEvents"],
  },
  {
    label: "EKS audit",
    actions: ["eks:ListClusters", "eks:DescribeCluster", "logs:FilterLogEvents"],
  },
  {
    label: "RDS export logs",
    actions: ["rds:DescribeDBInstances", "logs:FilterLogEvents"],
  },
  {
    label: "GuardDuty",
    actions: [
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
      "guardduty:ListFilters",
      "guardduty:GetFilter",
    ],
  },
  {
    label: "Security Hub",
    actions: [
      "securityhub:DescribeHub",
      "securityhub:GetEnabledStandards",
      "securityhub:GetFindings",
    ],
  },
  {
    label: "Macie",
    actions: ["macie2:GetMacieSession", "macie2:ListFindings", "macie2:GetFindings"],
  },
  {
    label: "Detective",
    actions: ["detective:ListGraphs", "detective:ListInvestigations"],
  },
  {
    label: "Inspector",
    actions: ["inspector2:ListFindings", "inspector2:BatchGetAccountStatus"],
  },
];

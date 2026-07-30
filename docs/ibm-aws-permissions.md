# IBM AWS profile — effective permissions

Enumerated from the live IAM policies attached to the **IBM** AWS CLI profile.

| Field | Value |
|---|---|
| Profile | `IBM` |
| Account | `910825235258` |
| Principal | `arn:aws:iam::910825235258:user/ventra-user` |
| User ID | `AIDA5IELKEM5G6IGLI5WF` |
| Inline policies | none |
| Groups | none |
| Enumerated | 2026-07-28 |

## Attached managed policies

1. `Ventra-Inventory-Read` (`arn:aws:iam::910825235258:policy/Ventra-Inventory-Read`, v2)
2. `Ventra-Log-Retrieval` (`arn:aws:iam::910825235258:policy/Ventra-Log-Retrieval`, v3)
3. `Ventra-Security-Telemetry` (`arn:aws:iam::910825235258:policy/Ventra-Security-Telemetry`, v2)

## Explicit denies (all three policies)

Every attached policy includes:

- **Effect:** Deny
- **Action:** `*`
- **Resource:** `*`
- **Condition:** `aws:RequestedRegion` ∈ `us-west-2`, `eu-west-2`

API calls targeting those regions are denied even if an Allow exists.

## Unique Allow actions (sorted)

**100** distinct Allow actions across all attached policies:

- `apigateway:GET`
- `cloudfront:GetDistributionConfig`
- `cloudfront:ListDistributions`
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetEventSelectors`
- `cloudtrail:GetInsightSelectors`
- `cloudtrail:GetTrailStatus`
- `cloudtrail:LookupEvents`
- `config:DescribeComplianceByConfigRule`
- `config:DescribeConfigurationRecorders`
- `config:DescribeDeliveryChannels`
- `dynamodb:DescribeTable`
- `dynamodb:ListTables`
- `ec2:DescribeFlowLogs`
- `ec2:DescribeImages`
- `ec2:DescribeInstanceAttribute`
- `ec2:DescribeInstances`
- `ec2:DescribeLaunchTemplates`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DescribeRegions`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeSnapshotAttribute`
- `ec2:DescribeSnapshots`
- `ec2:DescribeVolumes`
- `ec2:DescribeVpcs`
- `eks:DescribeCluster`
- `eks:ListClusters`
- `elasticloadbalancing:DescribeLoadBalancerAttributes`
- `elasticloadbalancing:DescribeLoadBalancers`
- `es:DescribeDomain`
- `es:ListDomainNames`
- `guardduty:GetDetector`
- `guardduty:GetFilter`
- `guardduty:GetFindings`
- `guardduty:ListDetectors`
- `guardduty:ListFilters`
- `guardduty:ListFindings`
- `iam:GenerateCredentialReport`
- `iam:GetAccessKeyLastUsed`
- `iam:GetAccountAuthorizationDetails`
- `iam:GetAccountPasswordPolicy`
- `iam:GetCredentialReport`
- `iam:GetGroupPolicy`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:GetRole`
- `iam:GetRolePolicy`
- `iam:GetUserPolicy`
- `iam:ListAccessKeys`
- `iam:ListAccountAliases`
- `iam:ListAttachedGroupPolicies`
- `iam:ListAttachedRolePolicies`
- `iam:ListAttachedUserPolicies`
- `iam:ListGroupPolicies`
- `iam:ListGroups`
- `iam:ListGroupsForUser`
- `iam:ListMFADevices`
- `iam:ListPolicies`
- `iam:ListRolePolicies`
- `iam:ListRoles`
- `iam:ListUserPolicies`
- `iam:ListUsers`
- `kms:DescribeKey`
- `kms:GetKeyPolicy`
- `kms:ListGrants`
- `kms:ListKeys`
- `lambda:GetFunction`
- `lambda:GetPolicy`
- `lambda:ListFunctions`
- `logs:DescribeLogGroups`
- `logs:FilterLogEvents`
- `macie2:GetFindings`
- `macie2:GetMacieSession`
- `macie2:ListFindings`
- `network-firewall:DescribeLoggingConfiguration`
- `network-firewall:ListFirewalls`
- `organizations:DescribeOrganization`
- `rds:DescribeDBInstances`
- `route53resolver:ListResolverQueryLogConfigAssociations`
- `route53resolver:ListResolverQueryLogConfigs`
- `s3:GetBucketAcl`
- `s3:GetBucketLocation`
- `s3:GetBucketLogging`
- `s3:GetBucketObjectLockConfiguration`
- `s3:GetBucketPolicy`
- `s3:GetBucketPolicyStatus`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetObject`
- `s3:ListAllMyBuckets`
- `s3:ListBucket`
- `secretsmanager:DescribeSecret`
- `secretsmanager:ListSecrets`
- `securityhub:DescribeHub`
- `securityhub:GetEnabledStandards`
- `securityhub:GetFindings`
- `sts:GetCallerIdentity`
- `wafv2:GetLoggingConfiguration`
- `wafv2:GetSampledRequests`
- `wafv2:GetWebACL`
- `wafv2:ListWebACLs`

## By AWS service

### `apigateway` (1)

- `apigateway:GET`

### `cloudfront` (2)

- `cloudfront:GetDistributionConfig`
- `cloudfront:ListDistributions`

### `cloudtrail` (5)

- `cloudtrail:DescribeTrails`
- `cloudtrail:GetEventSelectors`
- `cloudtrail:GetInsightSelectors`
- `cloudtrail:GetTrailStatus`
- `cloudtrail:LookupEvents`

### `config` (3)

- `config:DescribeComplianceByConfigRule`
- `config:DescribeConfigurationRecorders`
- `config:DescribeDeliveryChannels`

### `dynamodb` (2)

- `dynamodb:DescribeTable`
- `dynamodb:ListTables`

### `ec2` (12)

- `ec2:DescribeFlowLogs`
- `ec2:DescribeImages`
- `ec2:DescribeInstanceAttribute`
- `ec2:DescribeInstances`
- `ec2:DescribeLaunchTemplates`
- `ec2:DescribeNetworkInterfaces`
- `ec2:DescribeRegions`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeSnapshotAttribute`
- `ec2:DescribeSnapshots`
- `ec2:DescribeVolumes`
- `ec2:DescribeVpcs`

### `eks` (2)

- `eks:DescribeCluster`
- `eks:ListClusters`

### `elasticloadbalancing` (2)

- `elasticloadbalancing:DescribeLoadBalancerAttributes`
- `elasticloadbalancing:DescribeLoadBalancers`

### `es` (2)

- `es:DescribeDomain`
- `es:ListDomainNames`

### `guardduty` (6)

- `guardduty:GetDetector`
- `guardduty:GetFilter`
- `guardduty:GetFindings`
- `guardduty:ListDetectors`
- `guardduty:ListFilters`
- `guardduty:ListFindings`

### `iam` (25)

- `iam:GenerateCredentialReport`
- `iam:GetAccessKeyLastUsed`
- `iam:GetAccountAuthorizationDetails`
- `iam:GetAccountPasswordPolicy`
- `iam:GetCredentialReport`
- `iam:GetGroupPolicy`
- `iam:GetPolicy`
- `iam:GetPolicyVersion`
- `iam:GetRole`
- `iam:GetRolePolicy`
- `iam:GetUserPolicy`
- `iam:ListAccessKeys`
- `iam:ListAccountAliases`
- `iam:ListAttachedGroupPolicies`
- `iam:ListAttachedRolePolicies`
- `iam:ListAttachedUserPolicies`
- `iam:ListGroupPolicies`
- `iam:ListGroups`
- `iam:ListGroupsForUser`
- `iam:ListMFADevices`
- `iam:ListPolicies`
- `iam:ListRolePolicies`
- `iam:ListRoles`
- `iam:ListUserPolicies`
- `iam:ListUsers`

### `kms` (4)

- `kms:DescribeKey`
- `kms:GetKeyPolicy`
- `kms:ListGrants`
- `kms:ListKeys`

### `lambda` (3)

- `lambda:GetFunction`
- `lambda:GetPolicy`
- `lambda:ListFunctions`

### `logs` (2)

- `logs:DescribeLogGroups`
- `logs:FilterLogEvents`

### `macie2` (3)

- `macie2:GetFindings`
- `macie2:GetMacieSession`
- `macie2:ListFindings`

### `network-firewall` (2)

- `network-firewall:DescribeLoggingConfiguration`
- `network-firewall:ListFirewalls`

### `organizations` (1)

- `organizations:DescribeOrganization`

### `rds` (1)

- `rds:DescribeDBInstances`

### `route53resolver` (2)

- `route53resolver:ListResolverQueryLogConfigAssociations`
- `route53resolver:ListResolverQueryLogConfigs`

### `s3` (10)

- `s3:GetBucketAcl`
- `s3:GetBucketLocation`
- `s3:GetBucketLogging`
- `s3:GetBucketObjectLockConfiguration`
- `s3:GetBucketPolicy`
- `s3:GetBucketPolicyStatus`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetObject`
- `s3:ListAllMyBuckets`
- `s3:ListBucket`

### `secretsmanager` (2)

- `secretsmanager:DescribeSecret`
- `secretsmanager:ListSecrets`

### `securityhub` (3)

- `securityhub:DescribeHub`
- `securityhub:GetEnabledStandards`
- `securityhub:GetFindings`

### `sts` (1)

- `sts:GetCallerIdentity`

### `wafv2` (4)

- `wafv2:GetLoggingConfiguration`
- `wafv2:GetSampledRequests`
- `wafv2:GetWebACL`
- `wafv2:ListWebACLs`

## Policy details

### Ventra-Inventory-Read

#### AccountContext

- **Resource:** `*`
- **Actions:**
  - `sts:GetCallerIdentity`
  - `iam:ListAccountAliases`
  - `organizations:DescribeOrganization`
  - `ec2:DescribeRegions`

#### IAM

- **Resource:** `*`
- **Actions:**
  - `iam:GetAccessKeyLastUsed`
  - `iam:GetAccountAuthorizationDetails`
  - `iam:GetAccountPasswordPolicy`
  - `iam:GetCredentialReport`
  - `iam:GetGroupPolicy`
  - `iam:GetPolicy`
  - `iam:GetPolicyVersion`
  - `iam:GetRole`
  - `iam:GetRolePolicy`
  - `iam:GetUserPolicy`
  - `iam:GenerateCredentialReport`
  - `iam:ListAccessKeys`
  - `iam:ListAttachedGroupPolicies`
  - `iam:ListAttachedRolePolicies`
  - `iam:ListAttachedUserPolicies`
  - `iam:ListGroups`
  - `iam:ListGroupsForUser`
  - `iam:ListGroupPolicies`
  - `iam:ListMFADevices`
  - `iam:ListPolicies`
  - `iam:ListRoles`
  - `iam:ListRolePolicies`
  - `iam:ListUsers`
  - `iam:ListUserPolicies`

#### InfrastructureInventory

- **Resource:** `*`
- **Actions:**
  - `kms:ListKeys`
  - `kms:DescribeKey`
  - `kms:GetKeyPolicy`
  - `kms:ListGrants`
  - `secretsmanager:ListSecrets`
  - `secretsmanager:DescribeSecret`
  - `cloudtrail:DescribeTrails`
  - `cloudtrail:GetTrailStatus`
  - `cloudtrail:GetEventSelectors`
  - `cloudtrail:GetInsightSelectors`
  - `config:DescribeConfigurationRecorders`
  - `config:DescribeDeliveryChannels`
  - `config:DescribeComplianceByConfigRule`
  - `logs:DescribeLogGroups`
  - `es:ListDomainNames`
  - `es:DescribeDomain`
  - `dynamodb:ListTables`
  - `dynamodb:DescribeTable`
  - `network-firewall:ListFirewalls`
  - `network-firewall:DescribeLoggingConfiguration`
  - `ec2:DescribeFlowLogs`
  - `ec2:DescribeInstances`
  - `ec2:DescribeInstanceAttribute`
  - `ec2:DescribeVolumes`
  - `ec2:DescribeSnapshots`
  - `ec2:DescribeSnapshotAttribute`
  - `ec2:DescribeNetworkInterfaces`
  - `ec2:DescribeSecurityGroups`
  - `ec2:DescribeImages`
  - `ec2:DescribeLaunchTemplates`
  - `ec2:DescribeVpcs`
  - `elasticloadbalancing:DescribeLoadBalancers`
  - `elasticloadbalancing:DescribeLoadBalancerAttributes`
  - `cloudfront:ListDistributions`
  - `cloudfront:GetDistributionConfig`
  - `route53resolver:ListResolverQueryLogConfigs`
  - `route53resolver:ListResolverQueryLogConfigAssociations`
  - `wafv2:ListWebACLs`
  - `wafv2:GetWebACL`
  - `wafv2:GetLoggingConfiguration`
  - `apigateway:GET`
  - `s3:ListAllMyBuckets`
  - `s3:GetBucketLocation`
  - `s3:GetBucketPolicy`
  - `s3:GetBucketPolicyStatus`
  - `s3:GetBucketAcl`
  - `s3:GetBucketLogging`
  - `s3:GetBucketPublicAccessBlock`
  - `s3:GetBucketObjectLockConfiguration`
  - `lambda:ListFunctions`
  - `lambda:GetFunction`
  - `lambda:GetPolicy`
  - `eks:ListClusters`
  - `eks:DescribeCluster`
  - `rds:DescribeDBInstances`
  - `guardduty:ListDetectors`
  - `guardduty:GetDetector`
  - `guardduty:ListFilters`
  - `guardduty:GetFilter`
  - `securityhub:DescribeHub`
  - `securityhub:GetEnabledStandards`
  - `macie2:GetMacieSession`

### Ventra-Log-Retrieval

#### CloudTrailEvidence

- **Resource:** `*`
- **Actions:**
  - `cloudtrail:LookupEvents`

#### CloudWatchEvidence

- **Resource:** `*`
- **Actions:**
  - `logs:DescribeLogGroups`
  - `logs:FilterLogEvents`

#### S3LogEvidence

- **Resource:** `arn:aws:s3:::xfir-aws-logs/*`
- **Actions:**
  - `s3:ListBucket`
  - `s3:GetObject`

#### WAFEvidence

- **Resource:** `*`
- **Actions:**
  - `wafv2:GetSampledRequests`

### Ventra-Security-Telemetry

#### SecurityFindings

- **Resource:** `*`
- **Actions:**
  - `guardduty:ListDetectors`
  - `guardduty:GetDetector`
  - `guardduty:ListFilters`
  - `guardduty:GetFilter`
  - `guardduty:ListFindings`
  - `guardduty:GetFindings`
  - `securityhub:DescribeHub`
  - `securityhub:GetEnabledStandards`
  - `securityhub:GetFindings`
  - `macie2:GetMacieSession`
  - `macie2:ListFindings`
  - `macie2:GetFindings`

## Notable scope notes

- Most Allows are on `Resource: "*"` (account-wide read for that action).
- **S3 object/log read is scoped:** `Ventra-Log-Retrieval` allows `s3:ListBucket` and `s3:GetObject` only on `arn:aws:s3:::xfir-aws-logs/*` (not all buckets).
- No mutate/write/create/delete permissions appear in these policies — read/list/describe/get oriented.
- `iam:GetUser` is **not** granted (calls to get own user metadata fail with AccessDenied); listing attached policies and reading policy documents is allowed.

## Raw policy JSON

Full AWS `get-policy-version` responses are also saved under `docs/keys/ibm-policy-raw/`.

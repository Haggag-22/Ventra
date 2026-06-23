# Lab-native technique simulation

All traffic and MITRE-style techniques run from a **single script**:

```bash
./infrastructure/scripts/aws/generate.sh
./infrastructure/scripts/aws/generate.sh -n 5 --dry-run
```

Does **not** use Stratus Red Team (which provisions its own infrastructure).

## What runs

1. **Benign traffic** — ALB, CloudFront, S3, Lambda, API GW, KMS, DynamoDB, control-plane reads
2. **Route53 Resolver logs** — `kubectl run` busybox pods on EKS with `nslookup` (in-VPC DNS → CloudWatch query logs)
3. **EKS audit** — `kubectl get pods`
4. **15 techniques** — CloudTrail events against existing lab resources (auto-cleanup where reversible)

## Techniques included

| ID | Action |
|----|--------|
| `aws.discovery.ec2-download-user-data` | DescribeInstanceAttribute on lab EC2 |
| `aws.discovery.ses-enumerate` | SES list APIs |
| `aws.credential-access.secretsmanager-*` | Get + batch get lab secret |
| `aws.credential-access.ec2-get-password-data` | GetPasswordData on lab EC2 |
| `aws.exfiltration.s3-backdoor-bucket-policy` | Temp bucket policy, restored |
| `aws.persistence.lambda-backdoor-function` | Temp Lambda env, restored |
| `aws.persistence.iam-create-admin-user` | Temp admin user, deleted |
| `aws.persistence.iam-backdoor-user` | Attach/detach admin on readonly user |
| `aws.persistence.sts-federation-token` | GetFederationToken |
| `aws.defense-evasion.cloudtrail-stop` | Stop/start lab trail |
| `aws.defense-evasion.cloudtrail-lifecycle-rule` | Temp lifecycle rule, removed |
| `aws.defense-evasion.dns-delete-logs` | Describe resolver config only |
| `aws.lateral-movement.ec2-instance-connect` | SendSSHPublicKey |
| `aws.privilege-escalation.iam-update-user-login-profile` | Temp login profile, deleted |

## Excluded

SSM techniques, snapshot sharing, VPC flow log deletion, Lambda code overwrite, new EC2 launch — slow, disruptive, or would create separate infrastructure.

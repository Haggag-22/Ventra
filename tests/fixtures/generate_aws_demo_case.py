"""AWS demo case generator — canonical entry point (see generate_demo_case.py).

Re-exports the AWS synthetic attack-path builder so naming matches
generate_gcp_demo_case.py and generate_azure_demo_case.py.

Usage:
    python tests/fixtures/generate_aws_demo_case.py --out tests/fixtures/
"""

from __future__ import annotations

from generate_demo_case import (  # noqa: F401
    ACCOUNT,
    ALIAS,
    ATTACKER_IP,
    ATTACKER_IP2,
    BASE,
    EXFIL_IP,
    LEGIT_IP,
    REGION,
    VICTIM_ARN,
    VICTIM_USER,
    build_account_snapshot,
    build_cloudtrail,
    build_ec2_inventory,
    build_elb_alb,
    build_guardduty,
    build_iam_snapshot,
    build_route53_resolver,
    build_s3_access,
    build_s3_inventory,
    build_sts,
    build_vpc_flow,
    build_waf,
    generate,
    main,
)

if __name__ == "__main__":
    raise SystemExit(main())

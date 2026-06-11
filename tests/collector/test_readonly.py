"""The read-only guard is load-bearing: a mutating call in the collector is a security bug.

These tests fail CI if any collector declares a mutating action, or if the published IAM
policy contains one.
"""

from __future__ import annotations

import json
from pathlib import Path

from harbor_collector.common.base import assert_readonly
from harbor_collector.tools.verify_readonly import check_collectors, check_policy

REPO = Path(__file__).resolve().parents[2]


def test_all_registered_collectors_are_readonly() -> None:
    offenders = check_collectors()
    assert offenders == [], f"Mutating actions declared by collectors: {offenders}"


def test_published_iam_policy_is_readonly() -> None:
    policy = REPO / "docs" / "iam-policies" / "aws-collector-readonly.json"
    offenders = check_policy(policy)
    assert offenders == [], f"Mutating actions in published policy: {offenders}"


def test_guard_detects_a_mutating_action() -> None:
    # Sanity: the guard must actually catch something obviously mutating.
    assert assert_readonly(["s3:DeleteObject"]) == ["s3:DeleteObject"]
    assert assert_readonly(["ec2:DescribeInstances"]) == []


def test_generate_credential_report_is_allowlisted() -> None:
    # Looks mutating ("Generate") but only produces a report; explicitly allowed.
    assert assert_readonly(["iam:GenerateCredentialReport"]) == []

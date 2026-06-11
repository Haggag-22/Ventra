"""Unit tests for the IAM snapshot collector."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from collector.aws.identity.iam import IamCollector, _managed_policy_doc_index
from collector.lib.models import CollectionContext, GapReason, TimeWindow


class _FakePaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages

    def paginate(self, **kwargs: Any):
        return iter(self._pages)


def _ctx(tmp_path: Path) -> CollectionContext:
    staging = tmp_path / "staging"
    staging.mkdir()
    return CollectionContext(
        cloud="aws",
        staging=staging,
        case_id="CASE-TEST",
        account_id="123456789012",
        regions=["us-east-1"],
        time_window=TimeWindow(),
    )


def test_authorization_details_preserves_user_and_role_policies(tmp_path: Path) -> None:
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    pages = [{
        "UserDetailList": [{
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": admin_arn}],
            "UserPolicyList": [{
                "PolicyName": "inline",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": []},
            }],
        }],
        "RoleDetailList": [{
            "RoleName": "app-role",
            "Arn": "arn:aws:iam::123456789012:role/app-role",
            "AttachedManagedPolicies": [{"PolicyName": "ReadOnlyAccess",
                                          "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
            "RolePolicyList": [],
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
        }],
        "GroupDetailList": [],
        "Policies": [{
            "Arn": admin_arn,
            "PolicyVersionList": [{
                "IsDefaultVersion": True,
                "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            }],
        }],
    }]

    cf = MagicMock()
    client = MagicMock()
    client.get_paginator.return_value = _FakePaginator(pages)
    cf.client.return_value = client
    cf.call.side_effect = lambda svc, region, op, **kw: {
        "list_access_keys": {"AccessKeyMetadata": []},
        "list_mfa_devices": {"MFADevices": []},
        "get_account_password_policy": {"PasswordPolicy": {}},
        "generate_credential_report": {"State": "COMPLETE"},
        "get_credential_report": {"Content": b"user,arn\n"},
        "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
        "get_policy_version": {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}},
    }[op]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    collector = IamCollector(ctx)
    result = collector.collect()

    assert result.status.value == "collected"
    snapshot = json.loads((tmp_path / "staging/sources/iam/snapshot.json").read_text())
    alice = snapshot["users"][0]
    assert alice["AttachedManagedPolicies"][0]["PolicyDocument"]["Statement"][0]["Action"] == "*"
    assert alice["UserPolicyList"][0]["PolicyName"] == "inline"
    assert snapshot["roles"][0]["AssumeRolePolicyDocument"]["Version"] == "2012-10-17"


def test_managed_policy_doc_index_parses_url_encoded_document() -> None:
    doc = {"Version": "2012-10-17", "Statement": []}
    encoded = json.dumps(doc)
    index = _managed_policy_doc_index([{
        "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "PolicyVersionList": [{"IsDefaultVersion": True, "Document": encoded}],
    }])
    assert index["arn:aws:iam::aws:policy/ReadOnlyAccess"] == doc


def test_fallback_collects_attached_and_inline_policies(tmp_path: Path) -> None:
    from botocore.exceptions import ClientError

    cf = MagicMock()
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetAccountAuthorizationDetails",
    )
    cf.client.return_value = client

    def paginate(service, region, operation, result_key, **kwargs):
        if operation == "list_users":
            yield {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}
        elif operation == "list_attached_user_policies":
            yield {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        elif operation == "list_roles":
            yield {"RoleName": "app-role", "Arn": "arn:aws:iam::123456789012:role/app-role"}
        elif operation == "list_attached_role_policies":
            yield {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        elif operation == "list_groups":
            return
            yield  # pragma: no cover
        elif operation == "list_policies":
            return
            yield  # pragma: no cover

    cf.paginate.side_effect = paginate
    cf.call.side_effect = lambda svc, region, op, **kw: {
        "list_user_policies": {"PolicyNames": ["inline-one"]},
        "get_user_policy": {"PolicyDocument": {"Version": "2012-10-17", "Statement": []}},
        "list_groups_for_user": {"Groups": [{"GroupName": "ops"}]},
        "list_role_policies": {"PolicyNames": []},
        "get_role": {"Role": {"AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}},
        "list_access_keys": {"AccessKeyMetadata": []},
        "list_mfa_devices": {"MFADevices": []},
        "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
        "get_policy_version": {"PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}}},
        "get_account_password_policy": {"PasswordPolicy": {}},
        "generate_credential_report": {"State": "COMPLETE"},
        "get_credential_report": {"Content": b"user,arn\n"},
    }[op]

    ctx = _ctx(tmp_path)
    ctx.client_factory = cf
    collector = IamCollector(ctx)
    result = collector.collect()

    assert result.status.value == "collected"
    assert any(g[1] == GapReason.ACCESS_DENIED for g in result.gaps)
    snapshot = json.loads((tmp_path / "staging/sources/iam/snapshot.json").read_text())
    assert snapshot["users"][0]["AttachedManagedPolicies"][0]["PolicyArn"].endswith("ReadOnlyAccess")
    assert snapshot["users"][0]["UserPolicyList"][0]["PolicyName"] == "inline-one"
    assert snapshot["users"][0]["GroupList"] == ["ops"]

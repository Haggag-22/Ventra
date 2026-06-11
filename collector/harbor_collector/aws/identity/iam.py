"""IAM snapshot collector.

A point-in-time picture of every principal, their policies, key age, MFA, and the account
credential report. Answers "who could do what" and surfaces credential-hygiene red flags
(old keys, no-MFA root, dormant users) that the console's Identity panel renders.

Policy data comes from ``GetAccountAuthorizationDetails`` when permitted — each user/role
includes ``AttachedManagedPolicies``, inline policy lists (with documents), and group
membership. Managed policy documents are resolved from the top-level ``Policies`` array.
When the bulk API is denied, we fall back to per-principal list/get calls.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import unquote

from botocore.exceptions import ClientError

from ...common.base import Collector
from ...common.models import GapReason, SourceResult, SourceStatus
from ..client_factory import AccessDenied, ServiceNotEnabled


class IamCollector(Collector):
    name = "iam"
    tier = 1
    description = "IAM users, roles, groups, policies, access keys, credential report."
    required_actions = (
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
    )

    def collect(self) -> SourceResult:
        cf = self.ctx.client_factory
        gaps: list[tuple[str, GapReason, str]] = []
        files = []

        try:
            users, roles, groups, policies = self._fetch_authorization_details(cf)
        except AccessDenied as exc:
            gaps.append(("iam", GapReason.ACCESS_DENIED, exc.message))
            users, roles, groups, policies = self._fetch_via_lists(cf, gaps)

        if not users and not roles and gaps:
            return SourceResult(
                name=self.name,
                status=SourceStatus.ERRORED,
                gaps=gaps,
                errors=[g[2] for g in gaps if g[0] == "iam"],
            )

        self._enrich_users(cf, users)
        self._resolve_managed_policy_documents(users, roles, groups, policies, cf, gaps)

        snapshot = {
            "users": users,
            "roles": roles,
            "groups": groups,
            "policies": policies,
            "password_policy": self._password_policy(cf),
        }
        files.append(self.write_json(snapshot, "snapshot.json"))

        cred_csv = self._credential_report(cf, gaps)
        if cred_csv is not None:
            path = self.ctx.source_dir(self.name) / "credential_report.csv"
            path.write_bytes(cred_csv)
            from ...common.chain_of_custody.hashing import sha256_bytes
            from ...common.models import WrittenFile

            files.append(
                WrittenFile(
                    path=path.relative_to(self.ctx.staging).as_posix(),
                    sha256=sha256_bytes(cred_csv),
                    bytes=len(cred_csv),
                    record_count=cred_csv.count(b"\n") - 1,
                )
            )

        attached = sum(len(u.get("AttachedManagedPolicies") or []) for u in users)
        attached += sum(len(r.get("AttachedManagedPolicies") or []) for r in roles)
        inline = sum(len(u.get("UserPolicyList") or []) for u in users)
        inline += sum(len(r.get("RolePolicyList") or []) for r in roles)

        self.write_meta(
            {
                "source": self.name,
                "users": len(users),
                "roles": len(roles),
                "groups": len(groups),
                "policies": len(policies),
                "attached_managed_policies": attached,
                "inline_policies": inline,
            }
        )
        return SourceResult(
            name=self.name,
            status=SourceStatus.COLLECTED,
            files=files,
            record_count=len(users) + len(roles),
            gaps=gaps,
            notes=(
                f"{len(users)} users, {len(roles)} roles, "
                f"{attached} attached + {inline} inline policies."
            ),
        )

    def _fetch_authorization_details(
        self, cf,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """One paginated sweep — users/roles/groups include attached + inline policies."""
        users: list[dict[str, Any]] = []
        roles: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        policies: list[dict[str, Any]] = []
        client = cf.client("iam", None)
        try:
            paginator = client.get_paginator("get_account_authorization_details")
            for page in paginator.paginate():
                users.extend(page.get("UserDetailList", []))
                roles.extend(page.get("RoleDetailList", []))
                groups.extend(page.get("GroupDetailList", []))
                policies.extend(page.get("Policies", []))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            msg = exc.response.get("Error", {}).get("Message", str(exc))
            if code in {"AccessDenied", "AccessDeniedException"}:
                raise AccessDenied("iam:get_account_authorization_details", msg) from exc
            raise
        return users, roles, groups, policies

    def _fetch_via_lists(
        self, cf, gaps: list[tuple[str, GapReason, str]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Fallback when GetAccountAuthorizationDetails is denied."""
        users: list[dict[str, Any]] = []
        roles: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        policies: list[dict[str, Any]] = []

        try:
            for u in cf.paginate("iam", None, "list_users", "Users"):
                uname = u.get("UserName", "")
                detail = dict(u)
                try:
                    detail["AttachedManagedPolicies"] = list(
                        cf.paginate(
                            "iam",
                            None,
                            "list_attached_user_policies",
                            "AttachedPolicies",
                            UserName=uname,
                        )
                    )
                    detail["UserPolicyList"] = self._inline_user_policies(cf, uname)
                    detail["GroupList"] = cf.call(
                        "iam", None, "list_groups_for_user", UserName=uname
                    ).get("Groups", [])
                    detail["GroupList"] = [g.get("GroupName", "") for g in detail["GroupList"]]
                except AccessDenied as exc:
                    gaps.append(("iam", GapReason.ACCESS_DENIED, f"{uname}: {exc.message}"))
                users.append(detail)
        except AccessDenied as exc:
            gaps.append(("iam_users", GapReason.ACCESS_DENIED, exc.message))

        try:
            for r in cf.paginate("iam", None, "list_roles", "Roles"):
                rname = r.get("RoleName", "")
                detail = dict(r)
                try:
                    detail["AttachedManagedPolicies"] = list(
                        cf.paginate(
                            "iam",
                            None,
                            "list_attached_role_policies",
                            "AttachedPolicies",
                            RoleName=rname,
                        )
                    )
                    detail["RolePolicyList"] = self._inline_role_policies(cf, rname)
                    role_doc = cf.call("iam", None, "get_role", RoleName=rname).get("Role", {})
                    if role_doc.get("AssumeRolePolicyDocument"):
                        detail["AssumeRolePolicyDocument"] = role_doc["AssumeRolePolicyDocument"]
                except AccessDenied as exc:
                    gaps.append(("iam", GapReason.ACCESS_DENIED, f"{rname}: {exc.message}"))
                roles.append(detail)
        except AccessDenied as exc:
            gaps.append(("iam_roles", GapReason.ACCESS_DENIED, exc.message))

        try:
            for g in cf.paginate("iam", None, "list_groups", "Groups"):
                gname = g.get("GroupName", "")
                detail = dict(g)
                try:
                    detail["AttachedManagedPolicies"] = list(
                        cf.paginate(
                            "iam",
                            None,
                            "list_attached_group_policies",
                            "AttachedPolicies",
                            GroupName=gname,
                        )
                    )
                    detail["GroupPolicyList"] = self._inline_group_policies(cf, gname)
                except AccessDenied as exc:
                    gaps.append(("iam", GapReason.ACCESS_DENIED, f"{gname}: {exc.message}"))
                groups.append(detail)
        except AccessDenied as exc:
            gaps.append(("iam_groups", GapReason.ACCESS_DENIED, exc.message))

        try:
            policies = list(
                cf.paginate("iam", None, "list_policies", "Policies", Scope="Local", OnlyAttached=False)
            )
        except AccessDenied:
            pass

        return users, roles, groups, policies

    def _inline_user_policies(self, cf, user_name: str) -> list[dict[str, Any]]:
        names = cf.call("iam", None, "list_user_policies", UserName=user_name).get("PolicyNames", [])
        out: list[dict[str, Any]] = []
        for pname in names:
            pol = cf.call("iam", None, "get_user_policy", UserName=user_name, PolicyName=pname)
            out.append({"PolicyName": pname, "PolicyDocument": pol.get("PolicyDocument")})
        return out

    def _inline_role_policies(self, cf, role_name: str) -> list[dict[str, Any]]:
        names = cf.call("iam", None, "list_role_policies", RoleName=role_name).get("PolicyNames", [])
        out: list[dict[str, Any]] = []
        for pname in names:
            pol = cf.call("iam", None, "get_role_policy", RoleName=role_name, PolicyName=pname)
            out.append({"PolicyName": pname, "PolicyDocument": pol.get("PolicyDocument")})
        return out

    def _inline_group_policies(self, cf, group_name: str) -> list[dict[str, Any]]:
        names = cf.call("iam", None, "list_group_policies", GroupName=group_name).get(
            "PolicyNames", []
        )
        out: list[dict[str, Any]] = []
        for pname in names:
            pol = cf.call("iam", None, "get_group_policy", GroupName=group_name, PolicyName=pname)
            out.append({"PolicyName": pname, "PolicyDocument": pol.get("PolicyDocument")})
        return out

    def _enrich_users(self, cf, users: list[dict[str, Any]]) -> None:
        for user in users:
            uname = user.get("UserName", "")
            if not uname:
                continue
            try:
                keys = cf.call("iam", None, "list_access_keys", UserName=uname).get(
                    "AccessKeyMetadata", []
                )
                for k in keys:
                    last = cf.call(
                        "iam", None, "get_access_key_last_used", AccessKeyId=k["AccessKeyId"]
                    ).get("AccessKeyLastUsed", {})
                    k["LastUsed"] = last
                user["AccessKeys"] = keys
                user["MFADevices"] = cf.call(
                    "iam", None, "list_mfa_devices", UserName=uname
                ).get("MFADevices", [])
            except (AccessDenied, ServiceNotEnabled):
                continue

    def _resolve_managed_policy_documents(
        self,
        users: list[dict[str, Any]],
        roles: list[dict[str, Any]],
        groups: list[dict[str, Any]],
        policies: list[dict[str, Any]],
        cf,
        gaps: list[tuple[str, GapReason, str]],
    ) -> None:
        """Attach default-version policy documents to managed-policy references."""
        index = _managed_policy_doc_index(policies)
        for entity in (*users, *roles, *groups):
            for attached in entity.get("AttachedManagedPolicies") or []:
                arn = attached.get("PolicyArn", "")
                if not arn:
                    continue
                doc = index.get(arn)
                if doc is None:
                    doc = self._fetch_policy_document(cf, arn, gaps)
                if doc is not None:
                    attached["PolicyDocument"] = doc

    def _fetch_policy_document(
        self, cf, policy_arn: str, gaps: list[tuple[str, GapReason, str]]
    ) -> dict[str, Any] | str | None:
        try:
            meta = cf.call("iam", None, "get_policy", PolicyArn=policy_arn).get("Policy", {})
            version_id = meta.get("DefaultVersionId")
            if not version_id:
                return None
            version = cf.call(
                "iam", None, "get_policy_version", PolicyArn=policy_arn, VersionId=version_id
            ).get("PolicyVersion", {})
            return _parse_policy_document(version.get("Document"))
        except AccessDenied as exc:
            gaps.append(("iam_policies", GapReason.ACCESS_DENIED, f"{policy_arn}: {exc.message}"))
        except (ServiceNotEnabled, ClientError):
            pass
        return None

    def _password_policy(self, cf) -> dict:
        try:
            return cf.call("iam", None, "get_account_password_policy").get("PasswordPolicy", {})
        except (AccessDenied, ServiceNotEnabled):
            return {}

    def _credential_report(self, cf, gaps) -> bytes | None:
        try:
            for _ in range(5):
                state = cf.call("iam", None, "generate_credential_report").get("State")
                if state == "COMPLETE":
                    break
                time.sleep(2)
            report = cf.call("iam", None, "get_credential_report")
            content = report.get("Content")
            if isinstance(content, (bytes, bytearray)):
                return bytes(content)
            if isinstance(content, str):
                return base64.b64decode(content)
        except AccessDenied as exc:
            gaps.append(("iam_credential_report", GapReason.ACCESS_DENIED, exc.message))
        except ServiceNotEnabled:
            pass
        return None


def _managed_policy_doc_index(policies: list[dict[str, Any]]) -> dict[str, dict[str, Any] | str]:
    index: dict[str, dict[str, Any] | str] = {}
    for pol in policies:
        arn = pol.get("Arn", "")
        if not arn:
            continue
        versions = pol.get("PolicyVersionList") or []
        default = next((v for v in versions if v.get("IsDefaultVersion")), None)
        if default is None and versions:
            default = versions[0]
        if default is None:
            continue
        doc = _parse_policy_document(default.get("Document"))
        if doc is not None:
            index[arn] = doc
    return index


def _parse_policy_document(doc: Any) -> dict[str, Any] | str | None:
    if doc is None:
        return None
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(unquote(doc))
        except json.JSONDecodeError:
            return doc
    return None

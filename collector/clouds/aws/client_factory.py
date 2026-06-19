"""AWS client management used by every collector.

Wraps boto3 so collectors don't each reinvent region handling, pagination, and the
all-important AccessDenied detection (an AccessDenied is a *gap*, recorded as evidence, not a
crash). All clients are created from a single session so credentials are resolved once.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

# Error codes that mean "you can't see this" rather than "something broke".
ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "AuthFailure",
        "ForbiddenException",
    }
)

# Error codes that mean "this service/feature isn't enabled here".
NOT_ENABLED_CODES = frozenset(
    {
        "ResourceNotFoundException",
        "BadRequestException",
        "InvalidInputException",
        "SubscriptionRequiredException",
        "OptInRequired",
        # Security Hub raises this when the account is not subscribed to the hub.
        "InvalidAccessException",
        # WAFv2 raises this when e.g. a Web ACL has no logging configuration.
        "WAFNonexistentItemException",
        # Standalone accounts that are not part of an AWS Organization.
        "AWSOrganizationsNotInUseException",
        # CloudTrail trails without Insights enabled.
        "InsightNotEnabledException",
        # IAM raises this when e.g. no custom password policy exists on the account.
        "NoSuchEntity",
    }
)


class AccessDenied(Exception):
    """Raised by helpers when an API returns an access-denied style error."""

    def __init__(self, action: str, message: str) -> None:
        super().__init__(f"{action}: {message}")
        self.action = action
        self.message = message


class ServiceNotEnabled(Exception):
    def __init__(self, service: str, message: str) -> None:
        super().__init__(f"{service}: {message}")
        self.service = service
        self.message = message


@dataclass
class CallerIdentity:
    account_id: str
    arn: str
    user_id: str
    partition: str


class AwsClientFactory:
    """Creates per-service, per-region boto3 clients from one session."""

    def __init__(self, session: boto3.Session | None = None) -> None:
        self._session = session or boto3.Session()
        self._cfg = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="ventra")
        self._cache: dict[tuple[str, str | None], Any] = {}

    def client(self, service: str, region: str | None = None) -> Any:
        key = (service, region)
        if key not in self._cache:
            self._cache[key] = self._session.client(service, region_name=region, config=self._cfg)
        return self._cache[key]

    # -- identity / region discovery -----------------------------------------------------

    def caller_identity(self) -> CallerIdentity:
        try:
            ident = self.client("sts").get_caller_identity()
        except NoCredentialsError as exc:  # pragma: no cover
            raise RuntimeError(
                "No AWS credentials found. Run inside CloudShell or configure a profile."
            ) from exc
        arn = ident["Arn"]
        partition = arn.split(":")[1] if arn.startswith("arn:") else "aws"
        return CallerIdentity(
            account_id=ident["Account"],
            arn=arn,
            user_id=ident.get("UserId", ""),
            partition=partition,
        )

    def enabled_regions(self) -> list[str]:
        """Regions enabled for this account (opt-in regions included if active)."""
        try:
            resp = self.client("ec2", "us-east-1").describe_regions(
                Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
            )
            return sorted(r["RegionName"] for r in resp["Regions"])
        except ClientError:
            # Fall back to the SDK's static partition list.
            return sorted(self._session.get_available_regions("ec2"))

    # -- safe call helpers ---------------------------------------------------------------

    def paginate(
        self, service: str, region: str | None, operation: str, result_key: str, **kwargs: Any
    ) -> Iterator[dict[str, Any]]:
        """Yield items across pages, translating access/enablement errors into typed gaps."""
        client = self.client(service, region)
        try:
            paginator = client.get_paginator(operation)
            for page in paginator.paginate(**kwargs):
                yield from page.get(result_key, [])
        except ClientError as exc:
            _raise_typed(exc, f"{service}:{operation}")
        except EndpointConnectionError:
            return

    def call(self, service: str, region: str | None, operation: str, **kwargs: Any) -> dict[str, Any]:
        client = self.client(service, region)
        try:
            return getattr(client, operation)(**kwargs)
        except ClientError as exc:
            _raise_typed(exc, f"{service}:{operation}")
            raise  # unreachable, keeps type-checkers happy
        except EndpointConnectionError as exc:
            # The service has no endpoint in this region — same gap as "not enabled".
            raise ServiceNotEnabled(f"{service}:{operation}", str(exc)) from exc

    def paginate_manual(
        self,
        service: str,
        region: str | None,
        operation: str,
        result_key: str,
        *,
        token_request_key: str = "NextToken",
        token_response_key: str = "NextToken",
        max_pages: int = 500,
        **kwargs: Any,
    ) -> Iterator[dict[str, Any]]:
        """Token-loop pagination for operations botocore has no paginator for
        (e.g. wafv2 ListWebACLs / detective ListInvestigations)."""
        token: str | None = None
        for _ in range(max_pages):
            params = dict(kwargs)
            if token:
                params[token_request_key] = token
            page = self.call(service, region, operation, **params)
            items = page.get(result_key) or []
            yield from items
            new_token = page.get(token_response_key)
            # Stop on a missing, repeated, or itemless marker so a quirky
            # implementation can never loop us forever.
            if not new_token or new_token == token or not items:
                return
            token = new_token


def _raise_typed(exc: ClientError, action: str) -> None:
    code = exc.response.get("Error", {}).get("Code", "")
    msg = exc.response.get("Error", {}).get("Message", str(exc))
    if code in ACCESS_DENIED_CODES:
        raise AccessDenied(action, msg)
    if code in NOT_ENABLED_CODES:
        raise ServiceNotEnabled(action, msg)
    raise exc

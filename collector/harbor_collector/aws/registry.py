"""Registry of all AWS collectors. Profiles select collectors by name from here."""

from __future__ import annotations

from ..common.base import CollectorRegistry
from .control_plane.cloudtrail import CloudTrailCollector
from .control_plane.config import ConfigCollector
from .detections.detective import DetectiveCollector
from .detections.guardduty import GuardDutyCollector
from .detections.macie import MacieCollector
from .detections.securityhub import SecurityHubCollector
from .identity.account import AccountCollector
from .identity.iam import IamCollector
from .identity.kms import KmsCollector
from .identity.secrets import SecretsCollector
from .identity.sts import StsCollector
from .network.vpc_flow import VpcFlowCollector
from .network.waf import WafCollector
from .workloads.ec2 import Ec2Collector
from .workloads.lambda_ import LambdaCollector
from .workloads.s3 import S3Collector

AWS_REGISTRY = CollectorRegistry()

for _cls in (
    # Tier 1
    AccountCollector,
    CloudTrailCollector,
    StsCollector,
    IamCollector,
    VpcFlowCollector,
    WafCollector,
    GuardDutyCollector,
    MacieCollector,
    DetectiveCollector,
    # Tier 2
    ConfigCollector,
    SecurityHubCollector,
    KmsCollector,
    SecretsCollector,
    Ec2Collector,
    S3Collector,
    LambdaCollector,
):
    AWS_REGISTRY.register(_cls)


# Tier 3 services that the `full`/`data_exfil` profiles auto-detect when present. Mapping of
# collector name -> (service, describe-op) probe is kept here so the runner can opt them in.
TIER3_AUTODETECT: dict[str, tuple[str, str]] = {
    # Reserved for later phases (cloudfront, transit_gateway, route53_resolver, rds, eks...).
}

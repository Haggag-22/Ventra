"""Registry of all AWS collectors. The runner executes every registered collector."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
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

# Registration order — used when running all collectors.
COLLECTOR_ORDER: list[str] = []

for _cls in (
    # baseline
    AccountCollector,
    CloudTrailCollector,
    StsCollector,
    IamCollector,
    VpcFlowCollector,
    WafCollector,
    GuardDutyCollector,
    MacieCollector,
    DetectiveCollector,
    # extended
    ConfigCollector,
    SecurityHubCollector,
    KmsCollector,
    SecretsCollector,
    Ec2Collector,
    S3Collector,
    LambdaCollector,
):
    AWS_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    """Every registered AWS collector, in stable registration order."""
    return list(COLLECTOR_ORDER)


# conditional services auto-detected when present. Mapping of collector name -> (service, describe-op).
AUTODETECT_COLLECTORS: dict[str, tuple[str, str]] = {
    # Reserved for later phases (cloudfront, transit_gateway, route53_resolver, rds, eks...).
}

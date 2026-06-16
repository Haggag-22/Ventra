"""Azure collector registry."""

from __future__ import annotations

from ..lib.base import CollectorRegistry
from .control_plane.activity_log import ActivityLogCollector
from .detections.defender import DefenderCollector
from .identity.entra_audit import EntraAuditCollector
from .identity.entra_signin import EntraSigninCollector
from .identity.rbac import RbacCollector
from .identity.subscription import SubscriptionCollector
from .network.nsg_flow import NsgFlowCollector

AZURE_REGISTRY = CollectorRegistry()

COLLECTOR_ORDER: list[str] = []

for _cls in (
    SubscriptionCollector,
    ActivityLogCollector,
    EntraSigninCollector,
    EntraAuditCollector,
    RbacCollector,
    NsgFlowCollector,
    DefenderCollector,
):
    AZURE_REGISTRY.register(_cls)
    COLLECTOR_ORDER.append(_cls.name)


def all_collector_names() -> list[str]:
    return list(COLLECTOR_ORDER)

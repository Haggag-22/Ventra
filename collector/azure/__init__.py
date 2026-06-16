"""Azure collectors — Activity Log, Entra ID, NSG flow, Defender, RBAC.

Install Azure SDK dependencies::

    pip install 'ventra[azure]'
"""

from .registry import AZURE_REGISTRY, all_collector_names

__all__ = ["AZURE_REGISTRY", "all_collector_names"]

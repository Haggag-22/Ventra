"""Map artifact collector keys to engine API modules and collector classes.

Each cloud registry lives in its own module so AWS-only kits never import Azure/GCP SDKs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...lib.base import CollectorRegistry

if TYPE_CHECKING:
    from types import ModuleType

_CLOUDS = ("aws", "azure", "gcp")
_CLOUD_MODULES: dict[str, ModuleType] = {}

AUTODETECT_COLLECTORS: dict[str, tuple[str, str]] = {}

_api_module_by_collector: dict[str, str] | None = None


def _cloud_module(cloud: str):
    cloud = cloud.lower()
    if cloud not in _CLOUDS:
        raise ValueError(f"unsupported cloud: {cloud}")
    mod = _CLOUD_MODULES.get(cloud)
    if mod is None:
        if cloud == "aws":
            from . import aws as mod
        elif cloud == "azure":
            from . import azure as mod
        else:
            from . import gcp as mod
        _CLOUD_MODULES[cloud] = mod
    return mod


def registry_for_cloud(cloud: str) -> CollectorRegistry:
    reg, _ = _cloud_module(cloud.lower()).get()
    return reg


def collector_order_for_cloud(cloud: str) -> list[str]:
    _, order = _cloud_module(cloud.lower()).get()
    return list(order)


def collector_class_for(collector_key: str):
    """Resolve a registry id or alias to a collector class."""
    key = collector_key.strip()
    if "." in key:
        cloud_prefix, bare = key.split(".", 1)
        if cloud_prefix in _CLOUDS:
            cls = registry_for_cloud(cloud_prefix).get(bare)
            if cls is not None:
                return cls
    for cloud in _CLOUDS:
        cls = registry_for_cloud(cloud).get(key)
        if cls is not None:
            return cls
    if "." in key:
        _, bare = key.split(".", 1)
        for cloud in _CLOUDS:
            cls = registry_for_cloud(cloud).get(bare)
            if cls is not None:
                return cls
    raise KeyError(f"unknown collector: {collector_key}")


def _api_module_map() -> dict[str, str]:
    global _api_module_by_collector
    if _api_module_by_collector is None:
        _api_module_by_collector = {}
        for cloud in _CLOUDS:
            for name, cls in registry_for_cloud(cloud).all().items():
                mod = cls.__module__
                _api_module_by_collector[name] = mod
                _api_module_by_collector[f"{cloud}.{name}"] = mod
    return _api_module_by_collector


def artifact_type_for_collector(collector_key: str) -> str:
    return _api_module_map().get(collector_key, "")


def __getattr__(name: str):
    """Backward-compatible lazy exports (``AWS_REGISTRY``, ``AWS_COLLECTOR_ORDER``, …)."""
    if name == "AWS_REGISTRY":
        return registry_for_cloud("aws")
    if name == "AWS_COLLECTOR_ORDER":
        return collector_order_for_cloud("aws")
    if name == "AZURE_REGISTRY":
        return registry_for_cloud("azure")
    if name == "AZURE_COLLECTOR_ORDER":
        return collector_order_for_cloud("azure")
    if name == "GCP_REGISTRY":
        return registry_for_cloud("gcp")
    if name == "GCP_COLLECTOR_ORDER":
        return collector_order_for_cloud("gcp")
    if name == "API_MODULE_BY_COLLECTOR":
        return _api_module_map()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

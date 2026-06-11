"""Sealing the staging directory into a signed evidence package."""

from .packager import PackageResult, seal_package

__all__ = ["seal_package", "PackageResult"]

"""Sealing the staging directory into a signed evidence package."""

from .packager import PackageResult, seal_package, staging_directory

__all__ = ["seal_package", "staging_directory", "PackageResult"]

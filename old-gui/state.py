"""Mutable viewer state — supports loading a package from CLI or GUI upload."""

import shutil
import threading


class PackageNotLoadedError(Exception):
    """Raised when API routes need a package but none is loaded yet."""


class ViewerState:
    """Thread-safe holder for the currently opened evidence package."""

    def __init__(self, package=None, label=None):
        self.lock = threading.Lock()
        self.package = package
        self.label = label
        self._owned_paths = []

    def get(self):
        with self.lock:
            if self.package is None:
                raise PackageNotLoadedError()
            return self.package

    def status(self):
        with self.lock:
            if self.package is None:
                return {"loaded": False}
            scope = self.package.manifest.get("scope", {})
            return {
                "loaded": True,
                "label": self.label,
                "account_id": scope.get("account_id"),
                "profile": scope.get("profile"),
            }

    def replace(self, package, label):
        """Swap in a new package and release resources owned by the old one."""
        with self.lock:
            self._release(self.package)
            self.package = package
            self.label = label

    def track_path(self, path):
        """Mark an on-disk upload directory for cleanup on replace/shutdown."""
        self._owned_paths.append(path)

    def shutdown(self):
        with self.lock:
            self._release(self.package)
            self.package = None
            self.label = None

    def _release(self, package):
        if package is not None and package._tempdir is not None:
            package._tempdir.cleanup()
        for path in self._owned_paths:
            shutil.rmtree(path, ignore_errors=True)
        self._owned_paths.clear()

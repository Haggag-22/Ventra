"""Collector base class and a small registry.

Each artifact group subclasses :class:`Collector`, declares the AWS actions it needs (used
both for documentation and the read-only guard), and implements :meth:`collect`.
"""

from __future__ import annotations

import abc
import gzip
import hashlib
import json
from collections.abc import Iterable
from typing import Any

from .models import CollectionContext, SourceResult, WrittenFile

# Verbs that may never appear in a collector's declared actions. The readonly-guard CI check
# and tools.verify_readonly both rely on this list.
MUTATING_PREFIXES = (
    "Create",
    "Put",
    "Delete",
    "Update",
    "Modify",
    "Run",
    "Start",
    "Stop",
    "Terminate",
    "Reboot",
    "Attach",
    "Detach",
    "Associate",
    "Disassociate",
    "Add",
    "Remove",
    "Set",
    "Enable",
    "Disable",
    "Tag",
    "Untag",
    "Authorize",
    "Revoke",
    "Cancel",
    "Reset",
    "Restore",
    "Copy",
    "Import",
    "Send",
    "Invoke",
    "Replace",
    "Register",
    "Deregister",
    "Accept",
    "Reject",
)

# Read verbs that GenerateCredentialReport etc. legitimately use despite a mutating-looking
# prefix. Explicitly allow-listed so the guard stays strict everywhere else.
READONLY_EXCEPTIONS = frozenset(
    {
        "iam:GenerateCredentialReport",  # produces a report; does not change account state
    }
)


# Default per-source record cap. A collector may override via ``ctx.max_records_per_source``
# (raised for large pulls, or 0/negative for no cap). Kept here so the cap is one number.
DEFAULT_MAX_RECORDS = 200_000
# Effective "no cap" ceiling — large enough to never truncate in practice while still bounding
# paginators that require a finite limit.
_UNLIMITED_RECORDS = 1_000_000_000


class Collector(abc.ABC):
    """Base class for every Ventra collector.

    Subclasses set ``name`` (the logical source name in the manifest), ``priority`` (1 = baseline,
    2 = extended), and ``required_actions`` (cloud API actions, read-only), then implement
    :meth:`collect`.
    """

    name: str = ""
    priority: int = 1
    description: str = ""
    required_actions: tuple[str, ...] = ()

    def __init__(self, ctx: CollectionContext) -> None:
        self.ctx = ctx

    def max_records(self, default: int = DEFAULT_MAX_RECORDS) -> int:
        """Effective per-source record cap for this run.

        ``ctx.max_records_per_source`` overrides the collector default: a positive value sets the
        cap; 0 or negative disables it (returns a very large ceiling for large pulls).
        """
        cap = getattr(self.ctx, "max_records_per_source", None)
        if cap is None:
            return default
        return _UNLIMITED_RECORDS if cap <= 0 else cap

    def artifact_params(self) -> dict[str, Any]:
        """Per-artifact filter values for this collector from the acquisition spec (may be empty)."""
        return getattr(self.ctx, "artifact_parameters", {}).get(self.name, {})

    @abc.abstractmethod
    def collect(self) -> SourceResult:
        """Gather artifacts and return a SourceResult. Must not mutate cloud state."""
        raise NotImplementedError

    # -- helpers shared by concrete collectors -------------------------------------------

    def _log(self, msg: str) -> None:
        if self.ctx.logger:
            self.ctx.logger.event(self.name, msg)

    def write_jsonl(self, records: Iterable[dict[str, Any]], filename: str) -> WrittenFile:
        """Write records as gzip JSON-lines and return integrity metadata.

        zstd is preferred at the package level; per-source files use gzip so the collector
        has no hard dependency on the ``zstandard`` wheel inside a constrained cloud shell.

        The SHA-256 is taken over the *stored file bytes* (the compressed artifact), because
        that is exactly what the ingester re-hashes after transit to detect tampering. gzip
        mtime is pinned to 0 so re-running collection is deterministic.
        """
        out_path = self.ctx.source_dir(self.name) / filename
        count = 0
        with gzip.GzipFile(filename=out_path, mode="wb", mtime=0) as gz:
            for rec in records:
                line = json.dumps(rec, default=str, separators=(",", ":")) + "\n"
                gz.write(line.encode("utf-8"))
                count += 1
        data = out_path.read_bytes()
        return WrittenFile(
            path=out_path.relative_to(self.ctx.staging).as_posix(),
            sha256=hashlib.sha256(data).hexdigest(),
            bytes=len(data),
            record_count=count,
        )

    def write_json(self, obj: Any, filename: str) -> WrittenFile:
        """Write a single JSON document (snapshots, config) and hash it."""
        out_path = self.ctx.source_dir(self.name) / filename
        payload = json.dumps(obj, default=str, indent=2).encode("utf-8")
        out_path.write_bytes(payload)
        return WrittenFile(
            path=out_path.relative_to(self.ctx.staging).as_posix(),
            sha256=hashlib.sha256(payload).hexdigest(),
            bytes=len(payload),
        )

    def write_meta(self, meta: dict[str, Any]) -> WrittenFile:
        return self.write_json(meta, "_meta.json")


class CollectorRegistry:
    """Maps collector names to classes."""

    def __init__(self) -> None:
        self._collectors: dict[str, type[Collector]] = {}

    def register(self, cls: type[Collector]) -> type[Collector]:
        if not cls.name:
            raise ValueError(f"{cls.__name__} must set a name")
        self._collectors[cls.name] = cls
        return cls

    def get(self, name: str) -> type[Collector] | None:
        return self._collectors.get(name)

    def names(self) -> list[str]:
        return sorted(self._collectors)

    def all(self) -> dict[str, type[Collector]]:
        return dict(self._collectors)


def assert_readonly(actions: Iterable[str]) -> list[str]:
    """Return any actions that look mutating. Empty list == clean.

    Used by tools.verify_readonly and the test suite to keep collectors honest.
    """
    offenders: list[str] = []
    for action in actions:
        if action in READONLY_EXCEPTIONS:
            continue
        verb = action.split(":", 1)[-1]
        if verb.startswith(MUTATING_PREFIXES):
            offenders.append(action)
    return offenders

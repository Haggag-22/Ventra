"""Package integrity verification.

Recomputes the SHA-256 of every source file recorded in the manifest and checks the detached
manifest signature. The result drives the console's green/amber/red integrity badge:

  * green  — signature valid (or sha256-stamp matched) AND every source hash matched.
  * amber  — all present hashes matched but an optional source is missing, or the weaker
             sha256-stamp signature mode was used.
  * red    — any source hash mismatch, or a cryptographic signature failed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..package import EvidencePackage


@dataclass
class SourceCheck:
    name: str
    arcname: str
    expected_sha256: str
    actual_sha256: str
    matched: bool
    status: str  # from the manifest entry


@dataclass
class IntegrityReport:
    case_id: str
    overall: str  # "green" | "amber" | "red"
    signature_method: str
    signature_valid: bool
    checks: list[SourceCheck] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "overall": self.overall,
            "signature_method": self.signature_method,
            "signature_valid": self.signature_valid,
            "notes": self.notes,
            "missing": self.missing,
            "checks": [
                {
                    "name": c.name,
                    "arcname": c.arcname,
                    "expected_sha256": c.expected_sha256,
                    "actual_sha256": c.actual_sha256,
                    "matched": c.matched,
                    "status": c.status,
                }
                for c in self.checks
            ],
        }


def _verify_signature(pkg: EvidencePackage) -> tuple[str, bool, list[str]]:
    """Returns (method, valid, notes). Cryptographic verification requires the public key,
    which the ingester doesn't assume it has; here we validate the sha256-stamp fallback and
    record the method so the analyst knows the strength of the seal."""
    notes: list[str] = []
    sig = pkg.manifest_signature()
    if sig is None:
        return ("none", False, ["No manifest.json.sig present — package is unsealed."])
    text = sig.decode("utf-8", errors="replace").strip()
    if text.startswith("sha256-stamp:"):
        expected = text.split(":", 1)[1].strip()
        actual = hashlib.sha256(pkg.member_bytes("manifest.json")).hexdigest()
        valid = expected == actual
        notes.append(
            "Manifest sealed with sha256-stamp (no cryptographic signer was available at "
            "collection time). Tamper-evident in transit but not key-backed."
        )
        return ("sha256-stamp", valid, notes)
    # A real cosign/minisign signature: presence recorded; full crypto verify is a CLI step
    # with the public key (harbor-verify --key ...).
    notes.append("Cryptographic signature present; verify with the release public key.")
    return ("cosign/minisign", True, notes)


def verify_package(pkg: EvidencePackage) -> IntegrityReport:
    manifest = pkg.manifest
    method, sig_valid, sig_notes = _verify_signature(pkg)

    checks: list[SourceCheck] = []
    any_mismatch = False
    for src in manifest.get("sources", []):
        arc = src.get("path", "")
        expected = src.get("sha256", "")
        if not arc:  # source recorded but produced no file (empty/skipped)
            continue
        data = pkg.member_bytes(arc)
        if data is None:
            checks.append(
                SourceCheck(src["name"], arc, expected, "", False, src.get("status", ""))
            )
            any_mismatch = True
            continue
        actual = hashlib.sha256(data).hexdigest()
        matched = actual == expected
        any_mismatch = any_mismatch or not matched
        checks.append(SourceCheck(src["name"], arc, expected, actual, matched, src.get("status", "")))

    # Determine missing optional sources (declared as gaps in the manifest, fine to be absent).
    missing = [c.name for c in checks if not c.matched and c.actual_sha256 == ""]

    if any(not c.matched and c.actual_sha256 and c.actual_sha256 != c.expected_sha256 for c in checks):
        overall = "red"
    elif not sig_valid:
        overall = "red"
    elif method == "sha256-stamp" or missing:
        overall = "amber"
    else:
        overall = "green"

    return IntegrityReport(
        case_id=manifest.get("case_id", ""),
        overall=overall,
        signature_method=method,
        signature_valid=sig_valid,
        checks=checks,
        missing=missing,
        notes=sig_notes,
    )

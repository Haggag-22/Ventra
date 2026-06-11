"""Detached signing of the manifest.

Harbor prefers an external signer (cosign or minisign) when present, so the same keys and
verification flow used for release artifacts cover evidence too. When no signer is available
(common inside a bare cloud shell) Harbor falls back to an unkeyed SHA-256 *integrity stamp*
so the package is still tamper-evident in transit, and records which mode was used.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .hashing import sha256_file


@dataclass
class SigningResult:
    signature_path: Path
    method: str  # "cosign" | "minisign" | "sha256-stamp"
    verified_command: str = ""


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def sign_manifest(manifest_path: Path, key_path: Path | None = None) -> SigningResult:
    """Produce ``manifest.json.sig`` next to the manifest.

    Order of preference: cosign (keyless or keyed) → minisign → sha256 stamp.
    """
    sig_path = manifest_path.with_suffix(manifest_path.suffix + ".sig")

    cosign = _which("cosign")
    if cosign and key_path and key_path.exists():
        subprocess.run(
            [cosign, "sign-blob", "--yes", "--key", str(key_path),
             "--output-signature", str(sig_path), str(manifest_path)],
            check=True,
            capture_output=True,
        )
        return SigningResult(
            signature_path=sig_path,
            method="cosign",
            verified_command=(
                f"cosign verify-blob --key <pub> --signature {sig_path.name} "
                f"{manifest_path.name}"
            ),
        )

    minisign = _which("minisign")
    if minisign and key_path and key_path.exists():
        subprocess.run(
            [minisign, "-S", "-s", str(key_path), "-m", str(manifest_path), "-x", str(sig_path)],
            check=True,
            capture_output=True,
        )
        return SigningResult(signature_path=sig_path, method="minisign")

    # Fallback: write the manifest's own SHA-256 as the signature payload. Not a cryptographic
    # signature, but lets the ingester detect in-transit tampering and flags the weaker mode.
    digest = sha256_file(manifest_path)
    sig_path.write_text(f"sha256-stamp:{digest}\n", encoding="utf-8")
    return SigningResult(signature_path=sig_path, method="sha256-stamp")

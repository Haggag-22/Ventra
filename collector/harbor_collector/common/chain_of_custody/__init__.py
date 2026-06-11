"""Chain-of-custody primitives: hashing and manifest signing."""

from .hashing import sha256_bytes, sha256_file
from .signing import SigningResult, sign_manifest

__all__ = ["sha256_file", "sha256_bytes", "sign_manifest", "SigningResult"]

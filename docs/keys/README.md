# Release & evidence signing keys

This directory holds **public** keys only. Private keys never live in the repo.

- `harbor-release.pub` — the public key releases are signed with (cosign/minisign). Verify a
  downloaded artifact before running it in a client environment:

  ```bash
  cosign verify-blob --key docs/keys/harbor-release.pub \
    --signature harbor-collector.whl.sig harbor-collector.whl
  ```

The signing key is generated and published as part of the first tagged release (Phase 4).
Until then, packages produced without a signer fall back to a SHA-256 integrity stamp, which
the ingester reports as the weaker `amber` integrity state. See
[`docs/evidence-package-format.md`](../evidence-package-format.md) §4.

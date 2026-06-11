# Data Custodian Runbook — evidence lifecycle

For the **data custodian** responsible for evidence integrity and retention. Harbor defines
the evidence format and verifies integrity; **it is not a long-term vault** — your firm's
storage and retention policy governs the archived packages.

## Receiving a package

1. Record receipt: who sent it, when, through which channel.
2. **Verify before storing:**
   ```bash
   harbor-verify ./case-CASE-2026-0042-....tar.zst --key harbor-release.pub
   ```
   This checks the detached signature and recomputes every per-source SHA-256 against the
   manifest. Log the result.
3. Store the **original sealed package** read-only. All analysis works on copies — the
   ingester never modifies the original.

## Immutability recommendations

Mirroring AWS's forensic-environment guidance:

- Store originals in object storage with **Object Lock / WORM** and, where supported, **MFA
  delete**. Long-term: a vault-lock / Glacier-style tier.
- Keep the **manifest hash** in a separate ledger from the package itself, so tampering with
  one doesn't silently cover the other.
- Restrict access to the **data custodian and assigned investigators** only.

## Chain of custody

Every package's `manifest.json` already records: operator principal, source IP, collection
start/end, account, regions, tool version. Append your custody events (receipt, transfers,
access) to your firm's custody log keyed by `case_id`.

## Retention & disposal

- Follow the engagement's legal hold and retention schedule.
- On disposal, record the action and the package hash being destroyed.
- The console's per-case **audit log** (Settings → Audit) records analyst access for the life
  of the case store; export it before disposing of a case.

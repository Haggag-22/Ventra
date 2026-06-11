---
name: New collector / source request
about: Propose a new artifact source for the collector + ingester
labels: enhancement, collector
---

**Cloud & service**
e.g. AWS Transit Gateway Flow Logs.

**What it tells an investigator**
Which of the four questions does it answer — who authenticated, what they did, what changed,
or data exfil? Map to an ATT&CK Cloud technique if you can.

**Read-only API actions required**
List the `Describe*` / `Get*` / `List*` calls. Reminder: the collector is read-only — no
mutating actions.

**Tier**
- [ ] Tier 1 (baseline, always collected)
- [ ] Tier 2 (strongly recommended)
- [ ] Tier 3 (conditional / on-demand)

**Sample record (sanitized)**
A scrubbed example of the source's output, to design the parser/normalizer.

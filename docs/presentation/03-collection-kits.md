# Slide 3 — Collection Kits

**Sidebar:** Configuration → **Collection Kits**

## What it does

**Saved, reusable collection recipes** — named kits you can run again without rebuilding from scratch.

## Why it matters

IR teams repeat the same collection playbook across cases. Kits encode *which* collectors, *which* platform, and default scope so the next incident starts in minutes, not hours.

## What you do here

- **View all kits** — name, cloud, collector count
- **Run** — start a live scan with the saved definition (opens run wizard: connection, case ID, scope)
- **Download Kit** — generate offline acquisition package for the client
- **Edit** — opens Acquire with that kit loaded
- **Delete** — remove obsolete kits

## Kit = snapshot of Acquire

Each kit stores:

- Platform (AWS / Azure / GCP / Kubernetes)
- Selected collectors and artifact parameters
- Handoff / transport preferences
- Deployment profile (when applicable)

## In the walkthrough

**After you save from Acquire.** Show one named kit—e.g. `baseline-ir-aws` or your demo case kit.

**Next →** [04 — Running a kit](04-running-a-kit.md): press **Run** and start collection.

## Speaker notes

- Kits are **not cases**—they are templates. The case is created when a run completes and evidence is ingested.
- Good naming: `{customer}-{cloud}-{playbook}` or `CASE-template-baseline-gcp`.

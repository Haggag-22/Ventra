# Slide 2 — Acquire

**Sidebar:** Configuration → **Acquire**

## What it does

**Kit builder** — choose which collectors to run, set case scope, parameters, and how evidence gets back to you.

## Why it matters

This is where you define *what* to collect for an investigation: CloudTrail vs GuardDuty vs VPC flow, baseline IR pack vs custom cart, time window, regions, and handoff destination.

## What you do here

1. **Pick a platform** — AWS, Azure, GCP, or Kubernetes
2. **Set case ID** — ties all artifacts to one investigation (e.g. `CASE-2026-0042`)
3. **Select collectors** — browse by category or load a baseline pack
4. **Tune parameters** — lookback days, regions, resource filters, GCP log backend (if needed)
5. **Choose handoff** — how the client or Ventra server receives the bundle:
   - **Upload to my IR bucket** — kit writes to your S3 prefix; you import from S3
   - **Presigned URL** — one-time upload URL for the client (no long-lived bucket IAM on their side)
6. **Save as Collection Kit** or **Run** / **Download Kit** immediately

## Two deployment modes

| Mode | Who runs collectors | Typical scenario |
|------|---------------------|------------------|
| **Live scan** | Ventra server (uses Authentication) | Analyst machine or IR VPC with cloud API access |
| **Offline kit** | Customer downloads ZIP/script | Client environment; results uploaded via handoff |

## In the walkthrough

**After Authentication.** Build the kit you will demo—often a baseline IR pack for one cloud.

**Next →** [03 — Collection Kits](03-collection-kits.md): save and reuse what you built.

## Speaker notes

- Acquire is the **shopping cart** for forensic sources—not the investigation UI.
- Enterprise vs platform profiles affect packaging (single cloud vs multi-cloud kits).

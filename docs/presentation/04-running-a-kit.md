# Slide 4 — Running a kit

**From:** Collection Kits → **Run** (or Acquire → **Run collection**)

## What it does

**Starts acquisition** — either a **live scan** on the Ventra server or preparation of an **offline kit** for download.

## Why it matters

This is the handoff from *configuration* to *execution*. Until a kit runs (or an offline bundle is ingested), there is no case to investigate.

## Live scan flow

1. Click **Run** on a kit (or **Run collection** in Acquire)
2. **Select authentication** — connection from slide 1
3. **Confirm case ID** — new or existing investigation id
4. **Adjust scope** — time range, regions, optional resource filters
5. **Submit** — Ventra queues collectors and calls cloud APIs
6. Redirect to **Scans** — live run detail with per-collector progress

## Offline kit flow

1. Click **Download Kit** on a kit
2. Client runs the package in *their* environment (no Ventra cloud credentials on your server)
3. Upload result via **IR bucket** or **presigned URL** (configured in Acquire)
4. **Import** on Cases — package file or **Import from S3**

## What gets produced

- Raw collector outputs (archives, JSON, logs)
- Manifest describing sources, gaps, and parameters
- Ingested **case** ready for timeline and findings

## In the walkthrough

**The action step.** Run a live scan against your lab account or import a pre-built demo case if offline.

**Next →** [05 — Scans](05-scans.md): monitor the run until it completes.

## Speaker notes

- Live scan = you see progress in real time; offline = client air-gap friendly.
- Failed collectors still land as **gaps** in the manifest—missing telemetry is itself evidence.

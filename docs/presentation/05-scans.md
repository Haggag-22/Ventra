# Slide 5 — Scans

**Sidebar:** Configuration → **Scans**

## What it does

**Live collection monitor** — every run, its status, duration, and per-collector results.

## Why it matters

Cloud collection can take minutes to hours. Scans is where analysts watch progress, diagnose failures, and jump to the case when evidence is ready.

## What you do here

### Scans list

- Filter: **All / Running / Completed / Failed / Cancelled**
- See case ID, platform, collector progress, timestamps
- **View** — open run detail
- **Rerun** — same kit + scope, new run id
- **Cancel** — stop an in-flight live scan

### Run detail (live)

- **Status badge** — pending, running, completed, failed, cancelled
- **Collector matrix** — each source: running, collected, empty, error, gap
- **Event log** — streaming collector messages (SSE)
- **Open case** — when ingest finished and case exists
- **Elapsed time** and artifact counts

## “Live scan” in practice

While status is **Running**:

- Matrix rows flip from pending → complete as APIs return
- WAF / CloudFront / S3 log collectors may show gaps until logs land (normal)
- You can leave the page and return—Scans list still shows active runs

## In the walkthrough

**After starting a kit.** Keep this page open until the run shows **Completed**, then **Open case**.

**Next →** [06 — Cases](06-cases.md): investigate the ingested evidence.

## Speaker notes

- Scans = **operations**; Cases = **investigation**.
- Demo tip: use a pre-ingested case if the live run is slow; show Scans on a shorter lab run separately.

# Slide 7 — Export

**Sidebar:** Configuration → **Export**

## What it does

**SIEM handoff** — export normalized, case-scoped events to Elastic, Splunk, or generic NDJSON.

## Why it matters

Ventra is the collection and first-pass analysis layer. Most teams still replay timelines in Elastic or Splunk for correlation, alerting, and long-term retention.

## What you do here

1. **Select cases** — one or many investigations
2. **Choose target format**:

   | Target | Output |
   |--------|--------|
   | **Elastic** | ECS-shaped NDJSON + starter index template |
   | **Splunk** | CIM-normalized HEC NDJSON |
   | **Generic NDJSON** | One normalized event per line, unshaped |

3. **Filter sources** (optional) — export only CloudTrail, only findings, etc.
4. **Review counts** — events per source, approximate size
5. **Export** — download archive or stream batch to your pipeline

## What gets exported

- Normalized timeline events (not raw collector blobs)
- Per-source event counts from ingestion stats
- Case metadata for index routing (`case_id`, cloud, time bounds)

## In the walkthrough

**After showing a case.** Export one case to **Elastic** or **NDJSON** and mention Splunk HEC for Splunk shops.

**Next →** [08 — Documentation](08-documentation.md): where to look up IAM and collectors.

## Speaker notes

- Export is **outbound** from Ventra’s case store—not live cloud polling.
- Teams often export subsets (audit only) to control SIEM volume.

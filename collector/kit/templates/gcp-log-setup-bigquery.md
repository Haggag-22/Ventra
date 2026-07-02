# GCP log export setup — BigQuery

Ventra is **read-only**. The client admin must route logs to BigQuery **before** the operator runs collection with the BigQuery backend.

## Overview

1. Create or choose a BigQuery dataset (e.g. `my-project.audit_logs`).
2. Create a **log sink** that exports the log types you need to that dataset.
3. Grant the Ventra service account:
   - `bigquery.jobs.create`
   - `bigquery.datasets.get`
   - `bigquery.tables.get`
   - `bigquery.tables.getData`
   - `bigquery.tables.list`
   on the dataset (or project).

## Example (gcloud)

Replace `PROJECT`, `DATASET`, and `SA_EMAIL`.

```bash
# Create dataset
bq mk --dataset PROJECT:DATASET

# Sink all admin activity logs (adjust filter for your engagement)
gcloud logging sinks create ventra-audit-export \
  bigquery.googleapis.com/projects/PROJECT/datasets/DATASET \
  --log-filter='logName:"cloudaudit.googleapis.com"' \
  --project=PROJECT

# Grant sink writer identity on the dataset (command prints writer identity)
# gcloud logging sinks describe ventra-audit-export --project=PROJECT
```

Grant the collector service account read access on the dataset, then re-run `ventra.py` after exports have populated.

## Ventra note

When `gcp_log_backend.mode` is `bigquery` in `acquisition.yaml`, logging collectors query the configured dataset (per-collector table hints, falling back to `_Default`) and apply the same log filters as the Logging API path. Complete this setup before collection.

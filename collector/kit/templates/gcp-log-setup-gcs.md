# GCP log export setup — Cloud Storage

Ventra is **read-only**. The client admin must route logs to a GCS bucket **before** the operator runs collection with the GCS backend.

## Overview

1. Create or choose a GCS bucket (e.g. `gs://company-log-archive`).
2. Create a **log sink** that exports required log types to that bucket.
3. Grant the Ventra service account:
   - `storage.buckets.get`
   - `storage.objects.list`
   - `storage.objects.get`
   on the bucket prefix.

## Example (gcloud)

Replace `PROJECT`, `BUCKET`, and adjust the filter.

```bash
gsutil mb -p PROJECT gs://BUCKET

gcloud logging sinks create ventra-log-archive \
  storage.googleapis.com/BUCKET \
  --log-filter='logName:"cloudaudit.googleapis.com"' \
  --project=PROJECT

# Grant the sink's writer service account access to the bucket
# (see writer_identity from: gcloud logging sinks describe ventra-log-archive)
```

## Ventra note

When `gcp_log_backend.mode` is `gcs` in `acquisition.yaml`, logging collectors read JSON log objects under the configured bucket/prefix and apply the same log filters as the Logging API path. Complete this setup before collection.

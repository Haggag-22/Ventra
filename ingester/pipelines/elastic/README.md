# Elastic SIEM export (Track D4a)

Ventra normalizes every source into one schema. After ingest, export NDJSON and forward it
into the client's Elastic stack with Logstash.

## Local Docker demo (free, no Elastic Cloud account)

From this directory:

```bash
# Export a case (console **Export to Elastic** or CLI)
ventra-export --case-dir ../../cases/Test-AWS --out ./export

# Or point at an existing unzip:
EXPORT_DIR=~/Downloads/Test-AWS-elastic-export ./demo.sh

# Load all sources (slow — large NDJSON files):
EXPORT_DIR=~/Downloads/Test-AWS-elastic-export ./demo.sh --all
```

Opens **Kibana** at http://localhost:5601. Create a data view `ventra-*` with time field
`@timestamp`, then filter `ventra.case_id:"Test-AWS"`. Open **Security** for the SIEM UI.

Stop: `docker compose -f docker-compose.yml down`

## 1. Ingest and export

```bash
ventra-ingest case.tar.zst --case-store ./cases
ventra-export --case-dir ./cases/CASE-2026-0042 --out ./export
```

Or use **Export to Elastic** in the console — downloads a zip containing `{source}.ndjson`
files plus `export-manifest.json`.

## 2. Install the index template

```bash
curl -X PUT "$ELASTIC_HOSTS/_index_template/ventra-events" \
  -H 'Content-Type: application/json' \
  -d @ingester/pipelines/elastic/ventra-events-template.json
```

Adjust shard/replica settings for your cluster. The template maps `ventra.case_id`,
`ventra.source`, ECS-aligned fields, and `@timestamp`.

## 3. Forward with Logstash

All sources share the same field layout — use the unified pipeline:

```bash
export ELASTIC_HOSTS=https://es.example.com:9200

for f in export/*.ndjson; do
  VENTRA_NDJSON="$f" logstash -f ingester/pipelines/logstash/ventra-common.conf \
                              -f ingester/pipelines/logstash/ventra-unified.conf
done
```

CloudTrail-only (legacy path):

```bash
VENTRA_NDJSON=$PWD/export/cloudtrail.ndjson \
  logstash -f ingester/pipelines/logstash/ventra-common.conf \
           -f ingester/pipelines/logstash/cloudtrail.conf
```

Configure Elasticsearch auth/TLS via Logstash's `elasticsearch` output plugin environment
variables (`ELASTIC_USER`, `ELASTIC_PASSWORD`, CA paths) — never hardcode credentials.

## 4. Verify in Kibana

1. Open **Discover** and select index pattern `ventra-*`.
2. Filter on `ventra.case_id:"CASE-2026-0042"`.
3. Group or filter by `ventra.source` to pivot between CloudTrail, VPC flow, GuardDuty, etc.

## Index naming

Default index pattern: `ventra-{source}-YYYY.MM.dd` (e.g. `ventra-cloudtrail-2026.06.23`).

Override with Logstash environment variables or edit `ventra-unified.conf`.

## What not to rebuild in Ventra

Hunts, alerting, and correlation rules belong in Elastic/Kibana — not in the Ventra console.
Ventra export is the handoff path; Kibana is the primary SOC analysis surface.

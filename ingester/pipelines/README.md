# Forwarding pipelines

Ventra normalizes every source into one ECS-aligned schema. That same output can feed a
client's existing tooling, not just the Ventra console.

## Logstash → Elastic SIEM

Export an ingested case to NDJSON, install the index template, then forward with Logstash.
Full runbook: [`elastic/README.md`](elastic/README.md).

```bash
ventra-ingest case.tar.zst --case-store ./cases
ventra-export --case-dir cases/<id> --out ./export

curl -X PUT "$ELASTIC_HOSTS/_index_template/ventra-events" \
  -H 'Content-Type: application/json' \
  -d @ingester/pipelines/elastic/ventra-events-template.json

VENTRA_NDJSON=$PWD/export/cloudtrail.ndjson ELASTIC_HOSTS=https://es:9200 \
  logstash -f ingester/pipelines/logstash/ventra-common.conf \
           -f ingester/pipelines/logstash/ventra-unified.conf
```

All sources share the same field mapping — use `ventra-unified.conf` for every `{source}.ndjson`
file. `cloudtrail.conf` is an optional variant that indexes by AWS account ID.

Or download the export bundle from the console (**Export to Elastic** on any case).

## OCSF / STIX

[`ocsf/`](ocsf/) documents exporting the unified events as
[OCSF](https://schema.ocsf.io/) for interoperability, and IOCs as STIX bundles for sharing.
Because normalization already happened in the ingester, these are thin field re-mappings.

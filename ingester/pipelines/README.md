# Forwarding pipelines

Harbor normalizes every source into one ECS-aligned schema. That same output can feed a
client's existing tooling, not just the Harbor console.

## Logstash → Elastic SIEM

[`logstash/cloudtrail.conf`](logstash/cloudtrail.conf) forwards normalized CloudTrail events
into Elasticsearch. Export a source from a built case to NDJSON, then run Logstash:

```bash
duckdb -c "COPY (SELECT * FROM 'cases/<id>/events.parquet' WHERE harbor_source='cloudtrail') \
           TO 'cloudtrail.ndjson' (FORMAT JSON)"
HARBOR_NDJSON=$PWD/cloudtrail.ndjson ELASTIC_HOSTS=https://es:9200 \
  logstash -f ingester/pipelines/logstash/cloudtrail.conf
```

Add a `.conf` per source as needed; they all share the same field mapping because the input
is already normalized.

## OCSF / STIX

[`ocsf/`](ocsf/) documents exporting the unified events as
[OCSF](https://schema.ocsf.io/) for interoperability, and IOCs as STIX bundles for sharing.
Because normalization already happened in the ingester, these are thin field re-mappings.

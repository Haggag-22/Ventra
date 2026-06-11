# OCSF & STIX export

Harbor's unified event schema is ECS-aligned, which makes a mapping to
[OCSF](https://schema.ocsf.io/) (Open Cybersecurity Schema Framework) straightforward.

## Mapping sketch (unified event → OCSF)

| Harbor field | OCSF |
|--------------|------|
| `@timestamp` | `time` |
| `event.action` | `activity_name` |
| `event.category` | `category_uid` / `class_uid` (per category) |
| `event.outcome` | `status` |
| `user.name` / `user.arn` | `actor.user.name` / `actor.user.uid` |
| `source.ip` | `src_endpoint.ip` |
| `cloud.account.id` / `cloud.region` | `cloud.account.uid` / `cloud.region` |
| `resource.arn` | `resources[].uid` |
| `raw` | `unmapped` |

A `harbor-export --format ocsf` command is on the roadmap (Phase 8). Until then, the mapping
above plus the `events.parquet` columns is enough to script an export with DuckDB + a small
transform.

## STIX (IOCs)

The console's IOC list and any `related_ip` / `related_resource` of interest can be emitted as
a STIX 2.1 bundle of `indicator` objects for sharing with partners or a TIP.

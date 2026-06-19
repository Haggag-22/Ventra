# Artifacts layout

Ventra uses a **Velociraptor-style** separation between declarative artifacts and executable collector code.

## Repository structure

```
artifacts/                  # YAML catalog (what to collect)
  aws/                      # Category subfolders (management-plane, identity, …)
  azure/
  gcp/
  packs/                    # Curated artifact bundles (baseline-ir-*.yaml)

schemas/artifact.schema.json

collector/
  engine/
    loader.py               # Load + validate artifact YAML
    registry.py             # Map collector keys → API module classes
    executor.py             # List / run collectors (delegates to cloud runners)
    api/{aws,azure,gcp}/    # Collector implementations (read-only acquisition)
  clouds/{aws,azure,gcp}/   # SDK client factories (auth, pagination, gap typing)
  kit/                      # Operator zip builder (acquisition.yaml + templates)
  lib/                      # Shared models, packaging, chain of custody
  runner.py                 # Thin CLI/runner re-exports
```

## Artifact YAML

Each file under `artifacts/<cloud>/` describes one collector:

- **name** — hierarchical id (e.g. `GCP.ManagementPlane.CloudAuditAdmin`)
- **collector** — registry key used by `collector.engine.registry`
- **aliases** — alternate lookup names
- **required_actions** — read-only IAM/API permissions for operator docs
- **sources** — output shapes produced by the collector

Packs under `artifacts/packs/` list artifact `collector` keys for baseline IR scenarios.

## Runtime flow

1. **Loader** reads YAML from `artifacts/` and validates required fields.
2. **Registry** resolves `collector` → Python class under `collector.engine.api`.
3. **Executor** lists or runs collectors; full orchestration (manifest, seal) remains in per-cloud runners.
4. **Clouds** package provides SDK clients; collectors never import boto3/azure SDK directly in new code.

## Import paths

Use the canonical modules directly:

- `collector.clouds.aws.client_factory` (and `azure` / `gcp`)
- `collector.engine.api.aws.identity.iam` (and other collector modules)
- `collector.engine.registry`
- `collector.aws.runner.runner` (per-cloud orchestration only)

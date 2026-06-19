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
2. **Acquisition** (`collector.engine.acquisition`) loads an `acquisition.yaml` or a pack and
   resolves it — through the loader and registry — to an ordered collector list plus
   `ArtifactRef` provenance (`name`, `version`, `collector`, `parameters`).
3. **Registry** resolves `collector` → Python class under `collector.engine.api`.
4. **Executor** lists or runs collectors; full orchestration (manifest, seal) remains in per-cloud runners.
5. **Runners** record the resolved `ArtifactRef`s in the manifest's `artifacts[]` so every
   sealed package carries the artifact name + version that produced each source.
6. **Kit** (`collector/kit/build.py`) emits a zip with `acquisition.yaml` (global filters +
   per-artifact parameters), narrowed IAM, artifact YAML copies, and `run.sh` (venv bootstrap +
   `ventra collect --acquisition`).
7. **Clouds** package provides SDK clients; collectors never import boto3/azure SDK directly in new code.

## CLI

```
ventra collect gcp --pack baseline-ir-gcp --case CASE-001     # run a curated pack
ventra collect aws --acquisition acquisition.yaml             # run a kit-style spec
ventra collect gcp --list-packs                               # list packs for a cloud
ventra artifacts list [--cloud gcp]                           # browse the catalog
ventra artifacts validate [--cloud gcp] [--strict]            # CI gate (non-zero on error)
ventra artifacts diff                                         # registry vs YAML drift
ventra kit build --cloud gcp --pack baseline-ir-gcp --case CASE-001 --out kit.zip
```

`--acquisition` overrides `--collectors`; `--pack` resolves `artifacts/packs/<name>.yaml`.
Both still fall back to `--collectors` / all registered collectors for backward compatibility.

## Acquire API (console)

The console backend exposes the same catalog so the Acquire tab can build kits in-browser:

- `GET /api/artifacts?cloud=&search=` — artifact library
- `GET /api/artifacts/{collector}` — single artifact detail
- `GET /api/packs?cloud=` — curated packs
- `POST /api/acquisitions/build` — `{cloud, case_id, artifacts|pack, since, until, regions,
  project, subscription, max_records_per_source, artifact_parameters}` → kit zip (uses
  `collector.kit.build.build_kit`; no duplicated zip logic)

## Import paths

Use the canonical modules directly:

- `collector.clouds.aws.client_factory` (and `azure` / `gcp`)
- `collector.engine.api.aws.identity.iam` (and other collector modules)
- `collector.engine.registry`
- `collector.engine.api.{aws,azure,gcp}.runner` (per-cloud orchestration)

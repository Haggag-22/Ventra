# Ventra Engine Upgrade — Cursor Implementation Prompt

> **How to use:** Point Cursor at this file plus `obsidian/Ventra Enterprise Roadmap.md` and the existing chat history. Implement in order. Do not reintroduce `collector/aws/*` shim trees or duplicate collector paths. Run `uv run pytest tests/ -q` before finishing.

---

## Context: what Ventra is

Ventra is a **cloud IR evidence platform** (Velociraptor-style for cloud, not endpoints):

```
artifacts/*.yaml  →  engine (load + registry + runners)  →  sealed EPF  →  ingester  →  console
```

| Layer | Path | Role |
|-------|------|------|
| **Artifacts** | `artifacts/{aws,azure,gcp}/`, `artifacts/packs/` | Declarative collector catalog (YAML) — what to collect, IAM, params |
| **Engine API** | `collector/engine/api/{aws,azure,gcp}/` | Python collectors (read-only acquisition) |
| **Clouds** | `collector/clouds/{aws,azure,gcp}/` | SDK client factories only |
| **Runners** | `collector/engine/api/{aws,azure,gcp}/runner.py` | End-to-end run: context → collectors → manifest → seal EPF |
| **Kit** | `collector/kit/build.py` | Zip for client: `acquisition.yaml` + IAM + `run.sh` |
| **Console** | `console/` | Investigate ingested cases; **Acquire mode not built yet** |

**There is no separate “Phase 1 design” anymore.** Collectors + YAML + engine are one system. Do not add back top-level `collector/aws/`, `collector/azure/`, `collector/gcp/` package trees.

---

## Already done (do not redo)

- 23 AWS + 22 Azure + 16 GCP collectors in `collector/engine/api/`
- `collector/clouds/` client factories
- Runners moved to `collector/engine/api/*/runner.py`
- ~60 artifact YAMLs + `artifacts/packs/baseline-ir-{aws,azure,gcp}.yaml`
- `schemas/artifact.schema.json`
- `collector/engine/{loader,registry,executor,run_common}.py`
- `collector/kit/build.py` + templates
- GCP console UI (`catalog.ts`, `panel-collectors.ts`, `CLOUD_IMPLEMENTED.gcp = true`)
- GCP ingester normalizers (`gcp_audit.py`, `gcp_findings.py`)
- `docs/iam-policies/gcp-collector-readonly.json`
- 93 collector tests passing
- Removed unused `icons/`, backward-compat shims, local clutter

---

## Track A — Wire the engine loop (highest priority)

### A1. Acquisition spec module

Create `collector/engine/acquisition.py`:

- `load_acquisition(path: Path) -> AcquisitionSpec` — parse `acquisition.yaml`
- Schema:

```yaml
case_id: CASE-2026-0042
cloud: gcp
ventra_version: "0.4.0"   # optional
artifacts:
  - collector: cloud_audit_admin
    name: GCP.ManagementPlane.CloudAuditAdmin   # optional
    version: "1.0.0"
    parameters: { since: "30d" }
# OR legacy short form:
artifacts: [cloud_audit_admin, vpc_flow]
```

- `load_pack(name: str, artifacts_root: Path) -> list[str]` — read `artifacts/packs/*.yaml`, return collector keys
- `resolve_collectors_from_acquisition(spec, artifacts_root) -> tuple[list[str], list[ArtifactRef]]` — merge pack + explicit artifacts, validate against registry

### A2. CLI flags

Add to `ventra collect {aws,azure,gcp}` (and shared collect parser):

| Flag | Behavior |
|------|----------|
| `--acquisition PATH` | Load collectors + params from YAML; overrides `--collectors` |
| `--pack NAME` | e.g. `baseline-ir-gcp` → resolves `artifacts/packs/baseline-ir-gcp.yaml` |
| `--list-packs` | List pack names for cloud |

Keep `--collectors` and `--list-collectors` working for backward compatibility.

### A3. Runners use acquisition

Update `collector/engine/api/{aws,azure,gcp}/runner.py`:

- Accept optional `artifact_refs: list[ArtifactRef]` on run config
- Pass time-window / params from acquisition into `CollectionContext` where applicable
- After run, manifest includes `artifacts[]` (see A4)

### A4. Manifest provenance

Extend `collector/lib/models.py` `Manifest`:

```python
@dataclass
class ArtifactRef:
    name: str
    version: str
    collector: str
    parameters: dict[str, Any] = field(default_factory=dict)
```

- Add `artifacts: list[ArtifactRef]` to `Manifest`
- Serialize in `manifest.json` inside EPF
- When running via `--collectors` only, populate from registry + artifact YAML lookup by collector key

### A5. `ventra artifacts` subcommand

New top-level CLI group:

```
ventra artifacts list [--cloud aws]
ventra artifacts validate [--cloud gcp]
ventra artifacts diff    # optional: YAML vs registry ids
```

`validate` must check:

- Every YAML passes `load_artifact()` + JSON schema (`schemas/artifact.schema.json`)
- Every `collector` field exists in `collector.engine.registry` for that cloud
- Every registry collector (optional strict mode) has a YAML
- `required_actions` are read-only (`collector.tools.verify_readonly`)
- Pack files reference valid collector keys

Exit non-zero on failure (CI-ready).

### A6. Kit builder alignment

Update `collector/kit/build.py`:

- Output `acquisition.yaml` in the **full schema** (A1), not just collector name list
- `ventra kit build --cloud gcp --pack baseline-ir-gcp --case CASE-001 --out kit.zip` CLI subcommand
- Merge IAM from `docs/iam-policies/{cloud}-collector-readonly.json` filtered to selected `required_actions` when possible

---

## Track B — Prove GCP end-to-end (Phase 1 exit gate)

### B1. Demo fixture

Create `tests/fixtures/generate_gcp_demo_case.py` mirroring `generate_azure_demo_case.py`:

- Synthetic GCP manifest + source JSON under `sources/`
- Cover: `cloud_audit_admin`, `vpc_flow`, `scc_findings`, `iam_policy`, `login_events` at minimum
- Output sealed `.tar.zst` to `tests/fixtures/`

### B2. Ingester test

Create `tests/ingester/test_gcp_pipeline.py` mirroring `test_azure_pipeline.py`:

- Generate demo → ingest → assert `events.parquet`, inventory, cloud=gcp in manifest
- Assert normalized events from `gcp_audit` / `gcp_findings` normalizers

### B3. Makefile

```makefile
demo-gcp:
	python tests/fixtures/generate_gcp_demo_case.py --out tests/fixtures/
ingest-gcp:
	ventra-ingest $$(ls -t tests/fixtures/case-CASE-*-gcp-*.tar.zst | head -1) --case-store ./cases
```

### B4. Document scale caps

Add short section to `docs/runbooks/operator.md`:

- ~200k records per source cap
- 4 GB console upload cap
- Not blockers; Phase 4 addresses streaming/S3

---

## Track C — Acquisition API + GUI (minimal viable)

### C1. Backend routes (`console/backend/`)

| Route | Purpose |
|-------|---------|
| `GET /api/artifacts?cloud=&search=` | List artifacts from `load_artifacts_dir()` |
| `GET /api/artifacts/{collector}` | Single artifact detail |
| `GET /api/packs?cloud=` | List packs |
| `POST /api/acquisitions/build` | Body: `{cloud, case_id, artifacts: [...]}` → return zip bytes |

Use existing `collector.kit.build.build_kit` — do not duplicate zip logic.

### C2. Console — Acquire mode (first slice)

- New route or tab: **Acquire** (alongside existing case investigation)
- Artifact Library: browse/filter by cloud + category
- Cart + Download Kit button → calls `POST /api/acquisitions/build`
- **Do not** replace `catalog.ts` for investigation panels yet; add API-driven list for Acquire only

### C3. `catalog.ts` generation (optional in this pass)

If time: script `scripts/generate-catalog-ts.py` from artifacts YAML for `console_panels` / categories — else defer and document as follow-up.

---

## Track D — Cleanup (do while working)

- Remove any remaining dead imports pointing at deleted `collector.aws.*` paths
- Do not commit `cases/`, `.env`, `__pycache__`, `icons/`
- Update `docs/artifacts.md` when runtime wiring changes
- Add `ventra artifacts validate` to CI / `make readonly-guard` or new `make validate-artifacts`
- Tests for: `load_acquisition`, `load_pack`, `artifacts validate`, kit build CLI

---

## Implementation order

```
1. collector/engine/acquisition.py
2. Manifest ArtifactRef + runner wiring
3. CLI: --acquisition, --pack, ventra artifacts *
4. ventra kit build
5. GCP demo fixture + test_gcp_pipeline.py
6. Backend /api/artifacts + /api/acquisitions/build
7. Console Acquire tab (minimal)
8. Full test suite + update docs
```

---

## Acceptance criteria

- [ ] `ventra collect gcp --pack baseline-ir-gcp --case TEST-001` runs and EPF `manifest.json` lists `artifacts[]` with versions
- [ ] `ventra collect aws --acquisition acquisition.yaml` works with kit-style YAML
- [ ] `ventra artifacts validate` passes in CI (0 errors)
- [ ] `make demo-gcp && pytest tests/ingester/test_gcp_pipeline.py` passes
- [ ] `POST /api/acquisitions/build` returns a zip that contains `acquisition.yaml` + `run.sh`
- [ ] No `collector/aws/` top-level tree; runners only under `engine/api/`
- [ ] `uv run pytest tests/ -q` all green

---

## Files to read first

| File | Why |
|------|-----|
| `collector/engine/loader.py` | Artifact loading |
| `collector/engine/registry.py` | Collector registry |
| `collector/engine/executor.py` | List/run helpers |
| `collector/engine/api/aws/runner.py` | Runner pattern |
| `collector/cli.py` | CLI integration point |
| `collector/kit/build.py` | Kit zip |
| `collector/lib/models.py` | Manifest |
| `artifacts/packs/baseline-ir-gcp.yaml` | Pack format |
| `tests/fixtures/generate_azure_demo_case.py` | Demo pattern |
| `tests/ingester/test_azure_pipeline.py` | Ingest test pattern |
| `console/backend/app/` | API routes |

---

## Out of scope for this upgrade

- Phase 4: Elastic bulk ingest, managed workers, SSO, S3 streaming transport
- Deleting `testing/` terraform harness (dev tool; keep)
- Removing `__init__.py` from disk (only hidden in IDE via `.vscode/settings.json`)

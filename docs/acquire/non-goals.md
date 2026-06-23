# Acquire — explicit non-goals (v0 kit model)

Ventra Acquire builds a **portable operator kit** for the client to run in **their** cloud environment. The console orchestrates kit composition and ingests sealed evidence packages — it does **not** execute live collection against customer accounts.

## Run collection from the browser

**Status:** Out of scope for the v0 kit model.

Some enterprise buyers ask for “click Collect in the web UI with zero local CLI.” That requires **managed collection workers** (Track D): isolated compute in the client tenant, credential brokering, progress telemetry, and durable job queues.

Until Track D ships:

- Collection runs via the downloaded kit (`ventra.py` / `run.sh`) in Cloud Shell, on a workstation, or on EC2/VM.
- The console **Acquire** page composes kits, previews IAM, and records operator handoff — it does not hold cloud credentials or pull logs directly.

## When this may change

Track D will add optional worker-backed collection while preserving the kit path for air-gapped and client-operated IR workflows.

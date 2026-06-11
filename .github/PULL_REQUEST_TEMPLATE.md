<!-- Thanks for contributing to Harbor. Keep PRs focused. -->

## What & why

<!-- What does this change and why? Link any issue. -->

## Type

- [ ] Collector (acquisition)
- [ ] Ingester (parse / normalize / load)
- [ ] Console (backend / frontend)
- [ ] Docs / CI / infra

## Forensic-soundness checklist

- [ ] **No mutating cloud calls** added to the collector (the `readonly-guard` CI check passes).
- [ ] Integrity guarantees unchanged, or change reviewed by a second maintainer.
- [ ] No telemetry / outbound calls added to the console.
- [ ] No real customer data committed — fixtures are synthetic/sanitized.

## Tests

- [ ] Added/updated tests (parser round-trip, collector moto test, or console e2e).
- [ ] `pytest`, `ruff`, and the frontend `build` all pass locally.

# graph2otel review guide

## Software and operators

graph2otel exports Microsoft Graph and related Microsoft 365 signals to an OTLP backend. Start at `cmd/graph2otel` for wiring, `internal/collectors` for collector registration, and `charts/graph2otel` for the deployed configuration contract.

## Invariants

- Require measured API behavior for changes to payloads, paging or throttling. Trace raw requests and retries through `internal/graphclient` and the owning ingest pipeline.
- Preserve tenant and endpoint checkpoint isolation, overlap and deduplication. Verify that an unwritable checkpoint directory fails startup and that the documented container mount survives a restart.
- Keep per-entity detail in logs and metric label cardinality bounded. Drop events whose occurrence time cannot be parsed. Trace emitted fields through `internal/telemetry` and the signal capture tests.

## Sensitive changes

Review credential scope, opt-in collection, time windows, retry limits, telemetry attributes and chart values for effects on operators and data isolation. Require a redacted, measured sample when a change depends on an API response shape. Check collector registration, test coverage and generated references together when a collector changes.

## CI findings

Focus comments on a reproducible regression, missing evidence or a gate that has lost coverage. The root `justfile` and `.github/workflows/ci.yml` cover formatting, dependency checks, race tests and generated drift. Review the generator, its inputs and the relevant drift check when generated output changes.

## Verification

Use `just check </dev/null` for the four Go modules and generated assets. Use the focused package, Helm or container smoke check when that surface changes. Keep public logs, fixture data and review comments free of real tenant identifiers and credentials.

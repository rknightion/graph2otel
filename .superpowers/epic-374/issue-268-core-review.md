# #268 telemetry core Tasks 1-2 independent review

Date: 2026-07-26

Worktree reviewed: `/tmp/graph2otel-268.4DDwyq`

Base: `066c8aa33710f007dc4295e0a87a78404515fc88`

## Verdict

READY

No severity findings in the telemetry-core Tasks 1-2 scope.

## Contract review

- Metrics and logs use fixed, independent snapshot fields and never share state,
  counters, timestamps, or failure codes.
- Each wrapped `Export`, `ForceFlush`, and `Shutdown` delegates exactly once,
  records only after the delegate returns, and returns the delegate's original
  error unchanged. Metric temporality and aggregation selectors also delegate
  unchanged.
- Export accounting conserves exactly:
  `export_attempts = export_successes + export_failures`.
- Only a successful `Export` recovers a degraded signal. Successful
  `ForceFlush` and `Shutdown` calls neither create acceptance nor clear
  degradation.
- `Provider.Shutdown` still joins the metric and log SDK shutdown errors.
- Stdout delivery becomes healthy independently for metrics and logs on
  successful local writer/exporter callbacks.
- `DeliverySnapshot` is an immutable value copy. Tracker mutation, reads, and
  report deltas are mutex-protected; repeated and concurrent race tests passed.
- State retains only bounded failure codes. Raw error text, HTTP material,
  endpoints, credentials, bearer tokens, and authorization headers cannot enter
  the snapshot or delivery metrics.
- `Provider.ReportSelfObs` emits exactly the six frozen delivery metrics through
  the undecorated process emitter. Each has exactly one point attribute,
  `signal=metrics|logs`; the full degraded gauge always contains both rows.
- The five counters are monotonic `{operation}` counters with delta-to-SDK
  accounting, so repeated `ReportSelfObs` calls do not add the same
  process-lifetime callback count twice.
- No tenant, collector, transport, failure code, retry, endpoint, or raw-error
  attribute appears on the delivery metrics. The explicit process-scope
  registry and catalog exact-set gate include all six.
- `internal/telemetry/testdata/signals.json` and
  `spec/signal-catalog.json` contain exactly six delivery metrics, owned only by
  `internal/telemetry`, with only the `signal` attribute. Isolated regeneration
  reproduced both files byte-for-byte.
- The reviewed telemetry slice does not alter liveness, readiness, collector
  availability, admin behavior, Grafana, or alerting.

## Verification receipts

- `go test -race ./internal/telemetry ./internal/signalcatalog -count=1` — PASS
- `go test -race ./internal/telemetry -run 'Test(DeliveryTracker|DeliveryMetric|Provider_.*Delivery|Provider_Stdout|ProviderProcessSelfObsScopeRegistry|ProviderReportDeliverySelfObs)' -count=20` — PASS
- `go vet ./internal/telemetry ./internal/signalcatalog` — PASS
- `golangci-lint run ./internal/telemetry/... ./internal/signalcatalog/...` — PASS, `0 issues`
- Focused signal-golden, process-scope, and catalog-staleness tests — PASS
- `git diff --check` — PASS
- Isolated telemetry signal/catalog regeneration — PASS, unchanged SHA-256:
  - `internal/telemetry/testdata/signals.json`: `e87980e2000b215ddb582445b626874f8a5e51436691a30b5cb51d53daa85364`
  - `spec/signal-catalog.json`: `bf74e8208c70edb492d2ddc37d116a96a58b6a0922d994fb0b6d77edf3910c06`

Concurrent admin, documentation, dashboard, and Grafana changes were excluded
from review as instructed.

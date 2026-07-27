# #268 telemetry core and self-observability report

Date: 2026-07-26

Worktree: `/tmp/graph2otel-268.4DDwyq`

Base HEAD: `066c8aa33710f007dc4295e0a87a78404515fc88`

## Delivered seam

- Added one concurrency-safe `deliveryTracker` shared by the metric and log
  exporter wrappers.
- Added exported immutable value snapshots:
  - `DeliverySnapshot{Metrics, Logs DeliverySignal}`
  - `DeliverySignal` fields: `State`, `ExportAttempts`, `ExportSuccesses`,
    `ExportFailures`, `ForceFlushFailures`, `ShutdownFailures`,
    `LastSuccessAt`, `LastFailureAt`, and `LastFailureCode`
  - states: `starting`, `healthy`, `degraded`
  - failure codes: `export_failed`, `force_flush_failed`, `shutdown_failed`
- Added `Provider.Delivery() DeliverySnapshot`.
- Preserved the public `NewProvider(context.Context, Options)` signature.
  The unexported `newProviderWithExporters` constructor supplies controlled
  SDK exporters to real reader/batch-processor tests without adding SDK types
  to public `Options`.
- Wrapped OTLP and stdout metric/log exporters before SDK reader/processor
  construction. Metric temporality and aggregation selectors delegate
  unchanged.
- Export, force-flush, and shutdown callbacks delegate exactly once and return
  the original error. State updates happen after the delegate returns.
- A successful export is the only recovery transition. Successful force-flush
  and shutdown callbacks do not clear degradation or create acceptance.
- Metrics and logs retain independent counters, states, timestamps, and failure
  codes. Both obey `export_attempts = export_successes + export_failures`.
- Timestamps are canonical UTC RFC3339Nano strings and are empty until
  observed.
- Tracker state retains no raw error, status, HTTP body, endpoint, authorization
  header, credential, or token. A bearer-secret regression fixture verifies
  this boundary.

## Process self-observability

`Provider.ReportSelfObs` now emits these process-scoped metrics through the
undecorated emitter after the existing cardinality/limiter report:

- `graph2otel.otlp.delivery.export_attempts`
- `graph2otel.otlp.delivery.export_successes`
- `graph2otel.otlp.delivery.export_failures`
- `graph2otel.otlp.delivery.force_flush_failures`
- `graph2otel.otlp.delivery.shutdown_failures`
- `graph2otel.otlp.delivery.degraded`

The five counters use `{operation}` and only `signal=metrics|logs`. Internal
delta accounting prevents repeated `ReportSelfObs` calls from adding the same
process-lifetime count again. The `degraded` metric is a complete two-row
observable gauge with unit `1` and only `signal`.

Signal fixture and catalog regeneration added exactly those six metrics. Every
catalog row is owned by `internal/telemetry` and has exactly one attribute key,
`signal`.

## TDD receipts

RED:

- `go test ./internal/telemetry -run 'Test(DeliveryTracker|Provider_.*Delivery|Provider_Stdout)' -count=1`
  failed to compile on the intentionally absent delivery tracker, wrapper,
  snapshot, and provider APIs.
- `go test ./internal/telemetry -run 'Test(ProviderProcessSelfObsScopeRegistry|ProviderReportDeliverySelfObs|SignalGolden).*' -count=1`
  failed because all six delivery metrics were absent.
- After the behavior became green, `TestSignalGolden` failed with a stale
  fixture whose diff contained exactly the six delivery metrics.
- A mutation that removed log force-flush failure recording made
  `TestDeliveryTrackerWrappedExporters` fail on state, counter, timestamp, and
  recovery expectations; restoring the implementation returned it to green.
- `TestSelfObservabilityScopeIsGeneratedAndProcessSetIsExact` failed on the
  generated six-metric process set before its exact-set allowlist was updated.

GREEN:

- `go test -race ./internal/telemetry -run 'Test(DeliveryTracker|DeliveryMetric|Provider_.*Delivery|Provider_Stdout|ProviderProcessSelfObsScopeRegistry|ProviderReportDeliverySelfObs|SignalGolden)' -count=1`
  passed.
- `go test -race ./internal/telemetry ./internal/signalcatalog -count=1`
  passed:
  - telemetry: `ok` in 1.648s
  - signalcatalog: `ok` in 10.620s
- `go vet ./internal/telemetry ./internal/signalcatalog` passed.
- `golangci-lint run ./internal/telemetry/... ./internal/signalcatalog/...`
  passed with `0 issues`.
- `scripts/regen-generated.sh signals` passed.
- `scripts/regen-generated.sh catalog` passed.
- `git diff --check` passed.

## Files owned and changed

- `internal/telemetry/delivery.go` (new)
- `internal/telemetry/delivery_test.go` (new)
- `internal/telemetry/provider.go`
- `internal/telemetry/provider_internal_test.go`
- `internal/telemetry/provider_test.go`
- `internal/telemetry/selfobs_scope.go`
- `internal/telemetry/selfobs_scope_test.go`
- `internal/telemetry/signalgate_test.go`
- `internal/telemetry/testdata/signals.json`
- `spec/signal-catalog.json`
- `internal/signalcatalog/signalcatalog_test.go` (explicitly added to this lane
  by the coordinating agent after its exact-set gate went RED)

## Adversarial review

- Metric failures never update log state and log callbacks never update metric
  state.
- Only successful `Export` clears current degradation.
- Successful `ForceFlush` and `Shutdown` preserve the prior state and counters.
- No tracked or emitted field can carry raw error text, HTTP status/body,
  endpoint, credential, token, authorization header, tenant, collector,
  transport, or failure code label.
- Self-observability uses the undecorated process emitter and does not pass
  through tenant or cardinality decorators.
- No admin, availability, liveness, readiness, Grafana, docs, command, or
  collector implementation was changed by this lane.
- No retry, byte, pricing, replay, durable-queue, exactly-once, or backend
  retention behavior was introduced.

## Integration state

The detached worktree is deliberately left uncommitted and unstaged. No GitHub
mutation, commit, push, branch creation, or worktree cleanup was performed.

Concurrent admin and Grafana-lane changes became visible in the shared
worktree during the final pass. They are not part of this lane and were not
edited or evaluated here.

No telemetry-lane blocker remains. The coordinating integration pass still
owns the repository-wide gate after the admin and Grafana/docs lanes finish.

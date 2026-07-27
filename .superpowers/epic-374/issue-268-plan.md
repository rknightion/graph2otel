# #268 OTLP Delivery Health Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Expose independent, bounded, queryable metric and log exporter delivery health without claiming durable queuing, exactly-once delivery, or backend retention.

**Architecture:** Wrap both SDK exporter interfaces at the provider boundary, where a callback is the first local evidence of acceptance. One concurrency-safe, process-wide tracker is the only source for local admin status and self-observability. Existing #231 structured SDK error logging remains the raw-error sink.

**Tech stack:** Go 1.24; OpenTelemetry metric SDK v1.44.0; log SDK v0.20.0; standard-library `testing`; generated signal catalog and Grafana builder.

## Binding decision receipt

The owner approved all recommended defaults on 2026-07-26. The exact #268 receipt is: **“Maintainer decision: use the recommended health boundary. OTLP delivery degradation is exposed in delivery status and telemetry, but transient backend failure does not fail dependency-free liveness or the #267 readiness latch.”**

This leaves `/healthz` dependency-free and #267's lifetime first-success `/readyz` latch unchanged. Delivery is process-wide: it is neither #292 collector availability nor #289 collector-attributed capacity/cost accounting.

## Frozen delivery contract

- `metrics` and `logs` are independent closed `signal` values; they never share counters, state, timestamps, or failure code.
- An export attempt is one call to the wrapped SDK `Export`. For each signal, `export_attempts = export_successes + export_failures`. A nil result means the exporter accepted the batch. For OTLP this is a successful exporter callback, not exactly-once, durable-queue, or post-ingest-retention proof; for stdout it is a successful local writer/exporter callback.
- Initial state is `starting`. Successful `Export` changes only that signal to `healthy`, increments `export_successes`, records `last_success_at`, clears `last_failure_code`, and clears degradation. Failed `Export` changes only that signal to `degraded`, increments `export_failures`, records `last_failure_at`, and retains only `export_failed`.
- Wrap `ForceFlush` and `Shutdown` too. Their errors increment only `force_flush_failures` or `shutdown_failures`, record respectively `force_flush_failed` or `shutdown_failed`, and mark that signal degraded. A later successful **Export** is recovery; a successful empty flush/shutdown cannot invent backend acceptance or erase a prior failed export. `Provider.Shutdown` still returns joined SDK errors to the existing structured shutdown warning.
- Timestamps are process-local UTC RFC3339Nano and absent until observed. Counters are process-lifetime monotonic. The tracked state never contains error text, HTTP body/status, endpoint, credentials, token, or authorization header.
- Failure codes are exactly `export_failed`, `force_flush_failed`, and `shutdown_failed`. Raw errors remain only in #231's existing structured `otelErrorHandler` path and the existing shutdown warning. Do not copy them into tracker state, JSON, HTML, OTLP attributes, docs examples, or Grafana legends.
- `Provider.ReportSelfObs` emits process-scoped metrics after the existing cardinality/limiter report, using the un-decorated emitter: `graph2otel.otlp.delivery.export_attempts`, `.export_successes`, `.export_failures`, `.force_flush_failures`, `.shutdown_failures` (counter, unit `{operation}`, only `signal=metrics|logs`) and `.degraded` (complete `1` gauge snapshot, only `signal`, 0 or 1). Do not stack attempt/success/failure counters.
- Do not use `tenant_id`, collector, `collector.transport`, `ingest_transport`, endpoint, retry, error text, or failure code as a metric label. Delivery self-observability supplements direct admin status and existing structured logs; no alert, readiness, or liveness rule is added in #268.

## Current state and conflicts

`main` is `f7339e805e40d2cc2b992a5ff4110c5995329fd6`: #267 readiness and #269 outcome accounting are present. The working tree currently holds staged #292 availability work in `internal/admin/**`, `docs/signals.md`, `grafana/boards/selfobs.py`, `grafana/tests/test_build_dashboard.py`, and `dashboards/graph2otel-self-observability.json`.

Land #292 first; do not edit, stage, or regenerate across its staged files. Then #268 owns only its delivery additions. It may consume #292's resulting admin shape but must not change availability enums/census/derivation, `collector.transport`, or availability panels.

| Owner | Exact tracked files | Boundary |
| --- | --- | --- |
| Telemetry core | Create `internal/telemetry/delivery.go`, `internal/telemetry/delivery_test.go`; modify `internal/telemetry/provider.go`, `internal/telemetry/provider_internal_test.go`, `internal/telemetry/provider_test.go`, `internal/telemetry/selfobs_scope.go`, `internal/telemetry/selfobs_scope_test.go`, `internal/telemetry/signalgate_test.go`, `internal/telemetry/testdata/signals.json` | tracker, wrappers, Provider seam, process metrics/capture |
| Admin | Modify `internal/admin/admin.go`, `internal/admin/status.go`, `internal/admin/admin_test.go`, `internal/admin/status_test.go`, `internal/admin/page.html.tmpl`, `internal/admin/render_test.go`; modify `cmd/graph2otel/main_test.go` only if the existing composition test needs real-provider coverage | optional source, sanitized JSON/UI; no readiness change |
| Generated operator surface | Modify `grafana/boards/selfobs.py`, `grafana/tests/test_build_dashboard.py`, generated `dashboards/graph2otel-self-observability.json`, `docs/signals.md`, generated `spec/signal-catalog.json` | process board, docs, catalog |

Shared seams: #289 later owns bytes/retries/collector attribution/pricing and will share provider/admin/Grafana files; #268 adds none of those fields and does not decide decorator ordering for it. #380 owns the broad docs reconciliation; #268 adds only the bounded `docs/signals.md` delivery section. These are sequential integrations, never parallel edits.

## Task 1: Tracker and complete exporter wrappers

**Files:** `internal/telemetry/delivery.go`, `internal/telemetry/delivery_test.go`, `internal/telemetry/provider.go`, `internal/telemetry/provider_internal_test.go`, `internal/telemetry/provider_test.go`.

**Interfaces:**

- Export immutable `DeliverySnapshot` with deterministically ordered `Metrics` and `Logs` `DeliverySignal` values containing state, five counters, timestamps, and bounded last failure code.
- Add unexported wrappers satisfying every method of `sdkmetric.Exporter` and `sdklog.Exporter`; delegate exactly once, update the tracker, and return the original error.
- Keep public `NewProvider(ctx, opts)`. Add an unexported constructor accepting injected metric/log exporters for real reader/batch-processor tests; do not expose test SDK types through public `Options`.

- [ ] Write table-driven RED tests for clean state; metric `Export` failure containing `Authorization: Bearer secret-value`; independent log success; metric export recovery; and failing `ForceFlush`/`Shutdown`. Assert metric/log isolation, no secret in `fmt.Sprint(snapshot)`, the conservation equation, recovery only on a later export success, and unchanged returned errors.
- [ ] Run `go test ./internal/telemetry -run 'TestDeliveryTracker|TestProvider_Delivery' -count=1`; expect compile/test failure because delivery types, trackers, and injected exporters do not exist.
- [ ] Implement closed signal/state/failure-code types, mutex-protected state, copied snapshots, and wrappers for metric `Export`/`ForceFlush`/`Shutdown` plus log `Export`/`ForceFlush`/`Shutdown`. Do not inspect error text, HTTP responses, source records, tenant metadata, or introduce retries.
- [ ] Wire concrete exporters through wrappers before `sdkmetric.NewPeriodicReader` and `sdklog.NewBatchProcessor`; retain the tracker on `Provider` and add `Delivery() DeliverySnapshot`. Use controlled fakes to prove callback behavior, then extend the stdout provider test to prove metric and log stdout callbacks independently become healthy.
- [ ] Verify with `go test -race ./internal/telemetry -run 'Test(DeliveryTracker|Provider_.*Delivery|Provider_Stdout)' -count=1`, `go test -race ./internal/telemetry -count=1`, and `go vet ./internal/telemetry`.

## Task 2: Bounded process self-observability

**Files:** `internal/telemetry/delivery.go`, `internal/telemetry/selfobs_scope.go`, `internal/telemetry/selfobs_scope_test.go`, `internal/telemetry/signalgate_test.go`, generated `internal/telemetry/testdata/signals.json`, generated `spec/signal-catalog.json`.

**Interfaces:** Consume Task 1's snapshot in `Provider.ReportSelfObs`; produce the six frozen metrics and no other attributes.

- [ ] Extend the process-scope registry test and signal-golden fixture with one metric failure and one log success. Assert the degraded gauge always contains both signal rows, each metric has only `signal`, and no captured attribute has tenant, collector/transport, raw error, or failure code.
- [ ] Run `go test ./internal/telemetry -run 'Test(ProviderProcessSelfObsScopeRegistry|SignalGolden).*' -count=1`; expect failure because the six metrics are absent from the scope registry/golden.
- [ ] Emit cumulative tracker counters and a full two-signal observable gauge after the existing cardinality/limiter report through the un-decorated provider emitter. Do not route through `WithTenant` or the limiter and do not emit a new OTLP log event.
- [ ] Regenerate with `scripts/regen-generated.sh signals` then `scripts/regen-generated.sh catalog`. Inspect `git diff -- internal/telemetry/testdata/signals.json spec/signal-catalog.json`: exactly six graph2otel metrics, only bounded `signal` attributes.
- [ ] Verify with `go test -race ./internal/telemetry ./internal/signalcatalog -count=1` and `git diff --check`.

## Task 3: Admin JSON/UI uses the same sanitized snapshot

**Files:** `internal/admin/admin.go`, `internal/admin/status.go`, `internal/admin/admin_test.go`, `internal/admin/status_test.go`, `internal/admin/page.html.tmpl`, `internal/admin/render_test.go`; `cmd/graph2otel/main_test.go` only if required for real composition coverage.

**Interfaces:** Preserve `admin.New`'s argument list. Type-assert an optional `DeliverySource` from the existing throughput-provider argument. Add top-level `delivery.metrics` and `delivery.logs` JSON rows with only frozen state, counters, optional timestamps, and bounded failure code.

- [ ] After #292 commits, write RED tests with one fake implementing existing throughput and `DeliverySource`. Assert `/api/status.json` shows degraded metrics and healthy logs independently and does not contain an injected bearer token. Render HTML and assert it calls throughput “emitted to SDK” and delivery “exporter accepted.” Assert `/healthz` remains 200 and `waiting_for_first_success` remains unchanged when delivery degrades.
- [ ] Run `go test ./internal/admin -run 'Test(HandleStatusJSON|Render|Healthz|Readyz).*Delivery' -count=1`; expect the missing projection/markup failure, never a changed readiness code.
- [ ] Add only an optional delivery source to `Server`, snapshot it per request, project typed fields directly, and conditionally render the overview block. Do not derive delivery from `StatusTracker`, #292 availability, record-outcome counters, or error text.
- [ ] Verify with `go test -race ./internal/admin -count=1`, `go test -race ./cmd/graph2otel -run 'Test(NewTelemetryProvider|Run_|.*Delivery)' -count=1`, and `git diff --check`.

## Task 4: Generated Grafana and operator documentation

**Files:** `grafana/boards/selfobs.py`, `grafana/tests/test_build_dashboard.py`, generated `dashboards/graph2otel-self-observability.json`, `docs/signals.md`.

**Interfaces:** Consume catalog names/process scope. Add a process-wide **OTLP delivery** row with a current degraded-state table plus unstacked per-signal export attempt/success/failure and flush/shutdown-failure panels. Every expression deliberately omits `$tenant` and `$collector`.

- [ ] Write RED tests asserting all six metrics are panelled; delivery queries lack tenant/collector selectors; export rates group only by `signal`; overlapping attempt/success/failure counters are unstacked; and no alert/recording rule is added. Add a docs assertion for “exporter accepted”, “not exactly-once”, “not backend retention”, stdout local-writer semantics, and admin/structured-log fallback.
- [ ] Run `cd grafana && python3 -m unittest tests.test_build_dashboard -q`; expect failure because the catalog metrics are unpanelled and no delivery row exists.
- [ ] Implement the process row outside tenant-scoped availability/outcome sections. In `docs/signals.md`, document frozen semantics, raw-error boundary, stdout behavior, and that #269 `record.outcomes.emitted` means handed to the emitter, not accepted by the backend. Do not make #380's broad doc edits.
- [ ] Run `make dashboard`, inspect only generated dashboard output, then run `make grafana-check`.

## Task 5: Integration gate and evidence

- [ ] Regenerate `scripts/regen-generated.sh signals`, `scripts/regen-generated.sh catalog`, and `make dashboard`; then run `go test -race ./...`, `go vet ./...`, `golangci-lint run`, `make grafana-check`, `make check`, `git diff --check`, and `git status --short`.
- [ ] Adversarially confirm: per-signal isolation; recovery only on export success; flush/shutdown cannot claim a payload was accepted; raw data cannot reach status/UI/metric labels; delivery panels are process-scoped; #267 health/readiness behavior is byte-for-byte unchanged; #292 remains an independent typed availability source; and no #289 bytes/retries/pricing/replay or #380 sweep leaks in.
- [ ] Update #268 with actual RED/GREEN/full-gate/generated-count receipts, commit one green conventional change with `Closes #268`, push to `main`, and record real post-push workflows. Do not claim live backend acceptance beyond exporter callbacks unless separately measured.

## Self-review

- The tasks cover all #268 acceptance criteria: independent exporter failure state, later-success recovery, UI distinction from emitted-to-SDK throughput, stdout/flush/shutdown definition, and explicit readiness non-interaction.
- Names, bounded values, test commands, regeneration commands, generated artifacts, shared ownership, and no-goals are fixed; there are no implementation placeholders.
- `DeliverySnapshot` is the single cross-surface source. The optional `DeliverySource` preserves #292's `admin.New` seam.

## Decision needed

**None.** The approved receipt fixes the only policy boundary; all remaining work is constrained implementation.

# Issue #268 final integrated review

Date: 2026-07-26

Worktree: `/tmp/graph2otel-268.4DDwyq`

Base: `066c8aa33710f007dc4295e0a87a78404515fc88`

## Verdict

READY

No severity findings. The integrated telemetry, admin, documentation, Grafana, and
generated-artifact diff satisfies issue #268, its maintainer decision, and the frozen
delivery contract.

## Acceptance and contract review

### Export callback truth, isolation, and recovery

- `DeliverySnapshot` has fixed `Metrics` and `Logs` value fields, each with independent
  state, counters, timestamps, and bounded failure code
  (`internal/telemetry/delivery.go:13-64`).
- Metric and log `Export`, `ForceFlush`, and `Shutdown` wrappers delegate once, update only
  their own signal after the callback returns, and return the original error
  (`internal/telemetry/delivery.go:232-300`).
- Export attempts conserve exactly because every export increments attempts and then
  exactly one of successes or failures. Only a successful export clears degradation and
  the last failure code; successful flush/shutdown callbacks do not change state
  (`internal/telemetry/delivery.go:198-225`).
- Provider construction wraps both production exporters before attaching them to the
  periodic reader and batch processor, while preserving the public `NewProvider` seam
  (`internal/telemetry/provider.go:183-249`).
- Stdout metrics and logs cross the same independent wrapper boundary, so success means a
  successful local writer/exporter callback. The real-provider stdout regression covers
  both signals (`internal/telemetry/provider_test.go:14-47`).
- `Provider.Shutdown` still joins metric and log SDK errors
  (`internal/telemetry/provider.go:326-329`). Raw export errors still reach the unchanged
  structured OTel error handler, and raw shutdown errors still reach the unchanged
  structured warning (`cmd/graph2otel/main.go:30-35`, `cmd/graph2otel/main.go:190-195`).

### Sanitized admin JSON and UI

- Admin consumes the same `DeliverySnapshot` through an optional `DeliverySource`, without
  changing `admin.New`'s argument list (`internal/admin/status.go:59-109`,
  `internal/admin/admin.go:98-123`).
- The JSON projection contains only the frozen state, five counters, optional timestamps,
  and bounded failure code. It has no raw error, endpoint, status/body, credential, token,
  authorization header, tenant, collector, or transport field
  (`internal/admin/status.go:67-109`).
- The live snapshot derives health and readiness from tenant state before independently
  attaching delivery (`internal/admin/admin.go:188-220`).
- The page names emitter throughput `Emitted to SDK` and the separate callback evidence
  `Exporter accepted`, with independent metrics/logs cards, all counters, both timestamps,
  and bounded failure code (`internal/admin/page.html.tmpl:164-196`). Poll refresh updates
  the same bounded fields (`internal/admin/page.html.tmpl:572-586`).

### Liveness and readiness

- The maintainer decision is preserved. `/healthz` remains dependency-free and `/readyz`
  still reads only the lifetime collector-success latch
  (`internal/admin/handlers.go:9-29`).
- `deriveHealth` and `deriveReadiness` have no delivery input
  (`internal/admin/status.go:859-975`), and those implementations are unchanged from the
  base.
- The regression covers both a previously successful tenant remaining ready and a tenant
  still waiting for its first collector success under degraded delivery
  (`internal/admin/admin_test.go:311-365`).

### Exactly six bounded process metrics

- `Provider.ReportSelfObs` uses the undecorated process emitter and appends the delivery
  report after the existing cardinality report (`internal/telemetry/provider.go:294-313`).
- The only delivery instruments are the five frozen `{operation}` counters and the complete
  two-row `1` degraded gauge. Every point has only `signal=metrics|logs`
  (`internal/telemetry/delivery.go:82-171`).
- Delta-to-SDK accounting prevents repeated self-observability reports from adding the same
  process-lifetime callback count twice (`internal/telemetry/delivery.go:82-117`).
- Base comparison shows exactly these six additions and no removals in both the telemetry
  signal golden and aggregate catalog
  (`internal/telemetry/testdata/signals.json:15-67`,
  `spec/signal-catalog.json:2139-2228`).
- Every catalog row is process-scoped, owned only by `internal/telemetry`, and has exactly
  one attribute key, `signal`.

### Grafana, docs, and no alert

- The dashboard reads all six normalized Prometheus names from the generated catalog and
  places them in a process-wide OTLP delivery row
  (`grafana/boards/selfobs.py:90-158`).
- All delivery expressions group only by `signal`; none contains `$tenant`, `tenant_id`,
  `$collector`, or `collector`. Attempt, success, and failure rates are deliberately
  unstacked.
- The generated dashboard contains the degraded state, three callback rates, force-flush
  failure rate, and shutdown failure total with the same normalized names
  (`dashboards/graph2otel-self-observability.json`).
- Documentation defines exporter callback acceptance, stdout local-writer behavior,
  no exactly-once/durable-queue/backend-retention claim, the metrics-export observability
  gap, admin local truth, structured raw-error fallback, and the distinction from
  `record.outcomes{outcome="emitted"}` (`docs/signals.md:540-585`).
- Alerts, recording rules, `grafana/build_rules.py`, health handlers, and composition-root
  wiring are byte-for-byte unchanged from the base. The structural test also rejects any
  delivery metric in alert or recording-rule definitions
  (`grafana/tests/test_build_dashboard.py:199-290`).

## Fresh verification receipts

```text
go test -race ./internal/telemetry ./internal/signalcatalog ./internal/admin -count=1
PASS

go test -race ./cmd/graph2otel -run 'Test(NewTelemetryProvider|Run_|.*Delivery)' -count=1
PASS

go vet ./internal/telemetry ./internal/signalcatalog ./internal/admin ./cmd/graph2otel
PASS

golangci-lint run ./internal/telemetry/... ./internal/signalcatalog/... ./internal/admin/... ./cmd/graph2otel/...
0 issues.
```

The first focused lint attempt met golangci-lint's existing runner lock while another
integration gate was active. It was not interrupted; the focused command was rerun after
the lock cleared and passed with `0 issues`.

```text
go test -race ./internal/telemetry \
  -run 'Test(DeliveryTracker|DeliveryMetric|Provider_.*Delivery|Provider_Stdout|ProviderProcessSelfObsScopeRegistry|ProviderReportDeliverySelfObs)' \
  -count=10
PASS

go test -race ./internal/admin \
  -run 'Test(HandleStatusJSON_.*Delivery|DeliveryDegradation|Render_Delivery)' \
  -count=10
PASS

make grafana-check
coverage: 325/325 catalog metrics on a panel
rules: 14 alert rules (7 enabled, 7 paused), 2 recording rules
Ran 60 tests
OK

git diff --check
PASS
```

Generated idempotence was checked in an isolated temporary copy so the review did not rely
on a dirty-tree comparison. `scripts/regen-generated.sh signals`,
`scripts/regen-generated.sh catalog`, and `make dashboard` reproduced every signal golden,
the aggregate catalog, and all dashboards byte-for-byte:

```text
before=f7cd43ad9fdd82f0044858d17f58cc51b942416e8ebc6e4837965c9449628cc8
after=f7cd43ad9fdd82f0044858d17f58cc51b942416e8ebc6e4837965c9449628cc8
```

The final worktree status contains only the intended tracked paths plus the two intended
new files, `internal/telemetry/delivery.go` and
`internal/telemetry/delivery_test.go`. Nothing was staged, committed, pushed, or written to
GitHub during this review.

## Findings

None.

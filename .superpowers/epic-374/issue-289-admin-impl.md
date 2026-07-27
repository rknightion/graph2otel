# Issue #289 admin implementation report

## Outcome

Implemented the bounded admin JSON/UI lane in
`/tmp/graph2otel-289.Y9NQNW`.

- `admin.New` retains its existing argument list and type-asserts the existing
  telemetry provider argument to the optional `CapacitySource`:
  - `Volume() []telemetry.VolumeRow`
  - `Transport() telemetry.OTLPTransportSnapshot`
- `/api/status.json` conditionally exposes exact cumulative:
  - source records, metric points, and log points by bounded attribution;
  - process metric/log post-compression payload bytes and exporter retries.
- Opt-in cost output is explicitly observational. It includes operator price
  metadata and two machine-readable scope fields:
  - `interval_scope: all_observed_traffic`
  - `projection_scope: recurring_steady_state_only`
- Cost rows preserve both signal-specific estimated allocations
  (`allocated_metric_payload_bytes`, `allocated_log_payload_bytes`) and the
  existing summed `allocated_payload_bytes`.
- The dedicated cost history remains separate from the 10-second runtime
  trend sampler:
  - it waits at least 120 seconds before producing a projection;
  - sub-threshold observations do not advance or discard the baseline;
  - it projects over actual elapsed history, capped at the existing 10-minute
    horizon;
  - invalid/non-forward samples and post-gap immature baselines retain the last
    mature projection.
- Interval cost includes all observed traffic. Recurring projected totals and
  the budget ratio include steady-state traffic only. Cold-start/backfill rows
  therefore retain their interval cost and show a recurring projection of
  zero.
- The Overview page labels the distinction directly and renders both
  `Observed interval cost` and `Recurring projected` columns. Exceptional rows
  are not presented as free.
- There is no scheduler, limiter, exporter, or enforcement callback. Fake
  sources with an `EnforceBudget` method remain at zero calls in tests.
- The admin projection has no fields for raw payloads, endpoints, exporter
  errors, tokens, or secrets.

## Files changed

- `internal/admin/admin.go`
- `internal/admin/status.go`
- `internal/admin/sampler.go`
- `internal/admin/page.html.tmpl`
- `internal/admin/admin_test.go`
- `internal/admin/sampler_test.go`
- `internal/admin/render_test.go`

No telemetry, config, cmd, docs, generated artifact, staging, commit, push, or
GitHub write was performed by this lane.

## TDD receipts

Initial capacity/admin RED:

```text
go test ./internal/admin -run 'Test.*(Capacity|Cost|Volume)' -count=1

internal/admin/render_test.go:550:3: unknown field Capacity in struct literal of type Status
internal/admin/render_test.go:550:14: undefined: CapacityStatus
internal/admin/render_test.go:551:14: undefined: CapacityVolumeRow
internal/admin/render_test.go:560:15: undefined: CapacityTransportStatus
internal/admin/render_test.go:561:14: undefined: CapacityTransportSignalStatus
internal/admin/render_test.go:570:11: undefined: CostStatus
internal/admin/render_test.go:580:13: undefined: CostRowStatus
FAIL
```

Corrected rolling/scoped-cost RED:

```text
go test ./internal/admin -run 'Test.*(Cost|Capacity)' -count=1

internal/admin/render_test.go:581:5: unknown field IntervalScope in struct literal of type CostStatus
internal/admin/render_test.go:582:5: unknown field ProjectionScope in struct literal of type CostStatus
internal/admin/sampler_test.go:226:9: got.ProjectionScope undefined (type *CostStatus has no field or method ProjectionScope)
internal/admin/sampler_test.go:227:7: got.IntervalScope undefined (type *CostStatus has no field or method IntervalScope)
FAIL
```

Corrected focused GREEN:

```text
go test ./internal/admin -run 'Test.*(Cost|Capacity)' -count=1
ok github.com/rknightion/graph2otel/internal/admin 0.501s
```

Tests cover the 119-second no-projection boundary, the first mature
120-second projection, retained rolling baselines, the 10-minute horizon,
non-forward and post-gap immature samples, exceptional interval cost with zero
recurring projection, recurring-only budget ratio, JSON signal-allocation
fields, disabled pricing, UI wording, and the absence of enforcement calls.

## Final verification

```text
go test -race ./internal/admin -count=1
ok github.com/rknightion/graph2otel/internal/admin 1.601s

go vet ./internal/admin
exit 0

golangci-lint run ./internal/admin/...
0 issues.

git diff --check -- internal/admin
exit 0
```

The JSON test also scans for and rejects an injected bearer token, raw entity
payload, and private OTLP endpoint. Pricing-disabled tests verify `cost` is
absent/null in JSON and the pricing block is absent from HTML while exact
capacity remains visible.

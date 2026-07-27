# Issue #268 admin integration report

## Outcome

Implemented the admin/status lane against the frozen
`telemetry.DeliverySnapshot` seam in `/tmp/graph2otel-268.4DDwyq`.

- `admin.New` keeps its existing argument list. The existing
  `ThroughputSource` argument is type-asserted to the optional `DeliverySource`;
  callers that provide only throughput retain the prior behavior.
- `/api/status.json` conditionally includes top-level `delivery.metrics` and
  `delivery.logs` objects. Each row contains only the frozen state, five
  counters, optional timestamps, and bounded last failure code.
- The Overview page now distinguishes `Emitted to SDK` from `Exporter accepted`
  and renders metric/log delivery independently, including both last-success
  and last-failure timestamps.
- The polling refresh updates delivery cards from the same status JSON snapshot.
- Delivery state is not passed into `deriveHealth` or `deriveReadiness`.
  Degraded delivery leaves dependency-free `/healthz` and the #267 readiness
  latch unchanged.

## Files owned and changed

- `internal/admin/admin.go`
- `internal/admin/status.go`
- `internal/admin/admin_test.go`
- `internal/admin/page.html.tmpl`
- `internal/admin/render_test.go`

No telemetry, cmd, Grafana, docs, generated artifact, staging, commit, push, or
GitHub write was performed by this lane.

## TDD receipts

Initial RED:

```text
go test ./internal/admin -run 'Test(HandleStatusJSON|Render|Healthz|Readyz|Delivery).*Delivery' -count=1

internal/admin/render_test.go:496:3: unknown field Delivery in struct literal of type Status
internal/admin/render_test.go:496:14: undefined: DeliveryStatus
internal/admin/render_test.go:497:13: undefined: DeliverySignalStatus
internal/admin/render_test.go:508:10: undefined: DeliverySignalStatus
FAIL
```

Initial GREEN after the bounded projection and render block:

```text
go test ./internal/admin -run 'Test(HandleStatusJSON|Render|Healthz|Readyz|Delivery).*Delivery' -count=1
ok github.com/rknightion/graph2otel/internal/admin
```

Adversarial timestamp RED:

```text
go test ./internal/admin -run '^TestRender_DeliveryDistinguishesSDKHandoffFromExporterAcceptance$' -count=1

delivery status page missing "2026-07-26T10:00:00.123456789Z"
FAIL
```

This caught the first card shape hiding a recovered signal's
`last_success_at` whenever a historical `last_failure_at` existed. The page was
changed to render both timestamps independently.

Timestamp and readiness GREEN:

```text
go test ./internal/admin -run '^TestRender_DeliveryDistinguishesSDKHandoffFromExporterAcceptance$' -count=1
ok github.com/rknightion/graph2otel/internal/admin

go test ./internal/admin -run '^TestDeliveryDegradation_DoesNotChangeHealthzOrReadyz$' -count=1
ok github.com/rknightion/graph2otel/internal/admin
```

The readiness regression covers both:

- a tenant with a lifetime collector success: `/healthz` 200 and `/readyz` 200
  while metric delivery is degraded;
- a working tenant awaiting its first collector success: `/readyz` remains 503
  with `waiting_for_first_success`, rather than delivery changing the latch.

## Final verification

```text
go test -race ./internal/admin -count=1
ok github.com/rknightion/graph2otel/internal/admin

go test -race ./cmd/graph2otel -run 'Test(NewTelemetryProvider|Run_|.*Delivery)' -count=1
ok github.com/rknightion/graph2otel/cmd/graph2otel

go vet ./internal/admin
exit 0

golangci-lint run ./internal/admin/...
0 issues.

git diff --check
exit 0
```

The JSON regression also verifies independent degraded-metrics/healthy-logs
state, every frozen counter and timestamp, bounded failure code, and absence of
an injected `Authorization: Bearer delivery-secret` string.

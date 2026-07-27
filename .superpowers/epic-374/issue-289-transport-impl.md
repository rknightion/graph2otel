# Issue #289 transport implementation handoff

## Result

Implemented the exact cumulative OTLP transport seam in
`/tmp/graph2otel-289.Y9NQNW` without committing:

- `OTLPTransportSnapshot` keeps independent `Metrics` and `Logs` totals, each
  with `PayloadBytes` and `RetryAttempts`.
- Every SDK export callback gets its own attempt ordinal. Only the second and
  later exporter retry-loop invocations increment `RetryAttempts`.
- gRPC uses a chained unary interceptor for attempts and public
  `stats.OutPayload.CompressedLength` for post-compression payload bytes.
- HTTP uses pinned local exporter replacements with a narrow
  `WithRequestObserver` option. It does not use `WithHTTPClient`, so exporter
  TLS, mTLS, proxy, timeout, headers, compression, and environment handling stay
  intact.
- HTTP wraps both `Request.Body` and `Request.GetBody`. Every exporter retry
  rebuilds both wrappers from unwrapped factories using the current attempt
  context, preventing stale context and nested/double-counted wrappers.
- Existing `DeliverySnapshot` meaning is unchanged: one delivery attempt per
  SDK exporter callback, independent of internal transport retries.

## TDD receipts

- Core tracker first failed to compile because the transport types did not
  exist, then passed under `-race`.
- Provider wrapper first failed because `Provider.Transport` did not exist,
  then passed while asserting #268 delivery callback counts remained one.
- Provider gRPC integration first returned zero bytes for both signals; moving
  tracker creation ahead of exporter construction and adding both dial hooks
  made it pass.
- Both fork observer suites first failed on undefined `WithRequestObserver`.
- Provider HTTP integration then reached the real server but returned zero
  tracked bytes (`metrics=495`, `logs=481` observed by the server); installing
  both observer options made it pass.
- The fork integration tests exercise `307 -> 503 -> exporter retry -> 307 ->
  200` under gzip. They reconcile all four actually read bodies and count two
  retry-loop invocations, proving redirect replay and retry reset behavior.
- A partial-read metric test proves payload accounting uses bytes consumed by
  the transport, not the intended encoded buffer size.

## Local fork and release gates

- Root replacements pin metric HTTP at `v1.44.0` and log HTTP at `v0.20.0`.
- `third_party/otel-http-forks.tsv` records exact module/version, Apache-2.0,
  immutable upstream commit URLs, local directories, and the complete modified
  file allowlist.
- `third_party/check-otel-http-forks.sh` verifies root version/replace parity,
  exact upstream equality outside the allowlist, an unchanged upstream LICENSE,
  and a prominent modification notice in every changed Go file.
- The fork gate removes inherited `OTEL_EXPORTER_OTLP*` and proxy variable names
  without printing values, then runs both full nested module `vet` and
  `test -race` suites.
- `make tidy-check` and `make tidy` now cover both nested modules.
- `scripts/notices.sh` remaps the two local replacements through the same
  manifest, restoring exact versions and upstream URLs while retaining the
  Apache-2.0 license text.

## Fresh verification

Passed:

```text
bash -n third_party/check-otel-http-forks.sh scripts/notices.sh
bash third_party/check-otel-http-forks.sh check
make tidy-check
focused transport/provider integration suite under go test -race
make notices
git diff --check over every owned path
```

`make notices` produced 63 module entries, including:

```text
go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp (v0.20.0)
go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp (v1.44.0)
```

Both are Apache-2.0 with immutable upstream source URLs; the output contains no
`UNKNOWN`.

The whole `go test -race ./internal/telemetry` package gate is temporarily
blocked by the concurrent cost lane's unfinished `CostRow` payload allocation
fields/helpers in `cost_test.go`. No transport-owned failure remains.

## Owned files

```text
Makefile
go.mod
go.sum
internal/telemetry/otlptransport.go
internal/telemetry/otlptransport_test.go
internal/telemetry/provider.go
scripts/notices.sh
third_party/check-otel-http-forks.sh
third_party/otel-http-forks.tsv
third_party/otlpmetrichttp/**
third_party/otlploghttp/**
```

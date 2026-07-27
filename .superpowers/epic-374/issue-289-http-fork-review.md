# Issue #289 HTTP exporter fork review

## Verdict

**READY.** No remaining blocking or non-blocking findings in the final reviewed
fork, replacement wiring, provenance gate, license handling, or HTTP behavior.

The local replacements are a maintainable short-term way to expose the one
missing observer seam without taking ownership of the exporters' HTTP clients.
The implementation is deliberately fail-closed on dependency updates: Renovate
can still detect the versioned root `require` directives, while `make check`
fails until the local source and provenance manifest are refreshed together.

## Design and behavior

- Root `go.mod:5-7` replaces only the two pinned HTTP exporter modules and
  retains versioned requirements at `go.mod:26-28`. No gRPC module is forked.
- The graph2otel composition root installs only `WithRequestObserver` for HTTP
  (`internal/telemetry/provider.go:461-472`, `506-517`). It does not call
  `WithHTTPClient`, replace a `RoundTripper`, or reconstruct exporter config.
- Both forks invoke `Attempt` inside the existing exporter retry closure,
  immediately before reset and `http.Client.Do`
  (`third_party/otlpmetrichttp/client.go:179-192`,
  `third_party/otlploghttp/client.go:191-204`). Redirects therefore do not
  become exporter retry attempts.
- Both forks count successful body reads rather than intended buffer length.
  They rebuild `Body` and `GetBody` from unwrapped sources on every exporter
  attempt (`third_party/otlpmetrichttp/client.go:337-384`,
  `third_party/otlploghttp/client.go:347-394`). This counts 307/308 and
  transparent replay bodies without stale contexts, nested wrappers, or double
  counting across exporter retries.
- The observer option is additive and nil-safe. Endpoint, headers,
  compression, proxy, TLS/mTLS, timeout, retry policy, Retry-After handling,
  user agent, `ContentLength`, and the exporter-owned HTTP client construction
  remain upstream code.
- Real tests cover gzip plus 307 replay, a 503 exporter retry, and equality to
  server-observed bytes for both signals
  (`third_party/otlpmetrichttp/request_observer_test.go:37-110`,
  `third_party/otlploghttp/request_observer_test.go:37-110`). The metric fork
  additionally proves a partially consumed body contributes only the three
  bytes read (`third_party/otlpmetrichttp/request_observer_test.go:112-146`).
  The provider integration test proves both real HTTP exporters install the
  hook and reconcile to receiver body bytes
  (`internal/telemetry/otlptransport_test.go:228-279`).

## Maintainability and Renovate

- `third_party/otel-http-forks.tsv:1-3` is the single provenance manifest:
  exact module versions, Apache-2.0, immutable upstream commit URLs, local
  paths, and the complete modified-file allowlist.
- `third_party/check-otel-http-forks.sh:41-84` verifies root
  version/replacement parity, downloads the exact immutable upstream modules,
  compares LICENSE byte-for-byte, requires a modification notice in every
  changed Go file, and rejects any source difference outside the allowlist.
- `third_party/check-otel-http-forks.sh:19-30` removes inherited OTLP/proxy
  variables by name without printing values, so the copied upstream config
  tests are hermetic in operator shells. Lines 86-91 run full nested-module vet
  and race suites under `-mod=readonly`.
- `Makefile:68-96` puts nested-module tidy, provenance, vet, and race checks in
  the normal green bar and includes both modules in `make tidy`.
- Renovate's gomod parser treats local `replace` targets as local dependencies
  but parses versioned `require` directives independently. The existing
  OpenTelemetry group at `renovate.json:5-10` therefore still opens a grouped
  update. Because Renovate does not update the TSV provenance manifest, the
  root-version parity check intentionally turns that PR red until the fork is
  refreshed and reviewed. It cannot silently bump metadata while shipping old
  exporter code.

## License and release notices

- Both local LICENSE files are byte-identical to their exact upstream module
  LICENSE. The pinned upstream modules contain no NOTICE file.
- Every modified upstream Go file carries a prominent graph2otel modification
  notice, satisfying the Apache-2.0 section 4(b) condition while preserving the
  upstream copyright and SPDX headers.
- `scripts/notices.sh:50-69` corrects the known `go-licenses` behavior for local
  replacements: it remaps only the two declared modules back to the manifest's
  exact version/source while retaining the locally detected Apache license
  path and verbatim text.
- A read-only reproduction of the remap produced:
  - `otlploghttp v0.20.0`, `Apache-2.0`, pinned commit URL, local LICENSE.
  - `otlpmetrichttp v1.44.0`, `Apache-2.0`, pinned commit URL, local LICENSE.
  Neither row contained `UNKNOWN`.

## Verification receipts

- `bash third_party/check-otel-http-forks.sh check` — PASS, both complete
  nested suites under `-race`, plus provenance/drift/license verification.
- `go test -race ./internal/telemetry -run
  'Test(ProviderHTTPTransportHooksBothSignals|OTLPTransport|ProviderGRPCTransportHooksBothSignals|GRPC)'`
  — PASS.
- `go mod tidy -diff` — PASS in root, `third_party/otlpmetrichttp`, and
  `third_party/otlploghttp`.
- `git diff --check` — PASS.
- Context7 current Renovate gomod documentation/source was checked for local
  replacement and independent `require` parsing behavior.

This review made no source, index, commit, push, or GitHub changes.

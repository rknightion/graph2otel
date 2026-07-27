# Plan

Make `exclude_self` compare event `appId` only with the application identity proved by the Graph access token returned from the tenant-pinned `DefaultAzureCredential`. This corrects the present contradiction—`TenantAuth` ignores `tenants[].client_id`, while the composition root currently trusts that value (then `AZURE_CLIENT_ID`) to filter data—without changing credential selection, collector transport semantics, or permissions.

## Scope

- In: #266 only: authenticated application-ID extraction, one bounded startup resolution per opted-in tenant, fail-open self-exclusion behaviour, the affected tests, and operator documentation that currently says configuration selects an app identity.
- Out: credential-chain redesign or per-tenant secret storage; app registration, consent, scope, diagnostic-setting, or data-generation mutation; new telemetry/admin signals; permission-preflight redesign; logpipeline page-streaming; docs-site-wide reconciliation.

## Binding decision receipt

> Maintainer decision: use the recommended authenticated-identity policy. The authenticated application identity is authoritative. If it cannot be proven, disable `exclude_self` with a loud bounded diagnostic; configured `client_id` alone is not proof.

The implementation decision needed to make that receipt executable is: a successful Graph access token is the proof source; decode its unverified JWT payload exactly as the existing preflight adapter already does, require a non-empty string `appid`, and use that value as the sole comparison value. The token is obtained from graph2otel's own tenant-pinned credential over TLS, not supplied by an untrusted caller; it is inspected, never logged, stored, or used to authenticate anything. A configured `client_id` is retained as an optional non-secret consistency assertion only: a mismatch emits one structured warning and does not change the authoritative ID or fail the tenant. This is a safe non-fatal configuration discrepancy, so no maintainer choice remains.

## Identity and failure contract

- Resolve only when that tenant has `exclude_self: true`, once during its startup wiring, before either WindowDeps or BlobDeps is constructed. Reuse the resolved pair for both paths; do not independently resolve or warn in `registerBlobCollectors`.
- Request the existing `auth.GraphDefaultScope`; parse only a three-segment JWT payload and require `appid` to be a non-empty string. The value is the actual application/client ID for client-secret, certificate, workload-identity, and managed-identity credentials alike. Do not infer identity from `tenants[].client_id`, `AZURE_CLIENT_ID`, credential type, or a per-tenant environment convention.
- If token acquisition, JWT decoding, or the `appid` claim fails, set `ExcludeSelf=false` and the comparison ID empty for that tenant. Continue normal tenant startup and retain every record; emit exactly one startup WARN with the tenant and a bounded reason code (`token_request_failed`, `malformed_token`, or `missing_appid`), never a token or raw token payload.
- If a configured `client_id` disagrees with the proved `appid`, WARN once with the tenant and the two non-secret identifiers, then filter only `appid`. A third-party record matching the configured-but-wrong ID must pass; a record matching the proved ID may be excluded. If `exclude_self` is false, no identity token request or mismatch diagnostic occurs.
- Existing filter invariants remain: only collectors providing `SelfAppID` filter, all other records pass, excluded blob records still advance byte cursors, excluded Graph records stay `filtered` outcomes, and the existing `graph2otel.{blob,logpipeline}.self_excluded` counters remain the only per-record drop telemetry.

## Action items

- [ ] **RED — add auth proof tests in `internal/auth/auth_test.go`.** Extend the local fake token credential to return handcrafted, unsigned JWT payloads and first prove the missing API: a valid Graph token yields its `appid`; malformed JWT, absent/empty/non-string `appid`, and `GetToken` error return a tenant-contextual error; no configured or environment client ID can alter the returned proof. Run `go test ./internal/auth -run 'TestAuthenticatedApplicationID'` and observe compilation/failure before implementation.
- [ ] **Implement the small auth seam in `internal/auth/auth.go`.** Add `TenantAuth.AuthenticatedApplicationID(context.Context) (string, error)` (or equivalently named, documented public-to-internal method) that obtains the existing Graph-scope token and locally decodes the payload. Keep `NewTenantAuth` and `BuildAll` lazy and signature-stable; do not add a Graph SDK call, a new dependency, a cache, or a second credential chain. Keep the preflight role decoder separate unless a zero-risk shared private decoder can be extracted without an import cycle; #266 must not change preflight behaviour.
- [ ] **RED — replace the stale resolver contract in `cmd/graph2otel/tenants_selfid_test.go`.** With an injected `TenantAuth` fake token, specify: proved ID wins over a mismatched configured ID and the old `AZURE_CLIENT_ID` fallback; unprovable identity disables filtering and produces one bounded warning; `exclude_self: false` does not request a token; and the chosen ID would retain a record matching only the stale configured value while excluding one matching the proved identity. Run `go test ./cmd/graph2otel -run 'Test.*Self.*Identity|Test.*ExcludeSelf'` and observe the expected RED result.
- [ ] **Wire the contract once in `cmd/graph2otel/tenants.go`.** Replace `tenantExcludeSelf(cfg, tenantID)` with a context-aware resolver over the already-built `TenantAuth`; represent its resolved enabled/ID result once in `setupTenant`, pass it to WindowDeps and into `registerBlobCollectors`, and delete all `os.Getenv("AZURE_CLIENT_ID")` authority. Preserve the existing per-tenant partial-startup policy: identity proof failure is a warning plus no filtering, not a process failure or an availability/startup-failure state. Update the BlobDeps/WindowDeps and pipeline comments only where they still call the value a configured client ID.
- [ ] **Keep the existing engine behaviour covered, not redesigned.** Run targeted self-filter suites after the composition wiring: `go test ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/graphactivity ./internal/collectors/entra/signins`. Amend tests only if a renamed/documented dependency field requires compilation updates; do not alter filter predicates, counters, checkpoints, record outcomes, or collector registration.
- [ ] **Correct #266-owned operator wording.** Update `internal/config/config.go`, `config.example.yaml`, `README.md`, `docs/configuration.md`, `docs/getting-started.md`, and `docs/blob-ingest.md` so `tenant_id` pins the directory, ambient DefaultAzureCredential selects one application identity per process, a YAML `client_id` cannot select/override that identity, and `exclude_self` proves `appid` from the actual Graph token. Remove the README instruction to repeat credential environment variables per tenant. State the fail-open, one-warning behaviour and keep secrets out of YAML. If `charts/graph2otel/values.yaml` annotations change, regenerate only `charts/graph2otel/README.md` with `make helm-docs`; do not hand-edit generated Helm documentation.
- [ ] **Validate documentation and compile surfaces.** Run `make regen` if the config-example edit changes generated env reference output, `make helm-docs` if chart annotations change, and inspect the resulting diffs for only #266 statements. Run `go test ./internal/auth ./cmd/graph2otel ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/graphactivity ./internal/collectors/entra/signins`, then `make check`; if Helm files changed also run `go test ./charts/graph2otel`, `helm lint charts/graph2otel`, and `helm template t charts/graph2otel > /dev/null`.
- [ ] **Take the bounded live receipt only after local gates are green.** As `graph2otel-poller`, request one ordinary Graph access token for the already-enabled `https://graph.microsoft.com/.default` audience and inspect only whether it has a non-empty `appid` matching the known poller application. This is a read-only token acquisition, not a Graph REST probe: it requires no new app role, licence, tenant setting, diagnostic setting, or emitted synthetic data, and makes no tenant mutation. Do not log or save the token. If the deployed identity cannot be accessed safely, record that the local contract is fully tested and leave no live mutation request outstanding.

## Exact file ownership

| Owner | Files | Notes |
| --- | --- | --- |
| Auth proof | `internal/auth/auth.go`, `internal/auth/auth_test.go` | Token-derived `appid` only; no `azidentity` upgrade or new dependency. |
| Composition and TDD | `cmd/graph2otel/tenants.go`, `cmd/graph2otel/tenants_selfid_test.go` | Sole owner of once-per-tenant resolution, warnings, and wiring to both transports. |
| Auth/config/docs | `internal/config/config.go`, `config.example.yaml`, `README.md`, `docs/configuration.md`, `docs/getting-started.md`, `docs/blob-ingest.md` | Correct the user-facing authority model; no new config key. |
| Conditional chart generation | `charts/graph2otel/values.yaml`, `charts/graph2otel/README.md` | Touch only if the existing misleading annotation is corrected; README is generated. |

Do not take ownership of `internal/preflight/*`, `internal/{blobpipeline,logpipeline}/*`, `internal/collectors/*`, admin/availability files, telemetry signal catalogues, dashboard/rule files, generated collector/env catalogues unless compilation or the explicit `make regen` output proves a direct change. Their present self-filter tests are regression gates, not #266 implementation targets.

## Shared seams and conflict avoidance

| Issue | Shared boundary | #266 rule |
| --- | --- | --- |
| #265 config strictness | `TenantConfig`, YAML/env validation and config docs | Do not add/rename a config key or alter unknown-key handling; preserve `client_id` compatibility as a non-authoritative assertion. Coordinate only if #265 changes the same config comments/docs. |
| #268 delivery health | startup diagnostics and self-observability | Use bounded `slog` warnings only. Add no exporter delivery state, metric, admin status, readiness, or liveness behaviour. |
| #289 capacity attribution | record outcomes and any new self-observability dimensions | Retain existing `self_excluded` counters and `filtered` outcome semantics; add no bytes/retries/cost accounting or labels. |
| #291 logpipeline streaming | `internal/logpipeline` self-filter predicate and checkpoint semantics | Do not modify the predicate, buffering/streaming path, emission timing, or checkpoint handling; provide the resolved ID only through the existing dependency seam. |
| #380 docs reconciliation | README, configuration, getting-started, blob-ingest, Helm docs | #266 owns only auth identity claims and examples. #380 must retain these corrections when it performs its broader docs pass; do not fold unrelated shipped-surface/count work into this change. |

## Risks and checks

- Parsing a token claim is deliberately fail-open for filtering: a malformed/changed shape must retain third-party data, not risk dropping it. The warning must be bounded once per opted-in tenant, not emitted on every tick.
- Do not confuse an application ID with a service-principal object ID, tenant ID, or an `azp` fallback. The contract is the Graph access token's non-empty `appid` string; a claim-shape change is unproved identity until evidence supports a deliberate extension.
- A token request can fail even though client construction succeeds. That is not a reason to mark the tenant unavailable: other collection paths retain their existing lazy-auth partial-startup semantics.
- Keep raw access tokens out of errors, logs, tests, fixtures, admin state, and docs. Use fake unsigned JWTs only in unit tests.
- `make check` is the mandatory green bar. For a docs/chart change, include the additional generated-diff and Helm receipts above before committing; no implementation should start with the currently dirty availability/dashboard work altered or staged.

## Open questions

- None. The maintainer approved the recommended authority/failure policy; the non-fatal mismatch diagnostic and token-`appid` proof boundary above are the minimal implementation that satisfies it without changing auth or tenant configuration.

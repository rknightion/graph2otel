# Issue #266 composition wiring report

## Outcome

Implemented the composition-root half of #266 in
`/tmp/graph2otel-266-full.MvZ5ah`.

- `setupTenantWithGraphAndLicenseBuilders` resolves the authenticated
  application identity exactly once for an opted-in tenant, after `TenantAuth`
  and before either self-filter dependency path is built.
- The resolved `(enabled, appID)` pair is reused unchanged for `WindowDeps` and
  `BlobDeps`.
- `tenants[].client_id` is now only a non-secret consistency assertion.
  `AZURE_CLIENT_ID` is not read by the composition resolver and has no
  self-filter authority.
- Proof failure disables self-filtering, keeps tenant startup moving, and emits
  one WARN containing the tenant plus exactly one bounded reason:
  `token_request_failed`, `malformed_token`, or `missing_appid`.
- Proof-failure diagnostics contain no access token, JWT payload, configured
  ID, or raw credential error.
- A configured/proved mismatch emits one WARN containing the tenant and the two
  non-secret IDs. The proved token `appid` remains the comparison identity and
  startup continues.
- `exclude_self: false` performs no token request and emits no identity warning.
- No availability, startup-failure, collector registration, pipeline,
  checkpoint, outcome, or telemetry behavior was changed.

Key implementation locations:

- `cmd/graph2otel/tenants.go:519-544` — once-per-tenant resolution and WindowDeps wiring
- `cmd/graph2otel/tenants.go:580-586` — reuse of the same resolved value for blob registration
- `cmd/graph2otel/tenants.go:813-849` — BlobDeps receives the resolved value; no second resolution or warning
- `cmd/graph2otel/tenants.go:1291-1372` — typed bounded-reason mapping, resolved-pair type, fail-open resolver, mismatch warning
- `internal/auth/auth.go:77-101` — exported bounded failure codes and typed error
- `internal/auth/auth.go:162-236` — token-derived appid proof with typed failures

## TDD receipt

RED:

```text
go test ./cmd/graph2otel -run 'TestResolveTenantSelfIdentity'

cmd/graph2otel/tenants_selfid_test.go:85:14: undefined: resolveTenantSelfIdentity
cmd/graph2otel/tenants_selfid_test.go:155:14: undefined: resolveTenantSelfIdentity
cmd/graph2otel/tenants_selfid_test.go:193:16: undefined: selfIdentityReasonTokenRequestFailed
cmd/graph2otel/tenants_selfid_test.go:201:16: undefined: selfIdentityReasonMalformedToken
cmd/graph2otel/tenants_selfid_test.go:209:16: undefined: selfIdentityReasonMissingAppID
cmd/graph2otel/tenants_selfid_test.go:222:16: undefined: resolveTenantSelfIdentity
FAIL
```

GREEN:

```text
go test ./cmd/graph2otel -run 'TestResolveTenantSelfIdentity'
ok github.com/rknightion/graph2otel/cmd/graph2otel 1.302s
```

The tests prove:

- one Graph-default-scope token request for an opted-in tenant;
- zero token requests/warnings when disabled;
- stale configured and ambient IDs are retained as third-party records through
  the real logpipeline filter while the proved token identity is excluded;
- the same pair reaches both dependency types;
- one mismatch warning with both non-secret IDs;
- token request, malformed token, and missing `appid` failures all fail open
  with bounded/redacted diagnostics;
- applying the resolved result to both dependency paths cannot duplicate a
  warning.

### Integrated-review finding 1 follow-up

The integrated review found that cmd classified auth failures by matching
English error strings. The follow-up used a second strict TDD cycle.

RED:

```text
go test ./internal/auth ./cmd/graph2otel -run \
  'TestAuthenticatedApplicationID|TestApplicationIdentityError|TestSelfIdentityFailureReason'

internal/auth/auth_test.go:96:8: undefined: auth.ApplicationIdentityFailureCode
internal/auth/auth_test.go:98:24: undefined: auth.ApplicationIdentityError
cmd/graph2otel/tenants_selfid_test.go:328:19: undefined: auth.ApplicationIdentityFailureCode
cmd/graph2otel/tenants_selfid_test.go:354:55: undefined: auth.ApplicationIdentityError
FAIL
```

GREEN:

```text
go test ./internal/auth ./cmd/graph2otel -run \
  'TestAuthenticatedApplicationID|TestApplicationIdentityError|TestSelfIdentityFailureReason'
ok github.com/rknightion/graph2otel/internal/auth 0.366s
ok github.com/rknightion/graph2otel/cmd/graph2otel 1.283s
```

The replacement contract is structural:

- auth exports `ApplicationIdentityFailureCode` and
  `ApplicationIdentityError`;
- cmd classifies through `errors.As`, never `err.Error()` or substring
  matching;
- arbitrary outer wrapping and changed/misleading error prose cannot change
  the bounded warning reason;
- token-request failures retain the original credential cause through
  `errors.Is`;
- the typed error's printable text omits the raw credential cause, token, and
  payload;
- the auth package comments now state that one ambient application identity is
  selected per process and `tenant_id` only pins the directory.

### Fail-closed tenant credential seam follow-up

The auth seam now fails closed even when an underlying Azure credential ignores
or overrides tenant-selection inputs:

- `NewTenantAuth` passes the configured tenant to both `TenantID` and the sole
  `AdditionallyAllowedTenants` entry. The explicit non-empty allow-list prevents
  an ambient `AZURE_ADDITIONALLY_ALLOWED_TENANTS=*` from broadening the
  credential.
- `TenantAuth.Cred` is always a tenant-bound wrapper. Every `GetToken` call
  copies the request options (including the scopes slice), replaces any empty,
  wrong, or caller-supplied `TenantID` with the configured tenant, and delegates
  with that pinned copy.
- No successful Azure token reaches `SmokeToken`, application-identity proof,
  or Graph clients until its JWT payload has a non-empty string `tid` exactly
  matching the configured canonical tenant GUID.
- Malformed JWTs, missing/empty `tid`, and mismatched `tid` fail with typed,
  bounded `TenantBindingError` codes. Their printable errors omit token
  material, JWT payload fields, and tenant values.
- If the underlying credential itself fails, the wrapper returns a zero token
  and preserves the original error for `errors.Is`.
- The shared JWT decoder keeps the existing `appid` proof behavior intact.

RED:

```text
go test ./internal/auth -run \
  'TestNewTenantAuth|TestTenantBoundCredential|TestTenantBinding'

internal/auth/auth_test.go:37:21: undefined: buildDefaultAzureCredential
internal/auth/auth_test.go:80:25: undefined: tenantBoundCredential
internal/auth/auth_test.go:154:56: undefined: TenantBindingFailureCode
internal/auth/auth_test.go:156:18: undefined: TenantBindingError
internal/auth/auth_test.go:202:18: undefined: newTenantBoundCredential
FAIL
```

GREEN:

```text
go test ./internal/auth -run \
  'TestNewTenantAuth|TestTenantBoundCredential|TestTenantBinding'
ok github.com/rknightion/graph2otel/internal/auth 0.333s
```

Focused final verification:

```text
go test -race ./internal/auth -run \
  'TestNewTenantAuth|TestTenantBoundCredential|TestTenantBinding|TestAuthenticatedApplicationID|TestSmokeToken'
ok github.com/rknightion/graph2otel/internal/auth 1.307s

go test ./internal/auth
ok github.com/rknightion/graph2otel/internal/auth 0.267s

go vet ./internal/auth
PASS

golangci-lint run --allow-parallel-runners ./internal/auth/...
0 issues.

git diff --check -- internal/auth/auth.go internal/auth/auth_test.go
PASS
```

### Integrated-review finding 2 follow-up

Config deliberately accepts uppercase text for an otherwise canonical tenant
GUID, while Entra normally emits lowercase `tid` claims. The first
tenant-binding implementation compared those representations
case-sensitively, causing a false `tenant_mismatch`.

The comparison now uses case-insensitive semantic GUID equality. GUID format
validation remains owned by config; genuine differing GUIDs still fail with
the same bounded `tenant_mismatch` code and redaction behavior.

RED:

```text
go test ./internal/auth -run \
  '^TestTenantBoundCredentialAcceptsConfiguredGUIDCaseVariant$' -count=1

--- FAIL: TestTenantBoundCredentialAcceptsConfiguredGUIDCaseVariant (0.00s)
    auth_test.go:239: GetToken() error = tenant-bound credential rejected access token: tenant_mismatch, want semantic GUID match
FAIL
```

GREEN and regression verification:

```text
go test ./internal/auth -run \
  '^TestTenantBoundCredentialAcceptsConfiguredGUIDCaseVariant$' -count=1
ok github.com/rknightion/graph2otel/internal/auth 0.307s

go test -race ./internal/auth -run \
  'TestTenantBoundCredentialAcceptsConfiguredGUIDCaseVariant|TestTenantBoundCredentialRejectsInvalidTenantBeforeTokenEscape' \
  -count=1
ok github.com/rknightion/graph2otel/internal/auth 1.284s

go test -race ./internal/auth -count=1
ok github.com/rknightion/graph2otel/internal/auth 1.298s

go vet ./internal/auth
PASS

golangci-lint run --allow-parallel-runners ./internal/auth/...
0 issues.

git diff --check -- internal/auth/auth.go internal/auth/auth_test.go
PASS
```

## File ownership

Owned implementation/test files changed:

- `cmd/graph2otel/tenants.go`
- `cmd/graph2otel/tenants_selfid_test.go`
- `internal/auth/auth.go`
- `internal/auth/auth_test.go`

One compilation-only adjustment was unavoidable after adding the resolved
identity parameter to `registerBlobCollectors`:

- `cmd/graph2otel/tenants_startup_test.go:834-836` now passes
  `tenantSelfIdentity{}` to the isolated optional-runtime-factory test. No
  assertion or behavior in that test changed.

No config, docs, pipelines, collectors, availability, AGENTS, or telemetry
files were touched by this lane. A concurrent docs lane changed several of
those files in the shared worktree; those changes were not edited or reverted.

## Verification

All commands completed with exit code 0:

```text
go test -race ./cmd/graph2otel -run 'Test.*Self.*Identity|Test.*ExcludeSelf'
ok github.com/rknightion/graph2otel/cmd/graph2otel 2.524s

go test ./cmd/graph2otel
ok github.com/rknightion/graph2otel/cmd/graph2otel 5.425s

go test -race ./internal/auth -run 'TestAuthenticatedApplicationID'
ok github.com/rknightion/graph2otel/internal/auth 1.282s

go test ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/graphactivity ./internal/collectors/entra/signins
ok github.com/rknightion/graph2otel/internal/blobpipeline 0.751s
ok github.com/rknightion/graph2otel/internal/logpipeline 3.246s
ok github.com/rknightion/graph2otel/internal/collectors/entra/graphactivity 1.159s
ok github.com/rknightion/graph2otel/internal/collectors/entra/signins 3.281s

go test ./...
PASS (all packages)

go vet ./...
PASS

golangci-lint run
0 issues.

git diff --check
PASS
```

Review-fix verification:

```text
go test -race ./internal/auth ./cmd/graph2otel -run \
  'TestAuthenticatedApplicationID|TestApplicationIdentityError|TestResolveTenantSelfIdentity|TestSelfIdentityFailureReason'
ok github.com/rknightion/graph2otel/internal/auth 1.287s
ok github.com/rknightion/graph2otel/cmd/graph2otel 2.521s

go test ./internal/auth ./cmd/graph2otel
ok github.com/rknightion/graph2otel/internal/auth 0.201s
ok github.com/rknightion/graph2otel/cmd/graph2otel 2.503s

go vet ./internal/auth ./cmd/graph2otel
PASS

golangci-lint run --allow-parallel-runners \
  ./internal/auth/... ./cmd/graph2otel/...
0 issues.

git diff --check -- internal/auth/auth.go internal/auth/auth_test.go \
  cmd/graph2otel/tenants.go cmd/graph2otel/tenants_selfid_test.go
PASS
```

## Adversarial review and concerns

- Integrated-review finding 1 is addressed. Classification no longer depends
  on prose; unfamiliar/absent typed codes still fail open and remain inside the
  bounded diagnostic vocabulary.
- No `make check` was run by this lane. The requested focused/full tests, full
  vet, full lint, and diff checks are green; the coordinating thread should run
  the repository's final `make check` after the auth/docs lanes are integrated.
- Worktree remains detached and uncommitted at
  `/tmp/graph2otel-266-full.MvZ5ah` for the coordinating thread. HEAD before
  these uncommitted changes is `066c8aa33710f007dc4295e0a87a78404515fc88`.

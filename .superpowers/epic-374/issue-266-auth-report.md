# Issue #266 auth-proof core report

## Scope and decision

Implemented only the isolated `TenantAuth` authenticated-application-ID seam in
`/tmp/graph2otel-266.Kt5BOt`.

Binding contract applied:

- The Graph access token's non-empty string `appid` is the sole proof of the
  authenticated application identity.
- `tenants[].client_id` and `AZURE_CLIENT_ID` cannot change the proved result.
- Token acquisition and JWT/claim failures return tenant-contextual errors.
- Errors added by this seam do not contain the token or decoded payload.
- The signature-verification rationale states only that the token is returned
  by graph2otel's own tenant-pinned `TokenCredential`; it makes no transport
  claim, because managed identity can use HTTP IMDS.
- `NewTenantAuth` and `BuildAll` remain lazy and signature-stable.
- No cache, dependency, Graph SDK call, preflight change, or credential-chain
  change was added.

## Files changed

- `internal/auth/auth.go`
- `internal/auth/auth_test.go`

No other worktree files were changed. Nothing was staged, committed, pushed, or
written to GitHub.

## TDD evidence

RED command:

```text
go test ./internal/auth -run 'TestAuthenticatedApplicationID'
```

RED result (exit 1):

```text
# github.com/rknightion/graph2otel/internal/auth_test [github.com/rknightion/graph2otel/internal/auth.test]
internal/auth/auth_test.go:121:17: ta.AuthenticatedApplicationID undefined (type *auth.TenantAuth has no field or method AuthenticatedApplicationID)
internal/auth/auth_test.go:137:15: ta.AuthenticatedApplicationID undefined (type *auth.TenantAuth has no field or method AuthenticatedApplicationID)
internal/auth/auth_test.go:169:17: ta.AuthenticatedApplicationID undefined (type *auth.TenantAuth has no field or method AuthenticatedApplicationID)
internal/auth/auth_test.go:195:15: ta.AuthenticatedApplicationID undefined (type *auth.TenantAuth has no field or method AuthenticatedApplicationID)
FAIL	github.com/rknightion/graph2otel/internal/auth [build failed]
FAIL
```

Initial GREEN command:

```text
go test ./internal/auth -run 'TestAuthenticatedApplicationID'
```

Initial GREEN result (exit 0):

```text
ok  	github.com/rknightion/graph2otel/internal/auth	0.259s
```

Original uncached focused race command:

```text
go test -count=1 -race ./internal/auth -run 'TestAuthenticatedApplicationID'
```

Original focused result (exit 0):

```text
ok  	github.com/rknightion/graph2otel/internal/auth	1.197s
```

The tests cover:

- valid three-segment JWT with token `appid`;
- configured and ambient client IDs disagreeing with, but not influencing,
  the token-proved ID;
- malformed/non-three-segment JWT, invalid base64url, padded base64url payload,
  malformed JSON, and non-object JSON;
- absent, empty, and non-string `appid`;
- token request failure with wrapped cause;
- tenant context on every failure;
- no raw token or decoded payload in seam-generated error text;
- the existing `GraphDefaultScope` as the only requested scope.

### Reviewer follow-up mutation receipt

The additional malformed-token cases are characterization coverage over
defensive behavior already present in the reviewed implementation, so they
passed when first added. To prove that the tests catch the relevant regression,
`decodeAuthenticatedApplicationID` was temporarily mutated to accept every
token, the focused test was run, and the mutation was then removed.

Mutation RED command:

```text
go test -count=1 ./internal/auth -run 'TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken'
```

Mutation RED result (exit 1):

```text
--- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken (0.00s)
    --- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken/wrong_segment_count (0.00s)
        auth_test.go:184: AuthenticatedApplicationID() error = nil, want malformed-token error
    --- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken/invalid_base64url (0.00s)
        auth_test.go:184: AuthenticatedApplicationID() error = nil, want malformed-token error
    --- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken/padded_payload (0.00s)
        auth_test.go:184: AuthenticatedApplicationID() error = nil, want malformed-token error
    --- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken/malformed_JSON (0.00s)
        auth_test.go:184: AuthenticatedApplicationID() error = nil, want malformed-token error
    --- FAIL: TestAuthenticatedApplicationIDRejectsMalformedJWTWithoutLeakingToken/non-object_JSON (0.00s)
        auth_test.go:184: AuthenticatedApplicationID() error = nil, want malformed-token error
FAIL
FAIL	github.com/rknightion/graph2otel/internal/auth	0.256s
FAIL
```

Restored GREEN command:

```text
go test -count=1 -race ./internal/auth -run 'TestAuthenticatedApplicationID'
```

Restored GREEN result (exit 0):

```text
ok  	github.com/rknightion/graph2otel/internal/auth	1.326s
```

## Final verification

Command:

```text
go test -count=1 -race ./internal/auth -run 'TestAuthenticatedApplicationID' &&
go vet ./internal/auth &&
golangci-lint run ./internal/auth/... &&
git diff --check &&
git status --short &&
git diff --stat
```

Result (exit 0):

```text
ok  	github.com/rknightion/graph2otel/internal/auth	1.297s
0 issues.
 M internal/auth/auth.go
 M internal/auth/auth_test.go
 internal/auth/auth.go      |  52 +++++++++++++
 internal/auth/auth_test.go | 182 +++++++++++++++++++++++++++++++++++++++++++--
 2 files changed, 228 insertions(+), 6 deletions(-)
```

`go vet` and `git diff --check` emitted no output.

## Integration note

This auth seam deliberately does not cache or warn. The composition owner must
call it only once per opted-in tenant, map token-request/malformed-token/missing-
`appid` failures to the bounded startup reason codes, and disable filtering on
failure. The method returns the proved ID only; it has no configured-ID fallback.

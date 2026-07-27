# Issue #266 integrated review

## Verdict

Not ready. The authenticated-identity behavior is otherwise correctly fail-open
and the focused race suite is green, but one implementation seam is structurally
fragile and the issue-owned documentation correction is absent from this
worktree.

## Findings

### Medium — bounded failure classification depends on English error text

`AuthenticatedApplicationID` exposes the distinct proof failures only through
formatted strings (`internal/auth/auth.go:142-147`,
`internal/auth/auth.go:152-177`). The composition root then recovers the
operator-facing reason by substring matching those messages
(`cmd/graph2otel/tenants.go:1357-1367`).

This is a correctness contract crossing package boundaries through prose. A
harmless auth error rewording, additional wrapping, or new malformed-token
branch will still fail open, but it will silently report the wrong bounded
reason (normally `missing_appid`). The current tests pin today's wording rather
than proving a structural classification contract. That is especially
dangerous because these bounded codes are the only redacted diagnostic retained
when the raw credential error is deliberately discarded.

Fix before integration: make the auth seam return a typed proof-failure reason
or wrap stable sentinel errors, preserve the underlying token-request cause for
`errors.Is`, and classify in the composition root with `errors.As`/`errors.Is`.
Keep the three public reason strings and the redaction/fail-open behavior
unchanged.

### Medium — #266's operator-facing authority model is still incorrect

None of the plan's documentation/config-comment files changed. The reviewed
worktree still says that configured `client_id` selects an authenticating
identity (`internal/config/config.go:203-224`,
`docs/configuration.md:52-60`), that the configured value or
`AZURE_CLIENT_ID` is the self-filter authority
(`config.example.yaml:30-39`, `docs/blob-ingest.md:141-191`), and gives
multi-tenant setup wording based on that model
(`README.md:230-253`, `docs/getting-started.md:78-113`).

That directly contradicts the new runtime contract and leaves the acceptance
criterion requiring explicit workload/managed-identity behavior incomplete.
Apply the issue-266 plan's bounded corrections before calling the issue
complete: ambient `DefaultAzureCredential` chooses one application identity per
process, `tenant_id` pins the directory, configured `client_id` is only an
optional consistency assertion, and `exclude_self` trusts the token-proved
`appid` or disables itself with one bounded warning.

## Confirmed behavior

- A successful token-proved `appid` is authoritative; stale configured and
  ambient IDs cannot exclude third-party records
  (`cmd/graph2otel/tenants_selfid_test.go:84-209`).
- `exclude_self: false` performs no identity token request and emits no warning
  (`cmd/graph2otel/tenants_selfid_test.go:211-240`).
- Token, JWT, and claim failures disable filtering on both dependency paths and
  emit exactly one redacted warning
  (`cmd/graph2otel/tenants_selfid_test.go:242-322`).
- The resolved pair is computed once and reused by `WindowDeps` and `BlobDeps`
  (`cmd/graph2otel/tenants.go:519-544`,
  `cmd/graph2otel/tenants.go:575-586`,
  `cmd/graph2otel/tenants.go:813-850`).
- Identity-proof failure does not alter the availability inventory, startup
  failure state, registry gates, readiness, or liveness.
- The auth decoder requires exactly three JWT segments and a non-empty string
  `appid`, and its own parse errors do not expose token or decoded payload
  (`internal/auth/auth.go:134-179`,
  `internal/auth/auth_test.go:134-255`).
- The one-line `tenants_startup_test.go` change is a necessary signature
  adjustment only and does not weaken the existing optional-factory assertion
  (`cmd/graph2otel/tenants_startup_test.go:804-850`).

## Verification

Passed:

```text
go test -count=1 -race ./internal/auth ./cmd/graph2otel ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/graphactivity ./internal/collectors/entra/signins

ok github.com/rknightion/graph2otel/internal/auth
ok github.com/rknightion/graph2otel/cmd/graph2otel
ok github.com/rknightion/graph2otel/internal/blobpipeline
ok github.com/rknightion/graph2otel/internal/logpipeline
ok github.com/rknightion/graph2otel/internal/collectors/entra/graphactivity
ok github.com/rknightion/graph2otel/internal/collectors/entra/signins
```

No implementation, test, tracked documentation, Git state, or GitHub state was
modified by this review.

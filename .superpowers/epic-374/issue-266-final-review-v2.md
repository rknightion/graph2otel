# Issue #266 final review v2

## Verdict

**READY**

No correctness, safety, contract, generated-artifact, or regression findings remain against issue #266 and the maintainer's resolved fail-closed GUID decision.

Review base: `066c8aa`

Reviewed worktree: `/tmp/graph2otel-266-full.MvZ5ah`

## Contract conformance

- `tenants[].tenant_id` is now a canonical hyphenated Entra directory GUID. Runtime validation rejects domains, compact/braced UUIDs, whitespace, and duplicate GUIDs regardless of case. The Helm schema requires the field and enforces the same hyphenated shape.
- `NewTenantAuth` supplies the configured directory to `DefaultAzureCredentialOptions.TenantID` and replaces any ambient additional-tenant wildcard with the one explicit configured target.
- The returned credential is wrapped. Every `GetToken` call:
  - overwrites the caller's tenant option with the configured directory;
  - preserves the request scopes without aliasing the caller's slice;
  - rejects malformed JWTs, missing/invalid `tid`, and a non-matching `tid`;
  - returns a zero access token on any validation failure.
- `tid` comparison is case-insensitive, matching GUID semantics while retaining the canonical config contract.
- Exact azidentity v1.14.0 source inspection confirms the seam covers the credential-chain differences called out in the issue:
  - environment secret/certificate credentials receive the explicit target through the request and allowed-tenant contract;
  - workload identity, Azure CLI, Azure Developer CLI, and PowerShell receive the target tenant;
  - managed identity remains home-tenant-bound, but a wrong configured tenant is rejected by the wrapper's returned-token `tid` check.
- Startup requests and validates a Graph token before constructing Graph, blob, ARM, export, O365 activity, EXO, hunt, or collector paths. Failure creates bounded startup-failure availability state and no tenant-derived ingest path. The emitted availability diagnostic describes the configured tenant's failed startup; it does not contain data obtained under another directory.
- The authenticated token's non-empty `appid` is the self-exclusion authority. Configured `client_id` is only a diagnostic assertion. Mismatch cannot become a filter key.
- If application identity proof fails, self-exclusion receives an empty identity and therefore fails open, with one bounded warning. Third-party records continue to pass.
- Application and tenant proof errors expose stable bounded codes. JWTs, decoded payloads, tenant values, application IDs, and wrapped cause text are absent from their public error strings. Tests cover malformed base64/JSON, wrong claim types, missing/empty claims, mismatch, and sentinel redaction.

## Configuration and documentation

- README, configuration, getting-started, blob-ingest, example config, Helm values, generated Helm README, and install notes consistently describe:
  - one ambient application identity per process;
  - shared multi-tenant application support;
  - directory GUID tenant targeting and returned-token verification;
  - `client_id` as an optional assertion, not credential selection;
  - workload identity requirements;
  - managed identity's home-tenant boundary.
- Stale collector and test comments that still named configured `client_id` as the self-exclusion authority were corrected during this review wave.
- `make helm-docs` is idempotent.
- Helm lint succeeds, a valid uppercase directory GUID renders, and schema tests reject a verified domain or a tenant item with no `tenant_id`.

## Generated artifacts

The description-only source changes are reflected in all four required artifacts:

- `internal/blobpipeline/testdata/signals.json`
- `internal/logpipeline/testdata/signals.json`
- `internal/collectors/entra/signins/testdata/signals.json`
- `spec/signal-catalog.json`

Signal-catalog and package gates pass.

## Verification receipts

- `go test -race ./internal/auth ./cmd/graph2otel ./internal/config ./charts/graph2otel ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/graphactivity ./internal/collectors/entra/signins ./internal/signalcatalog -count=1` — pass
- Focused race rerun after final comment-truth follow-up — pass
- `helm lint charts/graph2otel` — pass
- `helm template graph2otel charts/graph2otel --set-string 'graph2otel.tenants[0].tenant_id=12345678-1234-1234-1234-123456789abc'` — pass
- `make helm-docs` with before/after status and README hash comparison — idempotent
- `git diff --check 066c8aa` — pass
- `make check` — pass:
  - vet
  - full race suite
  - golangci-lint: 0 issues
  - govulncheck: no called vulnerabilities
  - root and graphdrift tidy checks
  - graphdrift vet/tests
  - full build

No files were staged, committed, or pushed, and no GitHub state was changed by this review.

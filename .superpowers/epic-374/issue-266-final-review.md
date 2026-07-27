# Issue #266 final integrated review

Date: 2026-07-26

Worktree: `/tmp/graph2otel-266-full.MvZ5ah`

Base: `066c8aa33710f007dc4295e0a87a78404515fc88`

## Verdict

NOT READY

The typed-error/redaction finding from the prior integrated review is resolved,
and the token-proved self-filter wiring is otherwise sound. A load-bearing
multi-tenant premise is false for the current credential chain, the Helm
operator surface still carries the old `client_id` authority model, and the
intentional signal-description changes have not been regenerated.

## Findings

### High — `TenantConfig.TenantID` does not pin client-secret, certificate, or managed-identity token requests

The implementation and the corrected docs say that each `TenantAuth` pins token
requests to `tenants[].tenant_id`, allowing one ambient application identity to
poll multiple directories (`internal/auth/auth.go:23-29`,
`internal/auth/auth.go:111-124`, `README.md:228-254`,
`docs/getting-started.md:76-103`).

That is not what azidentity v1.14.0 does:

- `DefaultAzureCredentialOptions.TenantID` applies only to Azure CLI, Azure
  Developer CLI, and workload identity
  (`azidentity@v1.14.0/default_azure_credential.go:53-54`).
- The environment credential used for client-secret/certificate auth reads
  `AZURE_TENANT_ID` directly
  (`azidentity@v1.14.0/environment_credential.go:39-58`,
  `environment_credential.go:75-85`). The constructor does not receive
  `DefaultAzureCredentialOptions.TenantID`
  (`default_azure_credential.go:140-145`).
- The managed-identity credential has identity-selection options but no tenant
  option (`managed_identity_credential.go:85-105`), and the default-chain
  constructor does not pass one (`default_azure_credential.go:167-176`).
- graph2otel does not compensate at request time:
  `AuthenticatedApplicationID` requests only `Scopes`
  (`internal/auth/auth.go:168-175`), raw Graph requests request only `Scopes`
  (`internal/graphclient/rest.go:45`, `internal/graphclient/rest.go:89`), and
  Kiota's Azure access-token provider also omits
  `TokenRequestOptions.TenantID`
  (`kiota-authentication-azure-go@v1.3.1/azure_identity_access_token_provider.go:120-126`).

With environment client-secret/certificate auth, every configured tenant
therefore requests a token from ambient `AZURE_TENANT_ID`. A second configured
tenant can fail authorization or, worse, query the ambient tenant while
graph2otel stamps the records and metrics with the second configured
`tenant_id`. Managed identity is similarly not made cross-tenant by the current
constructor. This violates the issue acceptance criterion that shared-app
multi-tenant operation remains supported and makes the new operator
documentation unsafe.

Fix before integration: make tenant selection real for every supported
credential leg and every token request, with an environment-credential test
that observes the requested authority tenant. A tenant-binding credential
wrapper would need to set `TokenRequestOptions.TenantID` and configure allowed
tenants deliberately; an explicit per-tenant client-secret/certificate
credential over the same ambient material is another option. Document managed
identity's actual cross-tenant limit instead of implying that
`DefaultAzureCredentialOptions.TenantID` overrides it.

### Medium — the prior documentation finding is only partially resolved

The README, `config.example.yaml`, configuration/getting-started/blob docs, auth
package comments, dependency comments, and pipeline metric descriptions now
state the intended token-proved authority model. The Helm chart still tells
operators the opposite:

- `charts/graph2otel/values.yaml:105-107` says one ambient secret/certificate
  credential authenticates every listed tenant.
- `charts/graph2otel/values.yaml:119-125` says ambient
  `AZURE_TENANT_ID` is normally unnecessary and that per-tenant YAML
  `client_id` can replace `AZURE_CLIENT_ID`.
- `charts/graph2otel/values.yaml:151-152` still presents YAML `client_id` as the
  app-registration selector.
- The generated `charts/graph2otel/README.md:172,196,198` repeats those claims.

The collector implementations also retain stale authority comments:

- `internal/collectors/entra/graphactivity/graphactivity.go:72-75,145-150`
- `internal/collectors/entra/signins/blob.go:172-176`

Several regression-test comments retain the same obsolete model
(`internal/blobpipeline/blobpipeline_test.go:665-669,767-770` and
`internal/logpipeline/selfexclude_test.go:12-16,57-59,156-158`).

The chart is an operator-facing configuration surface explicitly included as a
conditional ownership lane in the plan. Correct its annotations, regenerate
`charts/graph2otel/README.md` with `make helm-docs`, and remove the stale
configured-`client_id` authority comments.

### Medium — intentional metric-description changes leave generated truth stale

The source descriptions for
`graph2otel.blob.self_excluded` and
`graph2otel.logpipeline.self_excluded` changed intentionally, but the committed
goldens still contain the old `client_id` wording. The current worktree fails:

```text
go test -p 1 -count=1 ./internal/blobpipeline ./internal/logpipeline ./internal/collectors/entra/signins ./internal/signalcatalog
```

The first three packages fail only their signal-drift gates.
`internal/signalcatalog` is still green because it aggregates those stale
goldens; it becomes stale after they are corrected.

Isolated regeneration proved the exact required generated changes:

1. `internal/blobpipeline/testdata/signals.json`
2. `internal/logpipeline/testdata/signals.json`
3. `internal/collectors/entra/signins/testdata/signals.json`
4. `spec/signal-catalog.json`

Each diff is description-only. No signal name, unit, kind, attribute, owner, or
Prometheus normalization changes. `docs/env-vars.md` does not need
regeneration (`go test ./internal/config` passes), and `docs/collectors.md` does
not contain these descriptions. `charts/graph2otel/README.md` additionally
needs regeneration after the Helm annotation fix above.

## Prior-finding resolution and confirmed behavior

- The prose-matching failure classifier is gone. Auth returns
  `ApplicationIdentityError` with a bounded
  `ApplicationIdentityFailureCode`; cmd classifies with `errors.As`.
- `ApplicationIdentityError.Error` omits the raw cause. `Unwrap` preserves the
  token-request cause for `errors.Is`, and tests prove both properties through
  arbitrary outer wrapping.
- JWT handling requires exactly three raw-base64url segments, a JSON object,
  and a non-empty string `appid`. Decoder errors expose neither token nor
  payload.
- The token's `appid` is the sole self-filter comparison identity. Configured
  and ambient client IDs cannot override it; a configured mismatch emits one
  warning and the proved ID wins.
- `exclude_self: false` makes no identity-proof token request and emits no
  identity warning.
- Proof failure disables filtering for both dependency paths, emits exactly
  one bounded/redacted warning, and leaves tenant startup running.
- One resolved pair is applied to `WindowDeps` and `BlobDeps`; both pipeline
  predicates remain fail-open for an empty/unproved ID.
- Existing filtered-outcome, cursor/watermark, and loud per-collector counter
  behavior is unchanged.

## Verification receipts

Passed in the reviewed worktree:

```text
go test -count=1 -race ./internal/auth ./cmd/graph2otel \
  -run 'Test(AuthenticatedApplicationID|ApplicationIdentityError|ResolveTenantSelfIdentity|SelfIdentityFailureReason|OptionalRuntimeFactoriesCannotSilentlyReturnNilWhenActive)'

go test -count=1 ./internal/config

go vet ./internal/auth ./cmd/graph2otel ./internal/blobpipeline \
  ./internal/logpipeline ./internal/collectors/entra/graphactivity \
  ./internal/collectors/entra/signins

golangci-lint run --allow-parallel-runners ./internal/auth/... \
  ./cmd/graph2otel/... ./internal/blobpipeline/... \
  ./internal/logpipeline/... \
  ./internal/collectors/entra/graphactivity/... \
  ./internal/collectors/entra/signins/...

git diff --check
```

Lint reported `0 issues`.

After regenerating the four signal artifacts in an isolated clone, the full
focused race set passed sequentially:

```text
go test -p 1 -count=1 -race ./internal/auth ./cmd/graph2otel \
  ./internal/blobpipeline ./internal/logpipeline \
  ./internal/collectors/entra/graphactivity \
  ./internal/collectors/entra/signins
```

No implementation, generated artifact, Git state, or GitHub state was changed
by this review.

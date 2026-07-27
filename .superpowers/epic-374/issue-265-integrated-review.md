# #265 final integrated review

## Verdict

**READY**

No severity findings remain in the complete intended diff against
`066c8aa33710f007dc4295e0a87a78404515fc88`.

The prior medium documentation finding is resolved. `README.md`,
`charts/graph2otel/values.yaml`, and the generated
`charts/graph2otel/README.md` now use the runtime-valid logical name
`entra.signins.interactive`; the environment example uses
`G2O_COLLECTORS__ENTRA.SIGNINS.INTERACTIVE__ENABLED`. No shipped operator
example in those files retains `sign_ins` or
`G2O_COLLECTORS__SIGN_INS__ENABLED`.

`TestShippedCollectorOverrideExamplesUseRuntimeName` connects all three shipped
examples to `collectorOverrideInventory()`, requires the valid YAML/environment
forms, and rejects either stale spelling. The documented escaped Helm command
also passes real `helm lint` and `helm template`. `make helm-docs` is
byte-for-byte idempotent for the generated chart README.

## Verified implementation

- The YAML node validator closes every typed fixed object, reports full paths,
  and leaves only collector-name maps and Pyroscope tags open.
- Unknown `G2O_*` variables are rejected by exact variable name without values.
  Collector override origins are per-`Config`, and semantic override
  validation runs before generic interval validation so the originating
  environment variable is retained.
- Both normal startup and `graph2otel check` use the same validated loader
  before telemetry or credential construction.
- The runtime inventory walks all seven registration paths and produces
  exactly 148 logical names. The Graph-polled/blob intersection produces
  exactly the three switchable names.
- The command-owned Helm contract compares both the 148-name and three-name
  sets bidirectionally with the runtime inventory. It also checks both global
  and tenant schema references.
- Helm enforces source applicability structurally: only the three switchable
  properties use the source-capable override; all other permitted names use
  the source-free closed override.
- Real Helm lint/template reject the typo-heavy issue reproduction, unknown
  names, invalid source values, and source on a non-switchable collector.
  Valid labels, annotations, tags, global overrides, and tenant overrides pass.
- The minimal `main.go` / `check.go` wiring preserves #292 availability,
  readiness, admin, and tenant startup paths. The full race suite is green.

## Fresh verification receipts

```text
go test -race ./internal/config ./cmd/graph2otel ./charts/graph2otel -count=1
ok github.com/rknightion/graph2otel/internal/config
ok github.com/rknightion/graph2otel/cmd/graph2otel
ok github.com/rknightion/graph2otel/charts/graph2otel

go test ./cmd/graph2otel -run \
  'TestShippedCollectorOverrideExamplesUseRuntimeName|TestHelmCollectorSchemaMatchesRuntimeInventory|TestCollectorOverrideInventoryHas148LogicalNamesAcrossAllSevenPaths|TestCollectorOverrideInventoryDerivesSwitchableNamesFromPolledBlobIntersection' \
  -count=1 -v
PASS

go test -race ./cmd/graph2otel ./charts/graph2otel -run \
  'Test(ShippedCollectorOverrideExamplesUseRuntimeName|Helm|CollectorOverrideInventory|ConfigSchema|CollectorOverrideSchema)' \
  -count=1 -v
PASS

make helm-docs
exit 0; generated README SHA-256 unchanged

rg '(\bsign_ins\b|SIGN_INS)' \
  README.md charts/graph2otel/values.yaml charts/graph2otel/README.md
exit 1 (no stale names)

helm lint charts/graph2otel
1 chart(s) linted, 0 chart(s) failed

helm template test charts/graph2otel
exit 0

helm lint/template with:
  --set 'config.collectors.entra\.signins\.interactive.enabled=false'
both exit 0

typo-heavy helm lint/template reproduction
both exit 1 and report the invalid fixed/config paths

go vet ./internal/config ./cmd/graph2otel ./charts/graph2otel
exit 0

golangci-lint run --allow-parallel-runners \
  ./internal/config/... ./cmd/graph2otel ./charts/graph2otel
0 issues.

git diff --check 066c8aa33710f007dc4295e0a87a78404515fc88
exit 0

make check
exit 0
```

No product source, index, commit, branch, push, or GitHub state was changed by
this review.

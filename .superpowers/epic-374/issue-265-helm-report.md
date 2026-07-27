# #265 Helm strict-schema lane report

## Scope

Implemented only:

- `charts/graph2otel/values.schema.json`
- `charts/graph2otel/helm_contract_test.go`

No files were staged, committed, pushed, or changed on GitHub.

## TDD receipt

Before the schema change, both commands accepted the reproduced misspellings
`persistence.enabeld`, `config.log_leevl`, `config.otlp.protocool`, and
`config.collectors.entra.users.soruce`:

```text
1 chart(s) linted, 0 chart(s) failed
helm template exit 0
```

After adding the failing Helm and structural contract tests, the focused RED
run failed because:

- `helm lint` and `helm template` still accepted and rendered every typo;
- the application config objects lacked `additionalProperties: false`;
- shipped config keys such as `tenants[].exclude_self` were absent;
- there was no collector-name inventory or collector override definition.

The independent review then found two missing contracts. A second focused RED
run proved both:

- `helm lint` and `helm template` accepted and rendered
  `config.collectors.entra.users.source: blob`, although `entra.users` has no
  blob twin;
- the old schema had one source-capable override for every collector and no
  shared source-switchable map representation.

## Implementation

- Closed every typed `config.Config` object and every
  `config.CollectorConfig` value with `additionalProperties: false`.
- Kept `profiling.pyroscope.tags` open to arbitrary string keys.
- Kept chart/Kubernetes extension maps such as labels and annotations open.
- Closed `persistence` so the issue's `enabeld` reproduction fails.
- Added every current typed application config key, including tenant blob,
  O365 activity, MDCA, Exchange Online, hunting, source-exclusion, recency, and
  secret-file path fields.
- Defined ordinary collector overrides as optional `enabled:boolean` and
  `interval:string`; only the three authoritative source-switchable names use
  the override that also permits `source:enum(graph,blob)`.
- Restricted global and tenant collector-map property names through the
  complete sorted 148-name logical inventory.
- Exposed one shared `definitions.collectorOverrides` map used by both global
  and tenant overrides. Its `properties` are the source-switchable set, each
  referencing `sourceSwitchableCollectorOverride`; its fallback references the
  source-free `collectorOverride`.
- Coordinated the cmd-owned
  `TestHelmCollectorSchemaMatchesRuntimeInventory`, which bidirectionally
  compares both the 148-name enum and the switchable property set with
  `collectorOverrideInventory()` derived from all seven runtime registration
  paths. It also checks every override/reference seam, so neither runtime
  additions nor stale Helm names remain green.
- Added real Helm integration coverage for typo rejection, unknown collector
  rejection, source-enum rejection, inapplicable-source rejection, and valid
  labels/annotations/tags/global and tenant collector overrides.
- Added a reflection-based structural contract that compares the chart's
  `config` subtree to `config.Config`, including exact property sets and closure
  of every fixed object.

## Green receipts

```text
go test -race ./charts/graph2otel -count=1
ok github.com/rknightion/graph2otel/charts/graph2otel

golangci-lint run ./charts/graph2otel
0 issues.

go vet ./charts/graph2otel
exit 0

jq empty charts/graph2otel/values.schema.json
exit 0

jq -e '.definitions.collectorName.enum | length == 148' ...
true

collector enum vs generated docs/collectors.md logical census
no diff

go test -race ./cmd/graph2otel -run TestHelmCollectorSchemaMatchesRuntimeInventory
ok github.com/rknightion/graph2otel/cmd/graph2otel

helm lint charts/graph2otel
1 chart(s) linted, 0 chart(s) failed

helm template valid charts/graph2otel
exit 0
```

The typo-heavy post-fix lint and template commands both exit non-zero and name
all four offending paths. The valid extension-map and override fixture passes
both commands in `TestHelmAcceptsExtensionMapsAndCollectorOverrides`.

The review reproduction now fails both Helm commands with:

```text
/config/collectors/entra.users: additional properties 'source' not allowed
```

`git diff --check` is clean. No review concern remains in the Helm lane.

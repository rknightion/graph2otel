# #265 Helm lane independent review

## Verdict

**CHANGES REQUIRED** before the complete #265 change can claim the planned Helm
inventory drift protection. The current schema is structurally sound for the
typed application config surface, and the real Helm typo diagnostics pass, but
the 148-name collector census is pinned rather than connected to the runtime
seven-path inventory.

## Findings

### High — the collector-name census is not runtime drift-gated

`TestCollectorOverrideSchemaHasBoundedNamesAndSourceEnum` reads the names back
from the schema, asserts the hard-coded count `148`, checks sorting/duplicates,
and samples seven representative names
(`charts/graph2otel/helm_contract_test.go:180-227`). The production enum is
itself a hand-written list
(`charts/graph2otel/values.schema.json:4-154`). No code in this test derives the
runtime logical collector names or compares the two exact sets.

Consequently, adding a collector to any runtime registration path while leaving
these two files untouched keeps this test green. Replacing an unsampled enum
member with another name while retaining 148 entries also keeps the census
portion green. This does not meet the plan's explicit requirement that a Go
contract test fail when a runtime collector is absent from the Helm schema
(`issue-265-plan.md:130-133`), which is assigned to the Helm regression/drift
test ownership (`issue-265-plan.md:142-148`). The lane report acknowledges the
missing runtime-inventory test (`issue-265-helm-report.md:90-96`).

Before #265 is complete, compare the schema enum with the exact logical-name set
derived from the frozen seven-path runtime visitor. The comparison must be
bidirectional so both missing and stale Helm names fail. It may be wired by the
command/integration lane, but the present two-file lane is not independently
drift-gated.

## Verified behavior

- The `config` schema is closed at every typed struct and has the exact current
  property set. The reflection contract recursively compares
  `config.Config`, closes structs, and verifies both collector-map references
  (`charts/graph2otel/helm_contract_test.go:173-178`,
  `charts/graph2otel/helm_contract_test.go:275-337`). The focused test passed.
- Intended open maps remain usable. `profiling.pyroscope.tags` accepts arbitrary
  string keys (`charts/graph2otel/values.schema.json:510-515`), while the Helm
  integration fixture also proves service-account annotations, pod
  annotations, pod labels, global collector overrides, and tenant collector
  overrides pass both lint and template
  (`charts/graph2otel/helm_contract_test.go:80-121`).
- Collector override values are closed and limited to `enabled`, `interval`,
  and `source`; `source` is exactly `graph|blob`
  (`charts/graph2otel/values.schema.json:157-174`). Both global and tenant
  collector maps use the same bounded-name and override definitions
  (`charts/graph2otel/values.schema.json:364-371`,
  `charts/graph2otel/values.schema.json:457-464`).
- Helm source **syntax** is proved, but source **applicability** is not a schema
  rule. The shared override definition permits either enum value for every
  known collector. Independently, both `helm lint` and `helm template` accepted
  `config.collectors.mdca.discovery_parse.source=graph`. This is consistent
  only if the command/config lane remains responsible for the plan's semantic
  rule that any non-empty source on a non-switchable collector fails
  (`issue-265-plan.md:51-56`). The Helm test currently covers an invalid enum
  token, not inapplicability
  (`charts/graph2otel/helm_contract_test.go:123-170`).
- The issue's four typo reproductions are covered for both real Helm commands
  (`charts/graph2otel/helm_contract_test.go:46-78`). Independent invocations of
  both commands exited non-zero and named the complete paths:
  `/persistence`, `/config`, `/config/otlp`, and
  `/config/collectors/entra.users`.

## Selective verification receipts

```text
go test -race ./charts/graph2otel -count=1 -v
PASS

go vet ./charts/graph2otel
exit 0

helm lint charts/graph2otel
1 chart(s) linted, 0 chart(s) failed

jq collector count/sort/unique/source-enum assertion
true

helm lint/template with the four typo values
both exit 1; all four full paths reported

helm lint/template with mdca.discovery_parse source=graph
both exit 0

git diff --check 066c8aa33710f007dc4295e0a87a78404515fc88 -- \
  charts/graph2otel/values.schema.json \
  charts/graph2otel/helm_contract_test.go
clean
```

No source files, commits, branches, pushes, or GitHub state were changed by this
review.

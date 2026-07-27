# #265 config-core and command-adapter review

READY

No severity findings in the config-core, command-adapter, or minimal
`main`/`check` wiring reviewed against
`066c8aa33710f007dc4295e0a87a78404515fc88`.

## Scope and binding contract

Read issue #265 and its maintainer comment in full. The binding decision is to
reject unknown YAML keys, collector names, transport values, and unknown
`G2O_*` variables during normal startup and `graph2otel check`, with diagnostics
that identify the exact offending key or variable.

Reviewed:

- `internal/config/config.go`
- `internal/config/env.go`
- `internal/config/strict.go`
- `internal/config/strict_test.go`
- the appended `internal/config/collectors_test.go` cases
- `cmd/graph2otel/config_validation.go`
- `cmd/graph2otel/config_validation_test.go`, excluding Helm-schema assertions
- the minimal `cmd/graph2otel/main.go` and `cmd/graph2otel/check.go` wiring

Helm schema, Helm tests, documentation, and examples were deliberately excluded
from this review.

## Evidence

- `internal/config/strict.go:16-122` validates the original YAML node tree
  before Koanf merging. Fixed structs are closed, sequence paths retain
  `tenants[index]`, collector map keys are quoted in full paths, collector map
  values remain typed and closed, and `map[string]string` tag values remain
  open.
- `internal/config/env.go:55-79` scans only `G2O_*`, sorts the environment for a
  deterministic first diagnostic, rejects unknown names by their exact variable
  spelling, and does not include values.
- `internal/config/env.go:81-143` derives fixed scalar environment names from the
  typed schema while preserving the established
  `G2O_COLLECTORS__<NAME>__(ENABLED|INTERVAL|SOURCE)` form.
- `internal/config/env.go:156-192` overlays dynamic collector environment
  fields onto the decoded YAML/default value, preserving field-level
  precedence and recording origins on the loaded `Config`, not in package
  globals.
- `internal/config/config.go:575-648` preserves defaults, then YAML, then
  environment precedence; retains the targeted removed-key diagnostic;
  enables unused-input rejection; applies dotted collector-name overrides
  without splitting the name; and leaves secret-file resolution last.
- `internal/config/strict.go:124-258` sorts collector names and suggestion
  candidates, rejects unknown global and tenant names, validates intervals,
  accepts only exact `graph`/`blob`, rejects `source` on non-switchable
  collectors, reports collector environment origins, and suppresses tied or
  distant suggestions.
- `cmd/graph2otel/config_validation.go:10-105` consumes the shared seven-family
  visitor, constructs only inert metadata, yields 148 logical names, and derives
  the three source-switchable collectors from the polled/blob intersection
  rather than a hand-maintained name list.
- `cmd/graph2otel/config_validation.go:107-123` validates collector identity and
  source before generic config validation. This preserves exact collector
  environment-origin diagnostics when an unknown collector also has an invalid
  interval.
- `cmd/graph2otel/main.go` and `cmd/graph2otel/check.go` call the shared loader
  before telemetry or credential construction. Their remaining startup,
  preflight, tenant, scheduler, admin, and #292 availability wiring is
  unchanged.
- `cmd/graph2otel/config_validation_test.go:20-65` pins the 148-name,
  seven-registration-path inventory and exact three-name source-switchable
  intersection.
- `cmd/graph2otel/config_validation_test.go:193-248` pins deterministic
  suggestions and the exact environment-origin precedence case.
- `cmd/graph2otel/config_validation_test.go:250-324` proves invalid and
  inapplicable sources stop both startup modes before telemetry or credential
  constructors.

## Verification

```text
go test -race ./internal/config ./cmd/graph2otel -count=1
ok github.com/rknightion/graph2otel/internal/config
ok github.com/rknightion/graph2otel/cmd/graph2otel

go vet ./internal/config ./cmd/graph2otel
exit 0

golangci-lint run --allow-parallel-runners ./internal/config/... ./cmd/graph2otel
0 issues.

git diff --check
exit 0
```

The parallel-runner flag was needed only because another lane held
golangci-lint's shared process lock.

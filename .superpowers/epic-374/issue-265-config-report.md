# #265 config-core lane report

## Outcome

Implemented strict application configuration parsing and the registry-dependent
collector override validation seam in `/tmp/graph2otel-265.A5nrFF`.

The command adapter API is:

```go
func (c *Config) ValidateCollectorOverrides(
    knownNames map[string]bool,
    sourceSwitchable map[string]bool,
) error
```

`Load` records collector environment origins in unexported per-`Config` state.
There is no package-global origin state and no exported origin map. The command
adapter should call `ValidateCollectorOverrides` before `Config.Validate` so an
unknown name wins over secondary interval validation and collector env failures
retain the exact `G2O_*` origin.

## Implemented behavior

- Parses a supplied YAML file as a `yaml.Node` before Koanf merging.
- Recursively derives the closed schema from the typed config structs.
- Reports full unknown-key paths, including `tenants[index]` and quoted dynamic
  collector names.
- Keeps `collectors`, `tenants[].collectors`, and
  `profiling.pyroscope.tags` open while validating each collector map value as
  a closed `CollectorConfig`.
- Enables mapstructure `ErrorUnused` as a defense-in-depth decode check.
- Derives the valid fixed scalar `G2O_*` names from the same typed schema.
- Rejects tenant/free-form-map env shapes and malformed collector override
  leaves by the exact variable name, without printing values.
- Applies `G2O_COLLECTORS__<NAME>__(ENABLED|INTERVAL|SOURCE)` separately after
  typed decode. This preserves names containing dots as one literal collector
  map key and retains defaults < YAML < env precedence.
- Preserves the targeted removed `cardinality.metric_limit` migration error.
- Validates global and per-tenant override names deterministically.
- Adds a unique bounded edit-distance suggestion and suppresses ties/distant
  guesses.
- Validates collector intervals, exact `graph`/`blob` source values, and source
  applicability against the caller-supplied Graph/blob intersection.
- Uses the exact originating collector `G2O_*` variable in semantic errors.
- Leaves existing `source: blob` runtime fallback behavior unchanged.
- Leaves secret-file resolution after all config layers, unchanged.

## Strict TDD receipts

Initial parser/env RED:

```text
go test ./internal/config -run 'Test(LoadRejectsUnknown|Strict.*)' -count=1
FAIL
- all six unknown YAML cases were accepted
- all five unknown G2O cases were accepted
- a dotted collector env name was not preserved
```

Parser/env GREEN:

```text
go test ./internal/config -run 'Test(LoadRejectsUnknown|Strict.*)' -count=1
ok github.com/rknightion/graph2otel/internal/config
```

Initial semantic RED:

```text
go test ./internal/config -run 'TestCollectorOverride' -count=1
FAIL (build)
cfg.ValidateCollectorOverrides undefined
```

Semantic GREEN:

```text
go test ./internal/config -run 'TestCollectorOverride' -count=1
ok github.com/rknightion/graph2otel/internal/config
```

## Fresh verification

```text
go test -race ./internal/config -count=1
ok github.com/rknightion/graph2otel/internal/config 1.777s

go vet ./internal/config
exit 0, no output

golangci-lint run ./internal/config/...
0 issues.

git diff --check
exit 0, no output

go test ./cmd/graph2otel \
  -run 'Test(CollectorOverrideInventory|LoadValidatedConfig|RunAndCheckRejectCollectorSources)' \
  -count=1
ok github.com/rknightion/graph2otel/cmd/graph2otel 1.160s

go test ./...
all repository packages passed
```

The last command exercised the sibling command-lane tests present in the shared
worktree; those command files are not owned or edited by this lane.

## Owned files changed

- `internal/config/config.go`
- `internal/config/env.go`
- new `internal/config/strict.go`
- new `internal/config/strict_test.go`
- existing `internal/config/collectors_test.go`
  - exact adjustment: added the `strings` import and appended collector semantic
    validation tests; no existing test body was changed

No command, chart, docs, example, AGENTS, git index, commit, push, or GitHub
state was changed by this lane.

## Integration note

The shared worktree also contains sibling-owned command and Helm changes. They
were visible during verification and were not edited by this lane.

# #265 command-adapter lane report

## Outcome

Implemented the command-local seven-path collector inventory and the shared
post-load validation gate in `/tmp/graph2otel-265.A5nrFF`.

The adapter now:

- constructs collector names from the existing
  `visitRegisteredCollectorFactories` contract across snapshot, window, blob,
  O365, MDCA, EXO, and Hunt;
- uses the existing inert window dependencies and zero/inert dependencies for
  the other paths, with no credentials or network I/O;
- returns 148 unique logical collector names;
- derives `source`-switchable names from the Graph-polled snapshot/window and
  blob-name intersection, yielding exactly:
  - `entra.directory_audits`
  - `entra.provisioning`
  - `entra.risk_detections`
- runs `config.Load`, `Config.Validate`, and
  `Config.ValidateCollectorOverrides` through one `loadValidatedConfig` helper
  shared by normal startup and `graph2otel check`;
- runs `ValidateCollectorOverrides` immediately after load and before
  `Config.Validate`, preserving exact `G2O_*` origin and unknown-name priority
  when an unknown collector also carries an invalid interval;
- fails override validation before telemetry construction in `run` and before
  credential construction in `dispatch check`.
- owns a cross-artifact drift gate that reads the Helm values schema and
  bidirectionally compares both runtime-derived inventories with the schema,
  including the frozen override `$ref` structure.

No auth, checkpoint, scheduler, preflight, telemetry-provider implementation,
collector inventory, internal config, Helm, docs, examples, or generated files
were changed by this lane.

## Owned files changed

- New: `cmd/graph2otel/config_validation.go`
- New: `cmd/graph2otel/config_validation_test.go`
- Minimal wiring/testability seam: `cmd/graph2otel/main.go`
- Minimal wiring/testability seam: `cmd/graph2otel/check.go`

The two package variables added to the existing command files
(`buildTelemetryProvider` and `buildTenantAuths`) let the regression test prove
that invalid/inapplicable sources stop before either constructor is called.
Production defaults remain the existing constructors.

## TDD receipt

RED:

```text
go test ./cmd/graph2otel -run 'TestCollectorOverrideInventory|TestLoadValidatedConfig|TestRunAndCheckRejectCollectorSources' -count=1

undefined: collectorOverrideInventory
undefined: loadValidatedConfig
undefined: buildTelemetryProvider
undefined: buildTenantAuths
FAIL github.com/rknightion/graph2otel/cmd/graph2otel [build failed]
```

The failure was the intended missing adapter/helper behavior.

GREEN:

```text
go test ./cmd/graph2otel -run 'TestCollectorOverrideInventory|TestLoadValidatedConfig|TestRunAndCheckRejectCollectorSources' -count=1
ok github.com/rknightion/graph2otel/cmd/graph2otel
```

Coverage added:

- exact 148-name logical inventory;
- one representative from each of all seven registration paths;
- exact switchable set plus an independent recomputation of the
  snapshot/window and blob intersection;
- unambiguous unknown-name suggestion;
- distant unknown name with no suggestion;
- invalid source spelling through `run` and `dispatch check`;
- inapplicable source through `run` and `dispatch check`;
- zero telemetry/credential constructor calls on both rejection paths.
- unknown environment collector with an invalid interval reports its exact
  `G2O_COLLECTORS__...` origin and unknown-name error before interval validation;
- Helm `definitions.collectorName.enum` exactly matches all runtime names in
  both directions;
- Helm `definitions.collectorOverrides.properties` exactly matches all runtime
  source-switchable names in both directions;
- every source-switchable property, the generic `additionalProperties`, and
  both global/tenant collector maps use the frozen schema references.

Validation-order RED:

```text
go test ./cmd/graph2otel -run TestLoadValidatedConfigReportsUnknownEnvironmentCollectorBeforeInvalidInterval -count=1

error "invalid config: collectors[\"entra.directory_audit\"].interval: 500ms ..."
does not name exact environment variable
does not prioritize the unknown collector diagnostic
FAIL
```

After moving override validation ahead of `Config.Validate`, the same command
passed and reported the exact environment-origin unknown-collector diagnostic.

The Helm lane's maintainable schema shape landed concurrently before the new
cmd-owned drift test's first run, so that cross-artifact characterization test
passed immediately. The Helm lane holds the schema RED/green receipt; this lane
owns the authoritative runtime-parity gate.

## Fresh verification

Final commands after the validation-order and schema-drift additions:

```text
go test ./cmd/graph2otel -run \
  'Test(HelmCollectorSchema|LoadValidatedConfig|CollectorOverrideInventory|RunAndCheckRejectCollectorSources)' \
  -count=1
ok github.com/rknightion/graph2otel/cmd/graph2otel 1.175s

go test -race ./cmd/graph2otel
ok github.com/rknightion/graph2otel/cmd/graph2otel 11.173s

go vet ./cmd/graph2otel
exit 0

golangci-lint run --allow-parallel-runners ./cmd/graph2otel
0 issues.

git diff --check
exit 0
```

The first final lint invocation encountered another lane's concurrent
`golangci-lint` process and exited with its runner-lock diagnostic. The explicit
parallel-runner retry above completed cleanly; this was tool contention, not a
finding.

## Integration notes

- The frozen config seam is consumed exactly as supplied:
  `func (c *Config) ValidateCollectorOverrides(knownNames, sourceSwitchable map[string]bool) error`.
- `cmd/graph2otel/collector_inventory.go` was read and consumed but not edited.
- The shared checkout also contains disjoint in-progress/final config and Helm
  lane changes. This lane did not alter those files.
- No files were staged, committed, pushed, or changed on GitHub.
- No open implementation concern remains in this lane. The coordinator still
  owns the combined config/command/Helm/docs gates and final `make check`.

# #265 — Strict configuration schema and override validation

## Status and decision receipt

Read-only plan against `main` at `f7339e805e40d2cc2b992a5ff4110c5995329fd6`. The
working tree contains staged #292 work; it is not part of this plan and must not
be edited, staged, or reset by #265.

The binding #265 receipt is: **“Maintainer decision: use the recommended strict
policy. Reject unknown YAML keys, collector names, transport values, and unknown
`G2O_*` environment variables at startup/check time; diagnostics name the exact
offending key or variable.”** There is no remaining policy choice.

## Validated premise

- `internal/config.Load` layers Koanf defaults, YAML and every `G2O_*` variable,
  then decodes without unused-key rejection. An unknown fixed YAML key therefore
  disappears before `Config.Validate` runs.
- `Config.CollectorSource` returns `blob` only for the exact string `blob`; every
  other value silently becomes `graph`.
- `Config.Validate` checks collector intervals but has no registry-backed name
  or source-applicability check. `run` and `graph2otel check` each call it after
  loading, so both require one shared post-load validation seam.
- `charts/graph2otel/values.schema.json` types only part of `config`, has no
  strict fixed objects, no collector-name constraint and no source enum. The
  issue's reproduced typo-heavy Helm lint can consequently pass.
- `cmd/graph2otel/collector_inventory.go` is the seven-registration-path visitor
  but is currently staged by #292. Its new inert-window factory helpers are the
  correct dependency for an inventory consumer; #265 must consume, not alter,
  that file.

## Behavioral contract

1. A supplied YAML document rejects every unknown field in a fixed object before
   defaults or environment overrides can mask it. Errors identify the complete
   config path, including `tenants[<index>]` and the actual collector map key.
2. Intentional extension maps remain open: `collectors` and
   `tenants[].collectors` accept a dynamic collector *name* while validating each
   value as a `CollectorConfig`; `profiling.pyroscope.tags` accepts arbitrary
   string keys. Kubernetes extension maps outside `config` remain open in Helm.
3. Every `G2O_*` variable is checked by its actual environment-variable spelling
   before decode. Only documented scalar paths and the established
   `G2O_COLLECTORS__<NAME>__(ENABLED|INTERVAL|SOURCE)` override shape are valid;
   flat variables cannot configure `tenants` or free-form tag maps. A bad name
   fails without printing its value (secrets included).
4. Global and per-tenant collector override names must be in the runtime
   seven-path inventory. An unambiguous nearest known name is appended as
   `did you mean ...`; ties/no close candidate contain no guess. Error paths are
   `collectors["…"]` and `tenants[i].collectors["…"]`, and an environment
   origin reports the actual offending `G2O_*` name.
5. `source` is unset or exactly `graph`/`blob`. A non-empty source is legal only
   for a source-switchable collector (the runtime intersection of polled and
   blob names); applying even `graph` to another collector is an inapplicable
   transport error. Existing `source: blob` plus no configured blob account
   retains its intentional graph fallback; this issue does not change transport
   registration or checkpoint semantics.
6. Both normal startup and `graph2otel check` fail before credentials, tenant
   construction, checkpoint verification, schedulers, or network work. Helm
   rejects equivalent fixed-key/name/enum mistakes at lint/template time.

## Strict TDD execution plan

1. **RED — configuration parser and environment boundary** (`internal/config/strict_test.go`).
   Add table-driven failing tests for unknown top-level, nested, tenant and
   collector-value YAML keys, asserting the full path; an unknown top-level and
   nested `G2O_*` variable asserting its exact original variable name; and valid
   arbitrary `tags`/collector-map syntax. Run and observe failure:

   ```sh
   go test ./internal/config -run 'Test(LoadRejectsUnknown|Strict.*)' -count=1
   ```

2. **RED — inventory-backed override validation** (`internal/config/collectors_test.go`,
   new `cmd/graph2otel/config_validation_test.go`). Add tests for unknown global
   and tenant names (one unique suggestion and one ambiguous/no-suggestion
   case), bad source spelling, `source` on a non-switchable name, both accepted
   source values on a switchable name, and the same faults through `run` and
   `dispatch check`. Assert neither CLI path reaches auth/network construction.
   Run:

   ```sh
   go test ./internal/config ./cmd/graph2otel -run 'Test(CollectorOverride|ConfigValidation|Run.*Config|Dispatch_Check)' -count=1
   ```

3. **Implement the minimal config-owned syntax validator** in
   new `internal/config/strict.go`. Before `koanf.Load` reads
   a supplied file, parse its YAML node tree and recursively validate YAML tags
   from the typed config structs: structs are closed, sequences recurse into
   their element type, `map[string]CollectorConfig` validates its values but not
   its names, and `map[string]string` remains open. Configure decoding to reject
   remaining unused input as a defense-in-depth invariant, then preserve the
   current defaults → YAML → env precedence and secret-file resolution.

4. **Implement exact environment-name validation** beside `envKey` in
   `internal/config/env.go`. Derive valid scalar paths from the same typed schema
   so a newly added fixed config field cannot be silently accepted in YAML but
   forgotten in env validation. Scan only `G2O_*`, reject unsupported collection
   paths and unknown leaves by actual variable name, and never echo a value.
   Keep Azure credential variables outside this namespace untouched.

5. **Implement semantic collector validation without a config→collectors import
   cycle.** Add an exported config function that accepts a complete known-name
   set, source-switchable-name set, and optional config-key-to-environment-origin
   lookup; it validates global/per-tenant overrides, interval paths, source enum
   and applicability, and makes the bounded suggestion deterministically. Add a
   new command-local inventory consumer (not an edit to
   `collector_inventory.go`) that uses the frozen seven-path visitor plus
   `snapshotWindowDeps` to construct names without network I/O. The inventory
   must include snapshot, window, blob, O365, MDCA, EXO and hunting factories;
   derive switchability from the polled/blob name intersection rather than a
   hand-maintained list.

6. **Wire one post-load check into both CLI entry points** (`cmd/graph2otel/main.go`,
   `cmd/graph2otel/check.go`, or a new command-local `load_config.go`). The
   common helper performs `config.Load`, static `Config.Validate`, inventory
   validation, and returns the same error style to `run` and `runCheck`. Do not
   change their later readiness, auth, preflight, telemetry, or scheduler paths.

7. **RED then implement Helm parity** (`charts/graph2otel/values.schema.json`,
   `charts/graph2otel/helm_contract_test.go`). First add a Helm test invoking
   the issue's typo-heavy `helm lint`/`helm template` values and a valid
   free-form map fixture; it must fail before the schema change. Make every
   fixed application object closed with `additionalProperties: false`; define
   collector override values as `{enabled:boolean, interval:string,
   source:enum(graph,blob)}`, restrict collector property names to the generated
   seven-path inventory, and retain dynamic `tags` plus chart/Kubernetes
   extension maps. Ensure the schema covers every presently shipped config key,
   not merely the subset it currently declares.

8. **Add drift protection and operator wording.** A Go schema/inventory contract
   test must fail when a runtime collector or config field is absent from the
   Helm schema or when a switchable collector/source enum drifts; the test owns
   the chart `config` subtree only, leaving arbitrary chart extensions open.
   Update the strictness paragraph in `docs/configuration.md` and the relevant
   comments in `config.example.yaml` to state that unknown YAML and `G2O_*`
   names fail at startup, that only collector override leaves have the dynamic
   env form, and that `source` is restricted to source-switchable collectors.
   This is targeted #265 contract documentation, not #380's broader doc audit.

## Tracked file ownership

| Owner | Files | Notes |
| --- | --- | --- |
| #265 config syntax | `internal/config/config.go`, `internal/config/env.go`, new `internal/config/strict.go` | YAML/env key validation and public semantic-validation input seam; no collector imports. |
| #265 config tests | new `internal/config/strict_test.go`, `internal/config/collectors_test.go` | RED/green parser, env, path, source and suggestion receipts. |
| #265 command adapter | new `cmd/graph2otel/config_validation.go` (and `_test.go`), `cmd/graph2otel/main.go`, `cmd/graph2otel/check.go` | Seven-path inventory consumer and the shared startup/check gate. |
| #265 Helm | `charts/graph2otel/values.schema.json`, `charts/graph2otel/helm_contract_test.go` | Strict `config` schema plus regression fixtures/drift test. |
| #265 operator contract | `config.example.yaml`, `docs/configuration.md` | Only strict-config wording. |
| Explicitly not #265 | `cmd/graph2otel/collector_inventory.go`, availability/admin/telemetry/Grafana files, broad README/docs-site files | First is #292's shared staged seam; the rest belong to other children. |

## Shared seams and child conflicts

- **#292:** prerequisite owner of the staged `collector_inventory.go` refactor.
  #265 must start after its inventory helpers are committed, add a separate
  consumer, and use the exact seven-family visitor. Do not copy its inert-factory
  logic or modify its availability/admin/Grafana work.
- **#266:** its binding authenticated-identity policy may adjust `client_id` and
  `exclude_self` semantics. #265 validates only structural key legitimacy; it
  must not reintroduce client-ID value matching, auth interpretation, or any
  self-exclusion diagnostic.
- **#268:** its binding delivery-health policy owns exporter/admin/readiness
  state. #265's fail-fast occurs before that lifecycle; no readiness change,
  delivery metric, exporter wrapper, or admin field belongs here.
- **#289:** it consumes #269's record-outcome attribution and will add
  collector/transport accounting. #265 may use existing collector names solely
  as configuration identifiers; it must not add cost/volume labels, counters or
  schema keys.
- **#291:** ordered streaming owns logpipeline emission/checkpoint behavior.
  Preserve `source: blob` fallback and existing source-selection predicates;
  neither page emission nor retry/checkpoint semantics change here.
- **#380:** coordinate one-file ownership for `docs/configuration.md`; #265 owns
  only the strictness paragraph and config-example comments. #380 must retain
  that contract while doing its broader documentation reconciliation.

## Generated artifacts and gates

- `charts/graph2otel/values.schema.json` is a tracked schema artifact. Its new
  config/collector inventory drift test must be green before commit.
- Do not regenerate `docs/env-vars.md` unless the strictness wording changes a
  generated block (it adds no env keys); do not regenerate collector docs,
  Grafana assets, signal catalog or Helm README unless their existing gates
  demonstrate a required diff.
- Run focused RED commands above, then `go test -race ./internal/config
  ./cmd/graph2otel ./charts/graph2otel`, `helm lint charts/graph2otel`, and the
  issue's typo-heavy `helm lint -f <temp-values>` receipt. Finish with
  `make check`; run `make grafana-check` only as the repository-wide generated
  asset gate before the final coordinated commit, expecting no #265-owned
  Grafana diff.

## Risks and protections

- A generic YAML parser can accidentally close intentional maps or expose a
  secret value. Test open-map fixtures; errors include paths/names only, never
  values.
- A hand-maintained collector list would immediately drift from a seventh/eighth
  path. Derive it through the compile-time visitor and test all seven paths.
- Helm's values merge must keep dynamic collectors and Kubernetes extension maps
  usable. Restrict only fixed objects and test a valid override plus free-form
  labels/annotations/tags.
- Rejecting unknown env variables is deliberately breaking for misspellings;
  preserve exactly documented existing `G2O_*` paths and the established
  collector override form, with a migration-quality exact-name diagnostic.

## Maintainer question

**NONE.** The strict fail policy, including unknown `G2O_*` handling, is
explicitly approved on #265.

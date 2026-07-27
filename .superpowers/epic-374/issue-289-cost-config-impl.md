# Issue #289 cost configuration implementation

## Outcome

Implemented the root `cost` application configuration and the matching Helm
values/schema/documentation contract in the isolated worktree
`/tmp/graph2otel-289.Y9NQNW`.

Owned files are frozen. Nothing was staged, committed, pushed, or written to
GitHub.

## Exported Go seam

`config.Config` now exposes:

```go
Cost CostConfig `yaml:"cost"`
```

The types are:

```go
type CostConfig struct {
    Enabled          bool            `yaml:"enabled"`
    Currency         string          `yaml:"currency"`
    Version          string          `yaml:"version"`
    Source           string          `yaml:"source"`
    EffectiveAt      string          `yaml:"effective_at"`
    Period           time.Duration   `yaml:"period"`
    Rates            CostRatesConfig `yaml:"rates"`
    BudgetMicrounits int64           `yaml:"budget_microunits"`
}

type CostRatesConfig struct {
    SourceRecord           *int64 `yaml:"source_record_microunits"`
    MetricPoint            *int64 `yaml:"metric_point_microunits"`
    LogRecord              *int64 `yaml:"log_record_microunits"`
    TransmittedPayloadByte *int64 `yaml:"transmitted_payload_byte_microunits"`
}
```

The pointers are deliberate: an omitted rate remains `nil`, while an explicit
zero becomes a non-nil pointer to zero through both YAML and environment
loading.

Exact environment paths accepted by the strict reflected registry are:

- `G2O_COST__ENABLED`
- `G2O_COST__CURRENCY`
- `G2O_COST__VERSION`
- `G2O_COST__SOURCE`
- `G2O_COST__EFFECTIVE_AT`
- `G2O_COST__PERIOD`
- `G2O_COST__RATES__SOURCE_RECORD_MICROUNITS`
- `G2O_COST__RATES__METRIC_POINT_MICROUNITS`
- `G2O_COST__RATES__LOG_RECORD_MICROUNITS`
- `G2O_COST__RATES__TRANSMITTED_PAYLOAD_BYTE_MICROUNITS`
- `G2O_COST__BUDGET_MICROUNITS`

## Defaults and validation

Defaults:

- disabled;
- 30-day projection period (`720h`);
- empty operator-supplied currency/version/source/effective timestamp;
- all four rates omitted (`nil`);
- budget `0`, meaning no comparison;
- no vendor prices.

When enabled, validation requires:

- an ASCII uppercase three-letter currency code;
- nonblank version and source;
- an RFC3339 `effective_at`;
- a positive period;
- all four rate fields explicitly present;
- every rate to be a nonnegative integer;
- a nonnegative budget (`0` disables comparison).

Explicit zero rates are accepted. The configuration remains observational and
contains no enforcement/drop setting.

## Helm contract

Updated:

- `charts/graph2otel/values.yaml`
- `charts/graph2otel/values.schema.json`
- `charts/graph2otel/README.md.gotmpl`
- generated `charts/graph2otel/README.md`
- `charts/graph2otel/helm_contract_test.go`

The disabled chart defaults use `null` rates. The schema closes the `cost` and
`cost.rates` objects, permits integer-or-null rates while disabled, rejects
negative rates and budgets, and conditionally requires complete concrete rate
and provenance values when enabled. Helm tests prove explicit-zero rates pass
and incomplete/invalid enabled configurations fail.

## TDD receipts

Observed RED:

1. `TestCostDefaultsDisabledWithoutVendorRates` failed to compile because
   `Config.Cost` did not exist.
2. `TestValidateCostContract` failed every invalid-case subtest because no cost
   validation existed.
3. `TestExampleConfigCoversEveryKey` and
   `TestHelmValuesConfigCoversEveryKey` reported the same 11 missing `cost`
   leaves.
4. `TestHelmCostConfigRequiresCompleteOperatorSuppliedRates` rejected the valid
   cost overlay because `/config` did not allow `cost`.
5. The zero-period Helm case was accepted until the enabled-period schema
   constraint was added.

Observed GREEN:

```text
go test -race ./internal/config -skip '^TestEnvReferenceDocInSync$' -count=1
ok github.com/rknightion/graph2otel/internal/config

go test -race ./charts/graph2otel -count=1
ok github.com/rknightion/graph2otel/charts/graph2otel

go vet ./internal/config ./charts/graph2otel
PASS

golangci-lint run ./internal/config/... ./charts/graph2otel/...
0 issues.

helm lint charts/graph2otel
1 chart(s) linted, 0 chart(s) failed

helm template test charts/graph2otel
PASS

helm template test charts/graph2otel <complete enabled explicit-zero cost flags>
PASS

make helm-docs
PASS

git diff --check -- internal/config/config.go internal/config/config_test.go \
  config.example.yaml charts/graph2otel
PASS
```

## Required integration follow-up

Per the lane boundary, `docs/env-vars.md` was not edited. The unskipped focused
race command therefore has exactly one expected failure:

```text
go test -race ./internal/config ./charts/graph2otel -count=1
--- FAIL: TestEnvReferenceDocInSync
docs/env-vars.md is out of date with config.example.yaml
```

Integration must regenerate the env reference after merging this lane:

```sh
scripts/regen-generated.sh envref
```

Then rerun the unskipped config/chart race test and the repository full gate.

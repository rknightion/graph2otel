---
title: Environment Variables
description: Reference every G2O_* environment variable, its default value, configuration precedence, and the graph2otel behavior it controls.
---

# Environment-variable reference

Every non-structured configuration field is settable from an environment
variable, so a container deployment needs no mounted config file at all (and the
env layer overrides any file that *is* present — keep secrets here, never in
YAML). See [`configuration.md`](configuration.md) for the layering model and the
prose reference, and
[`../config.example.yaml`](https://github.com/rknightion/graph2otel/blob/main/config.example.yaml)
for the same fields as a commented file.

**Naming.** Take the dotted config key, prefix it with `G2O_`, uppercase it, and
replace each `.` with `__` (a single `_` inside a name is preserved):

```text
otlp.grafana_cloud.token   ->  G2O_OTLP__GRAFANA_CLOUD__TOKEN
cardinality.global_limit   ->  G2O_CARDINALITY__GLOBAL_LIMIT
```

**Secrets and auth.** Tenant credentials are NEVER read from this config surface
at all — `azidentity.DefaultAzureCredential` reads `AZURE_TENANT_ID` /
`AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_CLIENT_CERTIFICATE_PATH` (or
ambient workload/managed identity) at run time. The only credential in the table
below is `otlp.grafana_cloud.token`; set it via `G2O_OTLP__GRAFANA_CLOUD__TOKEN`,
never in committed YAML.

> This table is **generated** from
> [`../config.example.yaml`](https://github.com/rknightion/graph2otel/blob/main/config.example.yaml).
> Do not edit between the markers; run `scripts/regen-generated.sh envref` (or
> `go test ./internal/config -run TestEnvReferenceDocInSync -update`) to refresh it.

<!-- BEGIN GENERATED: env-vars -->

| Environment variable | Default | Description |
| --- | --- | --- |
| `G2O_LOG_LEVEL` | `info` | debug \| info \| warn \| error |
| `G2O_OTLP__PROTOCOL` | `http` | grpc \| http \| stdout (stdout = print signals to the console for local debug, no backend) |
| `G2O_OTLP__ENDPOINT` | `https://otlp-gateway-prod-us-central-0.grafana.net/otlp` | OTLP base URL (the exporter appends /v1/metrics and /v1/logs itself) |
| `G2O_OTLP__GRAFANA_CLOUD__INSTANCE_ID` | `""` | Grafana Cloud OTLP instance ID |
| `G2O_OTLP__GRAFANA_CLOUD__TOKEN` | `""` | DO NOT set here — use G2O_OTLP__GRAFANA_CLOUD__TOKEN instead |
| `G2O_OTLP__GRAFANA_CLOUD__TOKEN_FILE` | `""` | OR read the token from a file (k8s/Docker secret mount); value XOR token, never both |
| `G2O_ADMIN__ENABLED` | `false` | run the admin health/readiness/status HTTP endpoint |
| `G2O_ADMIN__ADDR` | `:9090` | bind address for the admin endpoint |
| `G2O_ADMIN__REFRESH_INTERVAL` | `5s` | how often the status page re-polls /api/status.json (1s freshness ticker is independent) |
| `G2O_PROFILING__PYROSCOPE__ENABLED` | `false` | run the Pyroscope continuous-profiling push agent |
| `G2O_PROFILING__PYROSCOPE__SERVER_ADDRESS` | `""` | REQUIRED when enabled, e.g. http://pyroscope:4040 or https://profiles-prod-NNN.grafana.net |
| `G2O_PROFILING__PYROSCOPE__BASIC_AUTH_USER` | `""` | Grafana Cloud Profiles user/instance ID |
| `G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD` | `""` | DO NOT set here — use the env var above |
| `G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD_FILE` | `""` | OR read the password from a file (k8s/Docker secret mount); value XOR basic_auth_password, never both |
| `G2O_PROFILING__PYROSCOPE__TENANT_ID` | `""` | optional; leave empty for Grafana Cloud |
| `G2O_PROFILING__PYROSCOPE__UPLOAD_RATE` | `15s` | optional; 0/omit uses the pyroscope default |
| `G2O_PROFILING__MUTEX_PROFILE_FRACTION` | `5` | runtime.SetMutexProfileFraction; 0 = disabled |
| `G2O_PROFILING__BLOCK_PROFILE_RATE` | `100000` | runtime.SetBlockProfileRate (ns, 100µs); 0 = disabled |
| `G2O_CARDINALITY__PER_METRIC_LIMIT` | `5000` | per-metric active-series cap; beyond it the top series by value are kept and the tail folds into `other` (0 = unlimited) |
| `G2O_CARDINALITY__GLOBAL_LIMIT` | `100000` | total active-series cap across every metric; overage is absorbed by the worst offenders via max-min fairness (0 = unlimited) |
| `G2O_COST__ENABLED` | `false` | opt in to cost accounting; default off |
| `G2O_COST__CURRENCY` | `""` | uppercase 3-letter currency code, required when enabled |
| `G2O_COST__VERSION` | `""` | nonblank operator rate-schedule version, required when enabled |
| `G2O_COST__SOURCE` | `""` | nonblank operator rate source/provenance, required when enabled |
| `G2O_COST__EFFECTIVE_AT` | `""` | RFC3339 rate-schedule effective timestamp, required when enabled |
| `G2O_COST__PERIOD` | `720h` | positive projection period; 720h = 30 days |
| `G2O_COST__RATES__SOURCE_RECORD_MICROUNITS` | `null` | microunits per logical source record; explicit nonnegative integer required when enabled |
| `G2O_COST__RATES__METRIC_POINT_MICROUNITS` | `null` | microunits per emitted metric point; explicit nonnegative integer required when enabled |
| `G2O_COST__RATES__LOG_RECORD_MICROUNITS` | `null` | microunits per emitted log record; explicit nonnegative integer required when enabled |
| `G2O_COST__RATES__TRANSMITTED_PAYLOAD_BYTE_MICROUNITS` | `null` | microunits per post-compression OTLP payload byte; explicit nonnegative integer required when enabled |
| `G2O_COST__BUDGET_MICROUNITS` | `0` | nonnegative projection-period budget; 0 disables comparison |
| `G2O_BACKFILL__INITIAL_LOOKBACK` | `0s` | cold-start backfill window; 0 = each collector's own built-in lookback |
| `G2O_CHECKPOINT_DIR` | `./checkpoints` | root dir for the file-based CheckpointStore |
| `G2O_GRAFANA_ANNOTATIONS__URL` | `""` | Grafana base URL, e.g. https://grafana.example.com; setting it IS the opt-in (empty = feature off) |
| `G2O_GRAFANA_ANNOTATIONS__TOKEN` | `""` | Grafana service-account token; env/file only, never commit it (needs annotations:create only) |
| `G2O_GRAFANA_ANNOTATIONS__TOKEN_FILE` | `""` | path to a file holding the token; value XOR file, never both |
| `G2O_GRAFANA_ANNOTATIONS__DASHBOARD_UID` | `""` | optional: confine annotations to one dashboard; empty = organization annotations (visible to every board) |
| `G2O_GRAFANA_ANNOTATIONS__TIMEOUT` | `10s` | per-request timeout for POST /api/annotations |
| `G2O_GRAFANA_ANNOTATIONS__MAX_PER_MINUTE` | `60` | token-bucket ceiling on annotations written per process; overage is dropped and counted, never blocking |
| `G2O_GRAFANA_ANNOTATIONS__QUEUE_SIZE` | `512` | hand-off buffer; a full queue drops and counts rather than blocking collection |
| `G2O_GRAFANA_ANNOTATIONS__ROLLUP_INTERVAL` | `5m` | bucket width for rolled-up categories: one annotation per interval per category per tenant |
| `G2O_GRAFANA_ANNOTATIONS__DEDUPE_RETENTION` | `48h` | how long a published annotation's dedupe key is remembered, so a restart cannot re-publish it |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__CONFIG_POSTURE__ENABLED` | `true` | CA policy changes, Intune compliance/config policy changes, admin consent, app credential added |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__CONFIG_POSTURE__ROLLUP` | `true` | highest-volume of the four; rolled up by default so dashboards stay readable |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__SECURITY_INCIDENT__ENABLED` | `true` | medium/high security alerts and incidents becoming active |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__SECURITY_INCIDENT__ROLLUP` | `false` | naturally low volume, and a count would lose WHICH incident |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__SERVICE_HEALTH__ENABLED` | `true` | Microsoft 365 service-health incidents opening and closing |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__SERVICE_HEALTH__ROLLUP` | `false` | naturally low volume, and the single most useful annotation when a dashboard is red |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__LICENSE__ENABLED` | `true` | subscribed-SKU set changes and license exhaustion |
| `G2O_GRAFANA_ANNOTATIONS__CATEGORIES__LICENSE__ROLLUP` | `true` | a tenant-wide license change moves many SKUs at once |

**File-only** — these take structured values (a map or a list of objects) and must be set in the YAML config, not via an environment variable: `tenants`, `collectors`, `profiling.pyroscope.tags`.

<!-- END GENERATED: env-vars -->

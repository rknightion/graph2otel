---
title: Environment Variables
description: Every G2O_* environment variable, its default, and what it controls
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
cardinality.metric_limit   ->  G2O_CARDINALITY__METRIC_LIMIT
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
| `G2O_ADMIN__ENABLED` | `false` | run the admin/health HTTP endpoint (liveness + per-collector status) |
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
| `G2O_CARDINALITY__METRIC_LIMIT` | `2000` | hard per-instrument active-series cap; beyond it the SDK collapses extras into otel.metric.overflow (0 = unlimited) |
| `G2O_BACKFILL__INITIAL_LOOKBACK` | `0s` | cold-start backfill window; 0 = each collector's own built-in lookback. Warns past 7d (the measured OTLP accept window, #226) |
| `G2O_CHECKPOINT_DIR` | `./checkpoints` | root dir for the file-based CheckpointStore |

**File-only** — these take structured values (a map or a list of objects) and must be set in the YAML config, not via an environment variable: `tenants`, `collectors`, `profiling.pyroscope.tags`.

<!-- END GENERATED: env-vars -->

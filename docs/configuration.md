# Configuration

Config is layered, lowest precedence first: **built-in defaults** < an optional
**YAML file** (`--config path.yaml`) < **`G2O_*` environment variables**. A key you omit
from the YAML file keeps its default; env always wins over both. See
[`config.example.yaml`](https://github.com/rknightion/graph2otel/blob/main/config.example.yaml)
in the repo for the fully-commented authoritative source this page mirrors.

No config file is required at all — with no `--config` flag, graph2otel runs from
built-in defaults plus whatever `G2O_*` environment variables are set, which is the
container-friendly path (see [Getting Started](getting-started.md)).

## Environment variable mapping

Every key is settable via an environment variable named with the **`G2O_`** prefix and
**`__`** (double underscore) as the nesting delimiter. A single underscore inside a field
name (e.g. `client_id`, `log_level`) is preserved as-is — only level boundaries use `__`:

| YAML key | Environment variable |
| --- | --- |
| `log_level` | `G2O_LOG_LEVEL` |
| `otlp.protocol` | `G2O_OTLP__PROTOCOL` |
| `otlp.endpoint` | `G2O_OTLP__ENDPOINT` |
| `otlp.grafana_cloud.instance_id` | `G2O_OTLP__GRAFANA_CLOUD__INSTANCE_ID` |
| `otlp.grafana_cloud.token` | `G2O_OTLP__GRAFANA_CLOUD__TOKEN` |
| `admin.enabled` | `G2O_ADMIN__ENABLED` |
| `admin.addr` | `G2O_ADMIN__ADDR` |
| `checkpoint_dir` | `G2O_CHECKPOINT_DIR` |
| `backfill.initial_lookback` | `G2O_BACKFILL__INITIAL_LOOKBACK` |
| `collectors.sign_ins.enabled` | `G2O_COLLECTORS__SIGN_INS__ENABLED` |
| `collectors.sign_ins.interval` | `G2O_COLLECTORS__SIGN_INS__INTERVAL` |

`tenants` is the one section env cannot express: a flat environment variable can't
represent a list of structs, so multi-tenant setups need the YAML file for `tenants:`
even if every other key comes from the environment.

## Top-level keys

### `log_level`

`debug` | `info` | `warn` | `error`. Default `info`.

### `tenants`

A list of Entra tenants to poll. At least one entry is required unless
`otlp.protocol` is `stdout`. Each entry:

```yaml
tenants:
  - tenant_id: "00000000-0000-0000-0000-000000000000" # Entra tenant GUID or verified domain
    client_id: "" # app registration (application) ID; optional if AZURE_CLIENT_ID is set
    collectors: # optional per-tenant overrides — see "Per-collector overrides" below
      sign_ins:
        enabled: false
```

`tenant_id` / `client_id` are **non-secret identifiers only** — they select which
tenant/app registration a collector run targets. Auth material (client secret,
certificate, or workload/managed identity) always comes from environment variables read
by `azidentity.DefaultAzureCredential` — never from this file. See
[Getting Started](getting-started.md#auth-setup).

### `otlp`

```yaml
otlp:
  protocol: http # grpc | http | stdout
  endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
  grafana_cloud:
    instance_id: ""
    token: ""
```

- `protocol` — `grpc`, `http`, or `stdout`. `stdout` prints OTLP-shaped metrics and logs
  to the console instead of exporting over the network — the local-debugging path, and
  the only mode that's allowed to run with zero configured tenants.
- `endpoint` — the OTLP receiver URL. Defaults to Grafana Cloud's US-central OTLP
  gateway; override for another region or backend.
- `grafana_cloud.instance_id` / `.token` — Grafana Cloud OTLP auth. **`token` is a
  credential and must be set via `G2O_OTLP__GRAFANA_CLOUD__TOKEN`, never written into
  YAML** — it's documented here only to name the key.

### `collectors`

Global per-collector overrides, keyed by collector name, applied across every tenant:

```yaml
collectors:
  sign_ins:
    enabled: true
    interval: "5m" # duration string: "30s", "5m", "168h" (minimum 1s)
```

A collector absent from this map runs **enabled at its built-in default interval**.
`enabled` unset means "default true", which is distinct from an explicit `false` — the
config layer tracks that difference so a lower layer's explicit disable isn't silently
overridden by a higher layer's absence of an opinion. `interval` unset (or `0`) means
"use the collector's built-in default".

#### Per-collector overrides (tenant beats global)

The same `CollectorConfig` shape (`enabled` / `interval`) appears both at the top level
(`collectors:`, applied to every tenant) and per-tenant (`tenants[].collectors:`).
Resolution order, field-by-field:

**per-tenant override > global `collectors:` > collector's built-in default**

So one tenant can disable a collector — or retune its poll interval — that the rest of
the fleet keeps at its default, without touching the global block.

#### Experimental / beta collectors are opt-in, not default-on

Some collectors depend on a Microsoft Graph **`beta`** endpoint with no `v1.0`
equivalent (see [Signals](signals.md) and the per-collector reference for which ones).
These never register on the implicit "unset means enabled" default — they require an
**explicit** `enabled: true` at some config layer (global or per-tenant) before they run
at all. Setting `enabled: false` (or leaving a collector unmentioned) both mean "not
explicitly enabled" for this purpose; only an explicit `true` opts in. This is a
deliberate stability gate: a beta Graph endpoint can change shape or disappear without
the same compatibility guarantees as `v1.0`.

### `admin`

```yaml
admin:
  enabled: false
  addr: ":9090"
```

Exposes an operator health/status HTTP endpoint (liveness + per-collector status).
Disabled by default. When enabled, the status page also renders a per-tenant
**throttle-headroom** panel — the live client-side rate-limiter state (limit/s, burst,
tokens available, headroom %) for each Graph workload the tenant has actually hit since
start-up — so you can see how close a tenant is running to Graph's throttling ceilings.

### `profiling`

```yaml
profiling:
  pyroscope:
    enabled: false
    server_address: ""            # REQUIRED when enabled, e.g. https://profiles-prod-NNN.grafana.net
    basic_auth_user: ""           # Grafana Cloud Profiles user/instance ID
    basic_auth_password: ""       # supply via env, NEVER here — see below
    tenant_id: ""                 # optional; leave empty for Grafana Cloud
    upload_rate: 15s              # optional; 0/omit uses the pyroscope default
    tags: {}                      # optional static labels attached to every profile
  mutex_profile_fraction: 5       # runtime.SetMutexProfileFraction; 0 = disabled
  block_profile_rate: 100000      # runtime.SetBlockProfileRate (ns); 0 = disabled
```

Optional Grafana Pyroscope **continuous profiling**, off by default. graph2otel does not
expose an HTTP `pprof` endpoint — it only *pushes* profiles to Pyroscope, so nothing is
served or scrapeable from the process. Enabling it has no effect on the exporter's core
job, and a failure to reach Pyroscope is non-fatal (logged, then the process carries on).

`pyroscope.server_address` is required when `enabled` is true. `basic_auth_user` /
`basic_auth_password` authenticate to Grafana Cloud Profiles; on a self-hosted Pyroscope
they can be left empty. `upload_rate` controls how often profiles are flushed (default
`15s`); `tags` attaches static labels to every profile.

`mutex_profile_fraction` and `block_profile_rate` turn on the Go runtime's mutex- and
block-contention sampling that feed the corresponding Pyroscope profiles. Sampling them
is not free, so leave the defaults unless you are actively investigating contention.

`basic_auth_password` is a secret — set it via `G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD`,
never in committed YAML (see [Secrets](#secrets--what-never-belongs-in-this-file)). Every
field here also has a `G2O_PROFILING__*` env var — see [Environment variables](env-vars.md).

### `checkpoint_dir`

```yaml
checkpoint_dir: "./checkpoints"
```

Root directory for the file-based checkpoint store. Every window (log-stream) collector
persists its per-(tenant, endpoint) watermark under here, namespaced so a restart
resumes from `watermark - overlap` rather than re-fetching or dropping data across
out-of-order arrivals. See [Architecture](architecture.md#checkpointing).

### `backfill`

```yaml
backfill:
  initial_lookback: 0s
```

How far back a window (log) collector reaches on a **cold start** — no checkpoint yet:
a new tenant, a wiped volume, a first deploy. It bounds how much history that start
recovers.

`0` (the default) means *use each collector's own built-in lookback*, which is not one
value: most streams use 1h, `m365.unified_audit` 4h, `entra.security_incidents` 24h —
each tuned to its endpoint's data latency and throttling ceiling. A non-zero value
replaces **all** of them, so set it for a deliberate recovery rather than as a permanent
default.

It does not affect the steady state. Once a checkpoint exists, polling resumes from the
watermark, and a gap longer than a collector's max window is walked forward in capped
chunks across successive ticks — losslessly. This key only governs the case where there
is no checkpoint to resume from.

> **There is a ceiling, and exceeding it fails silently.** graph2otel ships logs over
> OTLP into Loki, which rejects samples older than `reject_old_samples_max_age` — about
> **13 days** on Grafana Cloud. A larger `initial_lookback` is not a longer recovery: it
> is a guaranteed drop at ingest. graph2otel polls Graph for the history, maps it, ships
> it, and reports no error, while the backend discards everything past its window. You
> see Graph calls being made, a clean log, and no data in Grafana — which is worse than
> a short lookback, because it looks like it is working.
>
> graph2otel **warns** past ~13d but deliberately does **not** clamp: a self-hosted Loki
> may be configured wider, and a non-Loki OTLP sink has its own rules, so graph2otel does
> not presume to know your backend's retention. If yours accepts more, ignore the warning.

## Secrets — what never belongs in this file

- Tenant credentials (client secret, certificate path, or workload/managed identity) are
  **never** read from `tenants[]` or any other key here — only from the environment
  variables `azidentity.DefaultAzureCredential` reads directly
  (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
  `AZURE_CLIENT_CERTIFICATE_PATH`).
- `otlp.grafana_cloud.token` is a credential and belongs in
  `G2O_OTLP__GRAFANA_CLOUD__TOKEN`, never in YAML.
- `config.local.yaml` and `.env` are gitignored in this repo for exactly this reason —
  don't commit a filled-in config that contains anything beyond tenant/client IDs.

See [Security](security.md) for the full rationale.

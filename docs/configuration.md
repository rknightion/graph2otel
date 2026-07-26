# Configuration

Config is layered, lowest precedence first: **built-in defaults** < an optional
**YAML file** (`--config path.yaml`) < **`G2O_*` environment variables**. A key you omit
from the YAML file keeps its default; a supported environment override always wins. See
[`config.example.yaml`](https://github.com/rknightion/graph2otel/blob/main/config.example.yaml)
in the repo for the fully-commented authoritative source this page mirrors.

No config file is required at all — with no `--config` flag, graph2otel runs from
built-in defaults plus whatever `G2O_*` environment variables are set, which is the
container-friendly path (see [Getting Started](getting-started.md)).

## Strict validation

Configuration mistakes stop the process. Normal startup and `graph2otel check` run the
same validation before constructing credentials, checkpoint stores, telemetry exporters,
collectors, or network clients:

- Unknown keys in fixed YAML objects fail with the complete path, including sequence
  indexes and collector map keys, such as
  `tenants[0].collectors["entra.directory_audits"].soruce`.
- Unknown `G2O_*` variables fail by their exact environment-variable name, such as
  `G2O_OTLP__GRAFANA_CLOUD__TOKNE`. Values are not included in these diagnostics.
- Collector override names must match a name in the generated
  [collector reference](collectors.md). An unambiguous near miss also gets a
  `did you mean "..."` suggestion.
- `source` must be unset or exactly `graph` or `blob`, and is accepted only for a
  source-switchable collector. Setting it on any other collector is an error, including
  an explicit `source: graph`.

Collector-name, interval, and source faults from YAML use paths such as
`collectors["entra.directory_audits"].source` or
`tenants[0].collectors["entra.directory_audits"].source`. The same faults supplied by
environment report the exact `G2O_COLLECTORS__...` variable instead.

The dynamic keys are deliberate and limited: collector-name maps remain open long enough
to validate names against the runtime registry, while `profiling.pyroscope.tags` accepts
arbitrary string keys. Their containing objects and collector override values remain
strict.

## Environment variable mapping

Fixed scalar keys are settable via environment variables named with the **`G2O_`** prefix
and **`__`** (double underscore) as the nesting delimiter. A single underscore inside a
field name (e.g. `log_level`) is preserved as-is — only level boundaries use `__`:

| YAML key | Environment variable |
| --- | --- |
| `log_level` | `G2O_LOG_LEVEL` |
| `otlp.protocol` | `G2O_OTLP__PROTOCOL` |
| `otlp.endpoint` | `G2O_OTLP__ENDPOINT` |
| `otlp.grafana_cloud.instance_id` | `G2O_OTLP__GRAFANA_CLOUD__INSTANCE_ID` |
| `otlp.grafana_cloud.token` | `G2O_OTLP__GRAFANA_CLOUD__TOKEN` |
| `admin.enabled` | `G2O_ADMIN__ENABLED` |
| `admin.addr` | `G2O_ADMIN__ADDR` |
| `admin.refresh_interval` | `G2O_ADMIN__REFRESH_INTERVAL` |
| `checkpoint_dir` | `G2O_CHECKPOINT_DIR` |
| `backfill.initial_lookback` | `G2O_BACKFILL__INITIAL_LOOKBACK` |
| `collectors["entra.signins.interactive"].enabled` | `G2O_COLLECTORS__ENTRA.SIGNINS.INTERACTIVE__ENABLED` |
| `collectors["entra.signins.interactive"].interval` | `G2O_COLLECTORS__ENTRA.SIGNINS.INTERACTIVE__INTERVAL` |
| `collectors["entra.directory_audits"].source` | `G2O_COLLECTORS__ENTRA.DIRECTORY_AUDITS__SOURCE` |

Global collector overrides are the only dynamic environment form:
`G2O_COLLECTORS__<NAME>__(ENABLED|INTERVAL|SOURCE)`. `<NAME>` is the exact collector
name uppercased, with dots and single underscores preserved. No other collector leaf is
accepted.

Structured `tenants` and free-form `profiling.pyroscope.tags` cannot be expressed by a
flat environment variable. Multi-tenant setups therefore need YAML for `tenants:`, and
profile tags must also stay in the file.

## Top-level keys

### `log_level`

`debug` | `info` | `warn` | `error`. Default `info`.

### `tenants`

A list of Entra tenants to poll. At least one entry is required unless
`otlp.protocol` is `stdout`. Each entry:

```yaml
tenants:
  - tenant_id: "00000000-0000-0000-0000-000000000000" # hyphenated Entra directory GUID
    client_id: "" # optional expected app ID; an assertion, not credential selection
    collectors: # optional per-tenant overrides — see "Per-collector overrides" below
      "entra.signins.interactive":
        enabled: false
```

`tenant_id` is required to be the hyphenated Entra directory GUID. Hex digits are
case-insensitive, but verified domains, arbitrary names, compact UUIDs and braced UUIDs
are rejected. graph2otel sets that GUID on every token request, permits the credential
to target only that directory, and verifies the returned token's `tid` before any
collector or tenant-labelled signal starts.

`azidentity.DefaultAzureCredential` independently selects one ambient application
identity for the process. A configured `client_id` is only an optional, non-secret
consistency assertion about that identity; it is never passed to the credential chain
and cannot select or override it. If it differs from the `appid` proved from the actual
Graph access token, startup warns once and the authenticated ID wins.

Client-secret and certificate material comes from the process environment. Workload
identity uses the platform-injected federated-token environment; managed identity uses
the host-assigned identity. `AZURE_CLIENT_ID` selects the single ambient workload or
user-assigned managed identity where required. Managed identity stays bound to its home
tenant and ignores a cross-tenant request; a returned `tid` mismatch fails that tenant
closed before data is emitted. None of that auth material belongs in this file. See
[Getting Started](getting-started.md#auth-setup).

When `exclude_self: true`, graph2otel compares record `appId` only with the authenticated
token's proved `appid`. If token acquisition or claim decoding cannot prove a non-empty
ID, the filter fails open: graph2otel retains every record and emits one bounded startup
warning for that tenant. A configured `client_id` alone is never proof.

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
  "entra.signins.interactive":
    enabled: true
    interval: "5m" # duration string: "30s", "5m", "168h" (minimum 1s)
```

A collector absent from this map runs **enabled at its built-in default interval**.
`enabled` unset means "default true", which is distinct from an explicit `false` — the
config layer tracks that difference so a lower layer's explicit disable isn't silently
overridden by a higher layer's absence of an opinion. `interval` unset (or `0`) means
"use the collector's built-in default". Collector names must match the generated
[collector reference](collectors.md) exactly.

`source` selects the ingest transport for the current source-switchable collectors:
`entra.directory_audits`, `entra.provisioning`, and `entra.risk_detections`. It is
optional; unset defaults to `graph`. The only accepted values are `graph` and `blob`.
Applying either value to any other collector is rejected:

```yaml
collectors:
  "entra.directory_audits":
    source: blob
```

#### Per-collector overrides (tenant beats global)

The same `CollectorConfig` shape (`enabled` / `interval` / `source`) appears at the top level
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

Exposes the operator health/status HTTP server. Disabled by default.

- `/healthz` is process liveness and does not depend on collector outcomes.
- `/readyz` returns 503 until the first successful collector run, then latches
  ready for the rest of the process lifetime.
- Partial tenant success is ready while failed tenants/collectors remain
  degraded in status. If no collector has ever succeeded, readiness stays 503.
- A zero-tenant `stdout` diagnostic run is ready immediately.
- Failure to bind `admin.addr` is fatal; the process never runs silently
  without its configured health surface.

The status page also renders a per-tenant **throttle-headroom** panel — the
live client-side rate-limiter state (limit/s, burst, tokens available,
headroom %) for each Graph workload the tenant has actually hit since start-up
— so you can see how close a tenant is running to Graph's throttling ceilings.

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
scalar field here also has a `G2O_PROFILING__*` env var; `tags` is file-only. See
[Environment variables](env-vars.md).

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

> **Grafana Cloud has a measured seven-day ceiling.** Its OTLP gateway strictly rejects
> entries older than **7 days**. The rejection is explicit and per-entry: an HTTP 400
> reaches the OTel error handler for each over-age entry, while in-window entries in the
> same batch remain accepted. `[live-measured 2026-07-22, #226]`
>
> Accepted in-window backdated records can be **indexed later** than fresh records. An
> immediately empty query is therefore not evidence of rejection; the explicit gateway
> response is. See [Backdated log records](signals.md#backdated-log-records-accepted-to-7-days-but-not-queryable-immediately).
>
> This value is **not clamped**. A self-hosted Loki may be configured wider, and a
> non-Loki OTLP sink has its own rules, so graph2otel does not generalize Grafana Cloud's
> measured ceiling to every backend. If yours accepts more, ignore the warning.

## Secrets — what never belongs in this file

- Tenant credentials (client secret, certificate path, or workload/managed identity)
  are **never** read from `tenants[]` or any other key here. They come from the ambient
  environment or host identity used by `azidentity.DefaultAzureCredential`.
- `tenants[].tenant_id` is the hyphenated directory GUID used to bind each token request
  and verify its returned `tid`. `tenants[].client_id` may assert the expected non-secret
  application ID, but it cannot choose the credential.
- `otlp.grafana_cloud.token` is a credential and belongs in
  `G2O_OTLP__GRAFANA_CLOUD__TOKEN`, never in YAML.
- `config.local.yaml` and `.env` are gitignored in this repo for exactly this reason —
  don't commit a filled-in config that contains anything beyond tenant/client IDs.

See [Security](security.md) for the full rationale.

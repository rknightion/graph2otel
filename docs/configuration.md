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
| `cost.enabled` | `G2O_COST__ENABLED` |
| `cost.period` | `G2O_COST__PERIOD` |
| `cost.rates.log_record_microunits` | `G2O_COST__RATES__LOG_RECORD_MICROUNITS` |
| `cost.budget_microunits` | `G2O_COST__BUDGET_MICROUNITS` |
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
    exclude_self: false
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

#### Per-tenant ingest and direct-API sources

The shipped registry has 154 logical collectors across 7 registration paths. These
tenant blocks enable or configure the non-default source paths; they are file-only because
the environment layer does not bind into the `tenants[]` slice:

```yaml
tenants:
  - tenant_id: "00000000-0000-0000-0000-000000000000"
    blob_ingest:
      account_url: "https://myaccount.blob.core.windows.net"
      metric_recency_window: 20m
    o365_activity:
      content_types: ["Audit.Exchange", "Audit.SharePoint"]
    mdca:
      portal_url: "https://<tenant>.<region>.portal.cloudappsecurity.com"
      token_file: "/run/secrets/mdca_token"
    exchange_online:
      enabled: true
    hunting:
      enabled: true
```

- `blob_ingest.account_url` is the opt-in for the read-only Azure Storage
  byte-offset consumer. The ambient identity needs **Storage Blob Data Reader** on the
  account; an Azure subscription Owner role does not grant blob-content reads.
  `metric_recency_window` defaults to `20m` and must be at most `1h`; older blob events
  still emit logs but not counters, so backfill is not credited to the current interval.
  Azure diagnostic delivery is at-least-once, so blob log duplicates are preserved and
  deduplicated downstream by record ID.
- `o365_activity.content_types` configures the default-on, stable-v1.0
  `m365.activity` collector. Empty means `Audit.Exchange` plus `Audit.SharePoint`.
  `Audit.AzureActiveDirectory`, `Audit.General`, and `DLP.All` are supported explicit
  additions; `DLP.All` requires `ActivityFeed.ReadDlp`. The API has no record-level
  server filter, so every record in a selected type is fetched and shipped.
  `Audit.General` is deliberately not a default: on the measured six-device tenant,
  3,865 of 4,035 records over 23 hours were Endpoint DLP. The common audit mapper does
  not emit `PolicyDetails`, `SensitiveInformation`, or `DetectedValues`; there is no
  dedicated `DLP.All` classification mapper.
- `mdca.portal_url` opts into Cloud Discovery parse health over the legacy MDCA portal
  API. `token_file` is required and contains the static portal token; the secret itself
  must not appear in YAML or an environment variable.
- `exchange_online.enabled` opts into the Exchange Online admin collectors. It needs
  both `Exchange.ManageAsApp` and an Entra directory role on the service principal
  (Security Reader is the least-privileged verified role).
- `hunting.enabled` opts into the Graph advanced-hunting query collectors. It needs
  `ThreatHunting.Read.All` and consumes a per-tenant CPU budget shared with interactive
  Defender portal queries.

These blocks do not map one-to-one to ingest engines. The 4 ingest engine shapes are
Graph window polling, async export jobs, Azure diagnostic blobs, and the O365 Management
Activity subscription/content-blob flow. Snapshot, MDCA, Exchange Online, and Hunt
collectors retain their direct API shapes.

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

It also exposes exact cumulative collector volume and process-level OTLP
transport totals. The optional cost view described below appears only when
`cost.enabled` is true. It is labelled **estimate, not invoice**.

### `cost`

```yaml
cost:
  enabled: false
  currency: ""
  version: ""
  source: ""
  effective_at: ""
  period: 720h
  rates:
    source_record_microunits: null
    metric_point_microunits: null
    log_record_microunits: null
    transmitted_payload_byte_microunits: null
  budget_microunits: 0
```

Cost projection is observational and disabled by default. graph2otel does not
ship a vendor price table or try to discover one. When enabled, the operator
must provide the currency and the identity, provenance, effective timestamp,
and rates for the schedule being modelled:

- `currency` — an upper-case three-letter ASCII currency code.
- `version` — a nonblank identifier for the supplied rate schedule.
- `source` — a nonblank description or reference identifying where the rates
  came from.
- `effective_at` — the schedule's RFC3339 effective timestamp.
- `period` — a positive duration used to project an observed interval. The
  default is `720h` (30 days).
- `rates.*` — four explicit, nonnegative integer rates: per logical source
  record, per emitted metric point, per emitted log record, and per
  post-compression OTLP payload byte. An explicit `0` is valid; an omitted rate
  is not valid while cost projection is enabled. Helm values are capped at
  `9007199254740991` so its YAML/JSON rendering path preserves each integer
  exactly.
- `budget_microunits` — a nonnegative comparison value for the projection
  period. `0` disables the comparison. The same Helm exact-integer cap applies.

A microunit is \(10^{-6}\) of the configured currency unit. Integer rates and
integer arithmetic keep the result exact at that scale without presenting
floating-point rounding as a billing fact.

The logical source-record, metric-point, and log-record components are exact
runtime counts. OTLP payload bytes are exact only for the process as a whole.
graph2otel allocates metric payload bytes over metric points and log payload
bytes over log points independently; one signal can never be charged to a
collector which emitted only the other. That allocation is always labelled
`estimated`. Signal bytes with no same-signal collector point share remain in
an explicit `_unattributed` / `process` row rather than disappearing. The
collector rows plus that row reconcile to the process interval estimate.

The interval estimate retains every traffic class. The configured-period
projection and budget ratio include `steady_state` only: a finite cold-start
backfill or replay is shown as interval cost but is never annualised as
recurring traffic. The admin waits for at least two complete metric-export
intervals and uses up to about ten minutes of observations to reduce exporter
cadence mismatch, refreshes the projection no more than once per minute, and
exposes the actual observed duration. A budget produces
only a ratio in the admin status and UI. Neither pricing nor a crossed budget
can sample, throttle, delay, disable, or drop a collector, and it cannot change
the cardinality limiter or exporter. See
[Volume, transport, and estimated cost](signals.md#volume-transport-and-estimated-cost)
for the exact measurement boundaries.

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
never in committed YAML (see [Secrets](#secrets-what-never-belongs-in-this-file)). Every
scalar field here also has a `G2O_PROFILING__*` env var; `tags` is file-only. See
[Environment variables](env-vars.md).

### `checkpoint_dir`

```yaml
checkpoint_dir: "./checkpoints"
```

Root directory for the file-based checkpoint store. Window collectors persist their
per-(tenant, endpoint) watermark and seen-ID overlap set; async jobs persist their job
and record cursor state; O365 Management Activity persists its arrival watermark plus
content- and record-ID sets; blob ingest persists exact byte offsets. A restart therefore
resumes each source's own cursor contract instead of inventing one universal timestamp
cursor. A correctly timestamped record with no ID still emits as undedupeable/degraded,
while a record with no parseable event time is dropped and counted rather than stamped
with arrival time. See [Architecture](architecture.md#checkpoints-and-delivery-semantics) and
[Signals](signals.md#event-time-and-dedupe-are-transport-contracts).

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
> The value still loads and validates as written, but the **poll is clamped to 165h**
> (#401) — deliberately 3h inside the 7-day window, because a rejection observed in
> production on 2026-07-27 was only about an hour past the limit. Reaching further back is
> not a longer recovery; it is the same recovery plus per-entry rejections. A self-hosted
> Loki may be configured wider and a non-Loki OTLP sink has its own rules, so raise the
> emit horizon deliberately if yours accepts more.

### `grafana_annotations`

The **opt-in Grafana annotation writer** — graph2otel's one non-OTLP egress path. Off unless
`url` is set. Full reference: [Grafana annotations](grafana-annotations.md).

```yaml
grafana_annotations:
  url: "" # Grafana base URL; setting it IS the opt-in
  token: "" # service-account token — env or token_file only, never here
  token_file: "" # path to a mounted token file; value XOR file
  dashboard_uid: "" # empty = organization annotations, visible to every board
  timeout: 10s
  max_per_minute: 60 # hard ceiling on writes; overage is dropped and counted
  queue_size: 512
  rollup_interval: 5m
  dedupe_retention: 48h
  categories:
    config_posture: { enabled: true, rollup: true }
    security_incident: { enabled: true, rollup: false }
    service_health: { enabled: true, rollup: false }
    license: { enabled: true, rollup: true }
```

The token needs exactly one Grafana action — `annotations:create` on
`annotations:type:organization` — and graph2otel uses no other Grafana permission. The built-in
**Annotations writer** role (`fixed:annotations:writer`) grants that plus `write` and `delete`,
which graph2otel never uses; the documented minimum is a custom role scoped to `create` alone.
See [The required Grafana permission](grafana-annotations.md#the-required-grafana-permission)
for the measured detail and how to create it.

Once `url` is set, **the process refuses to start** if the token cannot write an annotation.
That is deliberate: discovering it at the first real event means the annotations an operator
relies on for incident context are absent exactly when they look for them.

The persisted dedupe key set lives in `checkpoint_dir`, so it needs the same persistent
volume — without one, every restart republishes everything inside the source collectors'
overlap windows.

## Secrets — what never belongs in this file

- Tenant credentials (client secret, certificate path, or workload/managed identity)
  are **never** read from `tenants[]` or any other key here. They come from the ambient
  environment or host identity used by `azidentity.DefaultAzureCredential`.
- `tenants[].tenant_id` is the hyphenated directory GUID used to bind each token request
  and verify its returned `tid`. `tenants[].client_id` may assert the expected non-secret
  application ID, but it cannot choose the credential.
- `otlp.grafana_cloud.token` is a credential and belongs in
  `G2O_OTLP__GRAFANA_CLOUD__TOKEN`, never in YAML.
- `grafana_annotations.token` is a credential and belongs in
  `G2O_GRAFANA_ANNOTATIONS__TOKEN` or `grafana_annotations.token_file`, never in YAML.
- `config.local.yaml` and `.env` are gitignored in this repo for exactly this reason —
  don't commit a filled-in config that contains anything beyond tenant/client IDs.

See [Security](security.md) for the full rationale.

## The configuration fingerprint on the startup marker

Every process start emits a `graph2otel.startup` log record carrying a
**`config.fingerprint`** — 16 hex characters derived from the effective configuration, so a
dashboard can annotate "the configuration changed here" without publishing the
configuration. Two consecutive markers with different fingerprints mean something in this
file (or its environment overrides) changed between the restarts.

What matters for this file:

- **No configuration value is ever emitted, only the hash**, and the hash cannot be reversed
  into the configuration.
- **Credentials never enter the hash input at all.** Every credential key here is a
  redacting type, so `otlp.grafana_cloud.token`,
  `profiling.pyroscope.basic_auth_password` and `grafana_annotations.token` contribute the
  literal `REDACTED`. Tenant auth
  material is not on this surface in the first place.
- **Rotating a credential does not change the fingerprint.** Setting one that was previously
  unset does — that is a behavior change, not a secret.
- **Every key participates**, including keys added in later releases, so a cosmetic edit
  moves the fingerprint too. It over-reports rather than under-reports on purpose.
- **It is process-wide, not per-tenant.** Editing one tenant's block moves the fingerprint on
  every tenant's marker.
- **There is no key to turn it off**, by design — see
  [Signals](signals.md#graph2otelstartup-deploy-version-and-configuration-markers) for the
  full field set and the reasoning.

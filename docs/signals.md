# Signals

graph2otel exports every domain signal under one of three OTLP dot-notation
namespaces. A new collector emitting outside its domain's namespace is a bug, not a
style choice — see `CLAUDE.md`'s "Metric namespaces" section for the enforced
convention.

- **`entra.*`** — Entra ID directory, sign-in, and audit signals.
- **`intune.*`** — Intune device management and compliance signals.
- **`graph2otel.*`** — self-observability: collector success/duration/staleness,
  export-job health, active series counts, build info. Not tenant domain data.

For the exhaustive, per-collector metric/log/label reference (every gauge, counter, log
attribute set, and the Graph API permission scope each collector needs), see
[docs/collectors.md](collectors.md).

## OTLP → Prometheus name normalization

graph2otel emits **OTLP**; if your backend (Grafana Cloud, or any Prometheus-remote-write
receiver) ingests it into Mimir/Prometheus, names get **normalized**: dots become
underscores, and OTEL unit/type suffix rules may append `_total` (counters), `_seconds`,
`_bytes`, `_ratio`, and similar. So a metric this project documents as `entra.devices.total`
typically appears in PromQL as `entra_devices_total`; `graph2otel.scrape.errors` (a
counter) may land as `graph2otel_scrape_errors_total`.

Exact normalization depends on your OTLP→Prometheus pipeline configuration — some
setups preserve original names or omit the `_total` suffix. Treat the underscored form
as the convention to build dashboards/alerts against, not a byte-exact promise; expect to
adjust a query one clause if your pipeline normalizes differently. This is exactly the
convention the shipped [dashboards](https://github.com/rknightion/graph2otel/tree/main/dashboards)
are built against.

## Querying the logs in Loki — attributes are structured metadata, not stream labels

Every attribute graph2otel puts on a log record (`event_name`, `app_id`,
`user_principal_name`, `ip_address`, `activity_display_name`, `severity`, …) lands in Loki
as **structured metadata**, not as a stream label. Only `service_name` (and the OTLP
resource attributes) are stream labels. This changes how you write LogQL:

- A stream selector on an attribute — `{event_name="entra.signin"}` — matches **nothing**
  and returns zero rows silently. It is not an error; there just is no *stream label* by
  that name.
- Filter on attributes with a **`|` label-filter after** the `{service_name="graph2otel"}`
  stream selector instead:

  ```logql
  {service_name="graph2otel"} | event_name=`entra.signin` | app_id=`<guid>` | status_error_code!=`0`
  ```

  `=~` regex, `!=`, `or`, and `ip("…")` matchers all work directly on structured metadata
  after the selector. This is the form the shipped alert rules (e.g. the `entra-security-g2o`
  group) and any dashboard log panel must use — building a Grafana alert on
  `{event_name="…"}` is the single most common way to get a rule that silently never fires.

## Cardinality shape

**Metrics answer "how many"; logs answer "which one".** That is the single most useful
thing to know when querying graph2otel — the two pipelines answer different questions, and
per-entity detail lives in the logs.

Every metric this project emits carries **bounded, tenant-shaped** label dimensions —
counts by compliance state, operating system, policy name, risk level, license SKU, and
similar admin-configured categories. None grow with tenant size (user count, device
count, sign-in volume). So a metric tells you *three users are high-risk*; it will never
tell you *which* three.

High-cardinality per-entity data (UPNs, device IDs, IP addresses, correlation IDs) is
confined to the **logs** pipeline as structured attributes, never a metric label. It is
**not withheld** — graph2otel exports it by design, and every bounded aggregate metric has
a per-entity **log twin** carrying the detail behind it. To go from a metric to the
entities behind it, query the matching log stream:

| Question | Pipeline | Query |
| --- | --- | --- |
| How many users are at risk? | metric | `entra_risky_users_total{risk_level="high"}` |
| **Which** users are at risk? | logs | `{service_name="graph2otel"} \| event_name=`entra.risky_user` \| risk_level=`high`` |

Remember that log attributes are Loki **structured metadata**, not stream labels — the
label-filter form above (`\| event_name=…`) is required; a `{event_name="…"}` selector
matches zero rows silently. See the LogQL section above.

See [Security](security.md#the-cardinality-boundary-rule) for the full rule — including
why it is a cost/queryability rule rather than a privacy control — and
[docs/pii-cardinality-audit.md](pii-cardinality-audit.md) for the audit that confirmed it
holds against the actual collector source.

The rule is also **mechanically gated**, not just documented: every collector package runs
`internal/signalcapture` over the union of what its own tests emit, and a per-entity key on
a metric label fails `go test`. A collector package that does not install the gate fails
too, so a new one cannot ship unguarded. The gate reads metric labels only — per-entity
data on a **log** attribute is the design, not a violation.

## Attributes that mean the same thing on both M365 transports

`m365.unified_audit` (query API) and `m365.activity` (Management API) are twins over the
same underlying audit data, and both emit the event name `m365.audit`. The classic O365
schema carries **two distinct user identifiers**, and both transports now name them
identically:

| attribute | meaning | `m365.unified_audit` wire field | `m365.activity` wire field |
| --- | --- | --- | --- |
| `user_key` | classic **UserKey** — an opaque identifier | `userId` | `UserKey` |
| `user_principal_name` | classic **UserId** — the UPN, or a sentinel | `userPrincipalName` | `UserId` |

**There is no `user_id` attribute on either signal, and one must not be added back.** The
query API's top-level `userId` field is a Microsoft misnomer: its content is the classic
UserKey, not the classic UserId (live-verified 500/500 over one tenant and window,
2026-07-17). Both collectors map each field to what it *contains*, not to what it is
called. Anyone previously correlating the two signals on `user_id` was silently comparing
UserKeys against UserIds.

`user_principal_name` is **not always UPN-shaped** — about 9% of live records carry a bare
GUID, the literal `Not Available`, `ServicePrincipal_<guid>`, or a display name. Both
transports emit it verbatim with no shape gate, so do not assume an email address.

## Risk signals: the two transports are NOT interchangeable

Sign-ins are the same record whichever way they arrive — one shared mapper, byte-identical
output. **Risk is not**, and #141/#138 both reason from the sign-in case, so this is the
counter-example worth knowing:

- The Graph v1.0 `riskDetection` resource has **no `riskType` field** (live-verified
  2026-07-17); only `riskEventType` exists. The `UserRiskEvents` blob category carries
  both, with the same value. graph2otel emits `risk_event_type` and deliberately no
  `risk_type`, so the attribute set does not silently depend on the transport.
- **`riskLevel` disagrees across endpoints for the same event.** Live, `riskDetections`
  reported `medium` while `riskyUsers` reported `low` for one detection ~7 minutes apart.
  This is not a graph2otel bug: Microsoft aggregates *user* risk differently from
  *detection* risk. But it means `entra.risk_detections` and `entra.risk` will show
  different severities for the same incident, and a dashboard placing them side by side
  will look broken when it is not.
- **`mitre_techniques`** (e.g. `T1090.003,T1078`) is emitted on `entra.risk_detection`,
  extracted from `additionalInfo`. It is usually the most precise thing on the record —
  more specific than `riskEventType` — and is the field to pivot on for ATT&CK-aligned
  rules.
- **`isDeleted` is not emitted** on `entra.risk`. It returns `false` for users that are
  definitively deleted, so a filter on it would quietly include the accounts it was meant
  to exclude. The gauge therefore counts deleted-but-once-risky identities until Microsoft
  drops the row.

## Multi-tenant labeling

**Every signal carries a `tenant_id` attribute** — domain and self-observability, metrics
and logs alike (#143). Filtering or grouping any panel by `tenant_id` works.

graph2otel runs one Scheduler per configured tenant, and `telemetry.WithTenant` stamps the
tenant at the emitter boundary, so it reaches all 58 collectors without any of them knowing
about it. Two exceptions worth knowing:

- **A single-tenant deploy that configures no tenant id stamps nothing.** Empty means "no
  tenant configured", so the attribute is simply absent rather than blank — series are
  byte-identical to a pre-#143 build.
- **`tenant_id` is always the tenant graph2otel polled**, never a tenant named inside a
  record. `/security/alerts_v2` and `/security/incidents` carry their own `tenantId` field;
  it holds the same value (live-measured 2026-07-17, #143), and graph2otel deliberately
  does not map it — the emitter owns the key.

This is a metric label, so it changes series identity: `intune_compliance_devices{state="compliant"}`
is now per-tenant. That is the point. Before #143 there was one MeterProvider, one resource,
and no tenant anywhere on a domain metric, so two tenants' identical series collided and
interleaved — a multi-tenant deploy got a meaningless number rather than a coarse one.

Why this does not violate the cardinality rule: `tenant_id` grows with the number of tenants
an operator **deliberately configured**, not with tenant size. The [cardinality
rule](#cardinality-shape) forbids the latter.

## License/beta gating

Some signals only populate under a Microsoft Entra P2 license (risk detections, PIM
standing/eligible assignments) or a P1 license (sign-in activity recency), and some
collectors depend on a Graph `beta` endpoint with no `v1.0` equivalent (several Intune
signals — Settings Catalog, Autopilot profiles, Windows Update rings, certificates,
scripts, GPO analytics, endpoint-analytics detail — plus the non-interactive/service
principal/managed identity sign-in log filters). Beta collectors are opt-in, never
default-on — see [Configuration](configuration.md#experimental-beta-collectors-are-opt-in-not-default-on).
A panel or alert reading empty on a lower license tier, or with a beta collector left
disabled, is expected — not a broken signal.

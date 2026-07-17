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

## Multi-tenant labeling

**Domain telemetry (`entra.*`, `intune.*`, `m365.*`, `purview.*`) does NOT carry a
`tenant_id` attribute today — neither metrics nor logs.** Only the self-observability
signals do (`graph2otel.scrape.*`, `graph2otel.license.*`, the graphclient HTTP counters).
There is one MeterProvider per process, `tenant_id` is not a resource attribute, and
neither the emitter nor the scheduler injects anything into domain records — their
labels/attributes are exactly what the collector passed. Do **not** filter domain-metric
dashboard panels by `tenant_id`; the query returns no data, always (this exact mistake
shipped in `entra-compliance-overview.json` — #143). How multi-tenant separation should
work on domain signals is #143's open decision.

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

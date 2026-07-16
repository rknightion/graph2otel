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

Every metric this project emits carries **bounded, tenant-shaped** label dimensions —
counts by compliance state, operating system, policy name, risk level, license SKU, and
similar admin-configured categories. None grow with tenant size (user count, device
count, sign-in volume). High-cardinality per-entity data (UPNs, device IDs, IP
addresses, correlation IDs) is confined to the **logs** pipeline as structured
attributes, never a metric label — see [Security](security.md#the-cardinality-boundary-rule)
for the full rule and [docs/pii-cardinality-audit.md](pii-cardinality-audit.md) for the
audit that confirmed it holds against the actual collector source.

## Multi-tenant labeling

Every metric carries a `tenant_id` label so one process's telemetry for several tenants
stays distinguishable in a shared backend. Dashboards built against these signals should
add a `$tenant` template variable and filter every panel query by it — see the shipped
dashboards under `dashboards/` for the pattern.

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

# Signals

graph2otel exports every domain signal under one of three OTLP dot-notation
namespaces. A new collector emitting outside its domain's namespace is a bug, not a
style choice — see `CLAUDE.md`'s "Metric namespaces" section for the enforced
convention.

- **`entra.*`** — Entra ID directory, sign-in, and audit signals.
- **`intune.*`** — Intune device management and compliance signals.
- **`m365.*`** — Microsoft 365 service signals (unified audit, activity).
- **`purview.*`** — Purview compliance signals (retention / sensitivity labels).
- **`defender.*`** — Microsoft Defender XDR advanced-hunting tables (endpoint EDR,
  email/MDO, identity, alert evidence), ingested over the streaming API → Storage
  blob path. Log-only, Experimental, off by default (#106).
- **`m365.service_health.status{service}` enum** (#119) — the gauge encodes
  Microsoft's `microsoftServiceHealthStatus` as a numeric severity ladder:
  `0` = `serviceOperational` / `falsePositive`; `1` = resolved states
  (`serviceRestored`, `postIncidentReviewPublished`, `resolved`, `resolvedExternal`,
  `mitigated`, `mitigatedExternal`); `2` = in-recovery (`verifyingService`,
  `restoringService`, `extendedRecovery`, `investigationSuspended`); `3` = active
  investigation (`reported`, `investigating`, `confirmed`); `4` =
  `serviceDegradation`; `5` = `serviceInterruption`; `-1` = an unmapped/new
  Microsoft status (visible rather than silently bucketed as healthy). Alert on
  `> 3` for a live outage. There is deliberately no companion mapping metric — this
  table is the mapping. The per-issue detail (title/impact) is in the
  `m365.service_health_issue` log twin, never a metric label.
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

## Backdated log records: accepted to 7 days, but NOT queryable immediately

Two separate facts, and confusing them costs a day (#226 was filed on exactly that confusion,
and then re-made during its own investigation).

### 1. The accept window is 7 days, and rejection is loud

The Grafana Cloud OTLP gateway rejects log records timestamped more than **7 days** in the
past, and states the limit in the rejection body:

```text
400 Bad Request: entry for stream '{service_name="graph2otel"}' has timestamp too old:
2026-07-08T13:05:10Z, oldest acceptable timestamp is: 2026-07-15T13:05:10Z
```

`[live-measured 2026-07-22, #226]` — records backdated 12h, 1d, 2d and 3d all landed; 7d and
14d were refused. Two properties worth knowing:

- **Rejection is per-entry, not per-batch.** In the same push, the in-window records were
  accepted while the two out-of-window ones were refused. One over-old record cannot poison a
  batch of good ones.
- **The error reaches the OTel error handler**, so it appears on stderr. A backfill past 7
  days is not a silent failure.

`backfill.initial_lookback` beyond this window warns at startup for that reason.

### 2. A backdated record is not visible the moment it is accepted

**This is the trap.** Records timestamped more than a few hours in the past are indexed
through a late-data path (they carry a `__time_shard__` label) and become queryable
noticeably later than fresh ones — long enough that a verification query run immediately
after a poll returns **zero rows for records that were accepted and are now there**.

Nothing distinguishes that from a drop at the moment you look. It produced two wrong
conclusions on #226: the original report ("the twin never lands in Loki" — it does), and then,
during the investigation, an entire fabricated "~4h20m horizon" built from sweeps queried
seconds after each push. Every one of those "dropped" records was present when re-queried
later.

**So: never conclude a backdated record was dropped from a query run right after emitting
it.** Wait, re-query, and check for the explicit 400 — that error, not an empty result set,
is the evidence of rejection.

A related query-side footgun that caused one of those wrong readings: `count_over_time({…}[24h])`
looks back only 24h, so records timestamped 2–3 days ago are excluded **by the query**, not
missing from the store. Widen the range before drawing a conclusion.

## Deduplicating blob-sourced records — Azure delivers at-least-once

Records ingested over the blob transport (`ingest_transport="blob"`) can arrive **more than
once**: Azure Monitor's diagnostic-settings pipeline is at-least-once, so ~2.7% of
`MicrosoftGraphActivityLogs` and ~4% of sign-in records are re-delivered, with a max
multiplicity of **×4** (live-measured, steady-state — see
[blob-ingest.md](blob-ingest.md#azure-delivers-at-least-once-27-mgal--4-sign-ins-of-records-arrive-more-than-once)).
graph2otel ships these through faithfully by design — the byte-offset cursor is provably
exact, and deduping in the engine would need an unbounded, restart-persisted seen-id set to
do correctly, so the decision (#138) is to **dedupe downstream**, where it costs nothing and
cannot go stale. Every blob-sourced record already carries the key you need:

| collector | dedupe key (structured metadata) |
| --- | --- |
| `entra.signin` (and the service-principal / non-interactive sign-in twins) | `id` |
| `entra.graph_activity` | `request_id` |

The duplicates are **byte-identical** apart from a fresh envelope timestamp, so any one copy
is the whole event — dedupe on the identity key, never on time. Two ways to do it:

- **Counting / alerting** — count distinct identity values, not raw lines. Grouping by the
  structured-metadata key collapses the copies:

  ```logql
  count(sum by (id) (count_over_time({service_name="graph2otel"} | event_name=`entra.signin` [1h])))
  ```

  Counting `count_over_time` lines directly would over-count by the ~2.7–4% duplication rate.

- **Raw event export (SIEM feed)** — dedupe in whatever store consumes the feed, keeping one
  row per `id` / `request_id` (Loki has no row-level dedupe-on-read). **Do not assume
  at-most-two copies** — multiplicity reaches ×4.

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
| How many users fail to sync? | metric | `entra_directory_sync_errors_total` |
| **Which** users, and what conflicts? | logs | `{service_name="graph2otel"} \| event_name=`entra.directory_sync_error`` — carries `user_principal_name`, `property_causing_error`, and the actionable `conflicting_value` |
| How many groups have license errors? | metric | `entra_license_groups_with_errors_total` |
| **Which** groups? | logs | `{service_name="graph2otel"} \| event_name=`entra.license_group_error`` — carries the group `id` + `display_name` |

The same shape holds for the batch's other new signals: `intune.devices.os_version.count`
buckets the fleet by OS build for the "how exposed to CVE-X" question, with the exact
per-device build on the `intune.managed_device` twin's `os_version` attribute; and
`entra.users.population{user_type, account_enabled}` answers joint questions the marginal
`entra.users.total` axes cannot — e.g. `{user_type="guest", account_enabled="false"}` is the
disabled-guests count directly. All new metric names appear normalized in
[collectors.md](collectors.md) with their labels.

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
| `user_id` | classic **UserId** — usually the UPN, sometimes a sentinel | `userPrincipalName` | `UserId` |

**Correlate the two signals on `user_id`.** Both collectors map each wire field to what it
*contains*, not to what it is called — which is why the query API's row above looks
inverted and is not. Its top-level `userId` field is a Microsoft misnomer holding the
classic UserKey (live-verified 500/500 over one tenant and window, 2026-07-17), while its
`userPrincipalName` field holds the classic UserId. Reading the wire names at face value
silently compares UserKeys against UserIds.

`user_id` is **not always UPN-shaped** — about 9% of live records carry a bare GUID, the
literal `Not Available`, `ServicePrincipal_<guid>`, or a display name. Both transports emit
it verbatim with no shape gate, so do not assume an email address. It was called
`user_principal_name` until 2026-07-17; the name claimed a shape the value does not have.

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
- **`user_agent`** is also on `entra.risk_detection`, and also comes out of
  `additionalInfo` rather than a top-level field. `additionalInfo` is a JSON-encoded
  **string** holding `[{"Key":…,"Value":…}]` pairs — not an object — so a query written
  against the shape the name suggests finds nothing.
- **`location_latitude` / `location_longitude`** are emitted when the record carries
  coordinates, and are **presence-gated, not value-gated**: `0` is both a real coordinate
  and the canonical output of a failed geo-IP lookup, so it is emitted rather than
  treated as absent. `altitude` is documented by Microsoft but has never been observed
  live, so it is not mapped.
- `entra.risk_detection` also carries `token_issuer_type`, `user_display_name`,
  `location_state`, `location_city` and `location_country_or_region`.
- **`is_deleted` on `entra.risky_user` is reconciled, never the raw field.** Microsoft's
  `riskyUsers.isDeleted` returns `false` for users that are definitively deleted (live-verified
  2026-07-17 and 2026-07-19: 404 on `/users/{id}`, present in `/directory/deletedItems`), so it
  is never emitted. graph2otel instead reconciles risky users against
  `/directory/deletedItems/microsoft.graph.user` (#155): a tombstoned user is **excluded from
  the `entra_risky_users_total` gauge** (it no longer exists, so it is not currently at risk),
  and its `entra.risky_user` log twin carries a **reliable `is_deleted=true`** — so
  `{service_name="graph2otel"} | event_name=`entra.risky_user` | is_deleted=`true`` answers "which
  deleted accounts is Identity Protection still flagging". `is_deleted` is emitted only when the
  reconciliation ran (the polled `entra.risk` collector); the blob-sourced `entra.risky_users`
  twin and the service-principal twin omit it.

## SharePoint/OneDrive storage: derived quota state + report concealment

`m365.storage` is built on the M365 usage-**reporting** API, not the live per-drive `quota`
facet — two facts follow that a dashboard author must know.

- **`quota_state` is derived, not Microsoft's verdict.** The live `/sites/{id}/drive` facet
  carries Microsoft's own `state` (`normal`/`nearing`/`critical`/`exceeded`) and a `deleted`
  byte count, but reading it app-only needs `Sites.Read.All` + `Files.Read.All` —
  read-everything-in-SharePoint scopes, disproportionate for a capacity signal (live-measured
  2026-07-18, #120). So graph2otel computes `quota_state` from `used ÷ allocated`:
  `normal` <75%, `nearing` ≥75%, `critical` ≥90%, `exceeded` ≥100%, `unknown` when allocated
  is 0. There is **no `deleted_bytes` series** — the reporting API does not expose it.
  `m365.storage.drives.total{drive_type,quota_state}` emits the full grid every cycle, so
  `quota_state="critical"` exists at `0` for a stable alert baseline.
- **SharePoint `total_bytes` is the pooled ceiling, not a sum.** SharePoint storage is pooled:
  every site's `Storage Allocated` is the same tenant ceiling (~25 TiB on m7kni), so the
  tenant SP total is the max, not the sum. OneDrive quotas are per-user, so they *do* sum. The
  metric reflects this — do not add the two `drive_type` totals expecting a grand total.
- **Report name concealment silently hashes identity.** The tenant setting
  `displayConcealedNames` (M365 admin center → Settings → Org settings → Reports) hashes
  `owner_display_name`, `owner_principal_name`, and blanks `site_url` / zeroes `site_id`
  across *all* usage reports — storage bytes are unaffected. When it is on, `m365.drive_storage`
  carries `names_concealed="true"` and the collector logs a startup warning; the identity
  attributes are present but hashed. It was ON on m7kni at build time (live-measured
  2026-07-18). graph2otel reads `/admin/reportSettings` to detect it (optional
  `ReportSettings.Read.All`), falling back to a data heuristic (all-zeroed `site_id`) when that
  scope is absent.

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

## MDCA Cloud Discovery parse health: `ingest_transport="mdca"`

`mdca.discovery_parse` (#145) is the one signal reached over neither Graph, Azure Storage,
nor the O365 Management API, but the **Microsoft Defender for Cloud Apps legacy portal API**
(`<tenant>.<region>.portal.cloudappsecurity.com/api/v1/governance/`) — a static
`Authorization: Token` credential, not the Entra poller. Its records therefore carry a sixth
`ingest_transport` value, `mdca`, alongside `graph`/`blob`/`o365_activity`/`audit_query`/`report_export`.

Why the collector exists: a Cloud Discovery upload returns `200 {"success":true}` the moment the
blob lands and a parse task is **queued** — the parse runs asynchronously and writes its verdict
**only** to the governance log, so an uploader is structurally blind to whether its data actually
parsed. One `mdca.discovery_parse` log ships per parse task:

- A **queued** task carries `state="pending"` and NO `is_success` — a pending parse is not a failure.
- A **completed** task carries `state="completed"`, `is_success` (bool), `template` (the stable
  outcome enum — alert on this, never on localized prose), and, on success, `transactions_count` /
  `cloud_services_count`. `is_success=false` is emitted at `ERROR` severity.

Metrics (bounded to `input_stream_id` × `template`): `mdca.discovery.parse.last_success.age`
(seconds since a stream last parsed — the alert-on-**silence** signal, since a dead uploader emits
no failed tasks and this gauge keeps climbing), `mdca.discovery.parse.transactions` /
`.cloud_services` (last successful parse's discovered counts), and the
`mdca.discovery.parse.tasks` counter by outcome. Query the log as always with the
`{service_name="graph2otel"} | event_name="mdca.discovery_parse"` form. See
[alerts/README.md](../alerts/README.md) doc block 5 for the two rules.

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

# Signals

graph2otel exports every domain signal under a bounded OTLP dot-notation
namespace. A new collector emitting outside its domain's namespace is a bug, not a
style choice — see `CLAUDE.md`'s "Metric namespaces" section for the enforced
convention.

- **`entra.*`** — Entra ID directory, sign-in, and audit signals.
- **`intune.*`** — Intune device management and compliance signals.
- **`m365.*`** — Microsoft 365 service signals (unified audit, activity).
- **`purview.*`** — Purview compliance signals (retention and sensitivity labels,
  eDiscovery cases, and DLP policy posture). `purview.dlp_policies` reads the beta
  `policyFiles` surface and emits policy **definitions**: enforcement modes,
  workload/action bindings, and per-policy/per-rule log twins. It is Experimental
  and opt-in. It never emits matched content or a rule condition's value text.
- **`defender.*`** — Microsoft Defender signals, from two transports with two
  independent switches:
  - the **XDR advanced-hunting tables** (endpoint EDR, email/MDO, identity, alert
    evidence), ingested over the streaming API → Storage blob path. Log-only.
    **Not Experimental** — read-only Azure Storage ingest is not a beta Graph
    surface, and `Experimental` is reserved for genuine Graph beta APIs (#183).
    Setting `blob_ingest.account_url` is the entire opt-in: with it set every
    advanced-hunting table registers, with it unset none do.
  - **`defender.quarantine`** (#233), the one `defender.*` collector that is neither
    blob-sourced nor log-only: quarantine queue depth over the Exchange Online admin
    API, emitting a bounded gauge plus a per-message log twin. Its switch is
    `exchange_online.enabled`, and it needs two grants blob ingest does not — see
    [Quarantine](#quarantine-one-dataset-across-four-transports) below.
  - the **`DeviceTvm*` threat-and-vulnerability-management tables** (#249) —
    `defender.vulnerabilities`, `defender.secure_config` and
    `defender.software_inventory`, reached over the Graph advanced-hunting query API
    (`POST /security/runHuntingQuery`, v1.0, read-only KQL — the one non-GET Graph
    call). Each emits bounded gauges plus a per-entity log twin (`defender.vulnerability`,
    `defender.secure_config`, `defender.software`); `ingest_transport` is `graph`.
    **Not blob** — no `DeviceTvm*` container exists — and **not Experimental** — the
    endpoint is v1.0, not beta. Its switch is `hunting.enabled` and it needs
    `ThreatHunting.Read.All`. It polls on a long interval (6h) because the
    advanced-hunting CPU budget is SHARED with humans in the Defender portal (#106),
    which is exactly why the high-volume EDR event tables above take the blob path
    instead; the TVM tables are the exception because they are small current-state
    snapshots with nothing to tail. Twin fetches partition under the hard
    100,000-row-per-query cap so a large fleet is never silently truncated.
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
- **`entra.gsa.onboarding_status` enum** (#239) — the Global Secure Access tenant
  onboarding state as a numeric ladder, the same shape as `service_health.status`:
  `0` = `onboarded`; `1` = in-progress (`onboardingInProgress`,
  `offboardingInProgress`); `2` = `onboardingError` / `offboarded`; `-1` = an
  unmapped/new Microsoft status. This table is the mapping — there is no companion
  metric. The per-profile and per-policy detail rides the `entra.gsa_forwarding_profile`
  and `entra.gsa_filtering_policy` log twins, never a metric label. `entra.gsa` is
  Experimental (beta `networkAccess`, opt-in). The traffic endpoint is reachable
  with the poller's existing `NetworkAccess.Read.All` grant and returns 200/empty on
  m7kni because all forwarding profiles are disabled. Its wire record shape is
  therefore still unmeasured, so no traffic mapper is shipped.
- **`mdca.*`** — Microsoft Defender for Cloud Apps Cloud Discovery parse health over
  the legacy MDCA portal API. This is neither Graph nor the Entra poller credential;
  see [MDCA Cloud Discovery parse health](#mdca-cloud-discovery-parse-health-ingest_transportmdca).
- **`graph2otel.*`** — self-observability: collector success/duration/staleness,
  export-job health, active series counts, build info, and
  [`graph2otel.api.unexpected`](#graph2otelapiunexpected-when-microsoft-changes-something-under-us)
  (a Microsoft API response that no longer matches what a collector was built
  against). Not tenant domain data.

For the exhaustive, per-collector metric/log/label reference (every gauge, counter, log
attribute set, and the Graph API permission scope each collector needs), see
[docs/collectors.md](collectors.md).

## Shipped collector and ingest surface

The generated registry currently exposes **168 logical collectors** through
**7 registration paths**: Snapshot, Window, Blob, O365, MDCA, EXO, and Hunt. The generated
[collector reference](collectors.md) is authoritative; the registration-path inventory
contains 171 registration-path candidates because some logical collectors can register
through more than one transport.

Reusable ingest-engine shapes handle the event and export transports:

- `internal/logpipeline` polls Graph log endpoints with a time watermark, overlap
  window, pagination drain, and seen-ID dedupe.
- `internal/jobpipeline` plus `internal/exportjob` run create → poll → download jobs
  for the M365 audit-query and Intune report-export transports.
- `internal/blobpipeline` consumes Azure Storage diagnostic blobs by byte offset.
- `internal/o365pipeline` plus `internal/o365activityclient` manage the O365
  Management Activity API's subscription → content-blob flow.

Snapshot collectors and the MDCA, Exchange Online, and advanced-hunting registration
paths use their direct API shapes around those engines. `ingest_transport` records which
path produced each log: `graph`, `blob`, `o365_activity`, `audit_query`,
`report_export`, `mdca`, or `exchange_online`.

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

## Collector availability

`graph2otel.collector.availability` is a value-1 current-state gauge, normalized in the
shipped PromQL dashboards as `graph2otel_collector_availability`. It has exactly one row
per configured `tenant_id` and logical `collector`, with bounded `collector.transport`,
`state`, and `reason` labels. The complete generated state/reason contract and every
allowed pair are in [the collector reference](collectors.md#collector-availability).

`collector.transport` is the transport resolved for that logical collector in this tenant
after configuration, source selection, and capability checks. It is not
`ingest_transport`: that log-only field identifies the transport that produced an
individual record and is appropriate for record outcomes and event lag, not availability.

`healthy_empty` means a successful source response containing zero rows. It proves that
the collector's source answered, not that data was observed. `limited` with
`reason="partial_license"` means an otherwise running collector has a documented reduced
capability subset; it is non-alerting. `disabled` and `covered` are intentional absence;
`degraded`, `failed`, and `startup_failed` are the failure-oriented states. This snapshot
does not replace scrape freshness, lifetime readiness, or backend-delivery acceptance.

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

### `graph2otel.event_domain` — the one coarse dimension on the logs *resource*

Because Loki only promotes **resource** attributes to stream labels, graph2otel puts exactly
one coarse partition there: `graph2otel.event_domain`, the first segment of the event name.
The closed value set is `defender`, `entra`, `graph2otel`, `intune`, `m365`, `mdca`,
`purview`, plus an `other` bucket that nothing catalogued should ever land in (a test
asserts that against `spec/signal-catalog.json`). It rides the **logs** resource only —
never metrics, where a resource attribute would fork every series for no query benefit.

This exists so one hot log stream can be split into single-digit streams rather than
shard on write. It does **not** change how you query: `event_name` is still structured
metadata and the `{service_name="graph2otel"} | event_name=…` form above stays correct.

Two caveats worth knowing before you build on it. The attribute is emitted by graph2otel
unconditionally, but it only becomes a *stream label* once it is added to the tenant's Loki
**structured-metadata promotion** list — a Grafana Cloud-side setting, not a repo change.
Until then it is queryable as structured metadata like any other attribute. **As of
2026-07-28 it is not promoted:** a live `series` read for `{service_name="graph2otel"}`
returns only `service_name` plus Loki's internal `__stream_shard__` / `__time_shard__`, so
the single hot stream is still being auto-sharded. And the value is derived from the event
name alone, so it tells you which product area produced a record — not which transport
carried it. `ingest_transport` is still the attribute for that.

### Why no *log attribute* can ever be promoted, and what promotion would cost (#404)

This trips people up in a specific way, so it is worth stating flatly: **you cannot promote
`event_name`, `ingest_transport` or `tenant_id`, and no tenant setting will let you.**

Loki's `otlp_config` exposes the `index_label` action **only** under `resource_attributes`.
`scope_attributes` and `log_attributes` accept `structured_metadata` and `drop`, and nothing
else. So a dimension has to be on the OTLP **resource** before promotion is even a question,
and `graph2otel.event_domain` is the only graph2otel-specific attribute that is — which is
exactly why it exists.

Hoisting another dimension onto the resource is not a rename. An OTLP resource binds to a
`LoggerProvider`, not to a record, so **N distinct values means N `LoggerProvider`s**. That
is the shape `internal/telemetry` already carries for `event_domain`: one provider per
domain, all sharing a single OTLP exporter, with per-processor queue depth reduced in step
with the provider count and a shutdown path that closes the shared exporter exactly once,
last. Any future promotion candidate pays the same price, and the value set must be closed
and code-defined — `event_name` was rejected for this at 73 distinct values over 6h, which
would mint ~73 tiny streams for ~23 MB/day and grow with every collector added.

**The slot question, settled — an earlier framing here was wrong.** This page previously said
the promotion slots are *shared with other exporters pushing to the same tenant*, implying
graph2otel competes with `opnsense-exporter` and `tailscale2otel` for a pool of ~15. That is
**not** what the 15 is: `max_label_names_per_series` is the maximum number of label names on a
**single stream**, enforced by the distributor at ingest. A graph2otel stream never carries an
`opnsense_*` label, so the limits were never shared and each exporter independently gets its
own budget. The genuinely shared resource is the tenant's promoted-attribute *list*, which is
capped well above what three exporters need — adding entries is additive and cannot affect
another exporter's streams, but it is one list, so edits must be GET-merge-PUT rather than a
blind partial write.

Promotion buys **query scan only**. Loki bills on volume, so it does not reduce ingest cost at
all. Verify it with a `series` read, not a log query: structured metadata cannot appear in
`series` output, so presence there is the proof.

### An unset identifier filter matches everything, not nothing

An **absent** structured-metadata key compares equal to the empty string, so a filter built
from an empty template variable is not a no-op:

```logql
{service_name="graph2otel"} | event_name=`intune.device_hardware` | device_id=``
```

matches every record that has **no** `device_id` — the opposite of the intended "show me
nothing until an id is supplied". Require the key to be non-empty as well when the value is
supplied at query time:

```logql
{service_name="graph2otel"} | event_name=~`^(intune\.device_hardware|defender\.device_logon)$`
  | tenant_id=~"$tenant" | device_id=~`.+` | device_id=`$pivot_device`
```

The generated dashboard's entity pivots always emit both stages for this reason
(`grafana/pivots.py`).

## Investigating one entity across signals

An analyst holding one identifier can reach every other signal that names the same entity
from the generated dashboard's **Overview** tab: paste the value into the matching input
(`Device`, `Application`, `Account`, `Email message`, `Security alert id`, `Security
incident id`) and expand that entity's row. Every log panel in the estate also carries a
header link into the pivot for each entity kind its own event can name, preserving the
tenant selection and the time range.

Three things it deliberately does not claim:

- **It is not a join, and not a correlation verdict.** Records that name the same identifier
  are records that name the same identifier.
- **Several identifiers are source-scoped.** `device_id` is Intune's managed-device id on
  `intune.*` and Defender's machine id on `defender.*` — different namespaces for the same
  physical machine, and graph2otel does not map between them. `device_name` is usually what
  bridges them.
- **One UPN has three attribute names.** Entra writes `user_principal_name`, Intune writes
  `upn`, Defender writes `account_upn`. All three are queried from the one input, which is
  why a hand-written query on only one of them under-reports.

Object-id keys (`user_id`, `account_object_id`, `app_object_id`, `aad_device_id`) are
deliberately **not** folded into these inputs: a UPN pasted into an object-id filter matches
nothing, and that empty result reads like a verdict. Query them directly when you have one.

Per-entity identifiers are never metric labels (see [Cardinality shape](#cardinality-shape)),
so this question has no metric answer and never will — which is exactly what the log twin is
for.

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

## Event time and dedupe are transport contracts

An event record must carry a parseable source event time. The log, async-job, blob, and
O365 engines drop and count a record when neither the wire field nor the mapper can
establish that time. They never replace it with arrival time, a query-window boundary, or
the time graph2otel happened to poll it; doing that would turn an unknown time into a
confidently wrong one. The drop appears in
`graph2otel.record.outcomes{outcome="dropped"}` with the bounded
`missing_event_time` run cause (and the engine-specific watchdog where applicable).

Identity is different. A correctly timestamped record with no stable ID is still useful,
so it is emitted as **undedupeable/degraded** and the empty string is never inserted into
a seen-ID set. This deliberately prefers possible overlap duplicates over guaranteed,
silent data loss.

The dedupe clock and identity depend on the source:

- **Graph window polling** re-queries an overlap window and stores each non-empty record
  ID with its event-time watermark. Seen IDs suppress the repeated overlap after a
  checkpoint restore.
- **Azure diagnostic blobs** have an exact byte-offset cursor, but Azure can append the
  same logical event as new bytes. graph2otel preserves those at-least-once deliveries;
  dedupe them downstream by the record identity described below.
- **O365 Management Activity** dedupes both the content blob (`contentId`) and the audit
  record (`Id`). Both seen sets evict on the blob's `contentCreated` **arrival clock**,
  never the record's `CreationTime`: a newly-arrived blob can contain an older event, so
  event-time eviction would re-emit records while their blobs remain listable.

## Deduplicating blob-sourced records — Azure delivers at-least-once

Records ingested over the blob transport (`ingest_transport="blob"`) can arrive **more than
once**: Azure Monitor's diagnostic-settings pipeline is at-least-once, so ~2.7% of
`MicrosoftGraphActivityLogs` and ~4% of sign-in records are re-delivered, with a max
multiplicity of **×4** (live-measured, steady-state — see
[blob-ingest.md](blob-ingest.md#azure-delivers-at-least-once-27-mgal-4-sign-ins-of-records-arrive-more-than-once)).
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

`m365.activity` is the default-on, stable-v1.0 transport. Its default subscriptions are
`Audit.Exchange` and `Audit.SharePoint`; `Audit.General` and `DLP.All` are explicit
operator choices because the API has no record-level server filter; selecting `DLP.All`
also requires `ActivityFeed.ReadDlp`. `Audit.General` carried 3,865 Endpoint DLP records
out of 4,035 records over 23 hours on the measured six-device tenant, so enabling it is
a real SIEM feed and a real volume decision.

This audit feed is separate from the shipped `purview.dlp_policies` posture collector.
The common `m365.activity` mapper emits a strict audit-envelope allowlist and does not
read `PolicyDetails`, `SensitiveInformation`, or `DetectedValues`. A dedicated
`DLP.All` classification mapper is not shipped. Three live DLP.All records established
the classification shape, but their raw `DetectedValues` included credit-card and message
content in cleartext. Any future mapper may emit classification metadata, never those
values; the current allowlist excludes both.

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

## Security alerts: the two transports emit different VALUES for the same attributes

A Microsoft security alert reaches graph2otel twice — once as `entra.security_alert` (polled from
Graph `/security/alerts_v2`) and once as `defender.alert_info` (the Defender XDR `AlertInfo`
advanced-hunting table over the blob path). The attribute *names* match. The attribute *values* do
not, because Graph `alerts_v2` sends camelCase enums and the advanced-hunting table sends display
strings. Both collectors emit the wire verbatim, so the split is permanent and by design:

| source | `entra.security_alert` | `defender.alert_info` |
| --- | --- | --- |
| Defender for Endpoint | `microsoftDefenderForEndpoint` | `Microsoft Defender for Endpoint` |
| Defender for Cloud Apps | `microsoftDefenderForCloudApps` | `Microsoft Defender for Cloud Apps` |
| Entra ID Protection | `azureAdIdentityProtection` | `AAD Identity Protection` |
| `severity` | `medium` / `high` / `informational` | `Medium` / `High` / `Informational` |

`[live-measured 2026-07-22, #232 — every record on both streams over a 7d window, not a sample]`

**A filter written against one transport's vocabulary matches exactly zero rows on the other**, and
matches them silently — same failure mode as putting an attribute in the stream selector.

**`(?i)` is not a sufficient fix.** It rescues the `severity` row and the two `Defender for …` rows,
which differ only in case and spacing. It does nothing for Identity Protection:
`azureAdIdentityProtection` and `AAD Identity Protection` share no substring. A rule that must span
both transports has to match the alternation explicitly, or — better — not filter on
`service_source` at all.

**Do not scope an alert rule to a single `service_source`.** Three sources appear on a live tenant
and the set is Microsoft's to extend; a rule naming one of them silently covers a fraction of the
alert stream and looks healthy while doing it. Gate on `severity` and `status` instead:

```logql
sum(count_over_time({service_name="graph2otel"}
  | event_name=`entra.security_alert`
  | severity=~`(?i)(high|medium)`
  | status=~`(?i)(new|inProgress)` [5m])) or vector(0)
```

Excluding already-`resolved` alerts loses nothing: dedupe is on alert id, so each alert is emitted
once carrying its poll-time status and is never re-emitted when it later resolves. An alert that
arrives already `resolved` was auto-resolved before graph2otel first saw it.

**Expect ~20 minutes from alert creation to a page on the Graph path.** `entra.security_alerts`
polls a 10m interval behind a 15m safety lag, so the delay is the schedule, not a fault to debug.
The blob twin is faster (~10 min, measured on the same alert) because it is not lag-gated — but it
covers only the Defender XDR tables, so it is not a drop-in replacement for the Graph stream.

`entra.security_incidents` is the correlation layer above the alerts: one incident groups related
alerts and carries a `display_name` and `priority_score` the individual alert does not. Its
`status` vocabulary is different again — `active` / `resolved` / `redirected`, not `new`. Treat
`redirected` as a duplicate: it means the incident was merged into another one.

## Quarantine: one dataset across four transports

Quarantine is not one signal. "How many messages are held" and "who released that message"
are different questions with different natural transports, and graph2otel answers each over
the one that fits (#233). **All four key on `network_message_id`**, which is what makes them
one dataset rather than four islands.

| question | signal | `ingest_transport` | shape |
| --- | --- | --- | --- |
| **state** — held right now | `defender.quarantine` | `exchange_online` | bounded gauge + log twin per held message |
| **movement** — entering / leaving | `defender.email_post_delivery` | `blob` | log per post-delivery action |
| **history** — held/released/deleted/previewed, policy changes | `m365.unified_audit` | `audit_query` | log per audit record |
| **context** — the message itself | `defender.email` | `blob` | log per message, carries `delivery_location` |

### `defender.quarantine.held_messages.total` is queue DEPTH, not flow

This distinction is the one to keep straight, because the two answer opposite questions and
only one of them is a gauge.

The metric counts messages **currently held** — it is driven by
`Get-QuarantineMessage -ReleaseStatus NOTRELEASED`, which filters server-side
`[live-measured 2026-07-23, #233]`. Released messages stay visible to the API for the
remainder of their 30-day retention and are deliberately **not** counted: counting them
would leave the number elevated for a month after an incident instead of returning to zero
when quarantine drains. Labels are `quarantine_type` × `direction` × `entity_type` —
bounded by Microsoft's enums, never by tenant size or mail volume.

**Flow** — how many messages were quarantined this hour, how many were released, by whom —
is not this metric and is not any metric. It is a `count_over_time` over the log twins and
the audit records. That is the cardinality rule working as intended: a rate keyed by
sender, recipient or policy would be a series per entity, and LogQL answers it for free.

**An empty quarantine emits NO series at all**, not a zero. The gauge is an observable
snapshot, so a `(type, direction, entity)` combination that stops appearing drops out of the
export rather than ghosting forever under forced cumulative temporality — the same shape as
`entra.risky_users.total` on a healthy tenant. **Alert on the series exceeding a threshold,
never on its absence**; use the collector's own `graph2otel.*` success/staleness signals to
detect a dead collector.

### Worked LogQL

Remember attributes are structured metadata, not stream labels — always start from
`{service_name="graph2otel"}` (see [above](#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels)).

Everything currently held, most recent first:

```logql
{service_name="graph2otel"} | event_name="defender.quarantine"
```

Held messages nobody can self-release — the queue that needs an admin, which is usually the
one that actually backs up:

```logql
{service_name="graph2otel"} | event_name="defender.quarantine"
  | permission_to_release="false"
```

Release events with the message they released, over the audit trail:

```logql
{service_name="graph2otel"} | event_name="m365.audit"
  | record_type="Quarantine" | operation="QuarantineReleaseMessage"
```

Everything that ever happened to one message, across every transport — this is the join, and
it works because all four stamp the same id:

```logql
{service_name="graph2otel"}
  | network_message_id="80aa9dda-c565-45a0-6133-08dee7cf4a7a"
```

Messages moved into or out of quarantine after delivery (ZAP, remediation, redelivery):

```logql
{service_name="graph2otel"} | event_name="defender.email_post_delivery"
  | delivery_location="Quarantine"
```

Quarantine rate by policy over the last hour — the flow number the gauge deliberately is not:

```logql
sum by (policy_name) (
  count_over_time({service_name="graph2otel"} | event_name="defender.quarantine" [1h])
)
```

### What is NOT covered, and why

**Quarantined Teams messages have no queue-depth signal.** Reading them requires
`Get-QuarantineMessage -EntityType Teams`, which returns **403** to a service principal
holding `Security Reader` `[live-measured 2026-07-23, #233]`. The roles that permit it
(Quarantine Administrator, Security Administrator) are write-capable, which is a real
privilege increase over graph2otel's read-only posture for a single number on a surface
Microsoft made admin-only by design. Teams quarantine is covered through the **audit trail**
instead — the `teamsQuarantineMetadata` record type on `m365.unified_audit` — which needs no
new privilege. Records already carry `entity_type`, so the gauge is correctly scoped to what
it can see rather than silently claiming to cover Teams.

**`defender.quarantine` needs two grants and neither alone works.** The app role
`Exchange.ManageAsApp` authenticates and an Entra **directory** role (Security Reader is the
least-privileged sufficient one) authorizes: 401 with neither, 403 with the app role only,
200 with both `[live-measured 2026-07-23, #233]`. A directory-role assignment is a deliberate
act in the Entra portal, not something scope consent grants — which is why the collector is
opt-in behind `exchange_online.enabled` rather than default-on. See
[graph-api-gotchas.md](graph-api-gotchas.md#exchange-online-admin-api-quarantine-mdo-policy).

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

**Every tenant-domain signal and tenant-scoped self-observability signal carries a
`tenant_id` attribute** (#143). Filtering or grouping those panels by `tenant_id` works.
Process-wide facts are the deliberate exception: build identity, cardinality policy and
OTLP delivery health describe one graph2otel process and carry no tenant selector. The one
process-wide signal that *does* carry `tenant_id` is the
[`graph2otel.startup` marker](#graph2otelstartup-deploy-version-and-configuration-markers),
because a marker filtered out of every tenant-scoped view is a marker nobody sees.

graph2otel runs one Scheduler per configured tenant, and `telemetry.WithTenant` stamps the
tenant at the emitter boundary, so it reaches every logical collector across every
registration path without any of them knowing about it. Two exceptions worth knowing:

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

## `graph2otel.startup` — deploy, version and configuration markers

One **log record per process start**, per configured tenant. It is what a dashboard
annotates from to answer "what changed at 14:00" when a metric moves with no other
explanation (#310).

| Field | Type | Value |
| --- | --- | --- |
| event name | — | `graph2otel.startup` |
| severity | — | `INFO` |
| body | string | `graph2otel <version> started; config fingerprint <fp>` |
| record timestamp | — | **process start**, captured at package init in `cmd/graph2otel` |
| `version` | string | the build version — `internal/version.String()`, the ldflags target, the same source `graph2otel.build_info` reads |
| `go.version` | string | the Go runtime version the binary was built with |
| `config.fingerprint` | string | 16 lowercase hex characters; see below |
| `config.tenant_count` | int | how many tenants this process is configured with |
| `tenant_id` | string | stamped by `telemetry.WithTenant`; **absent** when no tenant is configured |

It is a **log, not a metric**. Build identity already has a metric —
`graph2otel.build_info`, a constant-1 gauge carrying the same `version` and `go.version` —
and a fingerprint that changes with the configuration would mint a new metric series per
configuration and then pay for it forever.

It carries **no `ingest_transport`**, and that is not an omission. `ingest_transport` names
the transport that *ingested* a record; nothing ingested this one, so any value would be a
lie and a new "internal" transport value would pollute the attribute for every consumer
grouping by it. This is the one log record with no transport.

### Querying it

```logql
# every startup marker for one tenant, newest first
{service_name="graph2otel"} | event_name="graph2otel.startup" | tenant_id="<guid>"

# just the version and fingerprint, for an annotation or a version timeline
{service_name="graph2otel"} | event_name="graph2otel.startup"
  | tenant_id="<guid>" | line_format "{{.version}} / {{.config_fingerprint}}"
```

Attributes are Loki **structured metadata**, not stream labels — `{event_name="…"}` matches
zero rows silently. See [Querying the logs in Loki](#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels).

### The configuration fingerprint

`config.fingerprint` is `SHA-256("graph2otel/config-fingerprint/v1\0" || json(effective
config))`, truncated to 16 hex characters (64 bits).

- **What it covers:** the *whole* effective configuration, as a deny-list. Every key
  participates, including keys added after this was written — an allow-list would silently
  stop covering new keys, and a fingerprint that under-reports is worse than none.
- **What it excludes:** credentials. Every credential on the config surface is typed
  `config.Secret`, which renders as `REDACTED` under JSON, so secret **bytes** cannot reach
  the hash input — by the type, not by a list anyone maintains. Tenant auth material
  (`AZURE_CLIENT_SECRET`, certificates) is not on the config surface at all.
- **Consequences of that:** rotating a credential does **not** move the fingerprint; a
  credential going from unset to set **does** (that is a behavior change).
- **It is one-way.** SHA-256 truncated to 64 bits, over an input containing no credential.
  There is nothing secret to recover even by brute force, and the truncation discards 192
  further bits.
- **It is process-wide.** It covers every configured tenant's settings, so it means "this
  process's configuration changed", never "your tenant's configuration changed". Changing
  tenant B's collectors moves the fingerprint on tenant A's marker too. That over-reporting
  is deliberate: a per-tenant fingerprint over the tenant's own subtree would **miss** a
  change to the global `collectors:` map that does alter what that tenant collects, and a
  marker that silently fails to fire is worse than one that fires for a neighbor's change.
- **`/v1` is the scheme version.** Changing what the fingerprint covers bumps it, and every
  fingerprint moves once — the honest signal that the definition, not the config, changed.

### Two things it deliberately does not say

- **Why the process started.** A restart after a crash, a rollout, and a config reload are
  indistinguishable from inside the process, so the marker does not guess at a reason.
- **That anything changed.** It is emitted on every start. "Changed" is a comparison between
  two consecutive markers' fingerprints, made by whoever reads them.

There is **no configuration key** gating this event, matching `graph2otel.build_info`. The
volume is one record per tenant per process start; a toggle's only real effect would be a
deployment whose deploy and config markers silently stop appearing.

## OTLP delivery health: exporter callbacks, not backend retention

graph2otel tracks metrics and logs delivery independently at the SDK exporter boundary. A
nil export callback means the **exporter accepted** that batch. It is local evidence of a
successful callback, **not exactly-once** delivery, not a durable queue, and **not backend
retention**, ingest completion, or queryability. With stdout export, success means the
**local writer** callback completed; it says nothing about a remote backend.

Six process-wide self-observability metrics expose that boundary. Their only attribute is
the closed `signal="metrics"|"logs"` value:

| Metric | Meaning |
| --- | --- |
| `graph2otel.otlp.delivery.export_attempts{signal}` | Export callbacks attempted since process start |
| `graph2otel.otlp.delivery.export_successes{signal}` | Export callbacks accepted since process start |
| `graph2otel.otlp.delivery.export_failures{signal}` | Export callbacks that returned an error since process start |
| `graph2otel.otlp.delivery.force_flush_failures{signal}` | Force-flush callbacks that returned an error since process start |
| `graph2otel.otlp.delivery.shutdown_failures{signal}` | Shutdown callbacks that returned an error since process start |
| `graph2otel.otlp.delivery.degraded{signal}` | Complete two-row snapshot: `1` after a callback failure, cleared to `0` only by a later successful export |

For each signal, `export_attempts = export_successes + export_failures`. Force-flush and
shutdown failures have separate lifetime counters; a successful empty flush or shutdown
cannot invent evidence that a payload was accepted. Delivery degradation is visible but
does not change dependency-free liveness or the lifetime first-success readiness latch.

These delivery metrics themselves travel through the metrics exporter. They may therefore
be unobservable in the backend precisely while metrics delivery is failing. The **admin
status** is the process-local source of truth in that case, and the existing **structured
logs** retain the raw exporter error for diagnosis. Error text, endpoints, credentials,
failure codes, tenants, collectors, and transports never become delivery metric labels.

## End-to-end record outcome accounting

Every collector run reconciles source records through two conservation equations:

```text
fetched = mapped + filtered + dropped + errored
mapped  = emitted + deduped
```

A source record counts once even when it produces several metric points and a log twin.
`emitted` means graph2otel handed useful telemetry to its emitter; it does not mean the
exporter accepted it or that a backend ingested it. Backend delivery and acceptance are
separate OTLP concerns. Intentional filters and overlap dedupe are visible without being
treated as loss. A failed reconciliation is itself a failed run with cause
`accounting_mismatch`.

Four self-observability metrics expose the result:

| Metric | Meaning |
| --- | --- |
| `graph2otel.record.outcomes{tenant_id,collector,ingest_transport,outcome}` | Source-record totals for `fetched`, `mapped`, `emitted`, `deduped`, `filtered`, `dropped`, and `errored` |
| `graph2otel.scrape.outcomes{tenant_id,collector,ingest_transport,result}` | Run totals for `empty`, `success`, `partial`, and `failure`; a healthy empty collection is explicitly `empty`, not generic success |
| `graph2otel.event.lag{tenant_id,collector,ingest_transport}` | Histogram of source-event timestamp to emitter time for timestamped log records; it does not measure OTLP delivery or backend acceptance |
| `graph2otel.payload.type_mismatches{tenant_id,collector,ingest_transport,field,expected_type,actual_type}` | Report-only JSON shape drift on otherwise usable records. Types are restricted to `null`/`boolean`/`number`/`string`/`array`/`object`; field values are never labels |

`graph2otel.scrape.success` is `1` for `empty` and `success`, and `0` for
`partial` and `failure`. A nonzero `dropped` or `errored` outcome means fetched source data
did not become useful telemetry and is default-alerted. A type mismatch keeps the usable
record, emits the mismatch counter, and marks the run partial so drift cannot look fully
healthy.

## Volume, transport, and estimated cost

graph2otel exposes two different measurement boundaries for capacity planning. Logical
volume is exact per tenant, collector, ingest transport, and traffic class. OTLP
transmitted payload and retry volume is exact only for the process and signal. A
collector-level payload allocation is therefore an estimate, never a wire measurement.

> **Evidence class:** `source-derived 2026-07-26, #289`. These boundaries are enforced
> by the runtime accounting seams and tests. They are not a live backend bill or a
> measured vendor pricing schedule.

### Exact logical volume

| Metric | Attributes | Meaning |
| --- | --- | --- |
| `graph2otel.ingest.source_records` (`{record}` counter) | `tenant_id`, `collector`, `ingest_transport`, `traffic_class` | Logical rows fetched by completed scheduler runs. It comes from the same immutable accounting snapshot as `graph2otel.record.outcomes{outcome="fetched"}`, so the two views reconcile without changing #269's frozen labels. |
| `graph2otel.ingest.emitted_points` (`{point}` counter) | `tenant_id`, `collector`, `ingest_transport`, `signal`, `traffic_class` | Points which survived the central cardinality limiter and reached the OTel SDK. `signal` is `metric` or `log`: each synchronous metric emission counts once, each retained gauge-snapshot point counts once, and each log event counts once. |

A source record and an emitted point are deliberately different units. One fetched row
may produce several metric points and a log twin; it still increments
`source_records` once. Conversely, filtering or deduplication can make a fetched row
produce no emitted point. Use the record-outcome equations above to explain that
difference rather than treating it as loss.

`traffic_class` has a closed boundary:

- `steady_state` — every snapshot collector run and ordinary window collection outside
  an initial backfill.
- `cold_start_backfill` — every slice of the initial no-checkpoint window, including a
  new tenant, first deploy, or wiped checkpoint. The scheduler persists the original
  catch-up target, so a backfill larger than one maximum window remains cold across
  later ticks and process restarts until that target is reached.
- `manual_replay` — reserved for the isolated replay workflow. The normal scheduler
  does not emit it, and #289 does not turn replay into ordinary runtime metrics.

A shutdown-cancelled run emits neither source-record accounting view. Point accounting
is cumulative from emissions which already happened, so a partial run retains its
successfully emitted points. No record ID, entity field, request URL, error text, or
collector-provided free text becomes an attribution label.

### Exact process transport

| Metric | Attributes | Meaning |
| --- | --- | --- |
| `graph2otel.otlp.transmitted_payload.bytes` (`By` counter) | `signal="metrics"|"logs"` | Post-compression OTLP payload bytes accepted by the client transport on every actual send, including sends performed by exporter retry loops. |
| `graph2otel.otlp.retry_attempts` (`{retry}` counter) | `signal="metrics"|"logs"` | Second-and-later attempts made by the exporter retry loop for an SDK export callback. |

These are exact for the graph2otel process, not for a collector. Payload bytes exclude
HTTP/gRPC framing, TLS, TCP/IP, kernel retransmission, and backend-side processing. Retry
attempts exclude redirects and transparent connection retries. Neither metric proves
backend acceptance or retention; use the exporter callback health above for that separate
boundary.

### Estimated cost, never enforcement

Cost projection is off unless the operator enables `cost` and supplies the complete,
versioned rate schedule described in [Configuration](configuration.md#cost). graph2otel
embeds no vendor prices. One microunit is \(10^{-6}\) of the configured currency unit.

For an observed interval, the source-record, metric-point, and log-record components use
the exact logical deltas above. Metric payload bytes are allocated over metric points and
log payload bytes over log points independently, using deterministic largest-remainder
allocation for each signal. A signal's bytes can therefore never move to a collector
which emitted points only for the other signal. Bytes which have no same-signal
collector point share remain visible as
`collector="_unattributed", ingest_transport="process"`. Every row carries
`attribution="estimated"`, and the rows reconcile to the process interval estimate.

The interval estimate retains `steady_state`, `cold_start_backfill`, and the reserved
`manual_replay` class. Only `steady_state` contributes to the recurring period
projection and budget ratio. Exceptional rows remain visible with a zero recurring
projection; that means “finite observed cost, not annualised,” not “free.” The admin
forms this estimate from a mature rolling window spanning at least two 60-second metric
export intervals and up to about ten minutes, refreshes it no more than once per minute,
and exposes the actual observed duration.
This reduces the mismatch between collector handoffs, periodic metric export, and the
separate log batch schedule; the collector byte allocation remains estimated.

When enabled, `graph2otel.ingest.cost.projected` is an estimated `{microunit}` gauge
labelled by `tenant_id`, `collector`, `ingest_transport`, configured `currency`,
configured `price_version`, and `attribution="estimated"`. It is a running projection
from cumulative process-lifetime observations rather than a single export interval, so
collector schedules longer than 60 seconds are not annualised from one active minute
and then reported as zero in every idle minute. The projected metric contains recurring
steady-state collector rows only.

The admin status exposes the same exact cumulative volume and process-transport totals,
plus the supplied pricing metadata, mature rolling interval estimate, period projection,
optional budget ratio, and estimated rows. The page labels the result **estimate, not
invoice**; while pricing is disabled, the cost object/card is absent. Exceptional
interval cost remains on the admin surface where its traffic class is explicit.

A budget is display-only. There is no scheduler, limiter, Graph-client, or exporter
control path from these values, so crossing it cannot sample, throttle, delay, disable,
or drop telemetry. Export retries are shown as exact transport activity but have no
invented price component.

For a collector marked `high-volume opt-in`, use the generated collector reference's
measured volume as the pre-enable planning baseline. Once it is running, use
`source_records` and `emitted_points` split by `traffic_class` to replace that baseline
with this deployment's observed volume. Do not project a cold-start backfill as steady
state, and do not infer per-collector wire bytes from the process counters.

## MDCA Cloud Discovery parse health: `ingest_transport="mdca"`

`mdca.discovery_parse` (#145) is the one signal reached over neither Graph, Azure Storage,
nor the O365 Management API, but the **Microsoft Defender for Cloud Apps legacy portal API**
(`<tenant>.<region>.portal.cloudappsecurity.com/api/v1/governance/`) — a static
`Authorization: Token` credential, not the Entra poller. Its records carry the
`ingest_transport` value `mdca`, one of seven:
`graph`/`blob`/`o365_activity`/`audit_query`/`report_export`/`mdca`/`exchange_online`.

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
[alerts/README.md](https://github.com/rknightion/graph2otel/blob/main/alerts/README.md) doc block 5 for the two rules.

## `graph2otel.api.unexpected` — when Microsoft changes something under us

Almost every load-bearing fact this project relies on was established by **measuring a
live tenant**, because the documentation was wrong about it. That leaves a standing
exposure: a measurement is true of one tenant at one moment, and Microsoft can add an enum
member, rename a field, or change what a filter does whenever it likes. Such a change is
**silent** — the API keeps answering HTTP 200 and the collector keeps emitting numbers that
are quietly wrong.

## Cardinality limiting: what gets clipped, and how you know

graph2otel caps its own active-series count, because Grafana Cloud bills on active series
and one mis-scoped label can grow them without bound. Two knobs, both in
`cardinality:` — `per_metric_limit` (default 5000) and `global_limit` (default 100000).
`0` on either means unlimited, which is the right setting for a self-hosted
Prometheus/Mimir where active series are free.

**Clipping is significance-ranked, not arrival-ordered.** Past the limit the top series
*by value* keep their own identity and the tail is folded into a bucket whose unbounded
dimension reads `other` — so `intune.detected_apps.device_count{app_name="other",
platform="windows"}` is the sum of every Windows app outside the top N, and the bounded
`platform` breakdown survives. The OTEL SDK's own per-instrument cap is disabled in favor
of this: it keeps whichever series arrived first and collapses the rest into
`otel.metric.overflow`, a name nothing can interpret.

**A non-additive metric's tail is dropped, not summed.** Folding a device count is
correct; folding a score, a ratio, a percentage or a duration would emit a number that was
never measured, under a name that looks legitimate. graph2otel decides from the metric's
unit and errs toward dropping — a smaller number that says it is smaller beats an invented
one that does not.

Three self-obs series make it impossible for this to happen quietly:

```promql
# series actually shipped, per metric — what you are billed for
graph2otel_series_active

# what was shed, and how
sum by (metric_name, mode) (graph2otel_series_clipped)

# total across every metric, against cardinality.global_limit
graph2otel_series_total
```

`mode` is `folded` (summed into `other`) or `dropped`. Any non-zero value means a metric
has outgrown its limit — raise `per_metric_limit`, or look at why that metric's dimension
is unbounded, which is usually the real answer. graph2otel also logs a WARN the first time
a metric starts clipping, once, not once per interval.

**`graph2otel.series.overflowing` is gone.** It reported the SDK overflow, which no longer
exists; `graph2otel.series.clipped` replaces it and says how much and in which mode.

**Self-observability is never clipped.** `graph2otel.*` is bounded by collector count and
tenant count by construction, and dropping health signals under load would remove the
evidence exactly when it is needed. Those series still count toward `series.total`.

**This is not a license to label metrics by entity.** With a 5000 cap on a 50,000-user
tenant, labeling by UPN buys an arbitrary 5000 series plus a meaningless bucket, at full
cost, when the log twin already answers "which one" better and for free. The rule in
[Cardinality shape](#cardinality-shape) is unchanged.

`graph2otel.api.unexpected` is the counter that breaks that silence.

```promql
sum by (collector, field, kind) (increase(graph2otel_api_unexpected_total[1h])) > 0
```

Labels are `collector`, `field` and `kind` — every one a string from graph2otel's own
source, so the series count is fixed by this codebase and cannot grow with tenant size or
with whatever Microsoft invents. **The offending VALUE is deliberately not a label**; it is
unbounded by definition, so it goes to a `WARN` log line instead. That is this project's
own cardinality rule applied to its own telemetry.

`kind` is one of:

| kind | means |
| --- | --- |
| `unmapped_value` | a field carried a value outside its known set — usually a new Microsoft enum member. Worst where the field is a **metric label**, because a new value silently creates a new series |
| `missing_field` | a field whose absence actually costs something (a join key, an event time) was not there |
| `invariant` | a **measured API guarantee stopped holding** — the highest-value finding, because these are exactly the assumptions taken on trust from a single observation |

**Each distinct finding logs once per process; the counter increments every time.** A
collector polling every 15 minutes would otherwise log the same surprise forever and train
you to ignore it. The log tells you *what* it is, the counter tells you it is *still
happening*. A restart re-logs, which is intentional.

**An unexpected value is never an error.** The record is emitted regardless. Dropping data
because a field grew a new enum member would turn a cosmetic surprise into a hole.

Non-zero does not mean broken — it means an assumption in that collector needs
re-checking, and the WARN log names the field and the value. Treat it as a prompt to go and
measure, then update the known set (and the ledger entry in
[graph-api-gotchas.md](graph-api-gotchas.md)).

### Which collectors are watched, and which deliberately are not

**25 collectors declare watched value sets** (#233, #254, #234): `defender.quarantine`,
`m365.message_trace`, `intune.autopilot`, `intune.devices`, `intune.certificates`,
`intune.cert_inventory`, `intune.app_install_status`, `intune.malware`,
`entra.secure_score`, `purview.retention_labels`, `purview.sensitivity_labels`,
`entra.access_reviews`, `entra.conditional_access`, `intune.gpo_analytics`,
`intune.config_profiles`, `intune.enrollment`, `intune.noncompliant_settings`,
`entra.risk`, `entra.risky_agents`, `m365.sharepoint_settings`, `entra.recommendations`,
`intune.device_encryption`, `intune.remediation_run_states`, `intune.mobile_apps` and
`intune.hardware_inventory`.

`entra.risky_agents` reuses `entra.risk`'s exported `KnownRiskLevels`/`KnownRiskStates`
directly — it is the agent analog on the identical Identity Protection enums, so the two
cannot drift.

Most derive their `Enum` from a bucket map the collector already keys on, so the watched
set cannot drift from the mapped set. The rest are declared explicitly from the Graph CSDL
`$metadata` (the API's own schema, not documentation), for raw-passthrough labels with no
bucket map to derive from — cross-checked against live values wherever the tenant carries
them:

- From the **v1.0** CSDL: `entra.risk`'s `riskLevel`/`riskState` and
  `m365.sharepoint_settings`' `sharingCapability`/`sharingDomainRestrictionMode` (the
  SharePoint set confirmed by cycling the live tenant setting through every member,
  `live-measured 2026-07-25`), and `intune.mobile_apps`' `publishing_state`.
- From the **beta** CSDL (`GET /beta/$metadata`, fetched 2026-07-25, poller read-only):
  `entra.recommendations`' `status`/`priority`/`recommendationType`,
  `intune.device_encryption`'s `encryption_state`/`encryption_readiness_state`/`device_type`
  (the plural `deviceTypes` enum)/`encryption_policy_setting_state`,
  `intune.remediation_run_states`' `detection_state`/`remediation_state`, and
  `intune.hardware_inventory`'s two Device Guard states (`vbs_state`,
  `credential_guard_state`).

In every set `unknownFutureValue` is deliberately excluded, so Microsoft's evolvable-enum
sentinel fires the watchdog rather than being silently accepted.

`defender.quarantine` carries more single-measurement assumptions than most, because it
shipped without ever observing a non-empty quarantine: the `quarantine_type` /
`entity_type` / `direction` enums (all three are metric labels), the `held_only_filter`
invariant that `ReleaseStatus=NOTRELEASED` really does filter server-side, the `page_cap`
invariant, and a `network_message_id` that must be recoverable from the composite
`Identity`. A `held_only_filter` finding is the serious one: it means `held_messages.total`
has stopped being queue depth.

**Several collectors bucket unrecognized values to `"unknown"` and are still
unwatched on purpose** — among them `intune.detected_apps`, `intune.connectors`,
`intune.settings_catalog` and `entra.domains`. In each case the legitimate value set could
only be taken from Microsoft's documentation, and **a watchdog that fires on correct data
is worse than none**: it trains the reader to ignore the signal, which costs more than the
gap it was meant to close. These are recorded evidence gaps, not oversights.

**Some fields on otherwise-watched collectors are left unwatched because they are free
text, not an enum** — no CSDL set exists to declare, so a watchdog would fire on correct
data. `intune.devices`' and `intune.hardware_inventory`'s `operating_system` (bucketed free
text, no Graph-side enum), `intune.hardware_inventory`'s `manufacturer` (hardware vendor
names) and `tpm_specification_version` (a comma-joined version triple), and
`intune.mobile_apps`' `app_type` (the `@odata.type` derived-subtype hierarchy off
`mobileApp` — a large catalog Microsoft extends whenever it ships a new app shape, so a
watchdog would fire on legitimate new types; the central limiter (#235) bounds its series
instead, same call as `intune.detected_apps`). None should be revisited.

### The rule for a new collector

**If your collector assumes a value set, declare it — and derive it from evidence, not
documentation.** Concretely:

1. **Watch a field whose value keys a METRIC LABEL.** An unmapped member there moves series
   membership: the number itself becomes wrong, silently. A log-only attribute is far less
   urgent — an odd string in a log is visible to anyone querying it — so watching those is
   optional and usually not worth the noise.
2. **Derive the `Enum` from the map the collector already keys on**, rather than restating
   the members. Then the watched set is by construction the set you actually map, it cannot
   drift when someone edits the map, and it can only fire on a hole in the mapping.
3. **Where no evidence exists — no fixture, no live sample, no constant the code keys on —
   leave the field unwatched** and say so in the package doc, naming what would close the
   gap. One observed value is not a value set.
4. **Report-only, always.** An unexpected value must never drop a record, change a count, or
   fail a fetch.

### Alerting on it

This is **dashboard-and-log territory, not a paging rule.** A non-zero counter means an
assumption needs re-checking, which is a next-working-day task, not an incident — and the
WARN log carries the offending value while the counter deliberately does not. Watch
`increase(graph2otel_api_unexpected_total[24h]) > 0` on a panel, then read the WARN to find
out what Microsoft sent. A 1-hour paging rule on a signal whose remedy is "go and measure,
then update the known set" would fire out of hours for something nobody can action until
morning.

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

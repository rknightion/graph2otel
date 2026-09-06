# Telemetry model and cardinality rules

Read before adding or changing any metric, log attribute, namespace or opt-in gate.
`docs/signals.md` is the user-facing catalogue; this file is the set of rules a change must obey.

## Namespaces and opt-in gates

- Domain metrics use `entra.*` / `intune.*` / `m365.*` / `purview.*` / `defender.*` / `mdca.*`.
  Self-observability uses `graph2otel.*`. A collector emitting outside its domain's namespace is
  a bug.
- `defender.*` is the Defender XDR advanced-hunting tables: log-only blob collectors and a peer
  domain, not folded into entra or m365. They are NOT `Experimental`; setting
  `blob_ingest.account_url` is the whole opt-in.
- `mdca.*` is Defender for Cloud Apps, reached over the **legacy portal API and not Graph**: a
  static `Authorization: Token` credential, no azidentity or app-role scope, no Graph successor.
  So `mdca.discovery_parse` IS `Experimental`, and `mdca.portal_url` plus `mdca.token_file` is
  the opt-in.
- **Two opt-in interfaces, gated identically, meaning different things.** `Experimental` means a
  genuine Graph *beta* surface. `HighVolume` means a firehose whose rate scales with **traffic**
  rather than tenant size (`m365.message_trace` is one record per message per recipient). Both
  register only when config explicitly enables them. Do not reach for `Experimental` to mean
  "expensive": it tells an operator a GA endpoint is beta while hiding the one fact they need. A
  `HighVolume` collector MUST carry a **measured** volume figure in its `collectordoc`
  annotation; "high volume" with no number is not something anyone can plan capacity against.

## Stamped attributes

- **`tenant_id` is on EVERY signal**, domain and self-obs, metrics and logs.
  `telemetry.WithTenant` stamps it at the emitter boundary, so no collector sets it itself:
  `Deps.TenantID` is for the collector's own use (URLs, prefixes, checkpoint keys), never for
  labelling. An empty tenant stamps nothing. It is deliberately a **metric** label, the opposite
  of `ingest_transport`, because without it two tenants' domain metrics are the *same series*,
  not merely unsliceable. It never means a tenant named inside a record: `/security/alerts_v2`
  carries its own `tenantId` holding the same value, and graph2otel deliberately does not map it.
- **Every log record names its transport**: `ingest_transport` is one of `graph` / `blob` /
  `o365_activity` / `audit_query` / `report_export`, stamped at the **emitter boundary**
  (`telemetry.WithTransport`) and not in the engines, because many collectors emit with no engine
  and `exportjob` never emits at all. Outermost stamp wins: the Scheduler sets the `graph`
  baseline and each engine and export collector overrides it. **Log-only** - a metric label would
  change series identity. It is deliberately NOT called `source`, which already has four live
  meanings.
- **Sign-ins are transport-identical; risk is NOT.** A blob and a Graph sign-in differ only by
  `ingest_transport` and share one gated mapper. Risk records differ in their field set
  (`riskType` is blob-only and does not exist on Graph v1.0), so do not generalise the sign-in
  case.

## Querying and naming

- **Log attributes are Loki structured metadata, not stream labels.** Only `service_name` is a
  stream label, so `{event_name="entra.signin"}` matches **zero rows silently**, the most common
  way to build an alert that never fires. Always `{service_name="graph2otel"} | event_name=...`.
- **OTLP to Prometheus normalization is real**: gauges gain `_ratio`/`_seconds`/`_percent`,
  counters `_total`. Dashboards and alerts use the normalized names.
- **OTEL lockstep:** `go.opentelemetry.io/otel` and `otel/sdk/log` bump together, never
  independently (Renovate-grouped).

## Wire-value watchdog

**A collector that ASSUMES a value set declares it to `internal/wirecheck`.** A measurement is
true of one tenant at one moment; when Microsoft adds an enum member the API still answers 200
and the collector quietly buckets it to `"unknown"`.

- Watch the fields whose value keys a **metric label**. There an unmapped member moves series
  membership, so the number itself becomes wrong.
- **Derive the `Enum` from the map the collector already keys on**, never restate it, so the
  watched set cannot drift from the mapped set.
- Report-only: an unexpected value must never drop a record.
- **Where no evidence exists - no fixture, no live sample, no constant the code keys on - leave
  the field UNWATCHED and say so in the package doc.** One observed value is not a value set, and
  a watchdog that fires on correct data trains the reader to ignore the signal. A dozen
  collectors are unwatched on exactly those grounds and that is a recorded decision, not a
  backlog.

## Cardinality: metrics carry aggregates, logs carry entities

This is a data-modeling rule, not a privacy control. The old "PII guidance" framing caused real
bugs three times. graph2otel exports UPNs, device serials, IPs and group membership to the OTLP
backend **by design**; the backend is a trusted sink and scoping its credentials is the actual
control. The rule only decides *which pipeline* each shape of data takes, on cost and
queryability.

- **Per-entity data never becomes a metric label.** Grafana Cloud bills on active series; a
  series keyed by UPN, device or sign-in grows with tenant size or gets one sample ever. A LogQL
  `count by` over the log twin answers the same question free.
- **Metrics carry bounded, tenant-shaped aggregates**: counts by state, OS, policy, risk level. A
  series whose cardinality grows with tenant size is a bug.
- **"Not a metric label" means LOG TWIN, never dropped.** A collector that fetches per-entity
  rows, buckets a count and discards the rest is a bug: it can answer "how many" but never "which
  one". `telemetry.Emitter` exposes `LogEvent`; `internal/collectors/entra/risk` is the reference
  shape, a bounded gauge plus one log per entity from one fetch.
- **Bounding a metric is CENTRAL, not per-collector.** `internal/telemetry`'s limiter caps every
  metric at `cardinality.per_metric_limit` (5000) and the process at `cardinality.global_limit`
  (100000), keeping the top series by value and folding the tail into a named `other` bucket.
  Additive metrics get the tail summed; non-additive ones (score, ratio, percent, duration,
  decided from the UNIT) get it dropped and counted, because a fabricated aggregate is worse than
  the loss. The OTEL SDK's own cap is disabled and ours supersedes it. **Do not write a new
  per-collector allow-list** - the two that existed were retired here, and both had discarded
  100% of the live data while reporting healthy. New units must be classified in
  `internal/semconv/additive.go` or CI fails.
- **The limiter is NOT permission to label by entity.** With a 5000 cap on a 50k-user tenant, a
  UPN label buys an arbitrary 5000 series plus a meaningless bucket, at full cost, answering
  nothing the log twin does not answer better.
- **The one content exclusion is SECRETS, not PII, and it is exactly one field:**
  `internal/collectors/intune/auditevents` emits the *names* of changed `modifiedProperties` but
  never their old or new *values* (for a credential change, the value IS the credential). **Do
  not generalise it by feel.** "Awkward to model" is not "unsafe to ship"; that mistake shipped
  three times. Change this only on evidence of a secret observed in a field.

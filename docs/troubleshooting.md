---
title: Troubleshooting
description: Symptom-first entry point for graph2otel failures, routing to the Graph API gotchas and alert runbooks that cover the detail.
---

# Troubleshooting

This page is a symptom-first index, not a second copy of the detail. Two pages already
cover most of the ground:

- [Graph API gotchas](graph-api-gotchas.md) — the live-verified quirk ledger for
  specific Microsoft Graph and O365 endpoint behavior (URL encoding, page-size
  ceilings, throttling shapes, per-endpoint traps).
- [Alert runbooks](runbooks.md) — one section per shipped alert rule, each covering the
  fired / no-data / errored / false-positive states for that exact signal.

If nothing here matches, check the two pages above before opening an issue on
[GitHub](https://github.com/rknightion/graph2otel/issues).

## Setup and permissions

### `graph2otel check` passes but a collector still 403s

`graph2otel check` only confirms a Graph permission is granted and admin-consented — it
cannot detect every prerequisite. Two known gaps:

- **A directory-role gate.** Identity Protection surfaces (`entra.risk`,
  `entra.risk_detections`) have been observed in Microsoft's docs to additionally
  expect a directory role (e.g. Security Reader) on the service principal, beyond the
  API permission grant. See [Permissions](permissions.md#3-directory-role-gating-gotcha-2-partially-confirmed).
- **A revoked consent grant on a collector that used to work.** Read `cause=` on the
  WARN `collector completed with degraded outcome` log line, or split
  `graph2otel_scrape_outcomes_total` by `result`. `permission_denied` on a
  previously-working endpoint means re-consent the app role named by the collector's
  `RequiredPermissions()`. See
  [runbooks: g2o-collector-degraded-sustained](runbooks.md#g2o-collector-degraded-sustained).

### A collector logs 401 even though the scope is already in the token

A 401 with the scope present, on Purview eDiscovery specifically, means the service
principal is not registered with the Security & Compliance data plane — a Graph scope
alone cannot fix it, no matter how it's re-granted. See
[Non-Graph data-plane registration](data-plane-registration.md).

### Admin consent shows granted in the Entra admin center but calls still 403

Adding an application permission is not the same as consenting to it. A tenant
administrator must separately click **Grant admin consent** — until then every call
using that permission returns 403 regardless of what the admin center's permissions
list shows. See
[Permissions](permissions.md#2-grant-admin-consent-gotcha-1).

### `mdca.discovery_parse` has no Graph scope to grant

That's expected — it's the one collector that authenticates with a static portal token
against the legacy MDCA API, not `DefaultAzureCredential` or a Graph token. `graph2otel
check` reports it as a manual prerequisite it cannot verify. See
[Permissions](permissions.md#4c-one-collector-authenticates-with-a-static-token-not-the-entra-app-gotcha-5).

## Startup and configuration

### The process exits immediately with a config validation error

Configuration mistakes stop the process before it constructs credentials, checkpoint
stores, or collectors. The error names the exact path — including sequence indexes and
collector map keys for YAML, or the exact `G2O_*` variable name for environment
overrides. A near-miss collector name gets a `did you mean "..."` suggestion. See
[Configuration](configuration.md#strict-validation).

### Startup fails because `checkpoint_dir` isn't writable

This is fatal by design — silently restarting from the initial lookback instead of the
real watermark would create an unbounded replay. In Kubernetes this is almost always
the Helm chart's default `emptyDir`; set `persistence.enabled=true`, since an
`emptyDir` also silently loses every watermark on pod replacement. See
[Architecture](architecture.md#checkpoints-and-delivery-semantics) and
[runbooks: g2o-checkpoint-persist-errors](runbooks.md#g2o-checkpoint-persist-errors).

### The process won't start because the admin address can't bind

A configured `admin.addr` that cannot bind is a fatal startup error — graph2otel never
runs silently without its configured health surface. Check for a port conflict or an
address the container/pod isn't allowed to bind. See
[Configuration](configuration.md#admin).

## Missing or empty data

### A collector shows `healthy_empty` on the availability gauge

`healthy_empty` means the source answered successfully with zero rows — it proves the
collector's source responded, not that graph2otel observed data. On a small tenant this
is routine: the default `m365.activity` content types (`Audit.Exchange` +
`Audit.SharePoint`) commonly carry zero content and the collector looks 100% healthy
doing it. See [Signals](signals.md#collector-availability) for the full state/reason
contract.

### An experimental or beta collector emits nothing

Beta-only collectors never register on the implicit "unset means enabled" default —
they need an **explicit** `enabled: true` at some config layer before they run at all.
Setting `enabled: false`, or leaving the collector unmentioned, both mean "not
explicitly enabled." See
[Configuration](configuration.md#experimental-beta-collectors-are-opt-in-not-default-on).

### `graph2otel.collector.availability` shows `disabled` or `covered`

Both are intentional absence, not a failure — `disabled` means the collector isn't
switched on for that tenant, `covered` means a logical signal is being served by a
different registered candidate. Look for `degraded`, `failed`, or `startup_failed`
instead when hunting for a real problem. See
[Signals](signals.md#collector-availability).

### Blob-ingest collectors show no data

Check three things in order: the diagnostic setting actually points at the storage
account you configured; `Storage Blob Data Reader` (a data-plane role — `Owner` alone
is not sufficient and fails silently, listing blobs but 403ing only on content reads)
is granted to graph2otel's app registration; and the container has actually received
its first write — Azure creates `insights-logs-<category>` containers on first write,
not at setting-creation time, so a missing container can just mean "nothing written
yet." See [Blob ingest](blob-ingest.md#traps).

### A collector's Graph call returns 200 but the data looks wrong or truncated

Several Graph endpoints answer with rows that look complete but aren't — a bare
Endpoint Analytics list can silently serve one device out of many, `$count=true` can
drop the rows it's counting, and other per-endpoint quirks are cataloged with their
exact wire evidence. Before concluding a tenant has no data, vary the request shape
(bare vs `$select` vs `$top` vs single-entity) — see
[Graph API gotchas](graph-api-gotchas.md#query-mechanics-all-workloads).

## Throttling and delivery

### Collectors are slow to update or fall behind their interval

Check `g2o-throttle-saturation` and `g2o-collector-staleness` first — none of the
throttled Graph workloads reliably send `Retry-After`, so throttling degrades
freshness silently rather than erroring loudly. The alert's `workload` label names the
ceiling being hit; Identity Protection's 1 req/s limit is shared tenant-wide across
every application, so another app in the tenant can throttle graph2otel. See
[runbooks: g2o-throttle-saturation](runbooks.md#g2o-throttle-saturation) and
[runbooks: g2o-collector-staleness](runbooks.md#g2o-collector-staleness).

### Metrics or logs aren't reaching the backend

Grep the process's stderr for the `otel sdk error` line, which quotes the backend's
rejection reason verbatim — a size limit, a timestamp-horizon rejection, or a
credential problem read very differently and need different fixes. See
[runbooks: g2o-otlp-delivery-failing](runbooks.md#g2o-otlp-delivery-failing).

### Records are being dropped as too old for the backend

Grafana Cloud's OTLP gateway rejects entries older than 7 days per-entry; graph2otel
clamps its own poll to 165h to stay inside that window. A blob-derived stream can push
records past the backend's window through ordinary aging — this is expected there, not
a misconfiguration, and the alert for it ships paused for exactly that reason. See
[Configuration](configuration.md#backfill) and
[runbooks: g2o-record-over-horizon](runbooks.md#g2o-record-over-horizon).

### A log record was truncated instead of dropped

This is content loss, not record loss — the record landed, but its largest attribute
values were shortened to fit the backend's structured-metadata size limit. Query for
`attrs_truncated = "true"` to find which records and which fields. See
[runbooks: g2o-record-attrs-truncated](runbooks.md#g2o-record-attrs-truncated).

## Querying logs and getting nothing back

### A LogQL query on an attribute returns zero rows

graph2otel's log attributes (`event_name`, `app_id`, `user_principal_name`, …) are Loki
**structured metadata**, not stream labels. A stream selector on one of them —
`{event_name="entra.signin"}` — matches nothing and fails silently. Filter with a `|`
label-filter after the `{service_name="graph2otel"}` stream selector instead. A line
filter (`|=`) also cannot see structured metadata, so an empty line-filter result is
not evidence a value is absent. See
[Signals](signals.md#querying-the-logs-in-loki-attributes-are-structured-metadata-not-stream-labels).

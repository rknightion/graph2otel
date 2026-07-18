# Blob ingest: reading Azure Storage instead of Graph

Some signals have **no Microsoft Graph read endpoint at all** — Graph cannot see them, no
matter how the poller is tuned. They exist only as Azure Monitor diagnostic-settings
output. graph2otel reads them from an Azure Storage account.

This is the **one place graph2otel reads from outside Graph**, and it is **opt-in**: set a
tenant's `blob_ingest.account_url` and the blob collectors register; leave it unset (the
default) and they do not exist. A deployment with no storage account is unaffected.

The Azure SDK lives behind one interface (`blobpipeline.Source`, implemented in
`internal/blobpipeline/azblob_adapter.go`). No collector imports an Azure type.

## What it is for

| signal | collector | why blob |
| --- | --- | --- |
| `MicrosoftGraphActivityLogs` | `entra.graph_activity` | **No Graph endpoint, permanently.** Graph's own per-request API-call telemetry. ~70% of billable diagnostic volume. |
| `GraphNotificationsActivityLogs` | `entra.graph_notifications` | **No Graph endpoint.** Change-notification (webhook/event-hub) delivery telemetry: which app owns a subscription, which workload it targets, and the publish result. A change-notification subscription is a persistence/supply-chain foothold, so `application_id` (the subscription owner) is the load-bearing attribute. **Built (#134), live-mapped 2026-07-17.** The other two #134 unknowns (`MicrosoftGraphPolicyLogs`, `PreAuthenticationDiscoveryLogs`) write nothing on the verification tenant and stay unmapped. |
| `MicrosoftServicePrincipalSignInLogs` | `entra.signins.microsoft_service_principal` | **No Graph endpoint.** Microsoft first-party service-to-service auth. Live-verified a genuinely different dataset from `entra.signins.service_principal` — see below. |
| `ServicePrincipalSignInLogs` | `entra.signins.service_principal.blob` | Retires a `/beta` dependency (see below). |
| `NonInteractiveUserSignInLogs` | `entra.signins.non_interactive.blob` | Retires a `/beta` dependency (see below). |
| `ManagedIdentitySignInLogs` | — | Same case as the two above, but **not built**: the container does not exist on the verification tenant, so there is no live sample to map against and this project does not map from documentation (#135). |
| Intune `OperationalLogs` | `intune.compliance_alerts` | **No Graph endpoint** (#94) — Graph exposes only the notification templates, never the compliance-alert *fired-event* stream. **Built (#135 group A), live-mapped 2026-07-17:** one log per fired compliance alert ("managed device X is not compliant"), naming the device (host/NetBIOS/DNS), its owner (`user_name`/`upn_suffix`), and the failing setting (the rule path in `description`). Emitted Warn. Records carry `OperationalLogCategory` (`DeviceCompliance` observed); the mapper passes it through so any other alert category that lands here is captured, not dropped. |
| `AuditLogs`, `ProvisioningLogs` | `entra.directory_audits` / `entra.provisioning` (blob source) | **Built (#135 group D).** Same collectors as the polled versions, switched by the per-collector `source: graph\|blob` config (default `graph`; set `blob` to consume the diagnostic-settings container instead). One transport per collector — never both, so no double-ship — via the `source` toggle rather than a second collector; the blob path reuses `mapDirectoryAudit`/`mapProvisioning` unchanged and binds the timestamp to `properties.activityDateTime`. These are log-only signals (zero metrics), so `source: blob` is a clean full swap; blob is the more scalable transport on a high-volume tenant. |
| `Devices` | `intune.devices_blob` (blob, keep-gauges/suppress-twin) | **Built (#135 group F).** A separate log-only collector emitting the same `intune.managed_device` records the polled `intune.devices` twin would (reuses `deviceLogTwin`). NOT a source swap — `intune.devices` keeps polling the fleet for its bounded gauges (an inventory dump can't produce counts), and the composition root suppresses only its per-device twin (same `RegisterBlobTwinOwner` mechanism as `entra.risky_users`). **The blob report uses PascalCase field names and different enum VALUES than the Graph managedDevice resource**, so each field is normalized onto the Graph shape before reuse (`CompliantState "Compliant"`→`compliant`, `OS "MacOS"/"IOS"`→`macOS`/`iOS`, `EncryptionStatusString "True"`→bool, `LastContact` (no TZ)→UTC), verified against both live shapes (2026-07-18) so the twin is identical across transports. Skips the per-batch `{Stats:{RecordCount}}` summary record; staleness is computed against the snapshot's envelope `time`. Full page-walk RETIREMENT stays #132; `DeviceComplianceOrg` (threat level, management agents) is a separate concern, not folded here. |
| `RiskyUsers` | `entra.risky_users` (blob, keep-gauges/suppress-twin) | **Built (#135 group C).** A SEPARATE log-only collector emitting the same `entra.risky_user` records the polled `entra.risk` twin would (reuses `logTwin`, bound to `riskLastUpdatedDateTime`). NOT a source swap — `entra.risk` is a SnapshotCollector whose bounded (riskLevel, riskState) gauge comes from a current-state query the blob feed can't reproduce, so it keeps polling for the gauge and the composition root suppresses only its per-entity twin while this runs (blob twin XOR polled twin, gauges always). Dodges the Identity Protection 1 req/s ceiling for the per-entity stream. Suppression is auto-wired via `RegisterBlobTwinOwner` (#135-C) — the general mechanism `intune.devices` reuses. `RiskyServicePrincipals` is the same shape but its container does not exist on the verification tenant (no risky-SP data), so it is unbuilt pending a live sample. |
| `UserRiskEvents` | `entra.risk_detections` (blob source) | **Built (#135 group C).** Same log-only collector as the polled `/identityProtection/riskDetections`, switched by `source: graph\|blob`. Blob dodges the Identity Protection **1 req/s per-tenant ceiling** (graph2otel's tightest throttle, no `Retry-After`) — the reason to prefer it on a tenant with real risk volume. The blob `properties` object IS the riskDetection resource (verified against the #129 synthesized event, 2026-07-18), so it reuses `mapRiskDetection` unchanged; the timestamp binds to `properties.detectedDateTime`. The blob adds one field the Graph v1.0 resource lacks — `riskType`, a duplicate of `riskEventType` — already accounted for by the mapper. |

### The sign-in collectors

The three shipped sign-in collectors emit `entra.signin` — the **same event name and the same
attributes** as the polled streams, because the diagnostic-settings `properties` object *is* the
Graph `signIn` resource (verified field-for-field against live samples of all four sign-in
categories). They share one mapper with the polled path, so the two sources are indistinguishable
downstream and an attribute added for one is automatically right for the other.

**`MicrosoftServicePrincipalSignInLogs` is not a duplicate of `ServicePrincipalSignInLogs`.**
Live-verified 2026-07-16: every sampled record in the former was owned by Microsoft's own tenant
(`f8cdef31-…`) and every record in the latter by the local tenant, with **zero** sign-in ids
overlapping. The two partition cleanly by app ownership, which is why the polled
`entra.signins.service_principal` — restricted to your own service principals — can never surface
the first-party half.

**The `.blob` suffix** marks a collector whose polled twin exists; the two are separate config keys
with separate intervals. They are **not Experimental** (configuring `blob_ingest.account_url` is
already the opt-in, and unlike the polled twins these are v1.0-stable sources), and they declare
Entra ID P1 so a Free tenant gets a stated skip rather than a silent empty container.

Running a `.blob` collector **and** its polled twin ships each sign-in twice. The polled twins are
`Experimental` and therefore off by default, so this needs a deliberate act; if you do both, dedupe
downstream on the `id` attribute, which is identical across the two sources.

Blob is **not** a general replacement for polling. Metrics want freshness and blob is
floored at ~4 minutes; logs want completeness and blob has no throttle ceiling. But a
collector's source is **graph XOR blob, never both** — #131 examined a "dual-ship" mode
(Graph for metrics, blob for logs) and closed rejecting it: the log-shaped collectors emit
zero metrics, so dual-ship is empty for every signal it would list, and mutual exclusion
is enforced in config (#144's `ConflictsWith`). The one genuinely dual-capable signal
(`intune.devices`) is tracked in #132.

## What it costs

**~£3.07/month** on a small tenant, dominated by `MicrosoftGraphActivityLogs` and the
service-principal sign-in categories. There is **no standing charge** — that was the point.

The bill is almost entirely **write operations**, not storage: ~5.0 GB/month of data costs
about 7p resident, while the AppendBlock calls that put it there cost ~£3.05. Measured live
on a backfill-free window at **935 appends/hour** (~7.3 KB per append), which is ~683,000
appends/month at the ~£0.0447/10K write rate. Storage is ~£0.0145/GB/mo, reads ~£0.0036/10K,
and **listing is billed at the write rate**. `[live-measured 2026-07-17, #137]`

> **Cost scales with graph2otel's own collector count, not just tenant size.** Every Graph
> call a collector makes writes a `MicrosoftGraphActivityLogs` record, which the blob path
> then pays to ingest — so **graph2otel is 59.9% of its own MGAL volume** (14,404 of 24,048
> records carry the poller's own appId; top URIs `/groups/$count`, `/devices/$count`,
> `/servicePrincipals`). Enabling a Graph-polled collector bills twice: once for the poll,
> once for ingesting the MGAL record it created, so a 60-collector tenant costs more than a
> 20-collector tenant of the same size. The opt-in self-exhaust exclusion (#154) is the lever;
> the self-share also means any "who is calling Graph in this tenant" reading of MGAL is ~60%
> the observer. A second, unrelated concentration distorts the bill the same way: one Defender
> TVM scan-agent SP is 96.4% of `ServicePrincipalSignInLogs`.

> **The £0.85/month figure previously here was measured 2026-07-16 mid-backfill**, before those
> volume drivers were fully in play — honest when taken, ~3.6× low at steady state. The append
> count is exactly measurable rather than modelled: `append_blob_committed_block_count` is a
> direct count of billable AppendBlock operations, because an append blob supports no other
> write. Don't guess at the batching; read the counter.

Log Analytics and Event Hub were both evaluated against this and closed (#89). The 3.6×
correction does not reopen either — re-ranked at the measured volume against #89's live-queried
uksouth prices, the margin **widens**: blob **£3.07** < Event Hub **£8.32** < Log Analytics
**£10.88**. Blob is priced on write operations and LA on GB ingested, so a volume underestimate
hurts LA harder, not blob. Event Hub's entire measured advantage was **12 seconds** of latency,
and the ~4-minute delay is Entra-side — upstream of where the transport forks — so a faster
destination cannot buy back time already spent. Full evaluation: #89.
`[live-measured volume × docs-priced meters, 2026-07-17, #137]`

### Excluding graph2otel's own exhaust (`exclude_self`)

Because ~60% of `MicrosoftGraphActivityLogs` is graph2otel calling Graph (above),
there is an opt-in filter that drops the poller's own records before they are
emitted: `blob_ingest.exclude_self`, **default off**.

```yaml
tenants:
  - tenant_id: "..."
    client_id: "<the poller's app registration id>"
    blob_ingest:
      account_url: "https://myaccount.blob.core.windows.net"
      exclude_self: true
```

- **Self-only, by `appId`.** A record is dropped **if and only if** its actor
  `appId` equals *this tenant's own* `client_id` — the poller's app registration
  (live-verified: the poller's `client_id` is exactly the MGAL `appId`, 14,404
  records matched, #154). Any other `appId` — including Microsoft's own
  first-party service principals — always passes through untouched.
- **Per-tenant.** "Self" is that tenant's `client_id`, never a global list, so one
  deployment polling many tenants filters each against its own poller identity.
- **Scope: the blob categories that carry an `appId`** — `MicrosoftGraphActivityLogs`
  (`entra.graph_activity`) and the service-principal sign-in categories
  (`entra.signins.*`). Categories with no `appId` (e.g. `AuditLogs`) are never
  filtered. The Graph-polled path and `m365.activity` are other transports and out
  of scope.
- **Loud, never silent.** Every dropped record increments the
  `graph2otel.blob.self_excluded` counter (`_total` on the Prometheus side),
  labelled `collector`, so a ~60%-quieter dashboard is visible and alertable rather
  than looking like breakage. The bytes are still consumed, so the byte-offset
  cursor advances exactly as for any other dropped record.
- **Resolving "self".** The poller's app id comes from the tenant's `client_id`,
  falling back to the `AZURE_CLIENT_ID` the `DefaultAzureCredential` env leg already
  uses — so an env-authenticated deployment (the common case) works without duplicating
  the id into config, while a per-tenant `client_id` still wins for a multi-app process.
  Only if neither is set can "self" not be identified; the filter then no-ops and
  graph2otel logs a warning at startup rather than silently doing nothing.

## Setup

1. **Create a storage account** (StorageV2, Hot, LRS is fine; disable public blob access)
   with a **lifecycle rule** deleting blobs after N days. Retention past your log backend's
   own reject-old-samples age is pointless — Loki would refuse the records anyway — so 7
   days is a reasonable default.
2. **Create the diagnostic settings** pointing at it. Entra categories live under the
   tenant-level `microsoft.aadiam` provider, Intune categories under `microsoft.intune`.
   These are **two separate settings**, not one.
3. **Grant the DATA-plane role** `Storage Blob Data Reader` to graph2otel's app
   registration, scoped to that account. See the traps below — this is not optional, and
   getting it wrong looks like success.
4. **Set the account URL** in config:

   ```yaml
   tenants:
     - tenant_id: "..."
       blob_ingest:
         account_url: "https://myaccount.blob.core.windows.net"
   ```

No credential goes in config: the tenant's existing `AZURE_*` credential is reused, and
the SDK requests the storage audience itself.

graph2otel is **read-only** on the account — it cannot write or delete a blob. Retention
belongs entirely to the lifecycle rule; see "Why read-only" below.

## Traps

Everything here was verified live against a real tenant on 2026-07-16. Several items
contradict Microsoft's own documentation, which is why this list exists.

### The blob layout is not what the docs say

```
DOCUMENTED:  resourceId=/tenants/<tid>/providers/microsoft.aadiam/y=/m=/d=/h=/m=00/PT1H.json
ACTUAL:      tenantId=<tid>/y=2026/m=07/d=16/h=13/m=00/PT1H.json
```

Every published Microsoft example is subscription-scoped. A **tenant-level**
(`microsoft.aadiam`) resource uses `tenantId=<guid>/` instead. Coding the listing prefix
to the docs yields a collector that lists zero blobs and reports success forever.

The container is `insights-logs-<category-lowercased>`. Records are JSON Lines with
**CRLF** terminators, in **append blobs**.

### Data-plane RBAC fails in a way that looks like success

`Owner` grants blob **container** list/create — those are control-plane Actions. Reading
blob **content** is a DataAction, and needs `Storage Blob Data Reader`. So an
under-privileged identity **lists blobs happily and 403s only on the read**.

(The Event Hub variant is worse, if you ever go that way: without `Azure Event Hubs Data
Receiver` the SDK returns **0 events with no error at all** while the hub reports
hundreds.)

### A closed hour's blob keeps growing — and nothing tells you when it stops

Blobs are partitioned by **event time**, and on enablement Azure backfills history into
those hour buckets progressively, oldest-first. While backfill is working on hour N, that
blob grows **regardless of how long ago hour N closed** — an `h=00` blob was observed
still being appended to 13 hours later. Once backfill passes an hour, that hour freezes.

So a "this hour is complete" state does exist, but **nothing signals when it is reached**,
and it is not derivable from the clock. Hence:

- The cursor is a **byte offset per blob**, never a timestamp watermark. A watermark
  cannot express this; an offset can, because append blobs never rewrite a byte.
- The consumer **re-checks every blob it has seen** on every tick, not just newer ones. A
  walk-forward-and-forget consumer silently loses every late-arriving record.
- This is affordable: the lifecycle rule bounds the set to ~168 blobs per category, an
  unchanged blob costs a size comparison rather than a read, and in steady state only one
  or two blobs actually grow per tick.

Backfill on enablement is **good news**, incidentally: turning the destination on recovers
history rather than starting from zero.

**Resolved** (#137, `[live-measured 2026-07-17, n=1 tenant, 19h window]`): backfill on this
tenant ended `2026-07-16T17:00Z`; in steady state a bucket freezes **~2–8 minutes after its
hour closes**, and no closed bucket was observed growing across a ~19h window (16 settled
hours, 6 categories). That is not proof it can *never* grow — a genuinely rare late record on
a larger or more distributed tenant would not necessarily surface in 19h here — so the
re-check-every-blob design stays: correct under both answers, and cheap. A settle-horizon
optimisation (stop re-reading blobs older than N) is **explicitly not built**: below a **13h**
horizon it would have silently dropped real backfill data on this very tenant on 2026-07-16.
Evidence class: cheap to reopen, not armored.

### Azure delivers at-least-once: ~2.7% (MGAL) / ~4% (sign-ins) of records arrive more than once

Measured live on a clean backfill-free window (2026-07-17, `[live-measured, #137]`), and
cross-checked against the backfill window — the two agreed within noise, so **at-least-once
re-delivery is a steady-state property of Azure's delivery, not a backfill artifact**. The
sign-in family clusters near **4%**, higher than MGAL's 2.7%, and one event was observed
delivered **four** times (an earlier measurement, on ~4–12× less data, saw a max of three and
a flat ~2.3–2.8%):

| category | records | re-delivered | max multiplicity |
| --- | ---: | ---: | ---: |
| `MicrosoftGraphActivityLogs` | 24,048 | 654 (2.72%) | ×4 |
| `ServicePrincipalSignInLogs` | 9,578 | 389 (4.06%) | ×4 |
| `MicrosoftServicePrincipalSignInLogs` | 2,927 | 120 (4.10%) | ×4 |
| `NonInteractiveUserSignInLogs` | 908 | 27 (2.97%) | ×4 |

`AuditLogs` showed 0/73 dupes across both windows, but n=73 is too small to tell exactly-once
from a ~3% rate (expected ~2 dupes) — **do not record it as exactly-once**. A downstream dedupe
must not assume at-most-two copies: multiplicity reaches ×4.

A re-delivered event is written as a **separate line**, usually into the same hour blob, with a
**byte-identical `properties` payload** and a **fresh envelope `time`**. One `h=04` blob carried the
same sign-in at line 15 (envelope `04:09:50`) and line 20 (envelope `04:16:16`) — identical `id`,
`createdDateTime`, `correlationId`, and `uniqueTokenIdentifier`, 6.4 minutes apart.

**This is not a cursor bug and it is not fixable by the cursor.** Both copies are real, distinct
bytes; a byte-offset cursor consuming them exactly once is behaving correctly. Verified directly:
across a cold start plus a restart, for all 1,035 emitted ids, the number of times graph2otel
emitted a record **exactly equalled** the number of times Azure wrote it — no over-emission, no
loss.

The consequence is real: **blob-sourced collectors ship Azure's duplicates through to your
backend.** The polled path does not have this problem — `logpipeline` carries a seen-id set in
its checkpoint and dedupes. `blobpipeline` has no equivalent, so ~2.7% (MGAL) / ~4% (sign-ins)
of blob-sourced records are duplicates.

**Decision (#138): dedupe downstream, not in the engine.** Engine-side dedupe is the wrong
trade here. It would need a seen-id set that (a) is **unbounded** — Azure re-delivers across the
full 7-day retention with no natural window to bound it by (MGAL alone is ~150k rows/7d), unlike
`logpipeline`'s overlap window; (b) **persists across restart**, growing the byte-offset
checkpoint without limit; and (c) is **correct across hour blobs** (re-deliveries cross blob
boundaries, so per-blob dedup is insufficient). Against that, the engine is *provably exact*
today — a bounded/lossy set risks dropping genuinely distinct events to catch a 2.7–4%
duplication that the backend deduplicates for free and exactly. Every blob-sourced record
already carries its identity attribute as structured metadata (`id` for sign-ins, `request_id`
for Graph activity), the duplicates are byte-identical, and the rate is steady-state — so
downstream dedupe costs graph2otel nothing, cannot go stale, and has no memory-bound failure
mode. The recipe (LogQL for counts, store-side `distinct` for raw export, with the ×4
multiplicity caveat) is in
[signals.md](signals.md#deduplicating-blob-sourced-records--azure-delivers-at-least-once).

### Field types are inconsistent within a single record

- `durationMs` is a **string** (`"497815"`) at the top level and an **int** (`497815`)
  inside `properties` — **on the same record**. Bind to `properties`.
- `level` is `"Informational"` on **every** `MicrosoftGraphActivityLogs` record, including
  the 500s (verified across a 335-record sample spanning
  200/201/204/400/401/403/404/500). Deriving severity from it marks every server error
  INFO, permanently. Use `properties.responseStatusCode`.
- `level` is a **numeric string** (`"4"`) on `SignInLogs` — so a severity mapper shared
  across categories would be wrong twice over. Map per category.
- `resourceId` casing differs per category (`/TENANTS/…/MICROSOFT.AADIAM` vs
  `/tenants/…/Microsoft.aadiam`). Never match on it.

### Timestamp binding differs per category family — and only parsed instants tell the truth

The envelope `time` is the **ingestion** time. Whether it equals the event time depends
on the category, and there are at least three patterns (live-verified 2026-07-16, #135):

| field | MGAL | SignInLogs family | AuditLogs |
| --- | --- | --- | --- |
| `time` vs event time | identical | **28s–1077s late, variable** | identical (as instant) |
| `level` | `"Informational"` (always) | numeric string (`"4"`) | `"Informational"` |
| `durationMs` (top level) | string | int `0` | int `0` |
| `resourceId` casing | `/TENANTS/…` | `/tenants/…` | `/tenants/…` |

Rules that fall out:

- **Sign-in categories bind to `properties.createdDateTime`, with NO fallback to `time`**
  — the gap is variable (0 of ~700 records matched), so a fallback silently backdates
  records by a random couple of minutes. MGAL and AuditLogs bind to `time` and are
  correct to. Copying a neighboring collector's timestamp rule onto a new category is
  the trap — verify per category.
- **Compare timestamps as PARSED INSTANTS, never as strings.** AuditLogs' `time` and
  `properties.activityDateTime` differ in serialization (7-digit fraction + `Z` vs
  6-digit + `+00:00`) — a string comparison reports "never equal" and points at the
  wrong binding; as instants the delta is 0.000s on every record.
- **The envelope is consistent within a category family, not across families.** The
  three sign-in categories share one schema (zero type conflicts, additive optional
  fields only) and correctly share one mapper; MGAL vs sign-ins agree on nothing.
  Verify agreement against live samples before sharing a mapper.
- **The blob `properties` object IS the Graph resource** — verified field-for-field for
  all four sign-in categories (`properties` = the `signIn` resource; same `id` as the
  polled record) and for AuditLogs (`properties.id` byte-identical to the polled
  checkpoint's seen ids). **Reuse the polled mapper; never write a second one.** Two
  categories is not a universal rule though — check per category before assuming.
- Records are JSON Lines with **CRLF** terminators; drop the
  `properties.__UDI_RequiredFields_*` keys (Microsoft-internal plumbing).

### An empty container is not evidence of a fault

Microsoft documents up to **24 hours** before data appears on a newly configured
destination. In practice first data landed in ~15 minutes, but do not "fix" a working
diagnostic setting during the first day. Azure also creates the `insights-logs-<category>`
containers on **first write**, not at setting-creation time, so a missing container means
"nothing written yet", not "misconfigured".

## Why read-only

graph2otel never deletes. The original design was read-and-delete, on the theory that
removing consumed data controls cost. It does not: the saving is **£0.002/month**, and
buying it would have required write access plus a "delete closed hours only" rule.

That rule would have **destroyed live data** — the `h=00` blob above looked safely closed
for 13 hours while Azure was still writing to it. Dropping delete was right for a reason
nobody had identified when the decision was made (#89).

The property that falls out: **nothing graph2otel does can destroy data it has not read.**
The only deleter is the lifecycle rule, on a clock you set.

## Related

- **#89** — the transport evaluation (Log Analytics vs Event Hub vs Storage), the live
  measurements, and every decision above with its reasoning.
- **#131** — the dual-ship proposal (Graph for metrics, blob for logs), **closed as rejected**:
  source is graph XOR blob per collector, enforced by #144. The one real dual candidate is #132.
- **#128** — deriving metrics from blob-sourced events, recency-gated so backfilled events
  cannot corrupt a cumulative counter.
- **#106** — raw Defender hunting-table ingest. Storage is a supported destination for the
  Defender streaming API and Log Analytics is not, so it can share this transport — but it
  must verify Defender's own blob write cadence rather than inherit #89's latency numbers.

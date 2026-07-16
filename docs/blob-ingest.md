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
| `MicrosoftServicePrincipalSignInLogs` | `entra.signins.microsoft_service_principal` | **No Graph endpoint.** Microsoft first-party service-to-service auth. Live-verified a genuinely different dataset from `entra.signins.service_principal` — see below. |
| `ServicePrincipalSignInLogs` | `entra.signins.service_principal.blob` | Retires a `/beta` dependency (see below). |
| `NonInteractiveUserSignInLogs` | `entra.signins.non_interactive.blob` | Retires a `/beta` dependency (see below). |
| `ManagedIdentitySignInLogs` | — | Same case as the two above, but **not built**: the container does not exist on the verification tenant, so there is no live sample to map against and this project does not map from documentation (#135). |
| Intune `OperationalLogs` | — | **No Graph endpoint** (#94). The compliance-alert *fired-event* stream; Graph exposes only the notification templates. |
| `AuditLogs`, `ProvisioningLogs` | — | Covered by Graph for **metrics**; blob supplies the **log** side under the dual-ship model (#131). |

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
floored at ~4 minutes; logs want completeness and blob has no throttle ceiling. The two
routes are complementary, split by signal type rather than competing for one slot (#131).

## What it costs

**~£0.05–0.24/month** at ~0.7 GB/month, dominated by `MicrosoftGraphActivityLogs`. There
is **no standing charge** — that was the point. Storage is ~£0.0145/GB/mo, reads
~£0.0036/10K, and listing is billed at the write rate (~£0.0447/10K).

Log Analytics (£1.54/mo) and Event Hub (£8.34/mo standing) were both evaluated against
this and closed. Event Hub's entire measured advantage was **12 seconds** of latency,
because the ~4-minute delay is Entra-side — upstream of where the transport forks — so
paying for a faster destination cannot buy back time already spent. Full evaluation: #89.

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

### Azure delivers at-least-once: ~2.3% of records arrive more than once

Measured live 2026-07-16 across every category with data — a consistent **2.3%–2.8%**, with one
event observed delivered **three** times:

| category | records | re-delivered |
| --- | ---: | ---: |
| `MicrosoftGraphActivityLogs` | 11,134 | 302 (2.71%) |
| `ServicePrincipalSignInLogs` | 771 | 18 (2.33%) |
| `MicrosoftServicePrincipalSignInLogs` | 216 | 6 (2.78%) |
| `NonInteractiveUserSignInLogs` | 40 | 1 (2.50%) |

A re-delivered event is written as a **separate line**, usually into the same hour blob, with a
**byte-identical `properties` payload** and a **fresh envelope `time`**. One `h=04` blob carried the
same sign-in at line 15 (envelope `04:09:50`) and line 20 (envelope `04:16:16`) — identical `id`,
`createdDateTime`, `correlationId`, and `uniqueTokenIdentifier`, 6.4 minutes apart.

**This is not a cursor bug and it is not fixable by the cursor.** Both copies are real, distinct
bytes; a byte-offset cursor consuming them exactly once is behaving correctly. Verified directly:
across a cold start plus a restart, for all 1,035 emitted ids, the number of times graph2otel
emitted a record **exactly equalled** the number of times Azure wrote it — no over-emission, no
loss.

The consequence is real and currently unmitigated: **blob-sourced collectors ship Azure's
duplicates through to your backend.** The polled path does not have this problem — `logpipeline`
carries a seen-id set in its checkpoint and dedupes. `blobpipeline` has no equivalent, so ~2.3% of
blob-sourced records are duplicates. Every collector emits the identifying attribute (`id` for
sign-ins, `request_id` for Graph activity), so downstream dedupe is possible today. Closing the gap
in the engine is **#138**.

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
- **#131** — the dual-ship model: Graph for real-time metrics, blob for comprehensive logs.
- **#128** — deriving metrics from blob-sourced events, recency-gated so backfilled events
  cannot corrupt a cumulative counter.
- **#106** — raw Defender hunting-table ingest. Storage is a supported destination for the
  Defender streaming API and Log Analytics is not, so it can share this transport — but it
  must verify Defender's own blob write cadence rather than inherit #89's latency numbers.

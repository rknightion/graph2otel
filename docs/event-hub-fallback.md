# Fallback ingest: Event Hub / Log Analytics (design note, deferred)

A set of signals graph2otel's users want have **no Microsoft Graph read endpoint at
all** — Graph cannot see them, no matter how the poller is tuned. This note records the
fallback-ingest strategy for those signals: consume them from the data the Azure Monitor
/ diagnostic-settings pipeline already emits, without going through Graph.

**Status: design only. Nothing is provisioned, no collector code exists.** This is the
escape hatch every "no Graph endpoint" gap in `README.md` and `CLAUDE.md` points at, and
the shared home for the near-real-time SIEM streaming work (#106). It is deferred infra:
read this before building either, do not treat it as shipped capability.

## The gaps this covers

Signals with no Graph endpoint (confirmed permanent — see the README "What this cannot
replace" section):

- `MicrosoftGraphActivityLogs` — Graph's own per-request API-call telemetry. No query
  endpoint exists.
- `ADFSSignInLogs` — Connect Health agent stream, diagnostic-settings-only.
- `NetworkAccessTrafficLogs` — Global Secure Access, diagnostic-settings-only.
- `EnrichedOffice365AuditLogs` — Sentinel-side ML enrichment synthesized downstream;
  no source API anywhere (so it is reachable only if the enriched rows land in a
  workspace/hub, never from an upstream call).
- Most of Intune `OperationalLogs` — the compliance-notification / SLA-alert fired-event
  stream (see #94).

Plus, on the streaming side, the **Defender XDR streaming API** raw Advanced Hunting
tables (`DeviceFileEvents`, `DeviceProcessEvents`, …) — polling `runHuntingQuery` cannot
match Event-Hub streaming on volume or latency for that data (#106). The same Event Hub
consumer built here is the transport for both.

## Two candidate paths

### (A) Log Analytics workspace query

graph2otel queries the workspace directly via the **Azure Monitor Log Analytics query
API** (KQL), reads new rows since a checkpoint, ingests them as OTLP logs, and either
deletes the ingested rows (needs a write scope; confirm the workspace even supports
row-level delete rather than only retention-based ageing) or leans on workspace retention
to age the data out (read-only, simpler — the default recommendation if this path is
used at all).

This path is itself floored by ingestion latency and adds a query-and-delete dance. It
makes sense **only** for a signal that exists at rest in a workspace and is never emitted
to an Event Hub.

### (B) Event Hub sub-client (recommended)

graph2otel registers as an **additional consumer group** on the same Event Hub that
diagnostic settings (or the Defender streaming API) already feed, reading the stream
independently and without disturbing the existing consumer. Passive, read-only by
construction.

## Recommendation

**Event Hub (option B) is the answer for near-real-time, and is the shared
streaming-ingest domain** — used both for the no-Graph log gaps above and for the raw
Defender hunting-table SIEM work (#106). Design the consumer once, reuse it for both.

**Log Analytics query (option A) is a narrow fallback only** — for a signal that has no
diagnostic-settings→hub route and therefore only exists at rest in a workspace. Do not
reach for it as the default; it is latency-bound and heavier.

### Latency tiers (why B wins for real-time)

- **UAL polling floor (~30 min–24h).** Both `security/auditLogQuery` (#97) and the O365
  Management Activity API (#100) are surfaces over the same unified audit log, so both
  inherit UAL record-availability latency. No poll tuning beats that floor.
- **Diagnostic-settings → Event Hub: near-real-time (minutes).** Genuinely a different
  tier. Prefer **direct diagnostic settings → Event Hub** over a Log Analytics
  **data-export rule** feeding the hub — the export rule writes 5-minute folders and adds
  latency for no benefit here.
- **Defender XDR streaming API → Event Hub: near-real-time**, push not poll.

Net: the polling paths (`security/auditLogQuery` #97, O365 Management Activity #100) are
worth building for lower overhead, but only the Event-Hub path actually beats the ~30-min
UAL floor.

## Relationship to the job-poll path (#97)

The `security/auditLogQuery` job-poll path (#97) and this Event-Hub path are **two
alternative transports** for overlapping audit signal, not a pipeline — users choose. The
job-poll path is a Graph surface (no new Azure domain, but UAL-latency-bound); the
Event-Hub path is a new ingest domain that beats that floor. Pick per signal and per
latency requirement.

## Auth model (new domain)

Both paths need Azure SDK auth **beyond** the Graph scope `azidentity.DefaultAzureCredential`
uses today — likely the **same credential, a different resource audience**:

- Log Analytics query: audience `https://api.loganalytics.io`.
- Event Hub: Event Hubs AMQP auth (consumer role).

Read-only for the passive consumer (B) by construction; option A needs a write-capable
(delete) scope only if delete-post-ingest is pursued — default to relying on workspace
retention instead. Confirm the scoping does not force a second app registration. This is
architecturally a **new ingest domain** (Azure Monitor / Event Hub, not Graph) — keep it
clearly separated in the codebase and docs so it is never conflated with "polls Graph."

## Deferred

Nothing here is provisioned. Both paths still need to be spiked against a real Log
Analytics workspace / Event Hub to confirm the auth model, minimum permissions, and
rough cost/effort before any collector is written. Until then this is the reference every
"no Graph endpoint" gap cites as the answer to "if I need one of these, what do I do."

# graph2otel

`graph2otel` polls the **Microsoft Graph API** (Entra ID + Intune) and exports
**OpenTelemetry-native metrics and logs** over OTLP, tuned for **Grafana Cloud** (or any
OTLP-compatible backend). It ships as a single static Go binary and pushes telemetry —
there is no Prometheus scrape endpoint to expose or firewall. It is multi-tenant from the
start: one process can poll several Entra ID tenants concurrently.

Two kinds of Graph data become telemetry:

- **Snapshot data** — directory objects, license inventory, device compliance state,
  Intune managed-device inventory, Conditional Access policy configuration, and similar
  inventory — becomes **OTEL metrics**: bounded, tenant-shaped aggregates, never a
  per-user or per-device label series.
- **Event-stream data** — sign-ins, directory audits, provisioning events, risk
  detections, Intune audit events, and similar activity — becomes **OTEL logs**,
  checkpointed and deduped by ID, since none of these Graph endpoints support delta
  queries or a reliable server-side cursor.

Both are pushed via **OTLP** (gRPC, HTTP, or `stdout` for local debugging) straight to
your backend. For the identity/device audit core — Entra audit logs, all four sign-in
event types, provisioning logs, risk detections, and Intune audit events — that means
**no diagnostic settings, no Log Analytics workspace, and no Event Hub required**, and
for Intune compliance state Graph is measurably fresher than the diagnostic-settings
export path (minutes vs. a 24-48h export lag).

## What this does not replace

Polling Graph cannot see everything Azure Monitor diagnostic settings can. A small set of
log categories are never materialized behind a queryable Graph endpoint, so diagnostic
settings → Event Hub/Log Analytics remains the only way to get them:

- **`MicrosoftGraphActivityLogs`** — the log of Graph API calls themselves; no query
  endpoint exists at all.
- **`EnrichedOffice365AuditLogs`** — the M365 Unified Audit Log, owned by Purview / the
  Office 365 Management Activity API, not Graph.
- **Most of Intune `OperationalLogs`** — only the enrollment-failure slice has a Graph
  equivalent (`enrollmentTroubleshootingEvent`).
- **`ADFSSignInLogs`** and **`NetworkAccessTrafficLogs`** — diagnostic-settings-only
  (the Connect Health agent stream / Global Secure Access, respectively).

If you need any of those, keep diagnostic settings wired up for that specific category.
`graph2otel` is the no-infrastructure default for the rest of the identity/device audit
surface, not a total replacement for Azure Monitor integration.

## Where to go next

- [Getting Started](getting-started.md) — auth setup, minimal config, first run.
- [Configuration](configuration.md) — the full `config.example.yaml` key reference.
- [Architecture](architecture.md) — the composition-root and collector-framework shape.
- [Signals](signals.md) — the `entra.*` / `intune.*` / `graph2otel.*` metric and log
  namespaces.
- [Security](security.md) — telemetry sensitivity, the cardinality boundary rule, and
  secrets handling.

Source, issues, and the release history live at
[github.com/rknightion/graph2otel](https://github.com/rknightion/graph2otel).

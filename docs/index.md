# graph2otel

`graph2otel` turns Microsoft 365 security and operations data into
**OpenTelemetry-native metrics and logs** and pushes it over OTLP to Grafana Cloud or
any compatible backend. It covers Entra ID, Intune, Microsoft 365, Purview, Defender
XDR, Defender for Cloud Apps, and Exchange Online. One static binary can poll multiple
tenants; there is no Prometheus endpoint to expose or scrape.

**v1.0.0 is released and production-tested.** The registry currently exposes **167 logical collectors**.
[The generated collector reference](collectors.md) is the authoritative inventory: its
contents and the collector census are checked against the same 7 registration paths
used by the application.

## What it collects

The data plane has two deliberate output shapes:

- **Bounded, tenant-shaped aggregates become metrics.** Directory inventory, license
  posture, device compliance, policy state, and similar snapshots are counted by bounded
  dimensions. A user, device, or event identifier never becomes a metric label.
- **Per-entity and event detail becomes logs.** Sign-ins, audits, risk detections,
  managed-device records, policy details, and other individual records retain the fields
  operators need to investigate them. Watermarked streams are checkpointed and deduped
  where the source supplies an identifier.

All signals carry `tenant_id`. Logs also carry `ingest_transport`, so a backend can
distinguish Graph polling, Azure Storage, the O365 activity feed, audit queries, and
report exports without changing the event contract.

## Ingest shapes

Microsoft does not expose one consistent API, so graph2otel ships 4 ingest engine shapes
behind the same collector and telemetry interfaces:

1. **Graph REST polling** reads current-state snapshots and watermark-window log
   endpoints. The window pollers use overlap plus seen-ID dedupe because those endpoints
   have no delta cursor.
2. **Asynchronous export jobs** create, poll, and download Microsoft 365 audit-query and
   Intune report-export jobs.
3. **Azure Storage blob ingest** consumes diagnostic-settings append blobs by byte
   offset. It covers signals with no Graph endpoint and can replace selected Graph log
   pollers with a more scalable transport. It is opt-in per tenant; see
   [Blob ingest](blob-ingest.md).
4. **The Office 365 Management Activity API** manages subscriptions, lists content
   blobs, and downloads the unified audit records in them. This stable v1.0 source is
   the default M365 audit transport; see
   [O365 Management Activity API](o365-management-api.md).

The process can also call the domain-specific MDCA portal, Exchange Online admin, and
Defender advanced-hunting surfaces through their collector registration paths. The
[architecture reference](architecture.md) documents the composition seams; the
[collector reference](collectors.md) names the exact source and permissions for every
collector.

## What it does not replace

graph2otel removes the need for a Log Analytics workspace or Event Hub for the signals
it supports, but some supported signals still originate in Azure Monitor diagnostic
settings. For example, `MicrosoftGraphActivityLogs`, Graph notification activity, and
Intune compliance fired events have no Graph read endpoint; configure diagnostic
settings to Azure Storage and let graph2otel's blob engine consume them.

The M365 unified audit stream is not a diagnostic-settings dependency:
`m365.activity` reads it directly from the Office 365 Management Activity API. Entra
Global Secure Access posture is also collected, while the separate GSA traffic-log
endpoint remains unimplemented pending a live-verified response shape. ADFS sign-in
logs and any other category absent from the generated collector reference still need
their existing export path.

Use the [collector reference](collectors.md), rather than a broad product-category
claim, to decide whether a specific signal is covered.

## Packaging

Every tagged release publishes:

- a signed multi-architecture container at
  `ghcr.io/rknightion/graph2otel`;
- Linux, macOS, and Windows binaries, checksums, per-archive SBOMs, a Sigstore bundle,
  and build provenance on the
  [GitHub release](https://github.com/rknightion/graph2otel/releases);
- an OCI Helm chart at
  `oci://ghcr.io/rknightion/charts/graph2otel`.

Start with [Getting Started](getting-started.md) for container, Helm, and binary
installation plus a local `stdout` smoke test.

## References

- [Configuration](configuration.md) and the generated
  [environment-variable reference](env-vars.md)
- [Permissions](permissions.md) and [data-plane registration](data-plane-registration.md)
- [Signals](signals.md), including normalized metric names and LogQL examples
- [Deploying observability](deploying-observability.md) for the shipped dashboards and
  rules
- [Security](security.md) for telemetry sensitivity, credential handling, and the
  cardinality boundary

Source, issues, and release history live at
[github.com/rknightion/graph2otel](https://github.com/rknightion/graph2otel).

---
title: FAQ
description: Answers on Graph permissions, app-only auth, data handling, throttling, and restart behaviour, each pointing to the authoritative page.
---

# Frequently Asked Questions

Short answers to common questions. Each answer links to the authoritative page for the
full detail — treat those linked pages as the source of truth.

## Getting started

### How do I run graph2otel for the first time?

Pick a container, Helm, or binary install, point it at one tenant, and set
`otlp.protocol: stdout` so output prints to the console instead of a real backend. Run
`graph2otel check --config config.yaml` first to catch missing Graph permissions before
the first real poll. See [Getting Started](getting-started.md).

### Do I need a config file?

No. With no `--config` flag, graph2otel runs from built-in defaults plus whatever
`G2O_*` environment variables are set — the container-friendly path. A config file is
only required for structured settings a flat environment variable can't express, such
as `tenants:` for multiple directories. See [Configuration](configuration.md).

## Permissions

### Which Graph permissions does graph2otel need?

Only the **application** (not delegated) permissions your **enabled** collectors
require — a disabled collector makes zero Graph API calls and needs zero scope. Start
from the per-collector scope column in the [collector reference](collectors.md), or run
`graph2otel check` once the app registration exists to compare granted roles against
what your configuration actually selects. See [Permissions](permissions.md).

### Application or delegated?

Application only. graph2otel authenticates as an app-only, client-credentials Entra ID
app registration via `azidentity.DefaultAzureCredential` — there is no signed-in user
and no interactive login. See [Getting Started](getting-started.md#auth-setup).

### Why does graph2otel ask for a write scope?

The Intune Reports Export API (`POST /deviceManagement/reports/exportJobs`) requires
`DeviceManagementManagedDevices.ReadWrite.All` purely to *create* the export job — this
is documented Microsoft Graph behavior, not a graph2otel design choice. graph2otel never
uses that scope to write Intune configuration or device state, and it never requests
`DeviceManagementManagedDevices.PrivilegedOperations.All`. Only opt-in export-report
collectors need it, so a default deployment never requests it. See
[Permissions](permissions.md#4-the-export-job-readwrite-caveat-gotcha-3).

### `graph2otel check` says my permissions are fine but a collector still fails — why?

`graph2otel check` only confirms a permission is granted and admin-consented; it cannot
detect a directory-role gate (some Identity Protection surfaces), a missing
Security & Compliance data-plane registration (Purview eDiscovery), or a static
non-Entra token (the legacy MDCA portal). See
[Permissions](permissions.md#5-verify-with-graph2otel-check) and
[Non-Graph data-plane registration](data-plane-registration.md).

## Data handling

### What data does graph2otel export, and where does it go?

Identity and device management data from every configured tenant — the exact set
depends on which collectors are enabled, and includes UPNs/email addresses, device
names and hardware identifiers, sign-in IPs and locations, directory/role membership,
and security alert/risk detail. All of it is exported over OTLP to your configured
backend. Treat the OTLP backend as a trusted data sink and scope its credentials
accordingly. See [Security](security.md#telemetry-payload-sensitivity).

### Does any per-user or per-device data end up on a metric?

No. High-cardinality, per-entity data — UPNs, device IDs, IP addresses, correlation
IDs — is never attached as a metric label; it belongs in the **logs** pipeline as
structured attributes. Metrics carry only bounded, tenant-shaped aggregates: counts by
compliance state, OS, policy, or risk level. This is not a privacy control — everything
is still exported — it's a cardinality rule that keeps metric series bounded regardless
of tenant size. See [Security](security.md#the-cardinality-boundary-rule).

### Does graph2otel ever drop per-entity data instead of emitting it?

No — the cardinality rule has a second half: anything too high-cardinality for a metric
label is still emitted as a **log twin**, never discarded. One deliberate exception is
`entra.agreements` (terms-of-use acceptance is a legal/HR question, not a security
signal). One deliberate redaction: the Intune audit-event stream emits the *names* of
changed properties but never their old/new values, which can carry credentials or PII.
See [PII & Cardinality Audit](pii-cardinality-audit.md).

### How do I reduce what graph2otel exposes?

Enable only the collectors you need per tenant, use least-privilege read-only scopes,
and prefer an aggregate signal over a raw per-entity export where both exist. This
doesn't change the cardinality rule above — it changes what's collected in the first
place. See [Security](security.md#levers-to-reduce-exposure).

## Operation

### What happens to in-flight data on restart?

Each ingest engine owns its own durable cursor in `checkpoint_dir` — a watermark for
window collectors, a byte offset for blob ingest, a content/record watermark for O365
Management Activity — so a restart resumes each source's own contract instead of one
universal timestamp. A gap longer than a collector's max window is walked forward in
capped chunks across successive ticks, losslessly, once a checkpoint exists. See
[Architecture](architecture.md#checkpoints-and-delivery-semantics).

### Why is a signal or collector showing no data?

An empty result and a broken collector look identical from the outside, and several
distinct causes produce it: a beta/experimental collector that isn't explicitly
enabled, a collector genuinely disabled or gated by license, or a source that answered
successfully with zero rows (`healthy_empty`). See
[Troubleshooting](troubleshooting.md#missing-or-empty-data) for how to tell them apart,
and [Signals](signals.md#collector-availability) for what each availability state means.

### How does Graph throttling affect graph2otel?

Client-side rate limiters in the Graph transport enforce per-workload ceilings —
Identity Protection is the tightest at 1 request/second per tenant, shared across
*every* application in that tenant, not just graph2otel. None of the throttled
workloads reliably send `Retry-After`, so sustained throttling degrades data freshness
before anything else visibly breaks. See
[Graph API gotchas](graph-api-gotchas.md#throttling-no-retry-after).

### Can I run more than one instance against the same tenant?

No. graph2otel is deliberately single-instance per configured tenant set — there is no
leader election or shared transactional checkpoint protocol, and running replicas would
duplicate polling and race the file-backed cursors. Scale by assigning disjoint tenant
sets to separate processes instead. See
[Architecture](architecture.md#single-instance).

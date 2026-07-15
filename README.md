# graph2otel

**Status: pre-1.0, under active development, scaffold stage.** The framework
(collectors, telemetry emitter, checkpointing) isn't built yet — this repo currently
holds the repo hygiene, CI, and a Go module skeleton. Follow along or see what's planned
on the [issue tracker](https://github.com/rknightion/graph2otel/issues).

Polls the **Microsoft Graph API** (Entra ID + Intune) and exports **OpenTelemetry-native
metrics and logs** over OTLP, tuned for **Grafana Cloud** (or any OTLP-compatible
backend). A single static Go binary, push-only — there is no Prometheus scrape endpoint.
Multi-tenant from the start: one process can poll several Entra ID tenants concurrently.

## What it does

`graph2otel` authenticates against one or more Microsoft Entra ID tenants (app-only,
client-credentials auth — no signed-in user) and turns two categories of Graph API data
into telemetry:

- **Snapshot data** (directory objects, license inventory, device compliance state,
  Intune managed-device inventory, Conditional Access policy config, …) → **OTEL
  metrics** — bounded, tenant-shaped aggregates, never per-user/per-device label series.
- **Event-stream data** (sign-ins, directory audits, provisioning events, risk
  detections, Intune audit events, …) → **OTEL logs** — checkpointed, incremental,
  deduped by ID, since none of these Graph endpoints support delta queries.

Both are pushed via **OTLP** (gRPC, HTTP, or `stdout` for local debugging) directly to
your backend. No Log Analytics workspace, no diagnostic settings, no Event Hub required
for the core identity/device audit signals — see the honest-scope section below for
where that claim stops holding.

## Planned coverage (roadmap — pre-1.0, none of this is built yet)

### Entra ID

| Category | Examples |
| --- | --- |
| Metrics (snapshot) | directory object counts, users/groups/devices aggregates, licensing (SKU consumption + assignment errors), domains, org/directory-sync freshness, app + service principal credential expiry, Conditional Access policy + named location counts, directory roles + PIM standing/eligible assignments, secure score + control profiles, MFA/auth-methods registration summaries, consent surface (OAuth2 grants, app-role assignments), risky users/service principals (current state), authentication methods policy config, terms-of-use agreements, Entra recommendations *(beta)* |
| Logs (event stream) | interactive sign-ins, non-interactive sign-ins *(beta filter)*, service principal sign-ins *(beta filter)*, managed identity sign-ins *(beta filter)*, directory audit logs, provisioning logs, risk detections, security alerts (`alerts_v2`) |

### Intune

| Category | Examples |
| --- | --- |
| Metrics (snapshot) | managed device inventory + compliance/encryption/sync-recency aggregates, compliance policy rollups (tenant + per-policy), configuration profile status overviews, Settings Catalog inventory *(beta)*, mobile app catalog, app protection (MAM) policy inventory, Autopilot device + deployment profile state *(beta)*, Windows Update rings + feature/quality/driver profiles *(beta)*, endpoint analytics scores, Defender/malware tenant overview, Apple token (APNS/VPP/DEP) expiry, connector health (Exchange/MTD/NDES), certificate state *(beta)*, detected-apps software inventory, enrollment configs |
| Logs (event stream) | Intune audit events, enrollment troubleshooting events, Autopilot events *(beta)*, plus export-job-based reports (app install status, feature-update device states, enrollment failures, certificate inventory, Defender agent health) via the Reports Export API |

Items marked *(beta)* rely on a Microsoft Graph `beta` endpoint with no v1.0 equivalent —
they ship behind a feature flag and are called out as a stability risk, not a promise.

## What this cannot replace

Polling Microsoft Graph fully covers the identity/device audit core most people actually
want — Entra audit logs, sign-ins (all four event types), provisioning logs, risk
detections, and Intune audit events — with **no diagnostic settings and no Log Analytics
workspace required**, and for Intune compliance state, Graph is measurably fresher than
the diagnostic-settings export (minutes vs. a 24-48h export lag).

It is **not** a full replacement for Azure Monitor diagnostic settings. A small set of
log categories are never materialized behind a queryable Graph endpoint — the diagnostic
settings pipeline is the *only* way to get them:

- **`MicrosoftGraphActivityLogs`** — ironically, the log of Graph API calls themselves.
  No query endpoint exists at all.
- **`EnrichedOffice365AuditLogs`** — the M365 Unified Audit Log; owned by Purview / the
  Office 365 Management Activity API, not Graph.
- **Most of Intune `OperationalLogs`** — only the enrollment-failure slice has a Graph
  equivalent (`enrollmentTroubleshootingEvent`); the rest doesn't.
- **`ADFSSignInLogs`** and **`NetworkAccessTrafficLogs`** — mostly diagnostic-settings-only
  (Connect Health agent stream / Global Secure Access, respectively).

If you need any of those, you still need diagnostic settings → Event Hub or Log
Analytics for that specific category — `graph2otel` is the no-infrastructure default for
the rest, not a total replacement for Azure Monitor integration.

## Auth setup

`graph2otel` uses `azidentity.DefaultAzureCredential` for app-only, client-credentials
auth against each configured tenant — no signed-in user, no interactive login. Create an
app registration per tenant (or one multi-tenant app registration reused across tenants),
grant it the minimum read-only Graph API application permissions your enabled collectors
need, and get admin consent. Then set:

```sh
export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
export AZURE_CLIENT_SECRET="..."          # or, for certificate auth:
# export AZURE_CLIENT_CERTIFICATE_PATH="/path/to/cert.pem"
```

For multiple tenants, list each one in `config.yaml` (see below) and repeat the
credential env vars per tenant per the config schema once it lands — auth material is
always supplied via environment, never written into YAML.

## Configuration

```yaml
log_level: info # debug | info | warn | error

tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111" # Entra tenant GUID or verified domain
    client_id: "22222222-2222-2222-2222-222222222222" # app registration (application) ID

otlp:
  protocol: http # grpc | http | stdout
  endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
  grafana_cloud:
    instance_id: "123456"
    token: "" # DO NOT set here — use G2O_OTLP__GRAFANA_CLOUD__TOKEN instead
```

Config is layered: built-in defaults < `config.yaml` (`--config` flag) < `G2O_*`
environment variables (double underscore for nesting, e.g. `G2O_OTLP__ENDPOINT`). See
`config.example.yaml` for the authoritative, fully-commented schema. Per-collector
enable/disable toggles and an admin/health endpoint (`collectors:` / `admin:` top-level
keys) arrive with the collector framework — the scaffold ships `log_level` / `tenants` /
`otlp` only.

## Roadmap

There is no framework code yet — collectors, the telemetry emitter, and checkpointing
all arrive via tracked GitHub issues. See the
[issue tracker](https://github.com/rknightion/graph2otel/issues) and its milestones for
the current plan and status; this README's coverage tables describe intent, not shipped
functionality.

## License

`graph2otel` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`) — see [`LICENSE`](./LICENSE).

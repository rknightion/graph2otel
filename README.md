# graph2otel

Polls the **Microsoft Graph API** (Entra ID + Intune) and exports **OpenTelemetry-native
metrics and logs** over OTLP, tuned for **Grafana Cloud** (or any OTLP-compatible
backend). A single static Go binary, push-only — there is no Prometheus scrape endpoint.
Multi-tenant from the start: one process can poll several Entra ID tenants concurrently.

> **Status:** pre-1.0 (`v0.1.0`), feature-complete for the v1.0 launch — the collector
> framework, all Entra ID and Intune collectors, checkpointing, and the permission
> preflight are built and shipped. What's left before the `v1.0.0` tag is ops/launch
> polish (dashboards, alerts, Helm chart, this docs pass). Track progress on the
> [issue tracker](https://github.com/rknightion/graph2otel/issues) and its milestones.

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
for the core identity/device audit signals — see [What this cannot replace](#what-this-cannot-replace)
for where that claim stops holding.

## Quickstart

1. **Register an Entra ID app** and grant it read-only Graph API application
   permissions, per collector, plus admin consent. See
   [`docs/permissions.md`](docs/permissions.md) for the full walkthrough and its three
   first-run gotchas (admin consent, directory-role gating, the Intune export-job
   `ReadWrite` caveat).
2. **Set auth via environment variables** — never in config:

   ```sh
   export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
   export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
   export AZURE_CLIENT_SECRET="..."          # or AZURE_CLIENT_CERTIFICATE_PATH
   export G2O_OTLP__GRAFANA_CLOUD__TOKEN="..."
   ```

3. **Write a minimal config** (`config.yaml`) naming the tenant and your OTLP backend:

   ```yaml
   tenants:
     - tenant_id: "11111111-1111-1111-1111-111111111111"
       client_id: "22222222-2222-2222-2222-222222222222" # or omit if AZURE_CLIENT_ID is set

   otlp:
     protocol: http
     endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
     grafana_cloud:
       instance_id: "123456"
   ```

4. **Run it** — as a container:

   ```sh
   docker run --rm \
     -e AZURE_TENANT_ID -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET \
     -e G2O_OTLP__GRAFANA_CLOUD__TOKEN \
     -v "$(pwd)/config.yaml:/etc/graph2otel/config.yaml:ro" \
     ghcr.io/rknightion/graph2otel:latest \
     --config /etc/graph2otel/config.yaml
   ```

   or as a local binary: `go build ./cmd/graph2otel && ./graph2otel --config config.yaml`.

5. **Verify permissions before trusting the data** — run the built-in preflight check,
   which reports missing Graph API permissions per tenant instead of a runtime 403:

   ```sh
   graph2otel check --config config.yaml
   ```

See [`docs/collectors.md`](docs/collectors.md) for what each collector needs and emits,
and [`docs/permissions.md`](docs/permissions.md) for the full setup path. A published
docs site (zensical, `#31`) collects all of this in one place once it lands.

## Coverage

### Entra ID

| Category | Examples |
| --- | --- |
| Metrics (snapshot) | directory object counts, users/groups/devices aggregates, licensing (SKU consumption + assignment), domains, org/directory-sync freshness, app + service principal credential expiry, Conditional Access policy + named location counts, directory roles + PIM standing/eligible assignments, secure score + control profiles, MFA/auth-methods registration summaries, consent surface (OAuth2 grants, app-role assignments), risky users/service principals (current state), authentication methods policy config, terms-of-use agreements, Entra recommendations *(beta)* |
| Logs (event stream) | interactive sign-ins, non-interactive sign-ins *(beta filter)*, service principal sign-ins *(beta filter)*, managed identity sign-ins *(beta filter)*, directory audit logs, provisioning logs, risk detections, security alerts (`alerts_v2`) |

### Intune

| Category | Examples |
| --- | --- |
| Metrics (snapshot) | managed device inventory + compliance/encryption/sync-recency aggregates, compliance policy rollups (tenant + per-policy), configuration profile status overviews, Settings Catalog inventory *(beta)*, mobile app catalog, app protection (MAM) policy inventory, Autopilot device + deployment profile state *(beta)*, Windows Update rings + feature/quality/driver profiles *(beta)*, endpoint analytics scores, Defender/malware tenant overview, Apple token (APNS/VPP/DEP) expiry, connector health (Exchange/MTD/NDES), certificate state *(beta)*, detected-apps software inventory, enrollment configs |
| Logs (event stream) | Intune audit events, enrollment troubleshooting events, Autopilot events *(beta)*, plus export-job-based reports (app install status, certificate inventory, Defender agent health) via the Reports Export API |

Items marked *(beta)* rely on a Microsoft Graph `beta` endpoint with no v1.0 equivalent —
they ship behind a feature flag (`collectors.Experimental`, opt-in, off by default) and
are called out as a stability risk, not a promise. Full per-collector detail — Graph
endpoint, required scope, license/beta gating, poll interval, metric namespace — is in
[`docs/collectors.md`](docs/collectors.md).

## What this cannot replace

Polling Microsoft Graph fully covers the identity/device audit core most people actually
want — Entra audit logs, sign-ins (all four event types), provisioning logs, risk
detections, and Intune audit events — with **no diagnostic settings and no Log Analytics
workspace required**, and for Intune compliance state, Graph is measurably fresher than
the diagnostic-settings export (minutes vs. a 24-48h export lag).

It is **not** a full replacement for Azure Monitor diagnostic settings. Some signals are
never materialized behind a queryable Graph endpoint. These are **confirmed-permanent**
gaps, not "not built yet" — but they are not a dead end: the diagnostic-settings pipeline
already emits most of them, and `graph2otel` **optionally reads that data straight out of
an Azure Storage account**, so you still do not need an Azure Function or a Log Analytics
workspace in the middle. It is opt-in (one config key), read-only, and measured at **~£0.85
a month** on a small tenant with no standing charge — against £1.54 for Log Analytics and
£8.34 standing for Event Hub. See [`docs/blob-ingest.md`](docs/blob-ingest.md).

**Served this way today:** `MicrosoftGraphActivityLogs` (`entra.graph_activity`) and three
sign-in categories — `MicrosoftServicePrincipalSignInLogs`
(`entra.signins.microsoft_service_principal`, which has no Graph route at all),
`ServicePrincipalSignInLogs` and `NonInteractiveUserSignInLogs` (the `.blob` collectors,
which reach those streams on a v1.0-stable source instead of the `/beta`-only
`signInEventTypes` filter the polled versions need). The remaining categories below are the
roadmap for the same path.

One honest caveat: Azure's diagnostic-settings pipeline is **at-least-once**, so roughly
2.3% of blob-sourced records arrive twice and graph2otel currently passes those duplicates
through (the polled path dedupes; see [#138](https://github.com/rknightion/graph2otel/issues/138)).
Every record carries its identifying attribute, so a backend-side dedupe works today.

**Log categories with no Graph endpoint (confirmed permanent):**

- **`MicrosoftGraphActivityLogs`** ✅ **served via blob ingest** — ironically, the log of
  Graph API calls themselves. No query endpoint exists at all, so `entra.graph_activity`
  reads it from blob storage instead: one log record per Graph call against your tenant,
  answering which app or user called which endpoint, with which permissions, from where,
  and what came back. Without it, the `graph2otel.graphclient.http_4xx` /
  `graph2otel.graphclient.http_5xx` self-observability counters cover only **graph2otel's
  own** outbound Graph responses — a narrow substitute for "is our poller hitting Graph
  friction," never the tenant-wide 403-burst signal across every app.
- **`MicrosoftServicePrincipalSignInLogs`** ✅ **served via blob ingest** — Microsoft's own
  first-party service-to-service auth against your tenant. Offered "as an opt-in through
  diagnostic settings only"; there is no API. Live-verified a genuinely different dataset
  from the polled `entra.signins.service_principal`, which only ever returns *your own*
  service principals: every sampled record here was owned by Microsoft's tenant, every
  record there by the local tenant, and **zero** sign-in ids overlapped.
- **`EnrichedOffice365AuditLogs`** — a Sentinel / Log-Analytics-side ML **enrichment**
  table (fields layered onto raw M365 activity by Sentinel itself). It has no source API
  in Graph *or* the O365 Management Activity API — it is synthesized downstream and does
  not exist as a retrievable source anywhere upstream.
- **Most of Intune `OperationalLogs`** — the compliance-notification / SLA-alert
  fired-event stream (e.g. `AlertType: "Managed Device Not Compliant"`) has no Graph read
  resource; Graph exposes only the notification *templates*
  (`deviceManagement/notificationMessageTemplates`, config only). Only the
  enrollment-failure slice has a Graph event equivalent (`enrollmentTroubleshootingEvent`).
  Distinct from compliance *state*, which `graph2otel` does poll.
- **`ADFSSignInLogs`** and **`NetworkAccessTrafficLogs`** — diagnostic-settings-only
  (Connect Health agent stream / Global Secure Access, respectively).

For any of these, the fallback path above (Event Hub near-real-time, Log Analytics query
as a narrow at-rest fallback) is the answer — you still need diagnostic settings feeding
that pipeline, but `graph2otel` can consume it directly rather than a bespoke Function.

**Purview / M365 configuration state with no Graph endpoint (confirmed permanent):**

These are policy/config surfaces exposed only through Security & Compliance PowerShell (or
a portal), with no Graph list/count equivalent — so there is no "count of policies in each
mode" metric to build:

- **DLP policy authoring / simulation state** (Block vs TestWithNotifications mode, which
  locations a policy covers) — S&C PowerShell only (`Get/Set-DlpCompliancePolicy`,
  `Get/Set-DlpComplianceRule`). Graph's only DLP-adjacent surface,
  `protectionScopes/compute`, evaluates what *would* apply to synthetic input; it is not
  an enumerable policy list.
- **Retention *policy* location bindings** — S&C PowerShell only
  (`Get/Set-RetentionCompliancePolicy`). Note retention *label* **definitions** *are*
  Graph-exposed (`security/labels/retentionLabels`); it is the policy-to-location binding
  that has no Graph surface.
- **Label encryption activation** (Azure RMS) — portal-only toggle, no PowerShell/API path.

**Open, pending live-verify (not a settled gap):**

- **`DLP.All` sensitive-data content** — not yet confirmed whether
  `/security/auditLog/queries` fully mirrors what the O365 Management Activity API's
  `ActivityFeed.ReadDlp` scope carries. Flagged as an open question, not assumed solved
  or assumed impossible.

**Deployment prerequisite (not a `graph2otel` limitation):**

- **Turning on the unified audit log** — `Set-AdminAuditLogConfig`, an Exchange Online
  cmdlet (not Graph, not even S&C PowerShell). A fresh tenant may have it off, which is a
  hard prerequisite for any unified-audit-event collector. It is **already on** for the
  m7kni reference tenant, so it is not a current blocker there — but a new deployment must
  check it. `graph2otel` cannot remediate this itself.

## Auth setup

`graph2otel` uses `azidentity.DefaultAzureCredential` for app-only, client-credentials
auth against each configured tenant — no signed-in user, no interactive login. Create an
app registration per tenant (or one multi-tenant app registration reused across tenants),
grant it the minimum read-only Graph API application permissions your enabled collectors
need, and get admin consent, then set:

```sh
export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
export AZURE_CLIENT_SECRET="..."          # or, for certificate auth:
# export AZURE_CLIENT_CERTIFICATE_PATH="/path/to/cert.pem"
```

For multiple tenants, repeat the credential env vars per tenant and list each tenant in
`config.yaml` (see below) — auth material is always supplied via environment, never
written into YAML. See [`docs/permissions.md`](docs/permissions.md) for the full app
registration + scope + admin-consent walkthrough.

## Configuration

```yaml
log_level: info # debug | info | warn | error

tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111" # Entra tenant GUID or verified domain
    client_id: "22222222-2222-2222-2222-222222222222" # app registration (application) ID
    # collectors:               # optional per-tenant overrides, layered on the global block
    #   sign_ins:
    #     enabled: false

otlp:
  protocol: http # grpc | http | stdout
  endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
  grafana_cloud:
    instance_id: "123456"
    token: "" # DO NOT set here — use G2O_OTLP__GRAFANA_CLOUD__TOKEN instead

collectors: {}    # per-collector enable/disable + interval overrides; omitted = enabled at its default
#   sign_ins:
#     enabled: true
#     interval: "5m"

admin:
  enabled: false  # operator health/status HTTP endpoint (liveness + per-collector status)
  addr: ":9090"

checkpoint_dir: "./checkpoints"  # window-log collector watermark persistence
```

Config is layered: built-in defaults < `config.yaml` (`--config` flag) < `G2O_*`
environment variables (double underscore for nesting, e.g. `G2O_OTLP__ENDPOINT`; a
collector name's own underscore is preserved, e.g.
`G2O_COLLECTORS__SIGN_INS__ENABLED=false`). See `config.example.yaml` for the
authoritative, fully-commented schema, and [`docs/collectors.md`](docs/collectors.md) for
what each `collectors:` key gates.

## Operating notes

**Expect a brief flat-line after a restart, not a gap.** `graph2otel` is OTLP push-only.
When the process stops, its push simply stops — unlike a Prometheus scrape target going
down, a stopped push carries **no staleness marker**, so the last-pushed value lingers in
the backend for the query lookback window (~5 min in Grafana Cloud / Mimir) before it ages
out. On a restart, panels therefore show a short **flat-line** across the gap, not a break
in the series. This is expected OTLP-push behaviour, not a stuck collector — the new
process picks the series back up on its first push.

## License

`graph2otel` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`) — see [`LICENSE`](./LICENSE).

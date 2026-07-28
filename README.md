# graph2otel

Polls Microsoft Graph, Azure Storage diagnostic logs, the Office 365 Management
Activity API, and specialist Microsoft security surfaces, then exports
**OpenTelemetry-native metrics and logs** over OTLP. It is tuned for Grafana Cloud
but works with any OTLP-compatible backend. The exporter is a single static Go
binary, push-only, and multi-tenant from the start.

> **Status:** v1.0.0 shipped on 2026-07-25 and is live in production. The generated
> registry currently contains **152 logical collectors** across Entra ID, Intune,
> Microsoft 365, Purview, Defender XDR, and Defender for Cloud Apps.

Release packaging is complete: multi-arch container images, platform binaries,
checksums, per-binary and container SBOMs, Sigstore signatures, SLSA provenance,
and an OCI Helm chart are published with each release. See the
[v1.0.0 release](https://github.com/rknightion/graph2otel/releases/tag/v1.0.0),
the [operator documentation](https://m7kni.io/graph2otel/), and the generated
[collector reference](docs/collectors.md).

## What it does

`graph2otel` turns two data shapes into telemetry:

- **Snapshot and report data** becomes bounded, tenant-shaped OTEL metrics, with
  log twins for per-entity detail. User, device, policy, and other tenant-sized
  identifiers never become metric labels.
- **Event streams** become OTEL logs with source timestamps, durable checkpoints,
  overlap windows, and transport-appropriate deduplication.

The exporter uses the source that fits each Microsoft workload:

- raw Microsoft Graph REST for directory, device, security, governance, and
  reporting APIs;
- Azure Storage byte-offset ingest for diagnostic and advanced-hunting logs that
  Graph cannot provide, or that scale better out of band;
- the stable Office 365 Management Activity API for subscription/content-blob
  audit ingest;
- async Graph audit queries and Intune report-export jobs where the service only
  exposes a create/poll/download flow;
- the Defender for Cloud Apps governance API, Exchange Online message trace, and
  Defender XDR advanced-hunting APIs for their specialist data.

Metrics and logs are pushed directly over OTLP using gRPC or HTTP. `stdout` is
available for local inspection. There is no Prometheus scrape endpoint and the
core Graph collectors need no Log Analytics workspace or Event Hub.

The repository also ships 1 dashboard, 14 alert rules, and 11 paused detection examples,
all generated. The dashboard is a Grafana v2 dynamic dashboard and needs
Grafana 13.0.0 or newer. See
[Deploying observability](docs/deploying-observability.md).

## Quickstart

### 1. Register the application

Create an Entra ID app registration, grant the application permissions required
by the collectors you enable, and apply admin consent. The defaults are
read-oriented, with two documented operation-level exceptions: Intune report
export creation and starting an O365 Management Activity subscription.

Use [the permission guide](docs/permissions.md) for the complete setup and
[the collector reference](docs/collectors.md) for per-collector scopes, license
requirements, beta status, interval, source, and output.

### 2. Set credentials

Authentication uses `azidentity.DefaultAzureCredential`; secrets never belong in
YAML:

```sh
export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
export AZURE_CLIENT_SECRET="..."          # or AZURE_CLIENT_CERTIFICATE_PATH
export G2O_OTLP__GRAFANA_CLOUD__TOKEN="..."
```

### 3. Write a minimal config

Create `config.yaml`:

```yaml
tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111"
    client_id: "22222222-2222-2222-2222-222222222222" # optional identity assertion

otlp:
  protocol: http
  endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
  grafana_cloud:
    instance_id: "123456"

checkpoint_dir: "/var/lib/graph2otel"

collectors: {}
#   "entra.signins.interactive":
#     enabled: true
#     interval: "5m"
```

For a first local inspection, set `otlp.protocol: stdout` and omit the endpoint
and Grafana Cloud block.

Every scalar also has a `G2O_` environment override. For example:

```sh
G2O_COLLECTORS__ENTRA.SIGNINS.INTERACTIVE__ENABLED=false
```

### 4. Check permissions

Run the built-in preflight before trusting the output:

```sh
graph2otel check --config config.yaml
```

It reports missing application permissions per tenant and collector before a
poll turns the same problem into runtime 403s. For a container-only install, run
the same command from the release image:

```sh
docker run --rm \
  -e AZURE_TENANT_ID -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET \
  -e G2O_OTLP__GRAFANA_CLOUD__TOKEN \
  --mount type=bind,src="$(pwd)/config.yaml",dst=/etc/graph2otel/config.yaml,readonly \
  ghcr.io/rknightion/graph2otel:1.0.0 \
  check --config /etc/graph2otel/config.yaml
```

### 5. Run the container

```sh
docker volume create graph2otel-checkpoints

docker run --rm \
  --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  -e AZURE_TENANT_ID -e AZURE_CLIENT_ID -e AZURE_CLIENT_SECRET \
  -e G2O_OTLP__GRAFANA_CLOUD__TOKEN \
  --mount type=volume,src=graph2otel-checkpoints,dst=/var/lib/graph2otel \
  --mount type=bind,src="$(pwd)/config.yaml",dst=/etc/graph2otel/config.yaml,readonly \
  ghcr.io/rknightion/graph2otel:1.0.0 \
  --config /etc/graph2otel/config.yaml
```

The checkpoint volume is required for a real deployment. It preserves window
watermarks and dedupe state across restarts. The image runs as UID/GID `65532`;
if a host bind mount is required, create it and set that ownership before
starting the container.

## Other installation paths

### Helm

The chart is published as an OCI artifact:

```sh
kubectl create secret generic graph2otel-credentials \
  --from-literal=AZURE_TENANT_ID="<your-tenant-guid>" \
  --from-literal=AZURE_CLIENT_ID="<app-registration-client-id>" \
  --from-literal=AZURE_CLIENT_SECRET="<client-secret>" \
  --from-literal=G2O_OTLP__GRAFANA_CLOUD__TOKEN="<your-otlp-token>"

helm install g2o oci://ghcr.io/rknightion/charts/graph2otel \
  --version 1.0.0 \
  --set "config.tenants[0].tenant_id=<your-tenant-guid>" \
  --set "config.otlp.grafana_cloud.instance_id=<your-instance-id>" \
  --set existingSecret=graph2otel-credentials \
  --set persistence.enabled=true
```

Production installs should keep `persistence.enabled=true`; an ephemeral
checkpoint loses watermarks on pod replacement. The full values reference is in
[the chart README](charts/graph2otel/README.md).

### Binary

Release archives for macOS, Linux, and Windows, their checksums and SBOMs, and
the signature/provenance bundles are attached to each
[GitHub release](https://github.com/rknightion/graph2otel/releases). To build from
source instead:

```sh
go install github.com/rknightion/graph2otel/cmd/graph2otel@v1.0.0
```

## Coverage

The generated [collector reference](docs/collectors.md) is authoritative; CI
regenerates it from every registration path and fails on drift.

| Domain | Shipped coverage includes |
| --- | --- |
| Entra ID | directory inventory, applications and credentials, Conditional Access, authentication methods, licensing, PIM and access reviews, secure score, all four sign-in families, audit/provisioning/risk streams, security alerts/incidents, and Global Secure Access posture |
| Intune | managed devices, compliance and configuration, endpoint analytics, apps and MAM, Autopilot, enrollment, certificates and Cloud PKI, Windows update surfaces, Apple tokens/connectors, report-export inventories, audit events, and compliance/enrollment log streams |
| Microsoft 365 | teams/groups, service health, unified audit over either async query or the O365 Management Activity API, Exchange Online message trace, and Defender-derived email/security activity |
| Purview | sensitivity and retention labels, DLP policy inventory, eDiscovery cases, and audit activity |
| Defender XDR | advanced-hunting tables for alerts, evidence, devices, identities, email, URLs, vulnerabilities, recommendations, exposure, and related security events |
| Defender for Cloud Apps | Cloud Discovery governance/parse health over the MDCA portal API |

Beta Graph collectors implement `Experimental` and are off unless explicitly
enabled. High-traffic collectors implement a separate `HighVolume` opt-in; a GA
firehose is not mislabeled as beta.

## Source boundaries and correctness contracts

### Global Secure Access

The `entra.gsa` Experimental snapshot collector is shipped. It reports onboarding,
forwarding-profile, filtering-policy, remote-network, signaling, and packet-tagging
posture from the Graph beta surface.

`NetworkAccessTrafficLogs` is not permission-blocked on the reference tenant:
`graph2otel-poller` holds `NetworkAccess.Read.All`, and
`GET /beta/networkAccess/logs/traffic` returns 200 with an empty `value`. It is
currently **data-blocked** because all three forwarding profiles are disabled and
no traffic is routed through GSA. No traffic mapper is written from documentation
alone; it remains unwritten until a real record can be captured.

### Purview DLP

`purview.dlp_policies` is shipped as an Experimental snapshot collector over
`/beta/security/dataSecurityAndGovernance/policyFiles`. It inventories policy
definitions, enforcement modes, rules, actions, workload bindings, and change age.

This is separate from `DLP.All` activity. A live DLP match proved that
`DetectedValues[].Name` and `DetectedValues[].Value` can contain the actual matched
secret and surrounding message text. graph2otel has no dedicated `DLP.All` mapper
and deliberately does not emit those raw values. The existing M365 activity mapper
is allowlisted and ignores that nested payload.

### Azure Storage duplicates

Azure Monitor diagnostic delivery is at-least-once. Steady-state measurement found
about **2.7%** duplicate `MicrosoftGraphActivityLogs` records and about **4%**
duplicate sign-in records, with a maximum observed multiplicity of **four**.
`blobpipeline` consumes every byte exactly once; the repeated logical records are
distinct bytes written by Azure.

The binding decision is downstream deduplication on each event's structured-metadata
identity (`request_id` for Graph activity and `id` for sign-ins). Do not count raw
blob lines or assume at most two copies. See
[Deduplicating blob-sourced records](docs/signals.md#deduplicating-blob-sourced-records-azure-delivers-at-least-once).

### Timestamps and dedupe IDs

An event without a parseable source timestamp is dropped and reported as
`missing_event_time`; stamping it with arrival time would silently claim that an
old event happened now. A correctly timed record without a dedupe ID still emits
and is reported as degraded. Undedupeable is recoverable; misdated is wrong.

## Auth setup

`DefaultAzureCredential` selects one ambient application identity for the process.
Each `tenants[].tenant_id` must be the hyphenated Entra directory GUID.
graph2otel sets that tenant on each token request, permits the credential to target
only that directory, and verifies the returned token's `tid` before collection or
tenant-labelled telemetry starts.

One multi-tenant app registration can serve every configured directory after its
service principal has the required permissions and admin consent in each tenant.
An optional YAML `client_id` is a non-secret consistency assertion only; it cannot
select or override the ambient credential.

Workload identity uses the platform-provided federated token. Managed identity uses
the Azure host identity and remains bound to its home tenant. Certificate and client
secret credentials use the normal `AZURE_*` environment variables. See
[Permissions and app registration](docs/permissions.md).

## Configuration

Configuration is layered:

```text
built-in defaults < config.yaml < G2O_* environment variables
```

Environment nesting uses a double underscore:
`otlp.endpoint` becomes `G2O_OTLP__ENDPOINT`. Collector names are preserved,
for example
`G2O_COLLECTORS__ENTRA.SIGNINS.INTERACTIVE__ENABLED=false`.

[`config.example.yaml`](config.example.yaml) is the fully commented source
configuration, and the generated [environment variable reference](docs/env-vars.md)
is drift-gated in CI.

When enabled, the admin server exposes `/healthz`, `/readyz`, collector status,
checkpoint state, and capacity/cost observations. Liveness is independent of
collector outcomes. Readiness returns 503 until the first successful collection,
then stays ready while partial failures remain visible as degraded status. Failure
to bind the configured admin address is fatal.

## Operating notes

`graph2otel` is OTLP push-only. When it stops, no Prometheus staleness marker is
written, so the last sample can appear flat until the backend query lookback ages
it out. A short flat line after restart is expected; the new process resumes each
series on its first export.

Persistent checkpoints are mandatory for window, job, blob, and O365 activity
collectors. Losing them causes cold-start replays and can create duplicates; an
outage longer than the initial lookback can also create an unrecoverable gap.

## License

`graph2otel` is licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`) — see [`LICENSE`](LICENSE).

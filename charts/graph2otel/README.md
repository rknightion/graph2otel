# graph2otel

Poll the Microsoft Graph API (Entra ID + Intune) and export OpenTelemetry-native
metrics + logs (OTLP). Optimized for Grafana Cloud.

**Homepage:** <https://github.com/rknightion/graph2otel>

> This README is maintained by hand (the chart does not run helm-docs/
> values.schema.json generation yet — see the sibling `tailscale2otel` chart
> for that heavier tooling if this chart grows to need it). Keep it in sync
> with `values.yaml` when either changes.

## Install

```sh
helm install g2o oci://ghcr.io/rknightion/charts/graph2otel --version <chart-version> \
  --set "config.tenants[0].tenant_id=<your-tenant-guid>" \
  --set "config.otlp.grafana_cloud.instance_id=<your-instance-id>" \
  --set "secret.AZURE_CLIENT_ID=<app-registration-client-id>" \
  --set "secret.AZURE_CLIENT_SECRET=<client-secret>" \
  --set "extraEnv[0].name=G2O_OTLP__GRAFANA_CLOUD__TOKEN" \
  --set "extraEnv[0].value=<your-otlp-token>"
```

Or from a checked-out repo copy: `helm install g2o charts/graph2otel -f my-values.yaml`.

## Configuration

The entire application config lives under a single top-level `config:` key in
`values.yaml`, mirroring `config.example.yaml`'s top-level keys 1:1 (`tenants`,
`otlp`, `collectors`, `log_level`, `admin`, `checkpoint_dir`) — not a parallel
schema. It is rendered verbatim into a ConfigMap as `config.yaml`. Helm
deep-merges maps, so single-key overrides work without restating the rest,
e.g. `--set config.log_level=debug`.

### Auth — never in the ConfigMap

Tenant credentials are never read from `config.tenants` or any other config
key: they come from `azidentity.DefaultAzureCredential` via well-known
`AZURE_*` environment variables, injected through a Secret. graph2otel's
multi-tenant model pins each `tenants[].tenant_id` into the credential per
call, so **one** app registration's `AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`
authenticates against every tenant listed in `config.tenants` — there is no
per-tenant secret to template.

Provide credentials either inline (rendered into a chart-managed Secret) or
reference a Secret you manage yourself:

```yaml
secret:
  AZURE_CLIENT_ID: "00000000-0000-0000-0000-000000000000"
  AZURE_CLIENT_SECRET: "..."
```

```yaml
existingSecret: my-graph2otel-credentials   # must expose AZURE_CLIENT_ID / AZURE_CLIENT_SECRET
```

For certificate-based auth (`AZURE_CLIENT_CERTIFICATE_PATH`), the container
filesystem is read-only, so mount the cert via `extraVolumes`/
`extraVolumeMounts` and point the env var at it via `extraEnv`:

```yaml
extraEnv:
  - name: AZURE_CLIENT_CERTIFICATE_PATH
    value: /etc/graph2otel/cert/tls.key
extraVolumes:
  - name: client-cert
    secret:
      secretName: graph2otel-client-cert
extraVolumeMounts:
  - name: client-cert
    mountPath: /etc/graph2otel/cert
    readOnly: true
```

The same `extraEnv` mechanism sources `G2O_OTLP__GRAFANA_CLOUD__TOKEN` (or any
other `G2O_*` env override) from a Secret via `valueFrom.secretKeyRef`,
without ever landing the token in the ConfigMap.

### Checkpoint persistence

`config.checkpoint_dir` (default `/var/lib/graph2otel/checkpoints`) is where
window-log collectors persist their per-(tenant, endpoint) watermarks. The
chart mounts a volume at exactly that path:

- `persistence.enabled: false` (default) — an `emptyDir`. Survives container
  restarts within a pod, but is lost on pod rescheduling/deletion. Losing a
  checkpoint is not silent data loss (every collector cold-starts from a zero
  watermark and re-runs its lookback window), but it is wasteful and
  duplicative on frequent reschedules.
- `persistence.enabled: true` — a PVC (`persistence.size`, `.storageClass`,
  `.accessMode`, or `.existingClaim` to reuse one). Recommended for any
  real deployment.

### Health probes

`config.admin.enabled` defaults to `true` in this chart (the graph2otel
binary itself defaults it to `false`) so the Deployment always has a working
liveness/readiness probe against the admin server's `/healthz` — its only
health route; there is no separate `/readyz`. Set `config.admin.enabled: false`
to disable both the admin server and the probes.

### Single instance, always

`replicaCount` is fixed at `1` by design: graph2otel is a single-instance
poller with no leader election in v1 (none of the polled Graph endpoints
support consumer-group/delta semantics that would make multi-replica
coordination worthwhile — see the app repo's CLAUDE.md). Do not raise it or
add a StatefulSet/HA topology; doing so double-polls every tenant and
double-emits every metric and log. `strategy.type: Recreate` reflects this —
a rolling update briefly runs zero replicas rather than ever running two.

## Values

See `values.yaml` for the full, inline-documented list. Highlights:

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Fixed — see "Single instance, always" above. |
| `image.repository` | `ghcr.io/rknightion/graph2otel` | Container image. |
| `image.tag` | `""` | Defaults to `.Chart.appVersion`. |
| `config.tenants` | one placeholder entry | Tenants graph2otel polls (values/file-only, no flat env equivalent). |
| `config.otlp.endpoint` | Grafana Cloud us-central-0 gateway | OTLP endpoint base URL. |
| `config.admin.enabled` | `true` (chart default; binary default is `false`) | Enables `/healthz` + wires liveness/readiness probes. |
| `config.checkpoint_dir` | `/var/lib/graph2otel/checkpoints` | Must stay an absolute path — the checkpoint volume mounts here. |
| `existingSecret` | `""` | Reference a pre-created Secret instead of rendering `secret:` inline. |
| `secret.AZURE_CLIENT_ID` / `secret.AZURE_CLIENT_SECRET` | `""` | Tenant auth credentials (never in the ConfigMap). |
| `persistence.enabled` | `false` | `emptyDir` (lossy on reschedule) vs a PVC. |
| `resources` | `50m/64Mi` requests, `500m/512Mi` limits | Starting point; raise for large tenants or many opt-in collectors. |

## Source Code

* <https://github.com/rknightion/graph2otel>

## Maintainers

| Name |
| ---- |
| rknightion |

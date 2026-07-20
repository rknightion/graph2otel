# graph2otel

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.1.0](https://img.shields.io/badge/AppVersion-0.1.0-informational?style=flat-square)

Poll the Microsoft Graph API (Entra ID + Intune) and export OpenTelemetry-native metrics + logs (OTLP). Optimized for Grafana Cloud.

**Homepage:** <https://github.com/rknightion/graph2otel>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| rknightion |  |  |

## Source Code

* <https://github.com/rknightion/graph2otel>

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

Bad values fail early: `values.schema.json` validates `values.yaml` on every
`helm install`/`upgrade`/`lint`, so a mistyped key or wrong type is rejected
before anything renders.

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

`replicaCount` is fixed at `1` by design (the schema rejects any other value):
graph2otel is a single-instance poller with no leader election in v1 (none of
the polled Graph endpoints support consumer-group/delta semantics that would
make multi-replica coordination worthwhile — see the app repo's CLAUDE.md). Do
not raise it or add a StatefulSet/HA topology; doing so double-polls every
tenant and double-emits every metric and log. `strategy.type: Recreate`
reflects this — a rolling update briefly runs zero replicas rather than ever
running two.

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod scheduling. |
| config.admin | object | `{"addr":":9090","enabled":true,"refresh_interval":"5s"}` | Admin health/status HTTP endpoint (liveness at /healthz, status page at / and /api/status.json). The graph2otel binary itself defaults this to disabled, but the chart default is true so the Deployment can always wire working liveness/readiness probes; set to false to run without probes. |
| config.backfill.initial_lookback | string | `"0s"` | Cold-start backfill window for window (log) collectors — no checkpoint yet: a new tenant, a wiped volume, a first deploy. 0 means "use each collector's own built-in lookback" (most 1h; m365.unified_audit 4h; entra.security_incidents 24h); a non-zero value replaces all of them. Does not affect the steady state, where polling resumes from the watermark. CEILING: Loki rejects samples older than reject_old_samples_max_age (~13d on Grafana Cloud), so a larger value is not a longer recovery — it is a silent drop at ingest. graph2otel warns past ~13d but does not clamp (your sink may accept more). |
| config.cardinality | object | `{"metric_limit":2000}` | Output-side active-series governance (Grafana Cloud bills on active series). metric_limit is a hard per-instrument cap: distinct attribute sets beyond it collapse into the SDK's otel.metric.overflow series instead of growing the bill. graph2otel's metrics are bounded aggregates, so 2000 is a blast-radius guard, not a normal constraint. Set 0 for unlimited. |
| config.checkpoint_dir | string | `"/var/lib/graph2otel/checkpoints"` | Where window-log collectors persist their per-(tenant, endpoint) watermarks, so a restart resumes rather than re-fetching or dropping data. Matches the checkpoint volume's mountPath below, so overriding this also moves where the volume is mounted — keep it an absolute path. |
| config.collectors | object | `{}` | Per-collector overrides, applied globally across all tenants, keyed by collector name. A collector omitted here runs enabled at its built-in default interval. Experimental/beta collectors need explicit enabling — see docs/collectors.md. Example: collectors:   sign_ins:     enabled: true     interval: "5m" |
| config.log_level | string | `"info"` | Log verbosity: debug | info | warn | error. |
| config.otlp.endpoint | string | `"https://otlp-gateway-prod-us-central-0.grafana.net/otlp"` | OTLP endpoint base URL. For Grafana Cloud use the otlp-gateway URL for YOUR region. |
| config.otlp.grafana_cloud.instance_id | string | `""` | Grafana Cloud OTLP instance ID. NOT a secret by itself, but set alongside the token below; kept out of values.yaml defaults on purpose so an empty chart install doesn't silently point at nothing. |
| config.otlp.grafana_cloud.token | string | `""` | Grafana Cloud OTLP token. DO NOT set here — this key is informational only; provide it via G2O_OTLP__GRAFANA_CLOUD__TOKEN in extraEnv sourced from a Secret, since it never belongs in a ConfigMap-rendered config.yaml. |
| config.otlp.grafana_cloud.token_file | string | `""` | Path to a file holding the OTLP token, as an alternative to the env var — e.g. a mounted k8s Secret. value XOR token, never both. Safe to render into the ConfigMap since it is only a path, not the credential. |
| config.otlp.protocol | string | `"http"` | Export protocol: http | grpc | stdout (stdout = local debug). |
| config.profiling | object | `{"block_profile_rate":100000,"mutex_profile_fraction":5,"pyroscope":{"basic_auth_password":"","basic_auth_password_file":"","basic_auth_user":"","enabled":false,"server_address":"","tags":{},"tenant_id":"","upload_rate":"15s"}}` | Optional Grafana Pyroscope continuous profiling (default off). Has no effect on the exporter's core job and a failure to reach Pyroscope is non-fatal. basic_auth_password is a credential — do NOT set it here; provide it via G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD in extraEnv from a Secret. The mutex/block sampling knobs are applied only while the Pyroscope push is enabled, so they cost nothing when profiling is off. |
| config.profiling.block_profile_rate | int | `100000` | runtime.SetBlockProfileRate in ns, 100µs (0 = disabled). |
| config.profiling.mutex_profile_fraction | int | `5` | runtime.SetMutexProfileFraction (0 = disabled). |
| config.profiling.pyroscope.basic_auth_password | string | `""` | DO NOT set here — this key is informational only; provide it via G2O_PROFILING__PYROSCOPE__BASIC_AUTH_PASSWORD from a Secret. |
| config.profiling.pyroscope.basic_auth_password_file | string | `""` | Path to a file holding the Pyroscope basic-auth password, as an alternative to the env var (e.g. a mounted k8s Secret). value XOR basic_auth_password, never both. |
| config.profiling.pyroscope.basic_auth_user | string | `""` | Grafana Cloud Profiles user/instance ID. |
| config.profiling.pyroscope.server_address | string | `""` | Grafana Cloud Profiles ingest endpoint (e.g. https://profiles-prod-NNN.grafana.net). Required when enabled. |
| config.profiling.pyroscope.tags | object | `{}` | Extra static profile tags; service_version is always set and cannot be overridden. |
| config.profiling.pyroscope.tenant_id | string | `""` | X-Scope-OrgID for multi-tenant Pyroscope servers; leave empty for Grafana Cloud. |
| config.profiling.pyroscope.upload_rate | string | `"15s"` | How often profiles are flushed; 0/omit uses the pyroscope default. |
| config.tenants | list | `[{"client_id":"","tenant_id":"00000000-0000-0000-0000-000000000000"}]` | Tenants graph2otel polls. At least one entry is required unless otlp.protocol is "stdout". A flat env var cannot express a list of structs, so this list is file/values-only (no G2O_TENANTS__<index>__* env equivalent) — use --set/-f to override it. |
| config.tenants[0].client_id | string | `""` | App registration (application) ID. Optional if AZURE_CLIENT_ID (secret, above) is set. |
| config.tenants[0].tenant_id | string | `"00000000-0000-0000-0000-000000000000"` | Entra tenant GUID or verified domain. |
| existingSecret | string | `""` | Name of a pre-created Secret exposing the AZURE_* env keys below. When set, no Secret is rendered. |
| extraEnv | list | `[]` | Extra env vars appended to the container, as-is (e.g. AZURE_CLIENT_CERTIFICATE_PATH pointing at a path mounted via extraVolumes below, for certificate auth instead of a client secret). |
| extraVolumeMounts | list | `[]` | Extra volume mounts appended to the main container's volumeMounts, as-is. Paired with extraVolumes above by name. |
| extraVolumes | list | `[]` | Extra volumes appended to the pod spec as-is (e.g. a Secret volume holding an AZURE_CLIENT_CERTIFICATE_PATH cert/key, since readOnlyRootFilesystem leaves no other place to put arbitrary files). Paired with extraVolumeMounts below by volume name. |
| fullnameOverride | string | `""` | Fully override the generated resource names. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"ghcr.io/rknightion/graph2otel"` | Container image repository. |
| image.tag | string | `""` | Image tag. Defaults to .Chart.appVersion when empty. |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries. |
| nameOverride | string | `""` | Override the chart name portion of resource names. |
| nodeSelector | object | `{}` | Node selector for pod scheduling. |
| persistence.accessMode | string | `"ReadWriteOnce"` | PVC access mode. |
| persistence.enabled | bool | `false` | Persist checkpoints (window-collector watermarks) across restarts. When false, an emptyDir is used (survives container restarts within a pod, but is LOST on pod rescheduling/deletion — every WindowCollector cold-starts from a zero watermark and re-runs its initial lookback window, so the backend gets a burst of DUPLICATE log records on every reschedule). When true, a PVC is created. Defaults to false to match a zero-config `helm install`; enable this for any real deployment.  Note the duplicates are not the worst case: if a pod stays down LONGER than a collector's initial lookback, the events between the lost watermark and (now - lookback) are never fetched by anyone — silently dropped. So on a cluster where reschedules are routine, treat enabled=true as required rather than advisory (#117). |
| persistence.existingClaim | string | `""` | Use an existing PVC instead of creating one (empty = create one). Only used when enabled. |
| persistence.size | string | `"64Mi"` | PVC size (checkpoint files are tiny — one small JSON file per tenant/endpoint). |
| persistence.storageClass | string | `""` | StorageClass for the PVC (empty = cluster default). Only used when enabled. |
| podAnnotations | object | `{}` | Extra annotations for the pod. |
| podLabels | object | `{}` | Extra labels for the pod. |
| podSecurityContext | object | `{"fsGroup":65532,"fsGroupChangePolicy":"OnRootMismatch","runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | Pod-level security context. Runs as non-root with the RuntimeDefault seccomp profile; the app needs no special privileges. fsGroup makes the opt-in PVC persistence path (persistence.enabled=true) reliably writable by the uid-65532 container regardless of the CSI driver's default ownership behavior — a freshly provisioned block PVC is typically root:root on many drivers. The default emptyDir checkpoint volume already works without this (kubelet chmods emptyDir roots 0777). |
| replicaCount | int | `1` | Replica count. Keep at 1 — graph2otel is a single-instance poller with no leader election or HA in v1 (see CLAUDE.md Architecture: none of the polled Graph endpoints support consumer-group/delta semantics that would make multi-replica coordination pay for itself). Scaling this up double-polls every tenant and double-emits every metric and log. |
| resources | object | `{"limits":{"cpu":"500m","memory":"512Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Resource requests and limits. graph2otel caches per-tenant inventory (users/devices/groups/etc.) between polls, so the working set scales with tenant size and enabled-collector count more than tailscale2otel's — raise limits for a large multi-tenant deployment or many opt-in Intune/beta collectors. |
| secret | object | `{"AZURE_CLIENT_ID":"","AZURE_CLIENT_SECRET":"","AZURE_TENANT_ID":""}` | Inline secret values rendered into a Secret and injected via envFrom. Keys left empty ("") are NOT rendered into the Secret, so azidentity's credential-chain fallbacks (workload identity, managed identity) still work when you deliberately omit a client-secret/certificate pair. |
| secret.AZURE_CLIENT_ID | string | `""` | App registration (application) client ID. Required unless every tenants[] entry sets client_id in config.tenants and you rely on workload/ managed identity instead. |
| secret.AZURE_CLIENT_SECRET | string | `""` | Client secret paired with AZURE_CLIENT_ID. Leave empty when using AZURE_CLIENT_CERTIFICATE_PATH (extraEnv/extraVolumes) or workload/managed identity instead. |
| secret.AZURE_TENANT_ID | string | `""` | Ambient fallback tenant ID for DefaultAzureCredential. Usually NOT needed: NewTenantAuth pins each tenants[].tenant_id explicitly per credential, regardless of this value. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsUser":65532}` | Container-level security context. Drops all capabilities and runs with a read-only root filesystem (the app writes only to the checkpoint volume). Runs as the distroless `nonroot` uid/gid 65532 (a high, non-system id > 10000) to satisfy hardened-cluster policy. |
| serviceAccount.annotations | object | `{}` | Annotations to add to the ServiceAccount. |
| serviceAccount.automountServiceAccountToken | bool | `false` | Automount the ServiceAccount API token into the pod. graph2otel makes no Kubernetes API calls, so this defaults to false to drop an unused, attacker-useful credential from the network-facing pod. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Generated when empty. |
| tolerations | list | `[]` | Tolerations for pod scheduling. |


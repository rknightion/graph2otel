# graph2otel

<!-- The two version badges are maintained by release-please: it bumps the ONE
     semver on each annotated line at release time. Two constraints its generic
     updater imposes, both learned the hard way on release PR #80:
       1. it replaces only the FIRST semver per line, so each version sits on its
          own line and appears exactly once;
       2. its semver match is prerelease-greedy — `1.0.0-informational` parses as
          `1.0.0` + prerelease `informational` and is replaced whole, eating the
          trailing word. So the version must be followed by a non-hyphen char.
     The shields static/v1 query form puts `&color=…` right after the version,
     satisfying both. helm-docs regenerates these same lines from Chart.yaml, so
     the two converge byte-for-byte. The Type badge is static, outside the block. -->
<!-- x-release-please-start-version -->
![Version](https://img.shields.io/static/v1?label=Version&message=1.0.0&color=informational&style=flat-square)
![AppVersion](https://img.shields.io/static/v1?label=AppVersion&message=1.0.0&color=informational&style=flat-square)
<!-- x-release-please-end -->
![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

Export Entra ID, Intune, Defender, M365, and Purview telemetry from Microsoft Graph, Azure Storage blobs, and the O365 Management Activity API as OpenTelemetry-native metrics and logs over OTLP.

**Homepage:** <https://github.com/rknightion/graph2otel>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| rknightion |  |  |

## Source Code

* <https://github.com/rknightion/graph2otel>

## Install

Stable releases publish this chart to GHCR alongside the matching graph2otel
container, binaries, SBOMs, and signatures. Set `<version>` to a released
graph2otel version without the leading `v`:

```sh
kubectl create secret generic graph2otel-credentials \
  --from-literal=AZURE_TENANT_ID="<your-tenant-guid>" \
  --from-literal=AZURE_CLIENT_ID="<app-registration-client-id>" \
  --from-literal=AZURE_CLIENT_SECRET="<client-secret>" \
  --from-literal=G2O_OTLP__GRAFANA_CLOUD__TOKEN="<your-otlp-token>"

helm install g2o oci://ghcr.io/rknightion/charts/graph2otel --version <version> \
  --set "config.tenants[0].tenant_id=<your-tenant-guid>" \
  --set "config.otlp.grafana_cloud.instance_id=<your-instance-id>" \
  --set existingSecret=graph2otel-credentials \
  --set persistence.enabled=true
```

To test unreleased chart changes from a checked-out repo:
`helm install g2o charts/graph2otel -f my-values.yaml`.

## Configuration

The entire application config lives under a single top-level `config:` key in
`values.yaml`, mirroring `config.example.yaml`'s top-level keys 1:1 (`tenants`,
`otlp`, `collectors`, `log_level`, `admin`, `profiling`, `cardinality`, `cost`,
`backfill`, `checkpoint_dir`) — not a parallel schema. It is rendered verbatim
into a ConfigMap as `config.yaml`. Helm
deep-merges maps, so single-key overrides work without restating the rest,
e.g. `--set config.log_level=debug`.

Bad values fail early: `values.schema.json` validates `values.yaml` on every
`helm install`/`upgrade`/`lint`, so a mistyped key or wrong type is rejected
before anything renders.

### Auth — never in the ConfigMap

Tenant credentials are never read from `config.tenants` or any other config
key: they come from `azidentity.DefaultAzureCredential` via well-known
`AZURE_*` environment variables, injected through a Secret. Each
`config.tenants[].tenant_id` must be a hyphenated Entra directory GUID;
verified domains and arbitrary names are rejected. graph2otel sets that GUID
on every token request, permits the credential to target only that directory,
and verifies the returned token's `tid` before any tenant-labelled collector
starts.

`DefaultAzureCredential` selects one ambient application identity for the
process. One multi-tenant app registration's `AZURE_CLIENT_ID` and credential
can authenticate against every listed directory after its service principal
has permissions and admin consent in each one — there is no per-tenant secret
to template. `config.tenants[].client_id` is only an optional non-secret
consistency assertion and cannot select or override that identity.

Workload identity uses the platform-injected environment and federated token.
Managed identity stays bound to its Azure home tenant; if its returned token
`tid` differs from a configured directory GUID, graph2otel fails that tenant
closed before emitting data.

Provide credentials either inline (rendered into a chart-managed Secret) or
reference a Secret you manage yourself:

```yaml
secret:
  AZURE_TENANT_ID: "11111111-1111-1111-1111-111111111111"
  AZURE_CLIENT_ID: "00000000-0000-0000-0000-000000000000"
  AZURE_CLIENT_SECRET: "..."
```

```yaml
existingSecret: my-graph2otel-credentials   # must expose the AZURE_* keys your credential leg requires
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

### Cost projections

`config.cost` is disabled by default and contains no vendor prices. Enabling it
requires an operator-supplied uppercase three-letter currency, rate schedule
version and source, RFC3339 effective timestamp, positive projection period,
and four nonnegative integer microunit rates. Every rate must be present;
explicit zero is valid and differs from an omitted rate. The four rates cover a
logical source record, emitted metric point, emitted log record, and
post-compression transmitted OTLP payload byte.

`config.cost.budget_microunits` is also operator-supplied. Zero disables budget
comparison. Cost accounting is observational: neither a rate nor a budget can
drop or suppress telemetry.

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
binary itself defaults it to `false`) so the Deployment can probe the admin
server. Liveness uses `/healthz` and remains independent of collector state.
Readiness uses `/readyz`: it returns 503 until any collector succeeds, then
latches ready for the rest of the process lifetime. One working tenant is
therefore ready even when another is degraded. Before that latch, zero working
collectors stays unready; later transient failures do not flap a latched-ready
process. A zero-tenant stdout-mode diagnostic run is ready immediately. Failure
to bind the admin address remains fatal. Set `config.admin.enabled: false` to
disable both the admin server and the probes.

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
| config.admin | object | `{"addr":":9090","enabled":true,"refresh_interval":"5s"}` | Admin health/status HTTP endpoint (liveness at /healthz, readiness at /readyz, status at / and /api/status.json). Readiness latches after the first successful collector run. The binary defaults this off, while the chart enables it so the Deployment can wire both probes. |
| config.backfill.initial_lookback | string | `"0s"` | Cold-start backfill window for window (log) collectors — no checkpoint yet: a new tenant, a wiped volume, a first deploy. 0 means "use each collector's own built-in lookback" (most 1h; m365.unified_audit 4h; entra.security_incidents 24h); a non-zero value replaces all of them. Does not affect the steady state, where polling resumes from the watermark. Grafana Cloud's strict 7 days ceiling was live-measured 2026-07-22 (#226): rejection is explicit and per-entry (HTTP 400 through the OTel error handler), while in-window entries in the same batch remain accepted. Accepted in-window backdated records can be indexed later, so an immediately empty query is not evidence of rejection. The poll is clamped to 165h (#401) — 3h inside the window, because a rejection seen in production was only about an hour past it. Reaching further back is not a longer recovery, just rejected requests. Raise the emit horizon deliberately if your sink accepts more. |
| config.cardinality | object | `{"global_limit":100000,"per_metric_limit":5000}` | Output-side active-series governance (Grafana Cloud bills on active series). Enforced by graph2otel's own limiter, which keeps the most significant series and folds the rest into a named `other` bucket; the OTEL SDK's arrival-ordered cap is disabled in favor of it. graph2otel's metrics are bounded aggregates (largest measured: 175 series), so these are blast-radius guards, not normal constraints. Set 0 for unlimited. |
| config.checkpoint_dir | string | `"/var/lib/graph2otel/checkpoints"` | Where window-log collectors persist their per-(tenant, endpoint) watermarks, so a restart resumes rather than re-fetching or dropping data. Matches the checkpoint volume's mountPath below, so overriding this also moves where the volume is mounted — keep it an absolute path. |
| config.collectors | object | `{}` | Per-collector overrides, applied globally across all tenants, keyed by collector name. A collector omitted here runs enabled at its built-in default interval. Experimental/beta collectors need explicit enabling — see docs/collectors.md. Example: collectors:   "entra.signins.interactive":     enabled: true     interval: "5m" |
| config.cost | object | `{"budget_microunits":0,"currency":"","effective_at":"","enabled":false,"period":"720h","rates":{"log_record_microunits":null,"metric_point_microunits":null,"source_record_microunits":null,"transmitted_payload_byte_microunits":null},"source":"","version":""}` | Optional observational cost projections from operator-supplied integer microunit rates. graph2otel ships no vendor prices and never enforces this budget by dropping or suppressing telemetry. All metadata and all four rates are required when enabled; an explicit zero rate is valid. |
| config.cost.budget_microunits | int | `0` | Nonnegative projection-period budget in microunits; 0 disables comparison. |
| config.cost.currency | string | `""` | Uppercase three-letter currency code; required when enabled. |
| config.cost.effective_at | string | `""` | RFC3339 rate-schedule effective timestamp; required when enabled. |
| config.cost.enabled | bool | `false` | Enable observational cost accounting. |
| config.cost.period | string | `"720h"` | Positive projection period. 720h is 30 days. |
| config.cost.rates.log_record_microunits | integer\|null | `nil` | Microunits per emitted log record; explicit nonnegative integer required when enabled. |
| config.cost.rates.metric_point_microunits | integer\|null | `nil` | Microunits per emitted metric point; explicit nonnegative integer required when enabled. |
| config.cost.rates.source_record_microunits | integer\|null | `nil` | Microunits per logical source record; explicit nonnegative integer required when enabled. |
| config.cost.rates.transmitted_payload_byte_microunits | integer\|null | `nil` | Microunits per post-compression transmitted OTLP payload byte; explicit nonnegative integer required when enabled. |
| config.cost.source | string | `""` | Operator rate source/provenance; required and nonblank when enabled. |
| config.cost.version | string | `""` | Operator rate-schedule version; required and nonblank when enabled. |
| config.grafana_annotations.categories.config_posture.enabled | bool | `true` | CA policy changes, Intune compliance/configuration policy changes, admin consent grants, app credential additions. |
| config.grafana_annotations.categories.config_posture.rollup | bool | `true` | Highest-volume of the four; rolled up so dashboards stay readable. |
| config.grafana_annotations.categories.license.enabled | bool | `true` | Subscribed-SKU set changes and license exhaustion. |
| config.grafana_annotations.categories.license.rollup | bool | `true` | A tenant-wide license change moves many SKUs at once. |
| config.grafana_annotations.categories.security_incident.enabled | bool | `true` | Medium/high security alerts and incidents becoming active. |
| config.grafana_annotations.categories.security_incident.rollup | bool | `false` | Individually annotated: a count would lose WHICH incident. |
| config.grafana_annotations.categories.service_health.enabled | bool | `true` | Microsoft 365 service-health incidents opening and closing. |
| config.grafana_annotations.categories.service_health.rollup | bool | `false` | Individually annotated; naturally low volume. |
| config.grafana_annotations.dashboard_uid | string | `""` | Optional: confine annotations to one dashboard UID. Empty publishes organization annotations, which is what makes them visible on every board. |
| config.grafana_annotations.dedupe_retention | string | `"48h"` | How long a published annotation's dedupe key is remembered, so a restart or an overlapping poll window cannot re-publish it. |
| config.grafana_annotations.max_per_minute | int | `60` | Token-bucket ceiling on annotations written per process. Overage is dropped and counted; it never blocks or fails collection. |
| config.grafana_annotations.queue_size | int | `512` | Hand-off buffer size. A full queue drops and counts rather than blocking a collector on Grafana being slow or down. |
| config.grafana_annotations.rollup_interval | string | `"5m"` | Bucket width for rolled-up categories: one annotation per interval per category per tenant, carrying a count and a bounded summary. |
| config.grafana_annotations.timeout | string | `"10s"` | Per-request timeout for POST /api/annotations. |
| config.grafana_annotations.token | string | `""` | Grafana service-account token. Leave empty here and supply it via environment or token_file — a token in values.yaml ends up in the release. |
| config.grafana_annotations.token_file | string | `""` | Path to a mounted file holding the token. value XOR file, never both. |
| config.grafana_annotations.url | string | `""` | Grafana base URL, e.g. https://grafana.example.com. Setting it IS the opt-in; empty means no annotation writer at all. Once set, the process fails to start unless the token can actually write an annotation. |
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
| config.tenants[0].client_id | string | `""` | Optional expected application ID. A non-secret consistency assertion only; never credential selection. |
| config.tenants[0].tenant_id | string | `"00000000-0000-0000-0000-000000000000"` | Hyphenated Entra directory GUID only. Verified domains and arbitrary names are rejected. |
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
| secret.AZURE_CLIENT_ID | string | `""` | Ambient application client ID used by environment credentials, workload identity, or to select a user-assigned managed identity. One value applies to the process. config.tenants[].client_id is only a consistency assertion and never replaces or overrides this credential selection. |
| secret.AZURE_CLIENT_SECRET | string | `""` | Client secret paired with AZURE_CLIENT_ID. Leave empty when using AZURE_CLIENT_CERTIFICATE_PATH (extraEnv/extraVolumes) or workload/managed identity instead. |
| secret.AZURE_TENANT_ID | string | `""` | Ambient/default tenant ID used by DefaultAzureCredential. Environment client-secret/certificate and workload-identity legs normally require it. It does not select a per-config tenant: graph2otel still sets each hyphenated config.tenants[].tenant_id on the request and verifies the returned tid. |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":65532,"runAsUser":65532}` | Container-level security context. Drops all capabilities and runs with a read-only root filesystem (the app writes only to the checkpoint volume). Runs as the distroless `nonroot` uid/gid 65532 (a high, non-system id > 10000) to satisfy hardened-cluster policy. |
| serviceAccount.annotations | object | `{}` | Annotations to add to the ServiceAccount. |
| serviceAccount.automountServiceAccountToken | bool | `false` | Automount the ServiceAccount API token into the pod. graph2otel makes no Kubernetes API calls, so this defaults to false to drop an unused, attacker-useful credential from the network-facing pod. |
| serviceAccount.create | bool | `true` | Create a ServiceAccount. |
| serviceAccount.name | string | `""` | ServiceAccount name. Generated when empty. |
| tolerations | list | `[]` | Tolerations for pod scheduling. |


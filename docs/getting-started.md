# Getting started

v1.0.0 is available as a signed GHCR image, an OCI Helm chart, and release binaries.
Choose one installation path, then use the same permission preflight and local-output
smoke test below.

## Install

### Container image

Tagged releases publish Linux amd64/arm64 images to
`ghcr.io/rknightion/graph2otel`. The image is keylessly signed and published with
provenance plus SPDX and CycloneDX SBOMs.

First verify the published image and version without configuring a tenant or
contacting Microsoft:

```sh
docker run --rm ghcr.io/rknightion/graph2otel:1.0.0 -version
```

For a real collection smoke test, create the checkpoint volume and mount a
one-tenant config. The image runs from built-in defaults plus `G2O_*`
environment variables; no config file is loaded unless you mount one and pass
`--config`:

```sh
docker volume create graph2otel-checkpoints

docker run --rm \
  --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  --mount type=volume,src=graph2otel-checkpoints,dst=/var/lib/graph2otel \
  --mount type=bind,src="$(pwd)/config.yaml",dst=/etc/graph2otel/config.yaml,readonly \
  -e AZURE_TENANT_ID="..." -e AZURE_CLIENT_ID="..." -e AZURE_CLIENT_SECRET="..." \
  ghcr.io/rknightion/graph2otel:1.0.0 \
  --config /etc/graph2otel/config.yaml
```

Set `checkpoint_dir: /var/lib/graph2otel` in the mounted config. The named volume keeps
each window collector's watermarks across restarts; do not rely on the writable
container layer. The image runs as UID/GID `65532`. If policy requires a host bind mount
instead of a named volume, prepare it first:

```sh
mkdir -p ./checkpoints
sudo chown 65532:65532 ./checkpoints
```

Then replace the volume mount in the commands above with:

```sh
--mount type=bind,src="$(pwd)/checkpoints",dst=/var/lib/graph2otel
```

### Helm

The release chart is published to GHCR as an OCI artifact. Create a Kubernetes Secret
for the ambient Azure credential, put the non-secret application configuration in
`values.yaml`, and enable persistent checkpoints for a real deployment:

```sh
kubectl create namespace graph2otel
kubectl -n graph2otel create secret generic graph2otel-credentials \
  --from-literal=AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111" \
  --from-literal=AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222" \
  --from-literal=AZURE_CLIENT_SECRET="..."
```

```yaml title="values.yaml"
existingSecret: graph2otel-credentials

config:
  tenants:
    - tenant_id: "11111111-1111-1111-1111-111111111111"
  otlp:
    protocol: stdout

persistence:
  enabled: true
```

```sh
helm install graph2otel oci://ghcr.io/rknightion/charts/graph2otel \
  --version 1.0.0 \
  --namespace graph2otel \
  --values values.yaml
```

Use `stdout` only for the first smoke test. Before a production install, configure the
OTLP backend and source its token from a Secret. The
[chart reference](https://github.com/rknightion/graph2otel/tree/main/charts/graph2otel)
documents Grafana Cloud values, workload identity, certificate mounts, and every chart
setting.

### Release binaries

The [v1.0.0 GitHub release](https://github.com/rknightion/graph2otel/releases/tag/v1.0.0)
contains archives for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64. It also
contains SHA-256 checksums, one SBOM per archive, a Sigstore bundle for the checksums,
and SLSA build provenance. The release-level SPDX and CycloneDX SBOMs and
`THIRD_PARTY_NOTICES.md` are published beside them.

Download the archive for the host, verify it against
`graph2otel_1.0.0_SHA256SUMS`, and put the binary on `PATH`.

### Build from source

```sh
go install github.com/rknightion/graph2otel/cmd/graph2otel@v1.0.0
```

Or clone and build a binary with the version stamped in:

```sh
git clone https://github.com/rknightion/graph2otel
cd graph2otel
go build -ldflags "-X github.com/rknightion/graph2otel/internal/version.Version=$(git describe --tags --always)" ./cmd/graph2otel
```

## Auth setup

`graph2otel` uses `azidentity.DefaultAzureCredential` for app-only authentication — no
signed-in user and no interactive login. The ambient credential chain selects one
application identity for the process. Each `tenants[].tenant_id` must be the hyphenated
Entra directory GUID; verified domains and arbitrary names are rejected. graph2otel sets
that GUID on every token request, permits the credential to target only that directory,
and verifies the returned token's `tid` before any collector or tenant-labelled signal
starts. One multi-tenant app registration can serve every listed directory after its
service principal has the required permissions and admin consent in each one.

For client-secret or certificate authentication, configure the process environment:

```sh
export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
export AZURE_CLIENT_SECRET="..."          # or, for certificate auth:
# export AZURE_CLIENT_CERTIFICATE_PATH="/path/to/cert.pem"
```

Workload identity uses the platform-injected federated-token environment, including its
single ambient `AZURE_CLIENT_ID`. Managed identity uses the identity assigned to the
Azure host; set `AZURE_CLIENT_ID` for a user-assigned identity, or leave it unset for the
system-assigned identity. Managed identity remains bound to its home tenant; if the
returned token `tid` differs from a configured directory GUID, graph2otel fails that
tenant closed before it emits data. These mechanisms still select one application
identity for the process.

For multiple tenants, add one YAML entry per directory GUID and keep one process-level
credential configuration. `tenant_id` binds and verifies the directory. An optional
`client_id` is only a non-secret consistency assertion about the ambient identity; it
cannot select or override `DefaultAzureCredential`. If it differs from the `appid`
proved from the actual Graph access token, startup warns once and the authenticated ID
wins. Secrets and credential material always stay out of YAML.

## Permission preflight

Once credentials and a config are in place, run the built-in permission preflight before
the first real poll. It validates that every enabled collector's required Graph
application permissions are granted and admin-consented, reporting omissions before
they become runtime 403s:

```sh
graph2otel check --config config.yaml
```

Some collectors use non-Graph data planes and need separate registration, storage
roles, or credentials. Follow [Permissions](permissions.md) and
[data-plane registration](data-plane-registration.md) for the enabled collector set;
the generated [collector reference](collectors.md) is the exact source/scope inventory.

## Minimal first run

The smallest useful config points at one tenant and sends output to stdout instead of a
real OTLP backend:

```yaml
log_level: info

tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111"
    client_id: "22222222-2222-2222-2222-222222222222" # optional identity assertion

otlp:
  protocol: stdout

checkpoint_dir: /var/lib/graph2otel
```

```sh
graph2otel --config config.yaml
```

`otlp.protocol: stdout` prints every metric and log record as OTLP-shaped output instead
of pushing over the network. Switch `protocol` to `grpc` or `http` and set
`otlp.endpoint` / `otlp.grafana_cloud` once the smoke test is complete. See
[Configuration](configuration.md) for the full YAML reference and
[Environment variables](env-vars.md) for generated `G2O_*` mappings.

For an operator health surface, enable `admin`. `/healthz` reports process liveness
independently of collection, while `/readyz` returns 503 until the first collector
succeeds and then remains ready for the process lifetime. Partial tenant success is
ready with the failures reported as degraded; if no collector ever works, readiness
stays 503. A zero-tenant `stdout` diagnostic run is ready immediately. A configured
admin address that cannot bind is a fatal startup error.

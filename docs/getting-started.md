# Getting started

## Install

### Container image

`graph2otel` publishes a multi-arch (amd64/arm64) container image to GHCR on each
tagged release, signed with cosign and shipped with an SBOM (`ghcr.io/rknightion/graph2otel`).
Pre-1.0 and pre-first-release, use the `:main` edge build if you want to try it before a
tagged version exists.

```sh
docker volume create graph2otel-checkpoints

docker run --rm \
  --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  --mount type=volume,src=graph2otel-checkpoints,dst=/var/lib/graph2otel \
  -e AZURE_TENANT_ID="..." \
  -e AZURE_CLIENT_ID="..." \
  -e AZURE_CLIENT_SECRET="..." \
  -e G2O_CHECKPOINT_DIR=/var/lib/graph2otel \
  -e G2O_OTLP__PROTOCOL=stdout \
  ghcr.io/rknightion/graph2otel:main
```

The image runs from built-in defaults plus `G2O_*` environment variables by default — no
config file is loaded unless you mount one and pass `--config`:

```sh
docker run --rm \
  --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  --mount type=volume,src=graph2otel-checkpoints,dst=/var/lib/graph2otel \
  --mount type=bind,src="$(pwd)/config.yaml",dst=/etc/graph2otel/config.yaml,readonly \
  -e AZURE_TENANT_ID="..." -e AZURE_CLIENT_ID="..." -e AZURE_CLIENT_SECRET="..." \
  ghcr.io/rknightion/graph2otel:main \
  --config /etc/graph2otel/config.yaml
```

Set `checkpoint_dir: /var/lib/graph2otel` in the mounted config. The named
volume keeps each window collector's watermarks across restarts; do not rely on
the writable container layer. The image runs as UID/GID `65532`. If policy
requires a host bind mount instead of a named volume, prepare it first:

```sh
mkdir -p ./checkpoints
sudo chown 65532:65532 ./checkpoints
```

Then replace the volume mount in the commands above with:

```sh
--mount type=bind,src="$(pwd)/checkpoints",dst=/var/lib/graph2otel
```

A Helm chart is planned but not published yet — see the
[issue tracker](https://github.com/rknightion/graph2otel/issues) for status.

### Build from source

```sh
go install github.com/rknightion/graph2otel/cmd/graph2otel@latest
```

or clone and build a binary with the version stamped in:

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

Once credentials and a config are in place, run the built-in permission preflight before
your first real poll — it validates that every enabled collector's required Graph
application permissions are both granted on the app registration and admin-consented,
and reports what's missing up front instead of failing at runtime with a 403:

```sh
graph2otel check --config config.yaml
```

## Minimal first run

The smallest useful config points at one tenant and sends output to stdout instead of a
real OTLP backend, so you can see what a collector emits without wiring up Grafana Cloud
first:

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

`otlp.protocol: stdout` is the local-debugging path — it prints every metric and log
record graph2otel emits to stdout as OTLP-shaped output, instead of pushing over the
network. Switch `protocol` to `grpc` or `http` and set `otlp.endpoint` /
`otlp.grafana_cloud` once you're ready to point at a real backend. See
[Configuration](configuration.md) for the full key reference.

For an operator health surface, enable `admin`. `/healthz` reports process
liveness independently of collection, while `/readyz` returns 503 until the
first collector succeeds and then remains ready for the process lifetime.
Partial tenant success is ready with the failures reported as degraded; if no
collector ever works, readiness stays 503. A zero-tenant `stdout` diagnostic
run is ready immediately. A configured admin address that cannot bind is a
fatal startup error.

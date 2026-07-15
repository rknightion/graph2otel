# Getting started

## Install

### Container image

`graph2otel` publishes a multi-arch (amd64/arm64) container image to GHCR on each
tagged release, signed with cosign and shipped with an SBOM (`ghcr.io/rknightion/graph2otel`).
Pre-1.0 and pre-first-release, use the `:main` edge build if you want to try it before a
tagged version exists.

```sh
docker run --rm \
  -e AZURE_TENANT_ID="..." \
  -e AZURE_CLIENT_ID="..." \
  -e AZURE_CLIENT_SECRET="..." \
  -e G2O_OTLP__PROTOCOL=stdout \
  ghcr.io/rknightion/graph2otel:main
```

The image runs from built-in defaults plus `G2O_*` environment variables by default — no
config file is loaded unless you mount one and pass `--config`:

```sh
docker run --rm \
  -v ./config.yaml:/etc/graph2otel/config.yaml:ro \
  -e AZURE_TENANT_ID="..." -e AZURE_CLIENT_ID="..." -e AZURE_CLIENT_SECRET="..." \
  ghcr.io/rknightion/graph2otel:main \
  --config /etc/graph2otel/config.yaml
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
go build -ldflags "-X main.version=$(git describe --tags --always)" ./cmd/graph2otel
```

## Auth setup

`graph2otel` uses `azidentity.DefaultAzureCredential` for app-only, client-credentials
auth against each configured tenant — no signed-in user, no interactive login. Create an
app registration per tenant (or one multi-tenant app registration reused across
tenants), grant it the minimum read-only Graph API application permissions your enabled
collectors need, get admin consent, then set:

```sh
export AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111"
export AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222"
export AZURE_CLIENT_SECRET="..."          # or, for certificate auth:
# export AZURE_CLIENT_CERTIFICATE_PATH="/path/to/cert.pem"
```

`tenants[].tenant_id` / `.client_id` in config are non-secret identifiers only — they
select which tenant/app registration a collector run targets. Auth material is always
supplied via environment, never written into YAML.

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
    client_id: "22222222-2222-2222-2222-222222222222"

otlp:
  protocol: stdout
```

```sh
graph2otel --config config.yaml
```

`otlp.protocol: stdout` is the local-debugging path — it prints every metric and log
record graph2otel emits to stdout as OTLP-shaped output, instead of pushing over the
network. Switch `protocol` to `grpc` or `http` and set `otlp.endpoint` /
`otlp.grafana_cloud` once you're ready to point at a real backend. See
[Configuration](configuration.md) for the full key reference.

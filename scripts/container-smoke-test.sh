#!/usr/bin/env bash
# Smoke-test the documented standalone-container layout: a nonroot image,
# read-only root filesystem, and a named volume holding checkpoint state.
set -euo pipefail

image="${IMAGE:-graph2otel:container-smoke}"
name="graph2otel-container-smoke-$$"
negative_name="${name}-without-mount"
volume="${name}-checkpoints"
workdir="$(mktemp -d)"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker rm -f "$negative_name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT

# Keep this fixture's config contract in lockstep with README's minimal
# container config. stdout only overrides the published HTTP backend so the
# smoke remains offline; the mounted checkpoint_dir is exactly the published
# absolute path.
cat >"$workdir/config.yaml" <<'EOF'
tenants:
  - tenant_id: "11111111-1111-1111-1111-111111111111"
    client_id: "22222222-2222-2222-2222-222222222222"
otlp:
  protocol: http
  endpoint: "https://otlp-gateway-prod-us-central-0.grafana.net/otlp"
  grafana_cloud:
    instance_id: "123456"
checkpoint_dir: "/var/lib/graph2otel"
EOF

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  docker build --tag "$image" .
fi
test "$(docker image inspect --format '{{.Config.User}}' "$image")" = "65532:65532"
docker volume create "$volume" >/dev/null

wait_for_stable_startup() {
  local container="$1"
  local running

  for _ in $(seq 1 5); do
    running="$(docker inspect --format '{{.State.Running}}' "$container")"
    if [ "$running" != "true" ]; then
      docker logs "$container" >&2 || true
      return 1
    fi
    sleep 1
  done

  if docker logs "$container" 2>&1 | grep -Fq 'checkpoint directory unusable'; then
    docker logs "$container" >&2 || true
    return 1
  fi
}

# No checkpoint mount must fail fast even though the image contains the owned
# seed directory: --read-only makes the image filesystem unsuitable for state.
docker run --detach --name "$negative_name" --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  --mount "type=bind,src=$workdir/config.yaml,dst=/etc/graph2otel/config.yaml,readonly" \
  -e AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111" \
  -e AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222" \
  -e AZURE_CLIENT_SECRET="container-smoke-test-secret" \
  -e AZURE_AUTHORITY_HOST=http://127.0.0.1:1 \
  -e G2O_OTLP__PROTOCOL=stdout \
  "$image" --config /etc/graph2otel/config.yaml >/dev/null

sleep 2
if [ "$(docker inspect --format '{{.State.Running}}' "$negative_name")" = "true" ]; then
  docker logs "$negative_name" >&2 || true
  echo "container started without an explicit checkpoint mount" >&2
  exit 1
fi
if ! docker logs "$negative_name" 2>&1 | grep -Fq 'checkpoint directory unusable'; then
  docker logs "$negative_name" >&2 || true
  echo "container did not fail at checkpoint verification without an explicit mount" >&2
  exit 1
fi

docker run --detach --name "$name" --read-only \
  --tmpfs /tmp:uid=65532,gid=65532,mode=1777 \
  --mount "type=volume,src=$volume,dst=/var/lib/graph2otel" \
  --mount "type=bind,src=$workdir/config.yaml,dst=/etc/graph2otel/config.yaml,readonly" \
  -e AZURE_TENANT_ID="11111111-1111-1111-1111-111111111111" \
  -e AZURE_CLIENT_ID="22222222-2222-2222-2222-222222222222" \
  -e AZURE_CLIENT_SECRET="container-smoke-test-secret" \
  -e AZURE_AUTHORITY_HOST=http://127.0.0.1:1 \
  -e G2O_OTLP__PROTOCOL=stdout \
  "$image" --config /etc/graph2otel/config.yaml >/dev/null

wait_for_stable_startup "$name"

# This valid checkpoint-shaped persisted state must survive a restart of the
# documented container + named-volume layout.
docker run --rm --mount "type=volume,src=$volume,dst=/checkpoints" \
  busybox:1.37 sh -c 'printf %s "{\"schema\":1,\"tenant_id\":\"smoke\",\"endpoint\":\"/smoke\",\"seen_ids\":[]}" > /checkpoints/smoke__checkpoint.json'

docker restart "$name" >/dev/null

wait_for_stable_startup "$name"

test "$(docker run --rm --mount "type=volume,src=$volume,dst=/checkpoints" \
  busybox:1.37 cat /checkpoints/smoke__checkpoint.json)" = '{"schema":1,"tenant_id":"smoke","endpoint":"/smoke","seen_ids":[]}'

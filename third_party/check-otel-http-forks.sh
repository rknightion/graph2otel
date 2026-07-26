#!/usr/bin/env bash
# Verify the two pinned OpenTelemetry HTTP exporter forks and run their module
# gates. The manifest is also consumed by scripts/notices.sh, keeping source
# provenance, versions, and local replacement paths in one drift-gated place.
set -euo pipefail

mode="${1:-check}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
manifest="$root/third_party/otel-http-forks.tsv"

case "$mode" in
  check|tidy) ;;
  *)
    echo "forks: unknown mode '$mode' (want check or tidy)" >&2
    exit 2
    ;;
esac

# Exporter environment belongs to the application using the fork. Upstream's
# own config tests assume a clean baseline and set every variable they need.
# Remove inherited names without ever expanding or printing their values.
clean_env=(env
  -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY
  -u http_proxy -u https_proxy -u all_proxy -u no_proxy
)
while IFS='=' read -r name _; do
  case "$name" in
    OTEL_EXPORTER_OTLP*) clean_env+=(-u "$name") ;;
  esac
done < <(env)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
gomodcache="$(go env GOMODCACHE)"

while IFS=$'\t' read -r module version license source local_dir modified_files; do
  case "$module" in
    ""|\#*) continue ;;
  esac

  local_abs="$(cd "$root/$local_dir" && pwd -P)"
  resolved="$(cd "$root" && go list -m -f '{{.Version}}|{{with .Replace}}{{.Dir}}{{end}}' "$module")"
  if [[ "$resolved" != "$version|$local_abs" ]]; then
    echo "forks: root module resolves $module as '$resolved', want '$version|$local_abs'" >&2
    exit 1
  fi
  if [[ "$license" != "Apache-2.0" || ! -f "$local_abs/LICENSE" || -z "$source" ]]; then
    echo "forks: incomplete Apache-2.0 provenance for $module" >&2
    exit 1
  fi

  # Download the immutable upstream source and prove the local copy differs
  # only in the declared minimal patch files.
  GOWORK=off GOFLAGS=-mod=mod go mod download "$module@$version"
  upstream="$gomodcache/$module@$version"
  if [[ ! -d "$upstream" ]]; then
    echo "forks: upstream module cache missing $upstream" >&2
    exit 1
  fi
  if ! cmp -s "$upstream/LICENSE" "$local_abs/LICENSE"; then
    echo "forks: local LICENSE differs from $module@$version" >&2
    exit 1
  fi

  expected="$tmp/$(basename "$local_dir")"
  cp -R "$upstream" "$expected"
  chmod -R u+w "$expected"
  IFS=',' read -r -a modified <<< "$modified_files"
  for rel in "${modified[@]}"; do
    if [[ ! -f "$local_abs/$rel" ]]; then
      echo "forks: manifest names missing file $local_dir/$rel" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$expected/$rel")"
    cp "$local_abs/$rel" "$expected/$rel"
    if [[ "$rel" == *.go ]] && ! grep -q 'Modified by the graph2otel project' "$local_abs/$rel"; then
      echo "forks: $local_dir/$rel lacks its Apache-2.0 modification notice" >&2
      exit 1
    fi
  done
  if ! diff -qr "$expected" "$local_abs"; then
    echo "forks: undeclared drift from $module@$version" >&2
    exit 1
  fi

  if [[ "$mode" == "tidy" ]]; then
    GOFLAGS=-mod=mod go mod tidy -C "$local_abs"
  else
    "${clean_env[@]}" GOFLAGS=-mod=readonly go -C "$local_abs" vet ./...
    "${clean_env[@]}" GOFLAGS=-mod=readonly go -C "$local_abs" test -race ./...
  fi
done < "$manifest"

echo "forks: $mode passed"

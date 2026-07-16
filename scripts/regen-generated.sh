#!/usr/bin/env bash
#
# Regenerate the repo's committed *generated* artifacts so they never drift from
# their sources (drift is what fails the `go test` / CI gates). Each artifact is
# a pure function of its inputs:
#
#   docs/env-vars.md  <- config.example.yaml  (TestEnvReferenceDocInSync -update)
#
# The env-var reference table is generated from config.example.yaml by the golden
# test's -update mode (root module; no separate tool). The drift gate itself is
# the same test under a plain `go test` run, so `make check` already fails on a
# stale doc — this wrapper is just the "regenerate it for me" convenience.
#
# Usage:
#   scripts/regen-generated.sh          # regenerate everything
#   scripts/regen-generated.sh envref   # just docs/env-vars.md
#
# NOTE — Helm chart docs/schema are NOT yet wired here. The chart's values.yaml
# `config:` block is kept in sync with the config struct by the pure-`go test`
# gate TestHelmValuesConfigCoversEveryKey (no external tooling needed). If/when
# helm-docs + values.schema.json generation lands (see the sibling
# tailscale2otel repo's scripts/regen-generated.sh + .github/workflows/helm.yml),
# add `helm-docs` / `helm-schema` targets here.
#
# A missing tool is a loud SKIP (not a failure) so the hook never blocks a
# commit — CI's `go test` gate remains the hard backstop. A regeneration that
# actually errors (e.g. the code doesn't compile) DOES fail.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

note() { printf '  regen: %s\n' "$1"; }
skip() { printf '  regen: SKIP %s\n' "$1" >&2; }

regen_envref() {
  if ! command -v go >/dev/null 2>&1; then
    skip "go not installed -> docs/env-vars.md not regenerated (CI will gate it)"
    return 0
  fi
  note "docs/env-vars.md (config env-var reference)"
  go test -C "$ROOT" ./internal/config -run TestEnvReferenceDocInSync -update -count=1 >/dev/null
}

main() {
  local targets=("$@")
  [ ${#targets[@]} -eq 0 ] && targets=(all)

  local do_envref=0
  for t in "${targets[@]}"; do
    case "$t" in
      all)    do_envref=1 ;;
      envref) do_envref=1 ;;
      *) printf 'regen-generated.sh: unknown target %q\n' "$t" >&2; exit 2 ;;
    esac
  done

  [ "$do_envref" = 1 ] && regen_envref
  return 0
}

main "$@"

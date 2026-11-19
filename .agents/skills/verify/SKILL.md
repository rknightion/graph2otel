---
name: verify
description: Verify Graph2otel Go, Helm, startup and checkpoint changes with the applicable local fixture and the full source gate.
---

# Verify Graph2otel

## Choose the first check

- For Go changes, run `just fmt-check </dev/null` and the affected package with the race detector. For
  checkpoint storage, run `go test -race ./internal/checkpoint </dev/null`.
- For a chart contract change, run `just helm-check </dev/null`. It checks the chart's Go contracts,
  lint, and renders of the standard and configured layouts.
- For an image, startup, or checkpoint mount change, use the existing container fixture below.

Run `just setup </dev/null` once for the pinned tools and `just check </dev/null` on the final
tree. Use the scoped runner route in [AGENTS.md](../../../AGENTS.md) when required. With Docker
available, `just ci </dev/null` runs the source gate and the smoke fixture together.

## Verify the standalone container

Run `just smoke </dev/null` with a Docker daemon that supports read-only filesystems and named
volumes. It builds the current checkout's image. CI uses `just smoke graph2otel:ci 1 </dev/null`
after building that tag from the same checkout. Use the short form with `1` only for an image
already built from the source under test. Builds and image pulls can use public registries.

[The smoke script](../../../scripts/container-smoke-test.sh) owns the assertions for the
[standalone layout](../../../README.md). A passing exit verifies that:

- The image runs as UID and GID `65532:65532`.
- A read-only container without the checkpoint mount stops with `checkpoint directory unusable`.
- With the named volume mounted, the container stays running without that startup diagnostic. It
  also starts after restart and preserves the seeded checkpoint bytes.

The fixture supplies synthetic credentials, a loopback authentication endpoint, and stdout output.
Use this fixture for container verification and keep live tenant and Grafana work in their separately
authorized routes.

Record the checked-out commit, the command, the image tag, the actual exit status, and the relevant
log on failure. Capture the command's exit status before inspecting the log. If Docker or its image
inputs are unavailable, record that the smoke did not run and retain the native CI result separately.

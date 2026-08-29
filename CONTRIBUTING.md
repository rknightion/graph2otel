# Contributing to graph2otel

Thanks for your interest in contributing. This is a small project with a strict green
bar — the workflow below keeps it that way.

## Ground rules

- **Tests first.** The project is built test-driven (strict TDD): a failing test, then the
  minimal code to make it pass. Table-driven tests using the standard library `testing`
  package — no third-party assertion library (no testify) unless a real need emerges.
- **The cardinality boundary is a review gate.** Per-entity data (per-user, per-device,
  per-sign-in) never becomes an OTEL metric label — it belongs in the logs pipeline. See
  `SECURITY.md`. Changes that weaken this will not be accepted.
- **Read-only, least-privilege by default.** Only request the Graph API application
  permissions a collector actually needs; never widen a scope speculatively.

## Dev setup

Requires **Go 1.27+**. `just setup` installs the pinned toolchain into `.tools/`.
The single green-bar command is:

```bash
just check   # fmt + lint + tests + vuln scan + generated-asset drift + build
```

Other useful targets:

```bash
just build         # -> bin/graph2otel (version stamped via git describe)
just test          # go test -race ./...
just lint          # go vet + golangci-lint run
just fmt           # golangci-lint fmt (gofmt + goimports) + just --fmt
just image         # build the container image locally
just dashboard     # regenerate dashboards/graph2otel.json from grafana/boards/*.py
just grafana-check # dashboard metric coverage + log coverage + freshness (a CI leg)
```

`dashboards/graph2otel.json` is **generated** — edit `grafana/boards/*.py`, not the JSON. A new
collector's metrics must reach a panel (or a documented waiver) or `just grafana-check`
fails; see [`grafana/AUTHORING.md`](grafana/AUTHORING.md). It needs only `python3` —
no packages to install.

## Making a change

1. Fork the repository and create a topic branch (external contributors — see the note on
   this project's own workflow below).
2. Write a failing test first, watch it fail for the right reason, then write the minimal
   code to make it pass.
3. Keep `just check` green.
4. Open a pull request with a clear description of the change and its motivation.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) — the
subject line drives the changelog that [release-please](https://github.com/googleapis/release-please)
generates. Use `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, etc. Mark breaking changes
with a `!` (e.g. `feat!:`) and a `BREAKING CHANGE:` footer.

## Releases

Releases are automated with release-please: once changes land on `main`, it opens a
release PR that bumps the version and `CHANGELOG.md` from the Conventional Commits.
Merging that PR tags the release, publishes the GitHub Release, and triggers the
container image build. Maintainers cut releases — contributors only need correct commit
subjects (`feat`/`fix`/breaking drive the version bump).

## A note on this project's own workflow

The maintainer (rknightion) works directly on `main` with GitHub Issues as the tracker for
first-party work — see `CLAUDE.md` if you're curious why. That's an internal convention,
not a requirement for outside contributors: send a pull request as usual.

## No DCO / CLA

No sign-off dance — by contributing you agree your work is licensed under the project
license (`AGPL-3.0-only`, see [LICENSE](./LICENSE)).

## Reporting issues

Use GitHub issues for bugs/features. For security problems use the private process in
[SECURITY.md](SECURITY.md) instead.

---
id: GTO-0007
title: Migrate the repo task surface to just and retire Makefiles and ad-hoc scripts
status: To Do
assignee: []
created_date: '2026-08-28 19:15'
updated_date: '2026-08-29 11:20'
labels:
  - 'wave:2-fleet'
dependencies: []
priority: medium
type: chore
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fleet-wide migration of the repo task surface from `make` + ad-hoc shell to a single top-level
`justfile`, per the frozen fleet standard (mandatory seven-recipe vocabulary, six groups, one
self-contained justfile per repo, CI calls `just`). This task is the complete plan; the executing
agent should need no design decisions of its own.

## 1. Outcome

`graph2otel` has one top-level `justfile` that is the only task surface. `Makefile` (233 lines,
40 targets) is deleted. `scripts/sbom.sh` is absorbed into a recipe and deleted. Every other script
survives as a file and is reachable through a recipe — `scripts/regen-generated.sh` and
`scripts/notices.sh` in particular are load-bearing outside `just` (a Go contract test reads the
former's text; `Dockerfile:29` executes the latter inside the image build). `just check` is the
truthful local gate: it is exactly the union of ci.yml's `build-test`, `lint`, `govulncheck`,
`helm` and `grafana` jobs, i.e. every leg in `ci-success`'s `needs:` except `goreleaser-snapshot`
and `docker-build`, which need a docker daemon and a 12 GB swapfile and are covered by `just ci`.
Seven workflow files call `just` after a SHA-pinned `extractions/setup-just` step; `ci-success`,
every `permissions:`, `concurrency:`, `persist-credentials: false`, every SHA pin, every
`uses: rknightion/.github/...` reusable and every matrix are untouched. `AGENTS.md`,
`CONTRIBUTING.md`, `grafana/AUTHORING.md`, four `docs/*.md` pages, the generated-doc header inside
`grafana/build_rules.py`, and `backlog/config.yml`'s `definition_of_done` all name `just` recipes.

Two real defects get fixed as a side effect, because the standard requires `check` to be exactly
what CI enforces:

- **govulncheck version drift.** `Makefile:184` installs `govulncheck@latest`; `ci.yml:85` pins
  `v1.3.0`. The justfile pins `v1.3.0` in one place and CI installs from that pin.
- **golangci-lint version drift.** `Makefile:11` pins `v2.13.1`; `ci.yml:69` (the
  `golangci-lint-action`) pins `v2.13.2`. The justfile owns one pin and ci.yml's `lint` job drops
  the action in favour of `just setup && just lint`, so there is exactly one version in the repo.
  Set the justfile pin to **`v2.13.2`** (CI's current effective version — do not silently downgrade
  the linter). `scripts/cloud-environment-setup.sh` also pins `v2.13.1` and
  `scripts/cloud_environment_setup_test.go:23` asserts that exact string; **both are out of scope
  for this task** (see §10) and stay at `v2.13.1`.

## 2. The complete justfile

Drop this in at the repo root as `justfile`. Adjust only where a command below is proven wrong by a
real run.

```just
# graph2otel — the task surface for this repo.
#
# `just check` is the full gate. It is exactly the union of ci.yml's build-test,
# lint, govulncheck, helm and grafana jobs. The two remaining ci-success legs
# (goreleaser-snapshot, docker-build) need a docker daemon and a 12 GB swapfile
# and live in `just ci`.
#
# Tool versions are pinned here and installed repo-locally into .tools/
# (gitignored) by `just setup`. There is no second copy of a version anywhere
# except scripts/cloud-environment-setup.sh, which provisions cloud agent
# sandboxes and is deliberately independent.

set shell := ["bash", "-euo", "pipefail", "-c"]

binary := "graph2otel"
version := env('VERSION', `git describe --tags --always --dirty 2>/dev/null || echo dev`)
ldflags := "-s -w -X github.com/rknightion/graph2otel/internal/version.Version=" + version

# Force module mode (no vendor/ in this repo) so local runs match CI exactly.
export GOFLAGS := env('GOFLAGS', '-mod=readonly')

tools := justfile_directory() / ".tools"

# renovate: datasource=github-releases depName=golangci/golangci-lint
golangci_lint_version := "v2.13.2"

# renovate: datasource=go depName=golang.org/x/vuln
govulncheck_version := "v1.3.0"

# go-licenses v1.x. A bump to v2+ needs the `/v2` module suffix in the install
# path below AND a re-check of the `report --template` CLI, so keep this on v1
# unless that path is updated too.
# renovate: datasource=go depName=github.com/google/go-licenses
go_licenses_version := "v1.6.0"

# renovate: datasource=go depName=github.com/anchore/syft
syft_version := "v1.48.0"

# renovate: datasource=go depName=github.com/norwoodj/helm-docs
helm_docs_version := "v1.14.2"

# show the task surface
default:
    @just --list

# install the pinned gate toolchain into .tools/ and warm the module cache
setup: _tools
    go mod download

# format Go sources and this justfile in place
[group('check')]
fmt: _tools
    {{ tools }}/golangci-lint fmt
    just --fmt

# verify formatting; never mutates
[group('check')]
[no-exit-message]
fmt-check:
    just --fmt --check

# vet + golangci-lint the root module (gofmt/goimports ride the formatters block)
[group('check')]
[no-exit-message]
lint: _tools
    go vet ./...
    {{ tools }}/golangci-lint run

# run the root module test suite with the race detector
[group('check')]
[no-exit-message]
test filter=".":
    go test -race -run '{{ filter }}' ./...

# scan the module graph for known vulnerabilities
[group('check')]
[no-exit-message]
audit: _tools
    {{ tools }}/govulncheck ./...

# fail if any of the four modules has a stale go.mod; never writes
[group('check')]
[no-exit-message]
tidy-check:
    go mod tidy -diff
    go -C tools/graphdrift mod tidy -diff
    go -C third_party/otlpmetrichttp mod tidy -diff
    go -C third_party/otlploghttp mod tidy -diff

# rewrite go.mod/go.sum across every module
[group('dev')]
tidy:
    go mod tidy
    go -C tools/graphdrift mod tidy
    bash third_party/check-otel-http-forks.sh tidy

# vet + test tools/graphdrift, which the root ./... pattern cannot see
[group('check')]
[no-exit-message]
tools-check:
    go vet -C tools/graphdrift ./...
    go test -C tools/graphdrift ./...

# prove both third_party OTLP/HTTP forks match upstream and pass their own gates
[group('check')]
[no-exit-message]
forks-check:
    bash third_party/check-otel-http-forks.sh check

# verify dashboards, alert rules and generated Grafana docs; writes nothing
[group('check')]
[no-exit-message]
[working-directory('grafana')]
grafana-check:
    python3 build_dashboard.py --check
    python3 build_rules.py --check
    python3 -m unittest discover -s tests -t . -q

# fail if charts/graph2otel/README.md has drifted from values.yaml
[group('check')]
[no-exit-message]
helm-docs-check: helm-docs
    git diff --exit-code charts/graph2otel/README.md

# lint and render the Helm chart, including its non-default branches
[group('check')]
[no-exit-message]
helm-check:
    go test ./charts/graph2otel -count=1
    helm lint charts/graph2otel
    helm template t charts/graph2otel > /dev/null
    helm template t charts/graph2otel --set persistence.enabled=true --set existingSecret=my-secret --set config.admin.enabled=false > /dev/null

# fail if any committed generated artifact has drifted from its source
[group('check')]
gen-check: grafana-check helm-docs-check

# write a coverage profile for the Codacy upload (non-gating)
[group('check')]
coverage:
    go test -covermode=atomic -coverprofile=coverage.out ./...

# THE GATE — everything a PR must pass, and exactly what ci.yml enforces
[group('check')]
check: fmt-check lint tidy-check tools-check forks-check test audit gen-check helm-check build

# check plus the docker legs; the goreleaser snapshot leg is action-driven and excluded
[group('check')]
ci: check smoke

# compile every package and stamp bin/graph2otel
[group('build')]
build:
    go build ./...
    go build -trimpath -ldflags '{{ ldflags }}' -o 'bin/{{ binary }}' ./cmd/{{ binary }}

# build the container image locally
[group('build')]
image tag="graph2otel:dev":
    docker build --build-arg 'VERSION={{ version }}' -t '{{ tag }}' .

# exercise the documented standalone-container layout (nonroot, read-only rootfs, named volume)
[group('build')]
smoke image="graph2otel:container-smoke" skip_build="0":
    IMAGE='{{ image }}' SKIP_BUILD='{{ skip_build }}' ./scripts/container-smoke-test.sh

# regenerate every committed generated artifact; idempotent
[group('gen')]
gen: regen dashboard rules helm-docs

# regenerate the Go-golden artifacts (env-vars, collectors, signals, signal catalog)
[group('gen')]
regen target="all":
    ./scripts/regen-generated.sh '{{ target }}'

# regenerate dashboards/graph2otel.json from grafana/boards/*.py
[group('gen')]
[working-directory('grafana')]
dashboard:
    python3 build_dashboard.py

# regenerate alerts/rules/*.yaml and docs/hunting.md from grafana/build_rules.py
[group('gen')]
[working-directory('grafana')]
rules:
    python3 build_rules.py

# regenerate charts/graph2otel/README.md from values.yaml annotations
[group('gen')]
helm-docs: _tools-helm-docs
    {{ tools }}/helm-docs --chart-search-root charts

# diff the live Microsoft Graph beta surface against spec/graph-beta-snapshot.json (network)
[group('gen')]
[no-exit-message]
graphdrift: _tool-graphdrift
    {{ tools }}/graphdrift -manifest spec/graph-beta-surface.json -snapshot spec/graph-beta-snapshot.json

# refresh spec/graph-beta-snapshot.json from the live beta surface (network, writes)
[group('gen')]
graphdrift-update: _tool-graphdrift
    {{ tools }}/graphdrift -manifest spec/graph-beta-surface.json -snapshot spec/graph-beta-snapshot.json -update

# generate THIRD_PARTY_NOTICES.md for the shipped binary (a release artifact, gitignored)
[group('release')]
notices: _tools-licensing
    GO_LICENSES={{ tools }}/go-licenses bash scripts/notices.sh

# generate SPDX + CycloneDX SBOMs of the shipped binary into dist/sbom/
[group('release')]
sbom target="bin/graph2otel" name="graph2otel" out="dist/sbom": _tools-sbom
    CGO_ENABLED=0 go build -trimpath -ldflags '{{ ldflags }}' -o 'bin/{{ binary }}' ./cmd/{{ binary }}
    mkdir -p '{{ out }}'
    {{ tools }}/syft '{{ target }}' -q -o 'spdx-json={{ out }}/{{ name }}.spdx.json' -o 'cyclonedx-json={{ out }}/{{ name }}.cdx.json'
    @echo "sbom: wrote {{ out }}/{{ name }}.spdx.json + {{ out }}/{{ name }}.cdx.json"

# deploy the generated alert rules to a Grafana stack (create-or-update, WRITES)
[confirm('This writes alert rules to a live Grafana stack. Continue?')]
[group('infra')]
rules-push context folder="graph2otel" include_detections="0":
    @python3 grafana/rules_deploy.py --context '{{ context }}' --folder-title '{{ folder }}' {{ if include_detections == "1" { "--include-detections" } else { "" } }}

# prove a Grafana stack still matches the repository's rules; read-only
[group('infra')]
[no-exit-message]
rules-readback context include_detections="0":
    @python3 grafana/rules_deploy.py --context '{{ context }}' --readback-only {{ if include_detections == "1" { "--include-detections" } else { "" } }}

# run the read-only Grafana semantic canary against a live stack (JSON receipt on stdout)
[group('infra')]
[no-exit-message]
grafana-canary context prometheus="grafanacloud-prom" loki="grafanacloud-logs":
    @python3 grafana/semantic_canary.py --context '{{ context }}' --prometheus-datasource '{{ prometheus }}' --loki-datasource '{{ loki }}'

# static, policy-free dashboard performance baseline (offline, JSON on stdout)
[group('infra')]
[no-exit-message]
grafana-performance-baseline:
    @python3 grafana/performance_baseline.py

# read-only live render measurement against a Grafana stack (JSON receipt on stdout)
[group('infra')]
[no-exit-message]
grafana-performance-render context budget="":
    @python3 grafana/performance_baseline.py --live-context '{{ context }}' --since 6h --width 1920 --height 1080 --theme dark --timezone UTC --repeat 1 --var datasource=grafanacloud-prom --var loki_datasource=grafanacloud-logs --var 'tenant=$__all' {{ if budget == "" { "" } else { "--budget-seconds " + budget } }}

# install the fast pre-commit gate into .git/hooks (runs `just lint`)
[group('dev')]
install-hooks:
    cp scripts/hooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    @echo "pre-commit hook installed"

# remove the repo-local toolchain and build output that setup + build reproduce
[group('dev')]
clean:
    rm -rf '{{ tools }}' bin dist/sbom coverage.out

[private]
_tools:
    @mkdir -p '{{ tools }}'
    @{ test -x '{{ tools }}/golangci-lint' && '{{ tools }}/golangci-lint' version >/dev/null 2>&1; } || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/{{ golangci_lint_version }}/install.sh | sh -s -- -b '{{ tools }}' {{ golangci_lint_version }}
    @{ test -x '{{ tools }}/govulncheck' && '{{ tools }}/govulncheck' -version >/dev/null 2>&1; } || GOBIN='{{ tools }}' go install golang.org/x/vuln/cmd/govulncheck@{{ govulncheck_version }}

[private]
_tools-licensing:
    @mkdir -p '{{ tools }}'
    @{ test -x '{{ tools }}/go-licenses' && '{{ tools }}/go-licenses' --help >/dev/null 2>&1; } || GOBIN='{{ tools }}' go install github.com/google/go-licenses@{{ go_licenses_version }}

[private]
_tools-sbom:
    @mkdir -p '{{ tools }}'
    @{ test -x '{{ tools }}/syft' && '{{ tools }}/syft' version >/dev/null 2>&1; } || GOBIN='{{ tools }}' go install github.com/anchore/syft/cmd/syft@{{ syft_version }}

[private]
_tools-helm-docs:
    @mkdir -p '{{ tools }}'
    @{ test -x '{{ tools }}/helm-docs' && '{{ tools }}/helm-docs' --help >/dev/null 2>&1; } || GOBIN='{{ tools }}' go install github.com/norwoodj/helm-docs/cmd/helm-docs@{{ helm_docs_version }}

# Built, not `go run`: live-measured on go1.26.5, `go run` collapses ANY non-zero
# exit to 1, which erases the difference between the drift signal (3) and a tool
# failure (2). CI builds it for the same reason.
[private]
_tool-graphdrift:
    @mkdir -p '{{ tools }}'
    go build -C tools/graphdrift -o '{{ tools }}/graphdrift' .
```

After writing it, run `just --fmt` once and commit the formatter's own output, then confirm
`just --fmt --check` and `just --dump --dump-format json > /dev/null` both exit 0.

## 3. Makefile disposition

`Makefile` is 233 lines with 40 `.PHONY` targets. Every one maps below.

| Make target (`Makefile:` line) | Replacement | Notes |
|---|---|---|
| `build` (32) | `just build` | Recipe also runs `go build ./...` first, absorbing `check`'s trailing `$(GO) build ./...` (line 66). |
| `test` (35) | `just test` | Gains a `filter="."` param → `-run`. |
| `vet` (38) | folded into `just lint` | `vet` is not in the frozen vocabulary. `lint` runs `go vet ./...` then `golangci-lint run`, preserving today's `make vet lint` pre-commit pair as one recipe. |
| `lint` (41) | `just lint` | Version pin moves to `golangci_lint_version` and rises to `v2.13.2` to match CI. |
| `fmt` (44) | `just fmt` | Also runs `just --fmt`. |
| `govulncheck` (47) | `just audit` | Renamed to the standard's optional vocabulary. Pin moves from `@latest` to `v1.3.0`. |
| `docker` (50) | `just image` | `tag="graph2otel:dev"` default. |
| `container-smoke` (57) | `just smoke` | Params `image` + `skip_build` replace `CONTAINER_SMOKE_IMAGE` / `SKIP_BUILD`. |
| `check` (65) | `just check` | Dependency list, not a shell pipeline. Gains `fmt-check`, `helm-check` and `helm-docs-check`, which CI ran but `make check` did not. |
| `tidy-check` (77) | `just tidy-check` | Four modules, unchanged commands. |
| `tidy` (84) | `just tidy` | Unchanged. |
| `forks-check` (92) | `just forks-check` | Wraps the KEPT `third_party/check-otel-http-forks.sh`. |
| `tools-check` (99) | `just tools-check` | Unchanged. |
| `tools-graphdrift` (111) | `just _tool-graphdrift` (private) | Hidden from `--list`; a dependency of `graphdrift` / `graphdrift-update`. |
| `graphdrift` (115) | `just graphdrift` | Unchanged flags. |
| `graphdrift-update` (118) | `just graphdrift-update` | Unchanged flags. |
| `regen` (125) | `just regen` | Wraps the KEPT `scripts/regen-generated.sh`, adds a `target="all"` param so `just regen envref` works. |
| `dashboard` (136) | `just dashboard` | `cd grafana` becomes `[working-directory('grafana')]`. |
| `rules` (144) | `just rules` | Same. |
| `grafana-check` (172) | `just grafana-check` | Same; three lines, each its own shell — safe, they share no state. |
| `grafana-canary-check` (179) | **dropped** | It is a strict subset of `grafana-check`'s `unittest discover` run. If a narrow lane is wanted, use `just grafana-check` or run the module directly; do not add a recipe per test module. |
| `grafana-canary` (186) | `just grafana-canary <context>` | The three `@test -n` guards become required/defaulted just params, which fail with a better message. |
| `grafana-rules-check` (200) | **dropped** | Same reason as `grafana-canary-check`. |
| `rules-push` (215) | `just rules-push <context>` | Gains `[confirm]`; see §5 for the CI `--yes`. |
| `rules-readback` (223) | `just rules-readback <context>` | Read-only, no confirm. |
| `grafana-performance-check` (227) | **dropped** | Subset of `grafana-check`. |
| `grafana-performance-baseline` (232) | `just grafana-performance-baseline` | Unchanged. |
| `grafana-performance-render` (250) | `just grafana-performance-render <context> [budget]` | `$$__all` becomes `$__all` (no make escaping). |
| `tools` (263) | `just _tools` (private) | Same idempotent install-if-missing shape. |
| `coverage` (271) | `just coverage` | Unchanged. |
| `tools-licensing` (275) | `just _tools-licensing` (private) | — |
| `tools-sbom` (279) | `just _tools-sbom` (private) | — |
| `notices` (286) | `just notices` | Wraps the KEPT `scripts/notices.sh`. |
| `sbom` (290) | `just sbom` | Script ABSORBED; see §4. |
| `install-hooks` (295) | `just install-hooks` | The copied hook body changes to `just lint`. |
| `tools-helm-docs` (300) | `just _tools-helm-docs` (private) | — |
| `helm-docs` (307) | `just helm-docs` | — |
| `GO`, `GOFLAGS`, `BINARY`, `VERSION`, `LDFLAGS`, `TOOLS_DIR`, `PATH` export (1-21) | justfile variables | `GO` is dropped (nothing overrides it). The `export PATH := $(TOOLS_DIR):$(PATH)` line is dropped: every tool is invoked by absolute `{{ tools }}/…` path already, and `scripts/notices.sh` / `scripts/sbom.sh` receive their binary via `GO_LICENSES=` / `SYFT=`, so nothing depended on it. |
| `.PHONY` (23-29) | delete | Meaningless in just. |

**Finally: `git rm Makefile`.** There is exactly one Makefile in this repo (no `GNUmakefile`, no
subdirectory Makefiles) — confirmed against `git ls-files`.

## 4. Script disposition

Every tracked `.sh`/`.py` used as a dev or CI task. `grafana/*.py` (13 modules, 8,993 lines total)
are the dashboard/rule/canary *programs*, not tasks — they are library code invoked by the recipes
above and are not listed individually.

| Script | Verdict | Recipe | Rationale / exact replacement |
|---|---|---|---|
| `scripts/sbom.sh` (44 lines) | **ABSORB — delete** | `just sbom` | Thin wrapper: four env defaults, one `command -v` guard, `mkdir -p`, one `syft` call. Exact recipe lines are in §2's `sbom` recipe: the `CGO_ENABLED=0 go build` line comes from `Makefile:291-292`, the `mkdir -p` and two-format `syft` invocation from the script. The `command -v` guard is replaced by `_tools-sbom`, which installs syft rather than telling you to. Nothing else in the repo references `sbom.sh` (`Dockerfile`, workflows and docs are all clean). |
| `scripts/notices.sh` (109 lines) | **KEEP** | `just notices` | Executed directly by `Dockerfile:29` inside the image build, where there is no `just`; also a real program (mktemp/trap, an awk-driven fork-remap loop over `third_party/otel-http-forks.tsv`, a per-module NOTICE walk). |
| `scripts/regen-generated.sh` (159 lines) | **KEEP** | `just regen [target]` | A real program: functions, `case`-based target parsing, an `rg`-driven package discovery loop, ordering constraints between four generators, and loud-SKIP semantics. It is also referenced by name from Go source that must keep resolving: `internal/collectordoc/collectordoc.go:63` (the literal generated-block marker in `docs/collectors.md`), `internal/collectordoc/signals.go:114`, `internal/config/envref_test.go:148`, `cmd/graph2otel/collectordoc_test.go:225`, `internal/signalcatalog/signalcatalog_test.go:234`, `grafana/catalog.py:92`. **Critically, `cmd/graph2otel/documentation_contract_test.go:213` reads the script's own text** and asserts three phrases are absent from it — deleting or moving the file fails that test. |
| `scripts/container-smoke-test.sh` (108 lines) | **KEEP** | `just smoke` | Non-trivial control flow: `trap`-based cleanup of two containers and a volume, a `wait_for_stable_startup` function with a retry loop, a deliberate negative-path assertion, a heredoc config fixture, and a restart-persistence check. |
| `scripts/hooks/pre-commit` (7 lines) | **KEEP** | `just install-hooks` | A shipped git hook: it executes from `.git/hooks/`, not from the repo tree. **Edit its body**: `make vet lint` → `just lint`, and update the comment that reads "without the full `make check`" → "`just check`" and "Install via `make install-hooks`" → "`just install-hooks`". |
| `third_party/check-otel-http-forks.sh` (89 lines) | **KEEP** | `just forks-check` / `just tidy` | Real program with `check`/`tidy` argument dispatch, an environment-scrubbing loop over `env`, a TSV-driven per-module loop, `mktemp -d` + trap, and upstream-vs-local `diff -qr`. Its manifest is also consumed by `scripts/notices.sh`. |
| `scripts/cloud-environment-setup.sh` (154 lines) | **KEEP, untouched** | none | Runs in Codex/Claude cloud provisioning where the repo may not even be checked out yet; the file header says "LOCAL AGENTS: DO NOT RUN THIS SCRIPT". `scripts/cloud_environment_setup_test.go` asserts seven exact substrings of it, including `GO_VERSION="1.27.0"` and three pinned tool versions. **Do not add a recipe for it and do not edit it** (see §10). |
| `scripts/grafana-prune-rules.py` (156 lines) | **KEEP** | none needed | A real program invoked once, by `.github/workflows/grafana-sync.yml:188`, with a run-generated `--keep-file`. It is not a developer task and gets no recipe; leave the workflow's `python3 scripts/grafana-prune-rules.py …` invocation exactly as it is. |
| `scripts/storage-report.py` (838 lines) | **KEEP, untouched** | none | An analysis program with its own test suite (`scripts/storage_report_test.py`), referenced from `docs/blob-ingest.md:92`. Not a task. |
| `scripts/seed-diagnostic-data.py` (408 lines) | **KEEP, untouched** | none | A live-tenant diagnostic seeding program. Not a task, and deliberately not one command away. |
| `scripts/storage_report_test.py` (218 lines) | **KEEP, untouched** | none | Test file for the above. |
| `scripts/notices.tsv.tmpl` | **KEEP, untouched** | — | A `go-licenses --template` data file read by `notices.sh`. |

## 5. CI changes

### 5.0 The setup-just step

Insert this verbatim wherever a job needs `just`. It goes **after** `actions/checkout` and after any
`actions/setup-go`, and **before** the first `run: just …` in that job.

```yaml
      - uses: extractions/setup-just@53165ef7e734c5c07cb06b3c8e7b647c5aa16db3 # v4.0.0
        with:
          just-version: '1.58.0'
```

Pin `just-version` exactly: `just --fmt` output is explicitly outside any backwards-compatibility
guarantee, so an unpinned bump can turn `fmt-check` red with no repo change. Keep the trailing
`# v4.0.0` comment — `.zizmor.yml`-equivalent policy in this fleet is `hash-pin` for all `uses:`, and
`zizmor.yml` runs on this repo.

### 5.1 `.github/workflows/ci.yml`

| Job | Step (line) | Change |
|---|---|---|
| `build-test` | `go.mod tidy check` → `run: make tidy-check` (33-34) | → `run: just tidy-check`. Add setup-just after the `setup-go` block (line 24-27). |
| `build-test` | `go vet` → `run: go vet ./...` (36-37) | **Leave unchanged.** Already a one-line bare command; pointing it at `just lint` would run golangci-lint a second time in a second job. `lint` covers vet locally, so `check` stays complete. |
| `build-test` | `go build` → `run: go build ./...` (39-40) | **Leave unchanged.** `just build` also stamps `bin/graph2otel`, which this job does not want. |
| `build-test` | `go test -race` (42-43) | → `run: just test`. |
| `build-test` | `vet + test the tools modules` → `run: make tools-check` (48-49) | → `run: just tools-check`. |
| `lint` | `golangci-lint` → `uses: golangci/golangci-lint-action@…` (66-69) | Replace the whole step with two steps: `- run: just setup` then `- name: golangci-lint` / `run: just lint`. Add setup-just first. This is the one place a `uses:` is removed — it is **not** a reusable workflow and not a `rknightion/.github` call; it exists only to install and run a tool whose version now lives in the justfile. Removing it kills the v2.13.1/v2.13.2 split. Keep `actions/setup-go` with `cache: true` (lines 59-62). |
| `govulncheck` | `install govulncheck (pinned)` (84-85) | Replace with `- run: just setup` (which installs the pinned govulncheck into `.tools/`). |
| `govulncheck` | `govulncheck` → `run: govulncheck ./...` (87-88) | → `run: just audit`. Add setup-just. |
| `goreleaser-snapshot` | all steps (90-138) | **No change at all.** The swap step is runner provisioning; the build is `uses: goreleaser/goreleaser-action` and §8 forbids converting a `uses:` into `run: just`. |
| `docker-build` | `smoke standalone container layout` → `run: make CONTAINER_SMOKE_IMAGE=graph2otel:ci SKIP_BUILD=1 container-smoke` (182-183) | → `run: just smoke graph2otel:ci 1`. Add setup-just after the checkout (line 144-146). Leave the cache, buildkit-cache-dance and `docker/build-push-action` steps untouched. |
| `helm` | `test rendered Helm contracts` (200-201), `helm lint` (203-204), `helm template` (213-214), `helm template (persistence …)` (219-224) | Replace **all four** with one step: `- name: helm lint + template + contracts` / `run: just helm-check`. |
| `helm` | `helm-docs README up to date` (208-211) | → `run: just helm-docs-check`. Add setup-just; keep `azure/setup-helm` and `actions/setup-go` verbatim. |
| `grafana` | `Verify dashboards, alert rules and generated docs` → `run: make grafana-check` (244-245) | → `run: just grafana-check`. Add setup-just after the checkout. |
| `coverage` | `Generate coverage profile` → `run: make coverage` (265-266) | → `run: just coverage`. Add setup-just. Leave the Codacy `uses:` step and its `if:` guard alone. |
| `ci-success` | (248-...) | **Do not touch.** Neither the job id, the `name: ci-success`, the `if: always()`, nor `needs: [build-test, lint, govulncheck, goreleaser-snapshot, docker-build, helm, grafana]`. The branch ruleset on `main` gates on that exact check name, and `coverage` is deliberately absent from `needs`. |

Also unchanged in this file: `permissions: contents: read` (line 8-9), the
`concurrency: group: ci-${{ github.ref }}` block (11-13), every `persist-credentials: false`, and
every action SHA pin.

### 5.2 `.github/workflows/grafana-canary.yml`

- Add setup-just after the `Verify gcx` step (line 67-68) and before `Run semantic canary`.
- Line 88-98, inside `run: |`, replace the `make grafana-canary \ GRAFANA_CONTEXT=… \
  GRAFANA_PROMETHEUS_DATASOURCE=… \ GRAFANA_LOKI_DATASOURCE=… > canary-receipt.json 2> …` invocation
  with:

  ```bash
            just grafana-canary "$GCX_CONTEXT" grafanacloud-prom grafanacloud-logs \
              > canary-receipt.json 2> canary-stderr.log
  ```

  Keep the surrounding `set +e` / `code=$?` / `echo "exit_code=…" >> "$GITHUB_OUTPUT"` / `exit 0`
  scaffolding exactly as-is: the three-way exit-code contract (0/1/2) and the receipt-before-outcome
  ordering are the point of this workflow.
- Do not touch the gcx install/checksum step, the `gcx login` step, the artifact upload, the
  `Evaluate canary outcome` case statement, `permissions:`, the `concurrency: grafana-semantic-canary`
  group, or the `GCX_SHA256` pin.
- Update the header comment on line 4 (`via \`make grafana-canary\``) → `via \`just grafana-canary\``.

### 5.3 `.github/workflows/grafana-render-baseline.yml`

- Add setup-just after `Verify gcx` (line 120-121).
- Line 145-152, replace `make grafana-performance-render \ GRAFANA_CONTEXT="$GCX_CONTEXT" \
  GRAFANA_PERFORMANCE_BUDGET_SECONDS=30 \ > render-baseline-receipt.json 2> …` with:

  ```bash
            just grafana-performance-render "$GCX_CONTEXT" 30 \
              > render-baseline-receipt.json 2> render-baseline-stderr.log
  ```

- The `30` positional arg is the budget. **Do not change it and do not delete the 40-line header
  comment explaining that it is a breakage tripwire, not a tuned threshold.** Keep the `set +e`
  scaffolding, the 90-day `retention-days`, the outcome `case`, and the `GCX_SHA256` pin.
- Update the header comment on line 4 (`via \`make grafana-performance-render\``).

### 5.4 `.github/workflows/grafana-sync.yml`

- The `dashboards` job (lines 51-108) contains **no** `make` and needs **no** setup-just. Do not
  touch the `broker-token` composite action call, the second checkout with the minted token, or the
  rebase-retry push loop.
- In the `rules` job, add setup-just after the `install gcx` step (line 121-135).
- Line 193-194: `run: make rules-push GRAFANA_CONTEXT=m7kni` → `run: just --yes rules-push m7kni`.
  The `--yes` is required because §2's `rules-push` carries `[confirm]` (it writes to a live Grafana
  stack) and `[confirm]` fails closed with no TTY. This is a deliberate, human-authored bypass in a
  workflow file, not an agent bypassing the rail — see §9.
- Line 198-199: `run: make rules-readback GRAFANA_CONTEXT=m7kni` → `run: just rules-readback m7kni`.
  Read-only, no confirm, no `--yes`.
- Do not touch: the `write the gcx context` heredoc, the `resolve the alerts folder UID` step and its
  `{"class"` banner filter, the `list the rules this repository deploys` inline Python heredoc, the
  `python3 scripts/grafana-prune-rules.py` step, the `remove the credential file` `if: always()`
  step, `concurrency: grafana-sync`, or the `paths:` trigger filter (which already covers
  `grafana/**` and `scripts/grafana-prune-rules.py`; **add `justfile` to that `paths:` list** so a
  recipe change re-runs the sync).
- Update the header comment on line 10 (`\`make rules-push\``) and line 173.

### 5.5 `.github/workflows/publish.yml`

- In the `notices` job, add setup-just after the `Set up Go` step (line 64-68).
- Line 69-70: `run: make notices` → `run: just notices`.
- Do not touch the `image` job (`uses: rknightion/.github/.github/workflows/container-publish.yml@…`),
  the `harden-runner` step, the `ref: ${{ inputs.release_tag }}` checkout, the `workflow_call`
  inputs, or any `permissions:` block.
- Update the header comment on line 47.

### 5.6 Workflows that must not change at all

`actionlint.yml`, `arm-automerge.yml`, `auto-rc.yml`, `codeql.yml`, `dependency-review.yml`,
`docker-security.yml`, `ghcr-cleanup.yml`, `graph-beta-drift.yml`, `notify-new-issue.yml`,
`release-please.yml`, `scorecard.yml`, `trigger-docs-sync.yml`, `zizmor.yml`. None of them invokes
`make`. `graph-beta-drift.yml` in particular builds `tools/graphdrift` inline with
`go build -C tools/graphdrift -o "${RUNNER_TEMP}/graphdrift" .` for a documented reason (exit-code
fidelity) and writes to `RUNNER_TEMP`, not `.tools/` — leave it. `release-please.yml`'s `binaries`
job `pre-cmd` installs syft and go-licenses on the runner; it is a string passed to a reusable
workflow, not a shell step in this repo — leave it.

## 6. Docs and agent-contract changes

### 6.1 `AGENTS.md`

Replace the `## Commands` fenced block (lines 27-35) and the paragraph at lines 37-39 with the §9
Task-interface section. **Do not paste the recipe list.** Exact replacement:

```markdown
## Task interface

This repo's task surface is a `justfile`. Discover it, don't guess it:

    just --list                        # human-readable
    just --dump --dump-format json     # machine-readable
    just --show <recipe>               # what a recipe actually runs

- `just check` is the full gate and is exactly what `.github/workflows/ci.yml` enforces. It must
  pass before you commit. It covers the root module, `tools/graphdrift`, and the two modules under
  `third_party/`, plus the generated-asset drift gates.
- `just ci` adds the docker legs (image build + container smoke) that need a local docker daemon.
- Prefer `just <recipe>` over the underlying tool. If you are typing `go test`, you want `just test`.
- Run `just` with stdin from /dev/null. Recipes marked `[confirm]` are destructive — stop and ask
  before running one; never pass `--yes` or `JUST_YES=1`.
- If a task you need does not exist, add a recipe with a `#` doc comment and a `[group(...)]`
  rather than running a bare command.
```

Also `AGENTS.md:248` — in the "Adding/changing a **beta** endpoint" table row, `make graphdrift-update`
→ `just graphdrift-update`.

### 6.2 `CLAUDE.md`

No change. It is a 6-line pointer at `AGENTS.md` with an `@AGENTS.md` import and names no target.

### 6.3 `CONTRIBUTING.md`

| Line | Current | New |
|---|---|---|
| 22 | `make check    # vet + test + lint + govulncheck + build` | `just check   # fmt + lint + tests + vuln scan + generated-asset drift + build` |
| 28 | `make build          # -> bin/graph2otel (version stamped via git describe)` | `just build         # …` |
| 29 | `make test           # go test -race ./...` | `just test          # go test -race ./...` |
| 30 | `make lint           # golangci-lint run` | `just lint          # go vet + golangci-lint run` |
| 31 | `make fmt            # golangci-lint fmt (gofmt + goimports)` | `just fmt           # golangci-lint fmt (gofmt + goimports) + just --fmt` |
| 32 | `make docker         # build the container image locally` | `just image         # build the container image locally` |
| 33 | `make dashboard      # regenerate dashboards/graph2otel.json …` | `just dashboard     # …` |
| 34 | `make grafana-check  # dashboard metric coverage …` | `just grafana-check # …` |
| 38 | ``or `make grafana-check` fails`` | ``or `just grafana-check` fails`` |
| 48 | ``3. Keep `make check` green.`` | ``3. Keep `just check` green.`` |

Add a line under "Dev setup" naming the bootstrap: `just setup` installs the pinned toolchain into
`.tools/`. Also replace the `make check` fence's language hint if it says `bash` — leave it.

### 6.4 `grafana/AUTHORING.md`

Lines 3-4: ``\`make grafana-check\` fails on a hand-edited file. Edit \`grafana/boards/*.py\` and run
\`make dashboard\`.`` → `just grafana-check` / `just dashboard`.

### 6.5 `docs/api-drift.md`

Lines 111 (`that offline in \`make check\``), 129 (`make graphdrift`), 132 (`make graphdrift-update`),
147 (`The make targets and the workflow both build first.` → `The just recipes and the workflow both
build first.`).

### 6.6 `docs/deploying-observability.md`

Sixteen occurrences: lines 80, 82, 116, 127, 130, 133, 273, 279, 323, 324, 333, 362, 363, 381, 456,
458. Mapping:

- `make grafana-check` → `just grafana-check` (80, 273, 323, 362, 456)
- `make dashboard` → `just dashboard` (82)
- `make rules` → `just rules` (116)
- `make rules-push GRAFANA_CONTEXT=<gcx-context>` → `just rules-push <gcx-context>` (127)
- `make rules-push GRAFANA_CONTEXT=<ctx> INCLUDE_DETECTIONS=1` → `just rules-push <ctx> graph2otel 1` (130)
- `make rules-readback GRAFANA_CONTEXT=<gcx-context>` → `just rules-readback <gcx-context>` (133)
- `make grafana-canary \ …` → `just grafana-canary <gcx-context>` (279 and its continuation lines)
- `make grafana-canary-check` (324) → `just grafana-check` — that narrow target is dropped; say so.
- `make grafana-performance-baseline > baseline.json` → `just grafana-performance-baseline > baseline.json` (333)
- `make grafana-performance-check` (363, 458) → `just grafana-check` — dropped, same note.
- `make grafana-performance-render GRAFANA_CONTEXT=<gcx-context>` → `just grafana-performance-render <gcx-context>` (381)

Leave lines 220 and 456's surrounding prose alone where "make" is an English verb.

### 6.7 `docs/runbooks.md:25`

``\`make grafana-check\` rather than shipping a dead link.`` → `just grafana-check`. This file is
hand-written but structurally validated by `grafana/build_rules.py` (it parses runbook sections and
UIDs) — a prose-only edit is safe, but re-run `just grafana-check` after.

### 6.8 `docs/hunting.md` is GENERATED — edit the generator

`docs/hunting.md:2` reads ``Edit the hunt there, then run `make rules`.`` That text is emitted from
**`grafana/build_rules.py:1400`**. Edit the Python string to `just rules`, then run `just rules` to
regenerate `docs/hunting.md`, and commit both. Editing `docs/hunting.md` directly will be reverted
and will fail `build_rules.py --check`.

Also in `grafana/build_rules.py`: line 7 (`Run from grafana/ (\`\`make rules\`\` / \`\`make
grafana-check\`\` do)` — these are `[working-directory('grafana')]` now), line 9 (`see Makefile and
ci.yml` → `see the justfile and ci.yml`), line 1662 (`then run \`make rules\``), line 1665 (`with
\`make rules-push\``), line 1953 (`re-run \`make rules\``), line 2551 (the stderr message
``run \`make rules\``` → ``run \`just rules\```). Line 1400 and line 1662's text may both land in
generated output — regenerate and check `git status` is clean afterwards.

`grafana/build_dashboard.py:7` — same `Run from grafana/` docstring note.

`grafana/tests/test_build_dashboard.py:8`, `grafana/tests/test_build_rules.py:9` and `:311`,
`grafana/tests/test_rules_navigation.py:5`, `grafana/tests/test_rules_deploy.py:451`: comment/message
text naming `make grafana-check` / `make rules` / `make rules-push`. `test_build_rules.py:881` is a
test failure message (``f"{fname} is stale — run \`make rules\`"``) — update the string; nothing
asserts on it.

### 6.9 Go source comments

`internal/config/envref_test.go:115` (`already part of \`make check\``),
`internal/collectordoc/betasurface_test.go:162` (`runs in \`make check\``),
`internal/collectordoc/collectordoc.go:8` (`Nothing in \`make check\` noticed`) → `just check`.
These are comments only; no test asserts on them. The many `scripts/regen-generated.sh` references
in Go source stay exactly as they are — that script is KEPT.

### 6.10 `README.md`

No `make` or script references. No change.

## 7. `backlog/config.yml`

Current `definition_of_done` names `make check` and `make regen`. Replace via the CLI
(`backlog config set` if available, otherwise the documented config edit path — **never hand-edit a
tracker file that the CLI owns**) with:

```yaml
definition_of_done:
  - "just check is green — fmt-check, lint, tidy-check, tools-check, forks-check, test, audit, gen-check, helm-check, build. Evidence, not assertion: paste or cite the run."
  - "just gen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, signal catalog, dashboards, alert rules, chart README, beta drift spec)."
  - "Committed green to main and pushed, with the resulting SHA recorded in this task."
```

Note the second line broadens `make regen` to `just gen`, which is the correct superset: `gen` runs
`regen` + `dashboard` + `rules` + `helm-docs`, so a contributor no longer has to remember three
separate regenerators.

## 8. Order of work

The repo is green at every numbered step.

1. **Write `justfile`** at the repo root with the §2 content. Add nothing else yet. Run
   `just --fmt`, then `just --fmt --check` (must exit 0) and `just --dump --dump-format json
   > /dev/null` (must exit 0 — proves no unstable feature is in the file).
2. **Prove every recipe locally, with the Makefile still present.** In order:
   `just setup`, `just fmt-check`, `just lint`, `just tidy-check`, `just tools-check`,
   `just forks-check`, `just test`, `just audit`, `just grafana-check`, `just helm-docs-check`,
   `just helm-check`, `just build`. Then `just check` end to end. Diff each recipe's behaviour
   against the equivalent `make` target where a result is surprising.
3. **Prove `gen` is idempotent.** `just gen` twice; `git status --porcelain` must be empty after the
   second run (it may be non-empty after the first only if the tree was already stale — in which
   case commit that regeneration separately, before this migration).
4. **Prove the docker legs** if a docker daemon is available: `just image`, `just smoke`. If not,
   say so explicitly rather than claiming green.
5. **Update `scripts/hooks/pre-commit`** to `just lint` and its comments. Run `just install-hooks`
   and make a throwaway commit to prove the hook fires.
6. **Switch CI** per §5 — all six workflow files in one commit. Push and watch `ci-success` go green
   on that commit. The Makefile is still present at this point, so a mistake is recoverable by
   reverting one file.
7. **Update docs and the agent contract** per §6, including the `grafana/build_rules.py` generator
   strings; run `just rules` and commit the regenerated `docs/hunting.md`; re-run `just grafana-check`.
8. **Update `backlog/config.yml`** per §7 through the `backlog` CLI.
9. **Deletions, last.** `git rm Makefile scripts/sbom.sh`. Before committing, prove nothing
   references them:
   ```bash
   git grep -nE '(^|[^a-z-])make [a-z][a-z-]+' -- ':!CHANGELOG.md' ':!archive'
   git grep -n 'sbom\.sh'
   git grep -n 'Makefile' -- ':!CHANGELOG.md' ':!archive'
   ```
   All three must return nothing outside `CHANGELOG.md` and `archive/`.
10. **Final gate**: `just check` green, `just --list` shows a doc comment and a group for every
    public recipe, `just --groups` prints only the six fleet groups plus the ungrouped
    `default`/`setup`.

## 9. Traps specific to this repo

1. **`scripts/regen-generated.sh` is read as data by a Go test.**
   `cmd/graph2otel/documentation_contract_test.go:213` passes `"../../scripts/regen-generated.sh"` to
   `readProjectDoc` and asserts three superseded phrases are absent. Deleting or renaming the script
   fails `just test`. It is a KEEP for that reason on top of being a real program.
2. **`Dockerfile:29` runs `bash scripts/notices.sh` inside the build stage.** There is no `just` in
   the builder image. Do not put `just` in the Dockerfile and do not absorb `notices.sh`.
3. **`docs/hunting.md` is generated.** Its `make rules` reference lives in
   `grafana/build_rules.py:1400`. Editing the markdown directly fails `build_rules.py --check`.
   Same class of trap for the generated block in `docs/collectors.md`
   (marker string in `internal/collectordoc/collectordoc.go:63`) and `docs/env-vars.md` — but those
   two name `scripts/regen-generated.sh`, which is unchanged, so they need no edit.
4. **`helm-docs-check` mutates a tracked file transiently.** It runs `helm-docs` (writing
   `charts/graph2otel/README.md`) then `git diff --exit-code`. On a clean tree the write is
   byte-identical, so `check` stays idempotent and re-runnable — but on a *dirty* tree it will leave
   the regenerated README behind. This is exactly what `ci.yml:208-211` does today; do not "fix" it
   by moving it out of `check`, because that would make `check` a subset of CI, which §1 forbids.
5. **`make check` never ran `fmt-check`, `helm-check` or `helm-docs-check`.** `just check` does.
   Expect the first `just check` to surface pre-existing helm-docs or formatting drift that the old
   local gate silently allowed. Fix the drift; do not weaken the gate.
6. **`[confirm]` + CI.** `rules-push` is genuinely destructive (it writes alert rules to a live
   Grafana stack), so it carries `[confirm]`, which fails closed with exit 1 when stdin is not a
   TTY. `.github/workflows/grafana-sync.yml:193` therefore uses `just --yes rules-push m7kni`. That
   `--yes` is authored into the workflow file by a human and is the only place in the repo it may
   appear. An agent must never add `--yes` or `JUST_YES=1` anywhere else.
7. **Recipes that must keep stdout clean.** `grafana-canary`, `rules-readback`,
   `grafana-performance-baseline` and `grafana-performance-render` print a JSON receipt on stdout
   that a workflow redirects to a file and later `cat`s. Keep the `@` prefix on those recipe lines
   (as §2 has them) so just's own command echo does not appear — and note that even without `@`,
   just echoes to **stderr**, so the receipt is safe either way; the `@` only keeps
   `canary-stderr.log` clean. Do not add `set quiet` to the file (§4 forbids it).
8. **Exit codes are load-bearing in three places.** `grafana/semantic_canary.py` (0/1/2),
   `grafana/performance_baseline.py` (0/1/2) and `tools/graphdrift` (0/2/3) all distinguish
   "assertion failed" from "the tool could not run". `just` is exit-code transparent, so wrapping
   them is safe — but `[no-exit-message]` is on those recipes so just's own
   `error: recipe X failed on line N` does not get mistaken for the tool's output.
9. **`go run` is banned for graphdrift.** `go run` collapses any non-zero exit to 1, erasing the
   difference between drift (3) and tool failure (2). `_tool-graphdrift` builds it, matching
   `Makefile:113` and `graph-beta-drift.yml`. Do not "simplify" it to `go run -C tools/graphdrift .`.
10. **`$$__all` → `$__all`.** `Makefile:259` writes `--var tenant='$$__all'` because make eats one
    `$`. In just, `$` is not a sigil; write `--var 'tenant=$__all'`. Getting this wrong sends the
    literal string `$$__all` to Grafana and the render silently measures nothing useful.
11. **`version` is evaluated once, at parse time.** `` version := env('VERSION', `git describe …`) ``
    runs `git describe` on every `just` invocation including `just --list`. That is fine (make's
    `?=` behaved comparably) but it means a tag created mid-session is not picked up until the next
    invocation. Do not try to make it lazy.
12. **Four Go modules, one repo.** `go mod tidy -diff`, `vet` and `test` with a bare `./...` see only
    the root module. `tools/graphdrift`, `third_party/otlpmetrichttp` and `third_party/otlploghttp`
    each need their own `-C`. `tidy-check`, `tools-check` and `forks-check` exist precisely for that
    and all three must stay in `check`.
13. **`helm` must be on PATH for `just check`.** `helm-check` and `helm-docs-check` are in the gate.
    `setup` does not install helm (it is a large third-party binary and
    `scripts/cloud-environment-setup.sh` already provisions it in cloud sandboxes). On a Mac,
    `brew install helm`. If `helm` is missing, `check` fails loudly — that is correct behaviour, not
    a bug to route around.
14. **`python3` only, no packages.** The entire `grafana/` toolchain is deliberately pure-stdlib
    (no PyYAML, no `setup-python` step in CI). Do not add a venv, a `uv sync`, or a
    `pip install` to `setup`.
15. **`cd grafana` cannot be a recipe line.** Each just recipe line runs in its own shell, so a bare
    `cd grafana` on line 1 does not reach line 2. `dashboard`, `rules` and `grafana-check` use
    `[working-directory('grafana')]`; `grafana-check` has three independent commands and works
    correctly with the attribute.
16. **The `.tools/` PATH export is gone.** `Makefile:21` did `export PATH := $(TOOLS_DIR):$(PATH)`.
    Every recipe in §2 invokes its tool by absolute `{{ tools }}/…` path instead. If a future recipe
    needs a `.tools/` binary, use the absolute path — do not re-add the PATH export, because it
    would silently shadow a system tool inside `scripts/*.sh` subprocesses.
17. **`just --fmt` sorts stacked attributes alphabetically.** `[confirm(…)]` must be written *above*
    `[group('infra')]` on `rules-push`, or `fmt-check` fails with a one-line diff. The §2 file above
    is already in canonical form — verified against `just 1.58.0` with
    `just --fmt --check` (exit 0), `just --dump --dump-format json` (exit 0, 37 public recipes, every
    one carrying a `doc`), and `just --groups` (exactly the six fleet groups).
18. **`.tools/` is gitignored** (`.gitignore:15`), as are `/bin/`, `/dist/`, `coverage.*` and
    `/THIRD_PARTY_NOTICES.md`. `clean` removes only those. Never add `git clean` to a recipe.

## 10. Out of scope

Do not touch any of the following as part of this task.

**KEEP scripts, unmodified except where §4/§6 names an exact line:**

- `scripts/cloud-environment-setup.sh` — cloud-agent provisioning; `scripts/cloud_environment_setup_test.go`
  asserts seven exact substrings including `GO_VERSION="1.27.0"`, `backlog.md@1.50.1`,
  `golangci-lint v2.13.1`, `govulncheck v1.3.0`, `helm-docs v1.14.2`. It stays on `v2.13.1` even
  though the justfile moves to `v2.13.2`; reconciling those two pins is separate work.
- `scripts/notices.sh`, `scripts/notices.tsv.tmpl` — executed by `Dockerfile:29`.
- `scripts/regen-generated.sh` — read by a Go contract test; named from six Go/Python source sites.
- `scripts/container-smoke-test.sh` — real program with traps and control flow.
- `third_party/check-otel-http-forks.sh`, `third_party/otel-http-forks.tsv` — drift-gated provenance.
- `scripts/grafana-prune-rules.py`, `scripts/storage-report.py`, `scripts/storage_report_test.py`,
  `scripts/seed-diagnostic-data.py` — real programs, not tasks.
- `scripts/hooks/pre-commit` — the file survives; only its two-line body and comments change.

**GitHub-native workflows — never fold into `just`:** `release-please.yml`, `auto-rc.yml`,
`arm-automerge.yml`, `publish.yml`'s `image` job (`container-publish` reusable), `codeql.yml`,
`zizmor.yml`, `actionlint.yml`, `scorecard.yml`, `dependency-review.yml`, `docker-security.yml`,
`ghcr-cleanup.yml`, `notify-new-issue.yml`, `trigger-docs-sync.yml`, `graph-beta-drift.yml`. Every
`uses: rknightion/.github/...` call, every `broker-token` composite-action call, and the
`goreleaser/goreleaser-action` step in `ci.yml` stay as `uses:`.

**Also untouched:** `ci-success`'s job name and `needs:` list; every `permissions:` block; every
`concurrency:` group; every `persist-credentials: false`; every action SHA pin and its `# vN`
comment; the `Increase swap space` steps and the `-p 2` goreleaser args in `ci.yml` and
`release-please.yml` (they exist to stop the msgraph-heavy linker OOM-killing a 7 GB runner);
`.goreleaser.yaml`; `Dockerfile`; `docker-compose.yml`; `.golangci.yml`'s linter selection;
`renovate.json`; `release-please-config.json`; `.release-please-manifest.json`; `CHANGELOG.md`;
`archive/`; anything under `docs/superpowers/` or `.superpowers/` (both gitignored scratch);
`grafana/**`'s dashboard/rule *logic* (only the docstring and message strings in §6.8 change);
`spec/graph-beta-snapshot.json` and `spec/signal-catalog.json` (regenerate only if `just gen` changes
them, which it should not).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A top-level justfile exists defining all seven mandatory recipes (default, setup, fmt, fmt-check, lint, test, check) plus build/ci/gen/gen-check/audit/image/smoke/clean; just --dump --dump-format json exits 0 (no unstable feature), and just --groups prints exactly build, check, dev, gen, infra, release.
- [ ] #2 just --list shows a # doc comment and a [group(...)] for every public recipe; helpers (_tools, _tools-licensing, _tools-sbom, _tools-helm-docs, _tool-graphdrift) are [private] and absent from --list.
- [ ] #3 just check passes on a clean checkout with dependency list 'fmt-check lint tidy-check tools-check forks-check test audit gen-check helm-check build', covering every ci-success leg except goreleaser-snapshot and docker-build, which just ci covers via smoke; evidence pasted, not asserted.
- [ ] #4 just --fmt --check exits 0 and is part of fmt-check; golangci-lint and govulncheck versions exist in exactly one place (the justfile), pinned to v2.13.2 and v1.3.0 respectively, with ci.yml no longer carrying its own golangci-lint-action version or go install govulncheck line.
- [ ] #5 Makefile is deleted with git rm; git grep for 'Makefile' and for a 'make <target>' invocation returns nothing outside CHANGELOG.md and archive/.
- [ ] #6 scripts/sbom.sh is deleted and its logic lives in just sbom; scripts/notices.sh, scripts/regen-generated.sh, scripts/container-smoke-test.sh, scripts/hooks/pre-commit and third_party/check-otel-http-forks.sh all still exist, each reachable via a recipe (notices, regen, smoke, install-hooks, forks-check/tidy), and cmd/graph2otel/documentation_contract_test.go still finds scripts/regen-generated.sh.
- [ ] #7 ci.yml, grafana-canary.yml, grafana-render-baseline.yml, grafana-sync.yml and publish.yml call just after a SHA-pinned extractions/setup-just step with just-version '1.58.0'; ci-success's job name and needs list, every permissions/concurrency block, every persist-credentials: false, every action SHA pin and every rknightion/.github reusable uses: call are byte-identical to before.
- [ ] #8 grafana-sync.yml uses 'just --yes rules-push m7kni' (the only --yes in the repo, because rules-push carries [confirm]) and 'just rules-readback m7kni'; Dockerfile line 29 still runs 'bash scripts/notices.sh' with no just in the image build.
- [ ] #9 AGENTS.md carries a '## Task interface' section naming just check as the gate and does not paste the recipe list; CONTRIBUTING.md, grafana/AUTHORING.md, docs/api-drift.md, docs/deploying-observability.md and docs/runbooks.md name just recipes; grafana/build_rules.py's generator strings are updated and docs/hunting.md regenerated via just rules.
- [ ] #10 backlog/config.yml definition_of_done names 'just check' and 'just gen' (set through the backlog CLI, not by hand-editing), and just gen run twice leaves git status --porcelain empty.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 make check is green — vet, go test -race ./..., lint, govulncheck, tidy-check, tools-check, forks-check, grafana-check, build. Evidence, not assertion: paste or cite the run.
- [ ] #2 make regen run and its output committed if the change touches a registry-driven or generated surface (collectors, env vars, beta drift spec).
- [ ] #3 Committed green to main and pushed, with the resulting SHA recorded in this task.
<!-- DOD:END -->

## Comments

<!-- COMMENTS:BEGIN -->
author: campaign-ordering
created: 2026-08-29 09:18
---
## Fleet ordering — WAVE 2. Starts after the Wave 0 pilot (`sf2loki` / SFL-0073) and the Wave 1 hubs land.

Within Wave 2 the order is free — these repos do not depend on each other. Batching by language is worthwhile so one lane reuses its Makefile-to-recipe mapping across similar repos.

Do not start before the pilot reports. The standard may be amended off the back of it, and picking this up early risks coding against a superseded seam.

**Provisioning `just` in CI.** Which mechanism depends on the runner, and the two must not be mixed:

| Runner | Mechanism |
| --- | --- |
| `arc-arm64` (m7kni self-hosted) | `just` is **baked into the runner image** by `m7kni/ci-tools` (`runner-image/Dockerfile`, `ARG JUST_VERSION`). Do **not** add `extractions/setup-just`, and delete the step if this repo already has one — it installs a second `just` earlier on `PATH` and turns the image pin into a lie. |
| GitHub-hosted (all `rknightion` repos) | `extractions/setup-just`, SHA-pinned, with an explicit `just-version:`. |

Both sides currently sit on **1.58.0** and are Renovate-managed. `ci-tools`' `Tool version drift` workflow fails if the Dockerfile `ARG` and the published image ever disagree, and lists any repo still carrying a second pin.

**While you are in the workflow files, check the hub pin.** On 2026-08-29 Renovate was unfrozen for `rknightion/.github` in `m7kni/renovate-config` — it had been `enabled: false` on the mistaken belief that callers tracked `@main`, which froze the fleet across 19 different hub SHAs (v1.3.1 June → v1.9.7 August) so that no hub fix ever propagated. Bumps now arrive as one grouped, CI-gated, automerged PR per repo. **A `uses:` whose comment is not a real `# vX.Y.Z` still cannot be bumped** (it resolves to a digest-only update, which the fleet rules disable) — if you find one, repair the comment as part of this task.
---

author: campaign-ordering
created: 2026-08-29 10:42
---
## Standard amendment — `ci` is the sanctioned superset of `check` (RATIFIED)

This supersedes the frozen wording *"`check` is the complete local gate and reproduces every CI job that can run off a GitHub runner"*, which several lanes could not honour without making the pre-commit gate depend on a Docker daemon.

**The definitions now are:**

- **`check`** — everything that runs with **only the language toolchain installed**. This is the pre-commit gate. A leg that runs on a bare toolchain belongs here *however long it takes*.
- **`ci`** — `check` plus the legs CI gates that need a **Docker daemon, a service container, or cross-compilation**, and nothing else. Written as `ci: check <heavy legs>`.

**Every leg you put in `ci` must carry a comment naming which of those three it needs.** That comment is the guard: without it `ci` becomes the bin for anything slow or awkward, `check` quietly stops meaning much, and the fleet is back to a per-repo gate.

Eleven of the 42 lanes arrived at this shape independently before it was ratified, which is why it won.

**If this repo has no such legs, it has no `ci` recipe at all** and `check` is the whole gate. Do not add an empty one.
---

author: campaign-ordering
created: 2026-08-29 10:57
---
## Fleet alignment — the 2otel family converges on one CI shape

These seven Go repos are near-identical applications and had drifted into **two naming dialects and materially different coverage**. The migration rewrites every `run:` block anyway, so converge them in the same change rather than preserving the drift in new clothes.

**Canonical job names** — used by tailscale2otel, graph2otel, polylens2otel and rfc6035-2otel, so this is the majority convention, not an invention:

`build-test` · `lint` · `govulncheck` · `goreleaser-snapshot` · `docker-build` · `coverage` · `ci-success`

`opnsense2otel` and `transceiver-exporter` currently use a second dialect — `tests`, `race`, `docker-build-verify`. Rename to the canonical set as part of this task.

**`ci-success` is the only check the branch ruleset gates**, so jobs can be renamed or merged freely *provided* `ci-success`'s `needs:` list is updated in the same commit. Never rename `ci-success` itself.

**Required gates, and where each lives after the migration:**

| Gate | Recipe | Note |
| --- | --- | --- |
| build + test + `-race` | `just test` | `-race` belongs in the standard test run |
| golangci-lint | `just lint` | needs a `.golangci.yml`, schema v2 |
| **gosec** | `just lint` | **a golangci-lint linter, NOT a separate job** — enable it in `.golangci.yml`. Four of the seven already do it this way; a standalone gosec job would be a third dialect |
| govulncheck | `just vuln` | pinned `golang.org/x/vuln/cmd/govulncheck@v1.3.0`, matching the family |
| goreleaser snapshot | `just snapshot` | cross-compile ⇒ belongs in `ci`, not `check` |
| container build | `just image` | needs a Docker daemon ⇒ belongs in `ci`, not `check` |

**Already done for you (2026-08-29):** `govulncheck` was added to `opnsense2otel`, `transceiver-exporter` and `codexlb2otel` ahead of the migration, because those three had no dependency vulnerability scanning at all. Convert those jobs to `just vuln` like any other; do not re-add them.

**Still missing, fix as part of this task:**

- `opnsense2otel` — has `.golangci.yml` but **`gosec` is not enabled** in it.
- `transceiver-exporter` — **no `.golangci.yml` at all**, and no `-race` in its test job.
- `codexlb2otel` — no `.golangci.yml`, no `-race`, no container build, and **no `ci-success` job and no branch ruleset**, so nothing gates its CI. Adding an aggregator is the right fix but is a separate decision; raise it rather than assuming.

**One known trap:** the `govulncheck@v1.3.0` pins are invisible to Renovate — `go install pkg@version` inside a `run:` block matches no manager. All five are four minor versions behind (current is v1.7.0). Once the version moves into the justfile as a `# renovate:`-annotated `:=` assignment, it becomes managed. That is a real benefit of this migration, not incidental.
---

author: campaign-ordering
created: 2026-08-29 11:20
---
## Correction — moving a pin into the justfile does NOT make it Renovate-managed

The 2otel alignment comment above ends with a claim that needs narrowing. It says the `govulncheck@v1.3.0` pins become managed "once the version moves into the justfile as a `# renovate:`-annotated `:=` assignment". The conditional in that sentence is doing real work, and **the first completed migration did not satisfy it**.

Verified on `tailscale2otel` at `origin/main` after TSO-0025 closed:

- `justfile:21` — `govulncheck_version := "v1.3.0"`, with **no `# renovate:` annotation** above it.
- `renovate.json` — **no justfile matcher at all**: no `customManagers` entry, nothing pointing at `/^justfile$/`.
- `justfile:17` — a comment stating the pin *tracks* the `go install` line in the CI jobs, so the workflow is still the source of truth.

The version relocated and nothing else changed. It is exactly as invisible to Renovate as it was in the `run:` block, and still four minors behind (`v1.3.0` against `v1.7.0`).

**Two things are required, and neither is implied by "move the pin into the justfile":**

1. The `:=` assignment carries a `# renovate: datasource=… depName=…` annotation directly above it.
2. `renovate.json` points a custom manager at the justfile — the `customManagers:dockerfileVersions` preset does **not** cover justfiles; that one only matches Dockerfiles and Containerfiles.

Treat "the pin is now managed" as **false unless you have done both and checked**. Do not record it as a benefit of this migration in a final summary without verifying `renovate.json` yourself.

Credit: caught by the `tailscale2otel` lane on its closeout, against the claim as originally written here.
---
<!-- COMMENTS:END -->

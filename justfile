# graph2otel — the task surface for this repo.
#
# `just check` is the full gate. It is exactly the union of ci.yml's build-test,
# lint, govulncheck, helm and grafana jobs. The docker-build leg needs a Docker
# daemon and lives in `just ci`; goreleaser-snapshot remains action-driven.
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
go_licenses_version := "v2.0.1"

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

# CI superset: smoke needs a Docker daemon and builds the local image when needed.
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

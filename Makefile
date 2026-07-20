GO ?= go
# Force module mode (no vendor/ dir in this repo) so local runs match CI exactly.
GOFLAGS ?= -mod=readonly
export GOFLAGS

BINARY := graph2otel
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Build with the goroutineleakprofile runtime experiment so the shipped binary
# registers the goroutineleak pprof profile (pushed to Pyroscope by default). The
# profiling code guards on availability, so a build without this simply omits that
# one profile type. Override to empty to drop it. Must match the Dockerfile and
# .goreleaser.yaml. A future Go that removes the experiment fails the build loudly.
GOEXPERIMENT ?= goroutineleakprofile
export GOEXPERIMENT

# Pinned tool versions (override via env; majors are load-bearing for the v2 config schema).
GOLANGCI_LINT_VERSION ?= v2.12.2
# go-licenses v1.x: `go install github.com/google/go-licenses@vX`. A bump to v2+
# needs the `/v2` module suffix in the install path below (and a re-check of the
# `report --template` CLI), so keep this on v1 unless that path is updated too.
GO_LICENSES_VERSION ?= v1.6.0
SYFT_VERSION ?= v1.48.0
HELM_DOCS_VERSION ?= v1.14.2

TOOLS_DIR := $(CURDIR)/.tools
export PATH := $(TOOLS_DIR):$(PATH)

.PHONY: build test lint fmt vet govulncheck docker check regen tools \
        coverage notices sbom tools-licensing tools-sbom install-hooks \
        helm-docs tools-helm-docs

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint: tools
	$(TOOLS_DIR)/golangci-lint run

fmt: tools
	$(TOOLS_DIR)/golangci-lint fmt

govulncheck: tools
	$(TOOLS_DIR)/govulncheck ./...

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):dev .

# The green bar — run this before every commit; CI runs the same steps. The
# generated-doc drift gate (docs/env-vars.md vs config.example.yaml) rides the
# `test` target as an ordinary `go test` (TestEnvReferenceDocInSync), so a stale
# doc fails `check` with no extra step.
check: vet test lint govulncheck
	$(GO) build ./...

# Regenerate committed generated artifacts (docs/env-vars.md) from their sources.
# The drift gate is enforced by `make test`; this is the "regenerate it for me"
# convenience after editing config.example.yaml.
regen:
	./scripts/regen-generated.sh

# Idempotent tool install into .tools/ (gitignored). Re-installs if the cached
# binary is missing or doesn't execute on this arch (e.g. a wrong-arch CI cache).
tools:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/golangci-lint && $(TOOLS_DIR)/golangci-lint version >/dev/null 2>&1; } || \
	  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $(TOOLS_DIR) $(GOLANGCI_LINT_VERSION)
	@{ test -x $(TOOLS_DIR)/govulncheck && $(TOOLS_DIR)/govulncheck -version >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@latest

# Test coverage profile for the Codacy upload (ci.yml `coverage` job; non-gating).
coverage:
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./...

# Pinned build tools for the release artifacts (installed into .tools/, gitignored).
tools-licensing:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/go-licenses && $(TOOLS_DIR)/go-licenses --help >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) $(GO) install github.com/google/go-licenses@$(GO_LICENSES_VERSION)
tools-sbom:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/syft && $(TOOLS_DIR)/syft version >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) $(GO) install github.com/anchore/syft/cmd/syft@$(SYFT_VERSION)

# THIRD_PARTY_NOTICES.md — release artifact (gitignored), baked into the image at
# /licenses/ and attached to the GitHub Release. See scripts/notices.sh.
notices: tools-licensing
	GO_LICENSES=$(TOOLS_DIR)/go-licenses bash scripts/notices.sh

# SPDX + CycloneDX SBOMs of the shipped binary -> dist/sbom/ (release artifacts).
sbom: tools-sbom
	CGO_ENABLED=0 GOEXPERIMENT=$(GOEXPERIMENT) $(GO) build -trimpath \
	  -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)
	SYFT=$(TOOLS_DIR)/syft bash scripts/sbom.sh

# Install the fast pre-commit gate (make vet lint). CI runs the full `make check`.
install-hooks:
	cp scripts/hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

tools-helm-docs:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/helm-docs && $(TOOLS_DIR)/helm-docs --help >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) $(GO) install github.com/norwoodj/helm-docs/cmd/helm-docs@$(HELM_DOCS_VERSION)

# Regenerate the Helm chart README from the values.yaml `# --` annotations. The CI
# helm job diffs the result, so run this after editing charts/graph2otel/values.yaml.
helm-docs: tools-helm-docs
	$(TOOLS_DIR)/helm-docs --chart-search-root charts/graph2otel

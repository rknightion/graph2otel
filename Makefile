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

TOOLS_DIR := $(CURDIR)/.tools
export PATH := $(TOOLS_DIR):$(PATH)

.PHONY: build test lint fmt vet govulncheck docker check tools

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

# The green bar — run this before every commit; CI runs the same steps.
check: vet test lint govulncheck
	$(GO) build ./...

# Idempotent tool install into .tools/ (gitignored). Re-installs if the cached
# binary is missing or doesn't execute on this arch (e.g. a wrong-arch CI cache).
tools:
	@mkdir -p $(TOOLS_DIR)
	@{ test -x $(TOOLS_DIR)/golangci-lint && $(TOOLS_DIR)/golangci-lint version >/dev/null 2>&1; } || \
	  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh | sh -s -- -b $(TOOLS_DIR) $(GOLANGCI_LINT_VERSION)
	@{ test -x $(TOOLS_DIR)/govulncheck && $(TOOLS_DIR)/govulncheck -version >/dev/null 2>&1; } || \
	  GOBIN=$(TOOLS_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@latest

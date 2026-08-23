# syntax=docker/dockerfile:1

# ---- build ----
# Digest-pinned (Renovate's docker:pinDigests keeps this current — see renovate.json).
FROM golang:1.27.0-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466 AS build
WORKDIR /src
COPY go.mod go.sum ./
# Root go.mod replaces both OTLP/HTTP exporters with narrow local forks. Copy
# their manifests into the dependency-cache layer before Go resolves the
# replacements; the full sources still arrive in the following COPY layer.
COPY third_party/otlploghttp/go.mod third_party/otlploghttp/go.sum ./third_party/otlploghttp/
COPY third_party/otlpmetrichttp/go.mod third_party/otlpmetrichttp/go.sum ./third_party/otlpmetrichttp/
RUN go mod download
COPY . .
ARG VERSION=dev
# GOEXPERIMENT=goroutineleakprofile registers the goroutineleak pprof profile, which
# is pushed to Pyroscope by default (the profiling code guards on availability). Keep
# in sync with the Makefile and .goreleaser.yaml.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOEXPERIMENT=goroutineleakprofile go build -trimpath \
    -ldflags "-s -w -X github.com/rknightion/graph2otel/internal/version.Version=${VERSION}" \
    -o /out/graph2otel ./cmd/graph2otel

# Third-party notices for the linked modules, baked into /licenses/ in the runtime
# stage below. Runs on the build platform against the module cache populated above
# (scripts/notices.sh also runs `go mod download`). Keep GO_LICENSES_VERSION in sync
# with the Makefile. bookworm ships bash, so no extra shell install is needed.
# v1.x install path (no `/v2` suffix); keep in sync with the Makefile pin.
ARG GO_LICENSES_VERSION=v1.6.0
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install github.com/google/go-licenses@${GO_LICENSES_VERSION} && \
    GO_LICENSES=go-licenses OUT=/THIRD_PARTY_NOTICES.md bash scripts/notices.sh

# Seed the runtime checkpoint mount point with the distroless nonroot identity.
# Docker copies this ownership into a new empty named volume on first use.
RUN install -d -m 0750 -o 65532 -g 65532 /out/checkpoints

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/graph2otel /usr/local/bin/graph2otel
# License compliance travels with the image (OCI /licenses convention): the AGPL
# text plus the verbatim third-party module notices generated in the build stage.
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
# config.example.yaml is copied for reference only; it is NOT loaded by default.
# The binary runs from built-in defaults + G2O_* environment variables. To use a
# config file, mount it and pass --config /path/to/config.yaml, e.g.:
#   docker run -v ./config.yaml:/etc/graph2otel/config.yaml:ro \
#              ghcr.io/rknightion/graph2otel:latest \
#              --config /etc/graph2otel/config.yaml
COPY config.example.yaml /etc/graph2otel/config.example.yaml
# Checkpoints must survive restarts. The directory is owned by the distroless
# nonroot user so Docker-created named volumes are writable without a wrapper.
COPY --from=build --chown=65532:65532 /out/checkpoints /var/lib/graph2otel
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/graph2otel"]
CMD []

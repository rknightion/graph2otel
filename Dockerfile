# syntax=docker/dockerfile:1

# ---- build ----
# Digest-pinned (Renovate's docker:pinDigests keeps this current — see renovate.json).
FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
# GOEXPERIMENT=goroutineleakprofile registers the goroutineleak pprof profile, which
# is pushed to Pyroscope by default (the profiling code guards on availability). Keep
# in sync with the Makefile and .goreleaser.yaml.
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOEXPERIMENT=goroutineleakprofile go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/graph2otel ./cmd/graph2otel

# Third-party notices for the linked modules, baked into /licenses/ in the runtime
# stage below. Runs on the build platform against the module cache populated above
# (scripts/notices.sh also runs `go mod download`). Keep GO_LICENSES_VERSION in sync
# with the Makefile. bookworm ships bash, so no extra shell install is needed.
ARG GO_LICENSES_VERSION=v2.0.1
RUN --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/usr/local/bin go install github.com/google/go-licenses@${GO_LICENSES_VERSION} && \
    GO_LICENSES=go-licenses OUT=/THIRD_PARTY_NOTICES.md bash scripts/notices.sh

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
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/graph2otel"]
CMD []

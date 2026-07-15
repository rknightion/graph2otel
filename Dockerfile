# syntax=docker/dockerfile:1

# ---- build ----
# Digest-pinned (Renovate's docker:pinDigests keeps this current — see renovate.json).
FROM golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/graph2otel ./cmd/graph2otel

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/graph2otel /usr/local/bin/graph2otel
# License compliance travels with the image (OCI /licenses convention).
COPY --from=build /src/LICENSE /licenses/LICENSE
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

#!/usr/bin/env bash
# LOCAL AGENTS: DO NOT RUN THIS SCRIPT. It is only for Codex or Claude cloud environment provisioning.
# Paste this file into the cloud environment's setup-script field; do not invoke it during local development.

set -euo pipefail

# Use the patched release accepted by this module's `go 1.26.5` minimum. The
# older patch is affected by standard-library findings that make govulncheck fail.
readonly GO_VERSION="1.26.6"
readonly HELM_VERSION="v3.18.4"
readonly INSTALL_BIN="/usr/local/bin"

as_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

install_os_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is unavailable; assuming the cloud image already provides OS dependencies"
    return
  fi

  as_root apt-get update
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash build-essential ca-certificates curl git make npm python3 shellcheck tar
  as_root rm -rf /var/lib/apt/lists/*
}

install_go() {
  if command -v go >/dev/null 2>&1 && [[ $(go env GOVERSION) == "go${GO_VERSION}" ]]; then
    return
  fi

  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac

  local archive
  archive=$(mktemp)
  curl --fail --location --retry 3 --output "${archive}" \
    "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  as_root rm -rf /usr/local/go
  as_root tar -C /usr/local -xzf "${archive}"
  rm -f "${archive}"
  export PATH="/usr/local/go/bin:${PATH}"
}

persist_path() {
  local path_line='export PATH="/usr/local/go/bin:/usr/local/bin:$PATH"'
  touch "${HOME}/.bashrc"
  grep -Fqx "${path_line}" "${HOME}/.bashrc" || printf '\n%s\n' "${path_line}" >>"${HOME}/.bashrc"
}

install_helm() {
  if command -v helm >/dev/null 2>&1 && [[ $(helm version --template '{{.Version}}') == "${HELM_VERSION}" ]]; then
    return
  fi

  local arch temp_dir
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac
  temp_dir=$(mktemp -d)
  curl --fail --location --retry 3 \
    "https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz" |
    tar -C "${temp_dir}" -xz
  as_root install -m 0755 "${temp_dir}/linux-${arch}/helm" "${INSTALL_BIN}/helm"
  rm -rf "${temp_dir}"
}

install_go_tool() {
  local binary=$1 package=$2 version=$3
  if command -v "${binary}" >/dev/null 2>&1; then
    return
  fi
  as_root env PATH="/usr/local/go/bin:${PATH}" GOBIN="${INSTALL_BIN}" \
    go install "${package}@${version}"
}

install_os_packages
install_go
persist_path

# Backlog.md is the repository's tracker and must be available before an agent
# runs the mandatory `backlog instructions overview` command.
if ! command -v backlog >/dev/null 2>&1 || [[ $(backlog --version 2>/dev/null) != *"1.50.1"* ]]; then
  as_root npm install --global backlog.md@1.50.1
fi

install_go_tool golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint v2.12.2
install_go_tool govulncheck golang.org/x/vuln/cmd/govulncheck v1.3.0
install_go_tool helm-docs github.com/norwoodj/helm-docs/cmd/helm-docs v1.14.2
install_helm

echo "Cloud environment ready: Go $(go version), Backlog.md $(backlog --version)"

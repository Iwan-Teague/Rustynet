#!/usr/bin/env bash
set -euo pipefail

if [[ "${RUSTYNET_CI_BOOTSTRAP_SYSTEM:-1}" == "1" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    sudo_cmd=""
    if [[ "$(id -u)" -ne 0 ]]; then
      sudo_cmd="sudo"
    fi
    ${sudo_cmd} apt-get update
    ${sudo_cmd} apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential pkg-config \
      python3 iproute2 nftables wireguard-tools
  fi
fi

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.85.0
  export PATH="$HOME/.cargo/bin:$PATH"
fi
if [[ -d "$HOME/.cargo/bin" ]]; then
  export PATH="$HOME/.cargo/bin:$PATH"
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    echo "$HOME/.cargo/bin" >> "${GITHUB_PATH}"
  fi
fi

rustup toolchain install 1.85.0 --profile minimal --component rustfmt --component clippy
rustup default 1.85.0

SECURITY_TOOLCHAIN="${RUSTYNET_SECURITY_TOOLCHAIN:-1.88.0}"
rustup toolchain install "${SECURITY_TOOLCHAIN}" --profile minimal

if ! command -v cargo-audit >/dev/null 2>&1 || ! cargo-audit --version | grep -q '^cargo-audit 0\.22\.'; then
  cargo +"${SECURITY_TOOLCHAIN}" install cargo-audit --locked --version 0.22.1 --force
fi
if ! command -v cargo-deny >/dev/null 2>&1 || ! cargo-deny --version | grep -q '^cargo-deny 0\.19\.'; then
  # Newer advisories use CVSS4 metadata; cargo-deny 0.19+ is required.
  cargo +"${SECURITY_TOOLCHAIN}" install cargo-deny --locked --force
fi

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

if ! command -v cargo-audit >/dev/null 2>&1; then
  cargo install cargo-audit --locked --version 0.22.1
fi
if ! command -v cargo-deny >/dev/null 2>&1; then
  # Keep cargo-deny aligned with the pinned Rust toolchain (1.85.0).
  cargo install cargo-deny --locked --version 0.18.3
fi

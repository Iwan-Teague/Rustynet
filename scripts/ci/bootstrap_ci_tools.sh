#!/usr/bin/env bash
set -euo pipefail

# This wrapper's only job is to dispatch to the Rust `bootstrap_ci_tools`
# binary, which does the real work (pinned toolchain, security toolchain,
# cargo-audit/cargo-deny, apt packages for the wider workspace). But on a bare
# container with no system Rust preinstalled (e.g. the `debian:trixie` image
# the "Debian 13" CI job runs in), `cargo` itself does not exist yet, so there
# is nothing to dispatch to — a Rust binary can't install Rust. Bootstrapping
# rustup is therefore the one step that must live in shell, not Rust; do not
# duplicate any other bootstrap logic here, it stays in bootstrap_ci_tools.rs.
if ! command -v cargo >/dev/null 2>&1; then
  if [ "${RUSTYNET_CI_BOOTSTRAP_SYSTEM:-1}" != "0" ] && command -v apt-get >/dev/null 2>&1; then
    if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      sudo_cmd=""
    fi
    $sudo_cmd apt-get update
    DEBIAN_FRONTEND=noninteractive $sudo_cmd apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${CARGO_HOME:-$HOME/.cargo}/bin" >>"$GITHUB_PATH"
  fi
fi

exec cargo run --quiet -p rustynet-cli --bin bootstrap_ci_tools -- "$@"

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
    # procps and unzip are not optional conveniences — the suite asserts on them:
    #   procps -> `ps`, spawned by the stage-deadline sweep
    #             (`orchestrator/diagnostics.rs`); without it
    #             `production_tree_enumerates_the_real_process_table_without_killing`
    #             fails with "No such file or directory (os error 2)".
    #   unzip  -> the artifact key-exclusion check
    #             (`orchestrator/adapter/windows_traffic.rs`). Its `python3`
    #             fallback is MORE PERMISSIVE than `unzip`: python's `zipfile`
    #             accepts a corrupted 22-byte end-of-central-directory record and
    #             returns an empty namelist, so a runner without `unzip` silently
    #             took a different code path than any developer machine. The
    #             checker now fails closed on an empty listing regardless, but the
    #             runner should still exercise the same tool production does.
    # The debian:trixie image ships neither, which is why this leg failed for
    # every one of the last 100 runs while macOS and the E2E leg passed.
    DEBIAN_FRONTEND=noninteractive $sudo_cmd apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config procps unzip
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain none
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
  if [ -n "${GITHUB_PATH:-}" ]; then
    echo "${CARGO_HOME:-$HOME/.cargo}/bin" >>"$GITHUB_PATH"
  fi
fi

exec cargo run --quiet -p rustynet-cli --bin bootstrap_ci_tools -- "$@"

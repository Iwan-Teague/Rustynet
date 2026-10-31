#!/usr/bin/env bash
# env-android.sh: Android compile-scope environment for rustynet-mobile-ffi (MC1d).
#
# Usage: source scripts/mobile/env-android.sh
#
# Scope: `cargo check` and `cargo clippy --target aarch64-linux-android` only.
# These need no Android NDK, no linker and no downloads. The Android Rust std
# (aarch64-linux-android) must already be installed on the pinned toolchain.
# This script never runs `rustup target add`. Only check and clippy are supported
# without the NDK. Anything that links an Android binary (cargo build, a cdylib
# .so, cargo test for the target) needs the NDK and is out of scope until MC1e.
#
# Exports:
#   RUSTYNET_ANDROID_MIN_SDK=31            minSdk 31 (DR-Q2, C8; PLAN section 8.1)
#   RUSTYNET_ANDROID_TARGETS               the Android target list for mobile checks
# and puts the pinned toolchain's bin directory first on PATH, so that
# `cargo clippy` runs the pinned clippy and not an older one found earlier on PATH.

RUSTYNET_ANDROID_MIN_SDK=31
RUSTYNET_ANDROID_TARGETS="aarch64-linux-android"
export RUSTYNET_ANDROID_MIN_SDK RUSTYNET_ANDROID_TARGETS

_rn_env_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_rn_env_repo_root="$(cd "$_rn_env_script_dir/../.." && pwd)"
_rn_env_channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$_rn_env_repo_root/rust-toolchain.toml" 2>/dev/null | head -1)"

if command -v rustup >/dev/null 2>&1 && [ -n "$_rn_env_channel" ]; then
  _rn_env_cargo="$(rustup which --toolchain "$_rn_env_channel" cargo 2>/dev/null || true)"
  if [ -n "$_rn_env_cargo" ]; then
    PATH="$(dirname "$_rn_env_cargo"):$PATH"
    export PATH
  fi
  if ! rustup target list --installed --toolchain "$_rn_env_channel" 2>/dev/null | grep -qx "aarch64-linux-android"; then
    printf 'env-android.sh: warning: aarch64-linux-android is not installed on toolchain %s; install it once with the owner-approved rustup step, not from this script\n' "$_rn_env_channel" >&2
  fi
fi

unset _rn_env_script_dir _rn_env_repo_root _rn_env_channel _rn_env_cargo

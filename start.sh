#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v cargo >/dev/null 2>&1; then
  cd "${ROOT_DIR}"
  exec cargo run --quiet -p rustynet-cli -- operator menu "$@"
fi

if [[ -x "${ROOT_DIR}/target/release/rustynet-cli" ]]; then
  exec "${ROOT_DIR}/target/release/rustynet-cli" operator menu "$@"
fi

if [[ -x "${ROOT_DIR}/target/debug/rustynet-cli" ]]; then
  exec "${ROOT_DIR}/target/debug/rustynet-cli" operator menu "$@"
fi

if command -v rustynet >/dev/null 2>&1; then
  exec rustynet operator menu "$@"
fi

if command -v rustynet-cli >/dev/null 2>&1; then
  exec rustynet-cli operator menu "$@"
fi

printf '[error] %s\n' "rustynet CLI not found and cargo is unavailable." >&2
printf '[info] %s\n' "Build first with: cargo build -p rustynet-cli" >&2
exit 127

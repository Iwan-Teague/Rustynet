#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <cargo-package> <test-filter> [cargo-test-args...]" >&2
  exit 2
fi

PACKAGE="$1"
shift
TEST_FILTER="$1"
shift
EXTRA_ARGS=("$@")

TMP_OUTPUT="$(mktemp "${TMPDIR:-/tmp}/rustynet-required-test.XXXXXX")"
cleanup() {
  rm -f "${TMP_OUTPUT}"
}
trap cleanup EXIT

cmd=(cargo test -p "${PACKAGE}" "${TEST_FILTER}")
if [[ "${#EXTRA_ARGS[@]}" -gt 0 ]]; then
  cmd+=("${EXTRA_ARGS[@]}")
fi
cmd+=(-- --nocapture)

if ! "${cmd[@]}" >"${TMP_OUTPUT}" 2>&1; then
  cat "${TMP_OUTPUT}" >&2
  echo "required test failed: package=${PACKAGE} filter=${TEST_FILTER}" >&2
  exit 1
fi

cat "${TMP_OUTPUT}"

cargo run --quiet -p rustynet-cli -- ops verify-required-test-output \
  --output "${TMP_OUTPUT}" \
  --package "${PACKAGE}" \
  --test-filter "${TEST_FILTER}"

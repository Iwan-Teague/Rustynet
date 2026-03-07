#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <cargo-package> <test-filter> [cargo-test-args...]" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing required command: python3" >&2
  exit 1
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

python3 - "${TMP_OUTPUT}" "${PACKAGE}" "${TEST_FILTER}" <<'PY'
import re
import sys
from pathlib import Path

output_path = Path(sys.argv[1])
package = sys.argv[2]
test_filter = sys.argv[3]
body = output_path.read_text(encoding="utf-8", errors="ignore")

total_passed = 0
for match in re.finditer(r"test result: ok\.\s+([0-9]+)\s+passed;", body):
    total_passed += int(match.group(1))

if total_passed < 1:
    raise SystemExit(
        f"required test did not execute any tests: package={package} filter={test_filter}"
    )
PY

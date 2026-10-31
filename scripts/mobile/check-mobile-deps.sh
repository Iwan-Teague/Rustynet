#!/usr/bin/env bash
# check-mobile-deps.sh: mobile dependency-boundary gate (MC1d; PLAN section 8.5; FINAL-REVIEW-3 5.3).
#
# rustynet-mobile-ffi must stay std-only. Its full aarch64-linux-android dependency graph
# (normal, build and dev edges) must be exactly one line: the package itself. Any dependency
# at all fails the gate. This is an exact-match rule, not a denylist, so an unlisted crate
# cannot pass. A later slice that legitimately adds a dependency must change this rule
# explicitly, through review.
#
# A stale lock fails too, because cargo tree runs with --locked.
#
# USAGE
#   scripts/mobile/check-mobile-deps.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PACKAGE="rustynet-mobile-ffi"
TARGET="aarch64-linux-android"

# shellcheck source=scripts/mobile/env-android.sh
. "$REPO_ROOT/scripts/mobile/env-android.sh"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/check-mobile-deps.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
TREE_FILE="$WORK_DIR/tree.txt"
ERR_FILE="$WORK_DIR/tree.err"

if ! cargo tree -p "$PACKAGE" -e all --target "$TARGET" --locked >"$TREE_FILE" 2>"$ERR_FILE"; then
  printf 'check-mobile-deps: FAIL: cargo tree failed for %s (%s)\n' "$PACKAGE" "$TARGET" >&2
  cat "$ERR_FILE" >&2
  exit 1
fi

entries="$(grep -c . "$TREE_FILE" || true)"
if [ "$entries" != "1" ]; then
  printf 'check-mobile-deps: FAIL: %s (%s) must be std-only: its graph has %s entries, expected exactly the package line\n' \
    "$PACKAGE" "$TARGET" "$entries" >&2
  head -5 "$TREE_FILE" | sed "s/^/  /" >&2
  exit 1
fi

if ! grep -qE "^${PACKAGE} v[0-9]" "$TREE_FILE"; then
  printf 'check-mobile-deps: FAIL: the single entry is not %s itself\n' "$PACKAGE" >&2
  head -5 "$TREE_FILE" | sed "s/^/  /" >&2
  exit 1
fi

printf 'check-mobile-deps: OK: %s (%s) is std-only (graph is the package line alone)\n' "$PACKAGE" "$TARGET"

#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib/required_test.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/required_test.sh"

echo "Running anchor secret redaction CI gates..."

rg -q 'MAX_ANCHOR_BUNDLE_PULL_TOKEN_BYTES' crates/rustynetd/src/daemon.rs
rg -q 'constant_time_ascii_eq' crates/rustynetd/src/daemon.rs
# AQ-44/E8: the anchor keeps NO per-flow logs (retention documented in the
# README). The old probes required `served peer=`/`request failed peer=`
# lines carrying a token thumbprint; those emission sites were removed by
# 6b08be403 and the probe must now assert the removal persisted — a per-flow
# line regressing back in fails the gate instead of a missing line doing so.
# Fail-closed on rg error (exit 2, e.g. daemon.rs unreadable): a probe that
# cannot assert anything is a failure, not a pass.
anchor_inverted_status=0
rg -q 'anchor_bundle_pull: (served|request failed) peer=' crates/rustynetd/src/daemon.rs || anchor_inverted_status=$?
if [ "$anchor_inverted_status" -eq 0 ]; then
  echo "per-flow anchor bundle-pull log lines must stay removed (AQ-44/E8: no per-flow logs, no token thumbprints in journals)" >&2
  exit 1
elif [ "$anchor_inverted_status" -ne 1 ]; then
  echo "anchor gate: AQ-44/E8 inverted probe could not assert removal (rg exit $anchor_inverted_status)" >&2
  exit 1
fi

# OI-20 gate hygiene: pattern 1 KEEPS ` token=` — the daemon's anchor
# emissions are often multi-line log:: macro calls whose format string
# sits on the line after `log::info!(`, which the single-line log-macro
# pattern below cannot see. The ONLY tolerated match is the
# negative-witness fixture in live_linux_anchor_test.rs (a #[test]
# literal journal line `... token=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456`
# fed to validate_bundle_pull_log_redaction to prove it FAILS CLOSED on
# leaky lines): that fixture is exempted below by EXACT CONTENT in its
# EXACT FILE (never by line number), and every exemption prints a note.
ANCHOR_REDACTION_FIXTURE_PATH='crates/rustynet-cli/src/bin/live_linux_anchor_test.rs'
ANCHOR_REDACTION_FIXTURE_LINE='"Jul 01 anchor_bundle_pull: peer=relay-1 token=ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";'
anchor_pattern1_status=0
anchor_matches=$(rg -n 'anchor_bundle_pull:.*(raw_token|token_material| token=|secret|presented|expected)' crates/rustynetd/src crates/rustynet-cli/src) || anchor_pattern1_status=$?
if [ "$anchor_pattern1_status" -ne 0 ] && [ "$anchor_pattern1_status" -ne 1 ]; then
  echo "anchor gate: pattern 1 rg could not scan (exit $anchor_pattern1_status)" >&2
  exit 1
fi
if [ "$anchor_pattern1_status" -eq 0 ]; then
  anchor_unexempted=""
  while IFS= read -r anchor_match; do
    [ -z "$anchor_match" ] && continue
    anchor_file="${anchor_match%%:*}"
    anchor_text="${anchor_match#*:*:}"
    anchor_trimmed="$(printf '%s' "$anchor_text" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    if [ "$anchor_file" = "$ANCHOR_REDACTION_FIXTURE_PATH" ] && [ "$anchor_trimmed" = "$ANCHOR_REDACTION_FIXTURE_LINE" ]; then
      echo "note: pattern 1 exempted the negative-witness fixture literal by exact content in $ANCHOR_REDACTION_FIXTURE_PATH (test input proving fail-closed redaction, not an emission)"
      continue
    fi
    anchor_unexempted+="$anchor_match"$'\n'
  done <<<"$anchor_matches"
  if [ -n "$anchor_unexempted" ]; then
    printf '%s' "$anchor_unexempted"
    echo "anchor bundle-pull log line appears to expose token/secret context" >&2
    exit 1
  fi
fi

anchor_pattern2_status=0
anchor_pattern2_matches=$(rg -n 'log::(info|warn|error|debug|trace)!\([^;]*(presented_token|expected_token|bundle_pull_token| token=|enrollment token written|--token)' crates/rustynetd/src crates/rustynet-cli/src) || anchor_pattern2_status=$?
if [ "$anchor_pattern2_status" -eq 0 ]; then
  printf '%s\n' "$anchor_pattern2_matches"
  echo "log macro appears to include sensitive token material" >&2
  exit 1
elif [ "$anchor_pattern2_status" -ne 1 ]; then
  echo "anchor gate: log-macro pattern could not scan (exit $anchor_pattern2_status)" >&2
  exit 1
fi

# Every filtered cargo test below must prove it RAN at least one test:
# a filter matching 0 tests (e.g. the thumbprint tests AQ-44 removed)
# used to pass vacuously, which is a fail-open gate.
run_anchor_test_filter() {
  local anchor_filter_label="$1"
  shift
  # run_required_test (scripts/ci/lib/required_test.sh) fails on a cargo
  # failure OR on zero passed tests.
  run_required_test "$@" || {
    echo "anchor gate: cargo test $anchor_filter_label failed or ran 0 tests (vacuous filter -- rename it to a real current test)" >&2
    exit 1
  }
}

run_anchor_test_filter "-p rustynetd 'daemon::tests::anchor_bundle_pull_response_is_token_gated'" -p rustynetd 'daemon::tests::anchor_bundle_pull_response_is_token_gated' -- --nocapture
run_anchor_test_filter "-p rustynetd 'daemon::tests::anchor_bundle_pull_response_path_exercises_existing_helpers'" -p rustynetd 'daemon::tests::anchor_bundle_pull_response_path_exercises_existing_helpers' -- --nocapture
# `anchor_bundle_pull_token_thumbprint_is_trimmed_digest_prefix` was DELETED
# here: AQ-44/6b08be403 removed the thumbprint tests, so the filter ran 0
# tests and passed vacuously. The inverted AQ-44/E8 probe above now asserts
# the removal persisted instead.
# The relay health-renderers test lives in the `rustynet-relay` BIN target,
# which is gated behind required-features = ["daemon"] (Cargo.toml:49-52) —
# without the feature cargo test silently runs 0 targets and every filter
# on this crate was vacuous, including the old
# `daemon::tests::health_renderers_expose_counts_without_secrets` one (the
# test is at crates/rustynet-relay/src/main.rs:4761, `mod tests`, not
# `daemon::tests`, and the bin was never built). Build with the feature and
# filter by the real test name.
run_anchor_test_filter "-p rustynet-relay --features daemon 'health_renderers_expose_counts_without_secrets'" -p rustynet-relay --features daemon 'health_renderers_expose_counts_without_secrets' -- --nocapture

echo "Anchor secret redaction CI gates: PASS"

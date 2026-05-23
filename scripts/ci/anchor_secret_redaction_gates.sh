#!/usr/bin/env bash
set -euo pipefail

echo "Running anchor secret redaction CI gates..."

rg -q 'MAX_ANCHOR_BUNDLE_PULL_TOKEN_BYTES' crates/rustynetd/src/daemon.rs
rg -q 'constant_time_ascii_eq' crates/rustynetd/src/daemon.rs
rg -q 'anchor_bundle_pull: served peer=' crates/rustynetd/src/daemon.rs

if rg -n 'anchor_bundle_pull:.*(token|secret|presented|expected)' crates/rustynetd/src crates/rustynet-cli/src; then
  echo "anchor bundle-pull log line appears to expose token/secret context" >&2
  exit 1
fi

if rg -n 'log::(info|warn|error|debug|trace)!\([^;]*(presented_token|expected_token|bundle_pull_token|enrollment token written|--token)' crates/rustynetd/src crates/rustynet-cli/src; then
  echo "log macro appears to include sensitive token material" >&2
  exit 1
fi

cargo test -p rustynetd daemon::tests::anchor_bundle_pull_response_is_token_gated -- --nocapture
cargo test -p rustynetd daemon::tests::anchor_bundle_pull_response_path_exercises_existing_helpers -- --nocapture
cargo test -p rustynet-relay daemon::tests::health_renderers_expose_counts_without_secrets -- --nocapture

echo "Anchor secret redaction CI gates: PASS"

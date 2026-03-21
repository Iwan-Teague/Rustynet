#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

ssh_identity="$temp_dir/id_test"
printf 'not-a-real-private-key\n' >"$ssh_identity"

run_expect_fail() {
  local script_path="$1"
  shift
  if bash "$script_path" "$@"; then
    echo "expected validator to fail without live lab prerequisites: $script_path" >&2
    exit 1
  fi
}

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --client-node-id "client-1" \
  --exit-node-id "exit-1" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --report-path "$temp_dir/cross_network_direct_remote_exit_report.json" \
  --log-path "$temp_dir/cross_network_direct_remote_exit.log"

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --relay-host "relay@example" \
  --client-node-id "client-1" \
  --exit-node-id "exit-1" \
  --relay-node-id "relay-1" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --relay-network-id "net-c" \
  --report-path "$temp_dir/cross_network_relay_remote_exit_report.json" \
  --log-path "$temp_dir/cross_network_relay_remote_exit.log"

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_failback_roaming_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --relay-host "relay@example" \
  --client-node-id "client-1" \
  --exit-node-id "exit-1" \
  --relay-node-id "relay-1" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --relay-network-id "net-c" \
  --report-path "$temp_dir/cross_network_failback_roaming_report.json" \
  --log-path "$temp_dir/cross_network_failback_roaming.log"

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --probe-host "probe@example" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --report-path "$temp_dir/cross_network_traversal_adversarial_report.json" \
  --log-path "$temp_dir/cross_network_traversal_adversarial.log"

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --client-node-id "client-1" \
  --exit-node-id "exit-1" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --report-path "$temp_dir/cross_network_remote_exit_dns_report.json" \
  --log-path "$temp_dir/cross_network_remote_exit_dns.log"

run_expect_fail "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh" \
  --ssh-identity-file "$ssh_identity" \
  --client-host "client@example" \
  --exit-host "exit@example" \
  --client-network-id "net-a" \
  --exit-network-id "net-b" \
  --report-path "$temp_dir/cross_network_remote_exit_soak_report.json" \
  --log-path "$temp_dir/cross_network_remote_exit_soak.log"

cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --artifact-dir "$temp_dir" \
  --output "$temp_dir/skeleton_validation.md"

echo "Cross-network remote-exit fail-closed bootstrap tests: PASS"

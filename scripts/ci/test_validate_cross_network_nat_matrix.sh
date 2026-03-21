#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

source_file="$temp_dir/source.txt"
log_file="$temp_dir/report.log"
printf 'source\n' >"$source_file"
printf 'log\n' >"$log_file"

current_commit="$(git rev-parse HEAD)"

generate_pass_report() {
  local suite="$1"
  local report_path="$2"
  local nat_profile="$3"

  local args=(
    cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report
    --suite "$suite"
    --report-path "$report_path"
    --log-path "$log_file"
    --status pass
    --environment ci
    --implementation-state implemented
    --source-artifact "$source_file"
    --client-host client@example
    --exit-host exit@example
    --client-network-id net-a
    --exit-network-id net-b
    --nat-profile "$nat_profile"
    --impairment-profile none
  )

  case "$suite" in
    cross_network_direct_remote_exit)
      args+=(
        --check direct_remote_exit_success=pass
        --check remote_exit_no_underlay_leak=pass
        --check remote_exit_server_ip_bypass_is_narrow=pass
      )
      ;;
    cross_network_relay_remote_exit)
      args+=(
        --relay-host relay@example
        --relay-network-id net-c
        --check relay_remote_exit_success=pass
        --check remote_exit_no_underlay_leak=pass
        --check remote_exit_server_ip_bypass_is_narrow=pass
      )
      ;;
    cross_network_failback_roaming)
      args+=(
        --relay-host relay@example
        --relay-network-id net-c
        --check relay_to_direct_failback_success=pass
        --check endpoint_roam_recovery_success=pass
        --check remote_exit_no_underlay_leak=pass
      )
      ;;
    cross_network_traversal_adversarial)
      args+=(
        --probe-host probe@example
        --check forged_traversal_rejected=pass
        --check stale_traversal_rejected=pass
        --check replayed_traversal_rejected=pass
        --check rogue_endpoint_rejected=pass
        --check control_surface_exposure_blocked=pass
      )
      ;;
    cross_network_remote_exit_dns)
      args+=(
        --check managed_dns_resolution_success=pass
        --check remote_exit_dns_fail_closed=pass
        --check remote_exit_no_underlay_leak=pass
      )
      ;;
    cross_network_remote_exit_soak)
      args+=(
        --check long_soak_stable=pass
        --check remote_exit_no_underlay_leak=pass
        --check remote_exit_server_ip_bypass_is_narrow=pass
        --check cross_network_topology_heuristic=pass
        --check direct_remote_exit_ready=pass
        --check post_soak_bypass_ready=pass
        --check no_plaintext_passphrase_files=pass
      )
      ;;
    *)
      echo "unsupported suite in test fixture generator: $suite" >&2
      exit 1
      ;;
  esac

  "${args[@]}" >/dev/null
}

# Baseline NAT profile coverage for every suite.
generate_pass_report cross_network_direct_remote_exit "$temp_dir/cross_network_direct_remote_exit_report.json" baseline_lan
generate_pass_report cross_network_relay_remote_exit "$temp_dir/cross_network_relay_remote_exit_report.json" baseline_lan
generate_pass_report cross_network_failback_roaming "$temp_dir/cross_network_failback_roaming_report.json" baseline_lan
generate_pass_report cross_network_traversal_adversarial "$temp_dir/cross_network_traversal_adversarial_report.json" baseline_lan
generate_pass_report cross_network_remote_exit_dns "$temp_dir/cross_network_remote_exit_dns_report.json" baseline_lan
generate_pass_report cross_network_remote_exit_soak "$temp_dir/cross_network_remote_exit_soak_report.json" baseline_lan

# Only one suite has symmetric_nat evidence initially; matrix should fail for full symmetric coverage.
generate_pass_report cross_network_direct_remote_exit "$temp_dir/cross_network_direct_remote_exit_report_symmetric_partial.json" symmetric_nat

cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan \
  --expected-git-commit "$current_commit" \
  --require-pass-status \
  --output "$temp_dir/nat_matrix_baseline.md"

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan,symmetric_nat \
  --expected-git-commit "$current_commit" \
  --require-pass-status; then
  echo "expected matrix validation to fail when only one suite has symmetric_nat evidence" >&2
  exit 1
fi

# Add symmetric_nat evidence for all suites and require dual-profile pass.
generate_pass_report cross_network_direct_remote_exit "$temp_dir/cross_network_direct_remote_exit_report_symmetric_full.json" symmetric_nat
generate_pass_report cross_network_relay_remote_exit "$temp_dir/cross_network_relay_remote_exit_report_symmetric_full.json" symmetric_nat
generate_pass_report cross_network_failback_roaming "$temp_dir/cross_network_failback_roaming_report_symmetric_full.json" symmetric_nat
generate_pass_report cross_network_traversal_adversarial "$temp_dir/cross_network_traversal_adversarial_report_symmetric_full.json" symmetric_nat
generate_pass_report cross_network_remote_exit_dns "$temp_dir/cross_network_remote_exit_dns_report_symmetric_full.json" symmetric_nat
generate_pass_report cross_network_remote_exit_soak "$temp_dir/cross_network_remote_exit_soak_report_symmetric_full.json" symmetric_nat

cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix \
  --artifact-dir "$temp_dir" \
  --required-nat-profiles baseline_lan,symmetric_nat \
  --expected-git-commit "$current_commit" \
  --require-pass-status \
  --output "$temp_dir/nat_matrix_dual.md"

echo "Cross-network NAT matrix validation tests: PASS"

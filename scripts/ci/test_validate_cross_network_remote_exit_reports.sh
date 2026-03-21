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
captured_at_unix="$(date +%s)"

generate_pass_report() {
  local suite="$1"
  local report_path="$2"

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
    --nat-profile baseline_lan
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

generate_pass_report cross_network_direct_remote_exit "$temp_dir/cross_network_direct_remote_exit_report.json"
generate_pass_report cross_network_relay_remote_exit "$temp_dir/cross_network_relay_remote_exit_report.json"
generate_pass_report cross_network_failback_roaming "$temp_dir/cross_network_failback_roaming_report.json"
generate_pass_report cross_network_traversal_adversarial "$temp_dir/cross_network_traversal_adversarial_report.json"
generate_pass_report cross_network_remote_exit_dns "$temp_dir/cross_network_remote_exit_dns_report.json"
generate_pass_report cross_network_remote_exit_soak "$temp_dir/cross_network_remote_exit_soak_report.json"

cat >"$temp_dir/invalid_same_network.json" <<JSON
{
  "schema_version": 1,
  "phase": "phase10",
  "suite": "cross_network_direct_remote_exit",
  "environment": "ci",
  "evidence_mode": "measured",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${current_commit}",
  "status": "pass",
  "participants": {
    "client_host": "client@example",
    "exit_host": "exit@example"
  },
  "network_context": {
    "client_network_id": "net-a",
    "exit_network_id": "net-a",
    "nat_profile": "baseline_lan",
    "impairment_profile": "none"
  },
  "checks": {
    "direct_remote_exit_success": "pass",
    "remote_exit_no_underlay_leak": "pass",
    "remote_exit_server_ip_bypass_is_narrow": "pass"
  },
  "source_artifacts": [
    "${source_file}"
  ],
  "log_artifacts": [
    "${log_file}"
  ]
}
JSON

cat >"$temp_dir/invalid_pass_with_failed_check.json" <<JSON
{
  "schema_version": 1,
  "phase": "phase10",
  "suite": "cross_network_relay_remote_exit",
  "environment": "ci",
  "evidence_mode": "measured",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${current_commit}",
  "status": "pass",
  "participants": {
    "client_host": "client@example",
    "exit_host": "exit@example",
    "relay_host": "relay@example"
  },
  "network_context": {
    "client_network_id": "net-a",
    "exit_network_id": "net-b",
    "relay_network_id": "net-c",
    "nat_profile": "baseline_lan",
    "impairment_profile": "none"
  },
  "checks": {
    "relay_remote_exit_success": "fail",
    "remote_exit_no_underlay_leak": "pass",
    "remote_exit_server_ip_bypass_is_narrow": "pass"
  },
  "source_artifacts": [
    "${source_file}"
  ],
  "log_artifacts": [
    "${log_file}"
  ]
}
JSON

cat >"$temp_dir/invalid_fail_without_summary.json" <<JSON
{
  "schema_version": 1,
  "phase": "phase10",
  "suite": "cross_network_traversal_adversarial",
  "environment": "ci",
  "evidence_mode": "measured",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${current_commit}",
  "status": "fail",
  "participants": {
    "client_host": "client@example",
    "exit_host": "exit@example",
    "probe_host": "probe@example"
  },
  "network_context": {
    "client_network_id": "net-a",
    "exit_network_id": "net-b",
    "nat_profile": "baseline_lan",
    "impairment_profile": "none"
  },
  "checks": {
    "forged_traversal_rejected": "fail",
    "stale_traversal_rejected": "pass",
    "replayed_traversal_rejected": "pass",
    "rogue_endpoint_rejected": "pass",
    "control_surface_exposure_blocked": "pass"
  },
  "source_artifacts": [
    "${source_file}"
  ],
  "log_artifacts": [
    "${log_file}"
  ]
}
JSON

symlink_source="$temp_dir/source-link.txt"
ln -sf "$source_file" "$symlink_source"

cat >"$temp_dir/invalid_symlink_artifact.json" <<JSON
{
  "schema_version": 1,
  "phase": "phase10",
  "suite": "cross_network_direct_remote_exit",
  "environment": "ci",
  "evidence_mode": "measured",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${current_commit}",
  "status": "pass",
  "participants": {
    "client_host": "client@example",
    "exit_host": "exit@example"
  },
  "network_context": {
    "client_network_id": "net-a",
    "exit_network_id": "net-b",
    "nat_profile": "baseline_lan",
    "impairment_profile": "none"
  },
  "checks": {
    "direct_remote_exit_success": "pass",
    "remote_exit_no_underlay_leak": "pass",
    "remote_exit_server_ip_bypass_is_narrow": "pass"
  },
  "source_artifacts": [
    "${symlink_source}"
  ],
  "log_artifacts": [
    "${log_file}"
  ]
}
JSON

cat >"$temp_dir/invalid_outside_artifact.json" <<JSON
{
  "schema_version": 1,
  "phase": "phase10",
  "suite": "cross_network_direct_remote_exit",
  "environment": "ci",
  "evidence_mode": "measured",
  "captured_at_unix": ${captured_at_unix},
  "git_commit": "${current_commit}",
  "status": "pass",
  "participants": {
    "client_host": "client@example",
    "exit_host": "exit@example"
  },
  "network_context": {
    "client_network_id": "net-a",
    "exit_network_id": "net-b",
    "nat_profile": "baseline_lan",
    "impairment_profile": "none"
  },
  "checks": {
    "direct_remote_exit_success": "pass",
    "remote_exit_no_underlay_leak": "pass",
    "remote_exit_server_ip_bypass_is_narrow": "pass"
  },
  "source_artifacts": [
    "/etc/hosts"
  ],
  "log_artifacts": [
    "${log_file}"
  ]
}
JSON

cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --artifact-dir "$temp_dir" \
  --output "$temp_dir/valid.md"

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/invalid_same_network.json"; then
  echo "expected invalid_same_network.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/invalid_pass_with_failed_check.json"; then
  echo "expected invalid_pass_with_failed_check.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/invalid_fail_without_summary.json"; then
  echo "expected invalid_fail_without_summary.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/invalid_symlink_artifact.json"; then
  echo "expected invalid_symlink_artifact.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/invalid_outside_artifact.json"; then
  echo "expected invalid_outside_artifact.json to fail validation" >&2
  exit 1
fi

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/cross_network_direct_remote_exit_report.json" \
  --expected-git-commit "0000000000000000000000000000000000000000"; then
  echo "expected mismatched git commit to fail validation" >&2
  exit 1
fi

cargo run --quiet -p rustynet-cli -- ops generate-cross-network-remote-exit-report \
  --suite cross_network_direct_remote_exit \
  --report-path "$temp_dir/valid_fail_status.json" \
  --log-path "$log_file" \
  --status fail \
  --failure-summary "synthetic failure" \
  --environment ci \
  --implementation-state implemented \
  --source-artifact "$source_file" \
  --client-host client@example \
  --exit-host exit@example \
  --client-network-id net-a \
  --exit-network-id net-b \
  --nat-profile baseline_lan \
  --impairment-profile none \
  --check direct_remote_exit_success=fail \
  --check remote_exit_no_underlay_leak=pass \
  --check remote_exit_server_ip_bypass_is_narrow=pass >/dev/null

if cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --reports "$temp_dir/valid_fail_status.json" \
  --expected-git-commit "$current_commit" \
  --require-pass-status; then
  echo "expected require-pass-status to reject failing report" >&2
  exit 1
fi

echo "Cross-network remote-exit report schema tests: PASS"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_command cargo
require_command git

./scripts/ci/run_required_test.sh rustynet-control operations::tests::redaction_covers_all_ingestion_paths
./scripts/ci/run_required_test.sh rustynet-control operations::tests::structured_logger_never_writes_cleartext_secrets
./scripts/ci/run_required_test.sh rustynet-control token_claims_debug_redacts_sensitive_fields
./scripts/ci/run_required_test.sh rustynet-control throwaway_credential_debug_redacts_sensitive_fields

./scripts/ci/run_required_test.sh rustynetd daemon::tests::validate_file_security_rejects_group_writable_parent_directory
./scripts/ci/run_required_test.sh rustynetd daemon::tests::validate_file_security_rejects_symlink_parent_directory
./scripts/ci/run_required_test.sh rustynetd daemon::tests::passphrase_permission_mask_accepts_systemd_runtime_credential_mode
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_removes_target_file
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_rejects_directory
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_removes_symlink_without_following_target

./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_rejects_group_readable_file
./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_rejects_symlink_path
./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_accepts_owner_only_file
./scripts/ci/run_required_test.sh rustynet-cli secure_remove_file_rejects_directory
./scripts/ci/run_required_test.sh rustynet-cli secure_remove_file_removes_target_file
./scripts/ci/run_required_test.sh rustynet-cli create_secure_temp_file_sets_owner_only_mode

cargo run --quiet -p rustynet-cli -- ops check-secrets-hygiene \
  --root "$ROOT_DIR"

echo "Secrets hygiene gate: PASS"

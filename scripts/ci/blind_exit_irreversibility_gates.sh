#!/usr/bin/env bash
# BlindExit irreversibility gates: verification method for SecurityMinimumBar
# section 6.D control 2.
#
#   "A node currently in role `blind_exit` MUST refuse every other-role
#    transition without an explicit factory-reset operator step ... The wizard
#    surface MUST require typed confirmation (not just Enter) when entering or
#    leaving `blind_exit`."
#
# Enforcement points (static checks below, then the tests that exercise them):
#   - rustynet-control role_presets::validate_transition classifies every
#     blind_exit -> other-role transition as TransitionKind::Blocked and every
#     other -> blind_exit transition as Irreversible (never allowed silently).
#   - rustynet-cli role_cli plans the same transitions as RoleSetPlan::Blocked
#     with BlindExitImmutable (leaving), BlindExitRequiresExplicitAcknowledgement
#     (entering without the acknowledgement) and RequiresStagedTransition
#     (entering with it: the staged factory-reset path, never a one-step switch).
#
# What this gate does NOT cover (stated so the control is not over-claimed): the
# interactive wizard's typed-confirmation prompt has no dedicated test; the
# explicit-acknowledgement flag on the CLI path is the pinned proxy.
#
# Every test below runs through run_required_test, so a renamed, deleted or
# cfg-gated test makes this gate FAIL (zero tests matched) instead of passing.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=lib/required_test.sh
source "${repo_root}/scripts/ci/lib/required_test.sh"
cd "${repo_root}"

echo "Running blind_exit irreversibility CI gates..."

# Static enforcement points. -F: these are literal identifiers/paths.
rg -qF 'pub fn validate_transition' crates/rustynet-control/src/role_presets.rs
rg -qF 'Irreversible(' crates/rustynet-control/src/role_presets.rs
rg -qF 'BlindExitImmutable' crates/rustynet-cli/src/role_cli.rs
rg -qF 'BlindExitRequiresExplicitAcknowledgement' crates/rustynet-cli/src/role_cli.rs
rg -qF 'RequiresStagedTransition' crates/rustynet-cli/src/role_cli.rs

# Transition matrix (rustynet-control): leaving blind_exit is blocked for every
# target; entering it is irreversible with a destructive reason; the lock-out
# reason text and empty side-effect set are pinned.
run_required_test -p rustynet-control --lib role_presets::tests::every_transition_leaving_blind_exit_is_blocked
run_required_test -p rustynet-control --lib role_presets::tests::blind_exit_to_anything_else_is_blocked
run_required_test -p rustynet-control --lib role_presets::tests::blind_exit_lockout_pins_reason_and_empty_side_effects
run_required_test -p rustynet-control --lib role_presets::tests::anything_to_blind_exit_is_irreversible
run_required_test -p rustynet-control --lib role_presets::tests::becoming_blind_exit_is_irreversible_with_destructive_reason
run_required_test -p rustynet-control --lib role_presets::tests::blind_relay_to_blind_exit_stays_irreversible

# Planner (rustynet-cli): leaving is Blocked, entering needs the explicit
# acknowledgement and even then only returns the staged factory-reset path,
# service-hosting roles cannot be reached from blind_exit.
run_required_test -p rustynet-cli --lib role_cli::tests::leaving_blind_exit_is_blocked
run_required_test -p rustynet-cli --lib role_cli::tests::entering_blind_exit_without_ack_is_blocked
run_required_test -p rustynet-cli --lib role_cli::tests::entering_blind_exit_with_ack_still_returns_staged_path
run_required_test -p rustynet-cli --lib role_cli::tests::blind_exit_to_nas_and_llm_is_locked

echo "blind_exit irreversibility CI gates: PASS"

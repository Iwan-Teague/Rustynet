#!/usr/bin/env bash
set -euo pipefail

# LLM default-deny gates (D13.d — LlmNodeRoleDesign §9 controls):
# service-context truth table, identity-from-tunnel (no API key),
# model/quota/rate scoping, session-token ≤ signed policy (E4),
# loopback-only engine boundary, revoke-mid-stream severance, and
# deny-on-malformed wire input (prompts are attacker-influenced).

echo "Running LLM default-deny gates..."

required_files=(
  crates/rustynet-llm-gateway/src/session.rs
  crates/rustynet-llm-gateway/src/enforce.rs
  crates/rustynet-llm-gateway/src/engine.rs
  crates/rustynet-llm-gateway/src/protocol.rs
  crates/rustynet-llm-gateway/src/main.rs
  scripts/systemd/rustynet-llm-gateway.service
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# Enforcement points present.
rg -q 'RoleCapability::ServesLlm' crates/rustynet-control/src/roles.rs
rg -q 'validate_engine_endpoint' crates/rustynet-llm-gateway/src/main.rs
# No API-key MECHANISM anywhere in the contract: identity is the
# tunnel. (Prose saying "no API key" is expected; an `api_key`
# identifier, header name, or env var is the defect.)
if rg -q 'api_key|apikey|x-api-key|API_KEY' crates/rustynet-llm-gateway/src/; then
  rg -n 'api_key|apikey|x-api-key|API_KEY' crates/rustynet-llm-gateway/src/ >&2
  echo "GATE DEFECT: api-key mechanism found in the llm gateway" >&2
  exit 1
fi
# Mid-stream severance: grants re-checked between token events.
rg -q 'stream severed' crates/rustynet-llm-gateway/src/main.rs

run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

# Truth table (shared with the NAS gate but pinned here too: the
# LlmService side of the scoped-allow test is the LLM evidence).
run_required_test -p rustynet-policy service_contexts_default_to_deny_on_empty_policy
run_required_test -p rustynet-policy service_allow_is_scoped_to_peer_and_service

# Model/quota/rate scoping (restrictions on a grant, never a grant).
run_required_test -p rustynet-policy llm_access_scope_permits_model_truth_table
run_required_test -p rustynet-policy llm_scope_policy_scope_for_prefers_most_specific_selector
run_required_test -p rustynet-llm-gateway enforce::tests::model_outside_allow_list_refused
run_required_test -p rustynet-llm-gateway enforce::tests::rate_limit_trips_on_third_request_and_resets_after_minute
run_required_test -p rustynet-llm-gateway enforce::tests::token_quota_severs_stream_and_window_resets

# E4 — token can never exceed CURRENT signed policy.
run_required_test -p rustynet-llm-gateway session::tests::e4_pin_valid_in_ttl_token_dies_under_current_deny
run_required_test -p rustynet-llm-gateway session::tests::issuance_refused_under_deny_token_never_originates_access

# Engine boundary: loopback only, fail-closed.
run_required_test -p rustynet-llm-gateway engine::tests::non_loopback_endpoints_refused_fail_closed

# Wire hardening: prompt caps before allocation; no decoder panics.
run_required_test -p rustynet-llm-gateway protocol::tests::oversize_prompt_refused_before_allocation
run_required_test -p rustynet-llm-gateway protocol::tests::decoders_never_panic_on_random_input

echo "LLM default-deny gates: PASS"

# Backend Agility Validation

## Objective
Guarantee that WireGuard remains the default backend adapter while the control/policy/domain layers stay protocol-agnostic and backend-swappable.

## Required Conditions
- WireGuard remains behind `TunnelBackend` interface boundaries.
- At least one additional backend path exists and is runnable through the same interface.
- Backend conformance suite must pass before support claims.
- Backend support claim requires security review completion.
- Any WireGuard leakage outside adapter crates blocks release.

## Implemented Backends
- Default: `rustynet-backend-wireguard`
- Additional path: `rustynet-backend-stub`

## Enforcement Points
- `crates/rustynet-backend-api/src/lib.rs` (`TunnelBackend` contract)
- `crates/rustynet-control/src/ga.rs` (`BackendAgilityValidation::passes`)
- `scripts/ci/phase1_gates.sh` (WireGuard leakage gate)
- `scripts/ci/phase9_gates.sh` (backend conformance + agility checks)

## Evidence
Artifact:
- `artifacts/operations/backend_agility_report.json`

Conformance and boundary checks:
- `cargo test -p rustynet-backend-wireguard --test conformance`
- `cargo test -p rustynet-backend-stub --all-targets --all-features`
- `scripts/ci/phase1_gates.sh`

## Fail-Closed Rule
If backend conformance fails, leakage is detected, or security review is incomplete, release promotion is blocked.

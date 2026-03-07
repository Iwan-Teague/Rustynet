# Backend Agility Validation

## Objective
Guarantee that WireGuard remains the default backend adapter while the control/policy/domain layers stay protocol-agnostic and backend-swappable.

## Required Conditions
- WireGuard remains behind `TunnelBackend` interface boundaries.
- At least one additional backend path exists and is runnable through the same interface.
- Additional backend path cannot be a stub/fake/mock/simulated backend.
- Backend conformance suite must pass before support claims.
- Backend support claim requires security review completion.
- Any detected WireGuard leakage outside adapter crates blocks release.

## Implemented Backends
- Default: `rustynet-backend-wireguard`
- Additional path: must be an implementation that is non-simulated and validated with measured evidence.

## Current Implementation Discrepancy (Needs Code Work)
- Current in-tree `TunnelBackend` implementations are:
  - `rustynet-backend-wireguard` (`WireguardBackend` / OS variants),
  - `rustynet-backend-stub` (`StubBackend`, simulated).
- Security/compliance discrepancy:
  - policy requires at least one **additional non-simulated** backend path,
  - current repository code does not yet contain a second non-simulated `TunnelBackend` implementation.
- Security risk truth:
  - release or readiness claims can overstate backend agility and recovery options,
  - architectural monoculture increases impact if a WireGuard-specific defect/security issue requires rapid backend substitution.
- Required improvement:
  - implement and validate a second non-simulated backend path in code (not artifact-only evidence).

## Enforcement Points
- `crates/rustynet-backend-api/src/lib.rs` (`TunnelBackend` contract)
- `crates/rustynet-control/src/ga.rs` (`BackendAgilityValidation::passes`)
- `scripts/ci/check_backend_boundary_leakage.sh` (shared protocol-boundary leakage gate)
- `scripts/ci/phase1_gates.sh` (invokes shared leakage gate)
- `scripts/ci/phase9_gates.sh` (backend conformance + agility checks)

## Boundary Leakage Gate (Hardened)
- Gate logic is centralized in `scripts/ci/check_backend_boundary_leakage.sh`.
- Scan behavior is case-insensitive and fail-closed for protocol-specific tokens (`wireguard`, `wg-`, `wg_`, `wgctrl`).
- Scan scope is protocol-agnostic runtime code only:
  - `crates/rustynet-control/src`
  - `crates/rustynet-policy/src`
  - `crates/rustynet-crypto/src`
  - `crates/rustynet-backend-api/src`
  - `crates/rustynet-relay/src`
- Shared use across phase gates removes regex drift and closes lowercase bypass class.

## Evidence
Artifact:
- `artifacts/operations/backend_agility_report.json`
- Generated via `scripts/operations/generate_phase9_artifacts.sh` from measured raw evidence inputs.

Conformance and boundary checks:
- `cargo test -p rustynet-backend-wireguard --test conformance`
- `cargo test -p rustynet-backend-api --all-targets --all-features`
- `scripts/ci/phase1_gates.sh`

## Fail-Closed Rule
If backend conformance fails, leakage is detected, security review is incomplete, or evidence uses simulated backend paths, release promotion is blocked.

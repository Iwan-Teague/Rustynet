# Compatibility and Support Policy

## Scope
This policy governs Rustynet control-plane/client compatibility, upgrade sequencing, and deprecation behavior for GA operation.

## Versioning Guarantees
- Control-plane and clients use `major.minor` API versions.
- Compatibility is allowed only when client `major == server major`.
- Minimum supported client is enforced as a hard floor.
- Clients below minimum support are rejected (fail closed).

Current policy artifact:
- `artifacts/operations/compatibility_policy.json`

## Support Window
- Minimum supported client: `1.2`
- Latest server version: `1.9`
- Deprecation window: `90 days`
- Older in-major clients above minimum are admitted as deprecated and tracked for upgrade.

## Upgrade and Migration Rules
1. Upgrade control plane first.
2. Enforce minimum compatible client version from control plane.
3. Upgrade clients before deprecation window closes.
4. Disable legacy compatibility mode by default throughout rollout.

## Insecure Compatibility Exceptions
- Disabled by default.
- Exception enablement requires explicit risk acceptance ID and security approver.
- Exception TTL must be bounded and auto-expiring.
- Expired/missing-trust exception state is rejected (fail closed).

## Enforcement Points
- `crates/rustynet-control/src/ga.rs`
  - `CompatibilityPolicy::evaluate`
  - `InsecureCompatibilityException::validate_active`
- `scripts/ci/check_phase9_readiness.sh`
  - validates policy artifact invariants for support windows and exception constraints.

## Verification
- `cargo test -p rustynet-control --all-targets --all-features`
- `scripts/ci/phase9_gates.sh`

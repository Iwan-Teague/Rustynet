# Cryptographic Deprecation and Removal Schedule

## Policy
Rustynet only allows production cryptographic primitives that satisfy the approved allowlist policy. Legacy/insecure algorithms are denied by default unless explicitly approved by time-bounded risk acceptance.

## Schedule Source
- `artifacts/operations/crypto_deprecation_schedule.json`

## Current Deprecation Calendar
| Algorithm | Deprecates At (UTC) | Removal At (UTC) | Release Behavior |
|---|---|---|---|
| `sha1` | 2026-03-01T00:00:00Z | 2026-06-01T00:00:00Z | Warning during deprecation, denied after removal |
| `3des` | 2026-03-01T00:00:00Z | 2026-06-01T00:00:00Z | Warning during deprecation, denied after removal |

## Exception Rules
- Insecure compatibility modes are disabled by default.
- Exceptions require explicit risk acceptance ID and security approver.
- Exceptions must auto-expire; expired exceptions are rejected (fail closed).

## Enforcement Points
- `crates/rustynet-crypto/src/lib.rs` (algorithm allowlist/denylist)
- `crates/rustynet-control/src/ga.rs`
  - `CryptoDeprecationCalendar::lifecycle_for`
  - `InsecureCompatibilityException::validate_active`
- `scripts/ci/check_phase9_readiness.sh` validates schedule and exception defaults.

## Verification
- `cargo test -p rustynet-crypto --all-targets --all-features`
- `cargo test -p rustynet-control --all-targets --all-features`
- `scripts/ci/phase9_gates.sh`

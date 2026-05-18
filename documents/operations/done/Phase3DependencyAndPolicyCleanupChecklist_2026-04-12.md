# Phase 3 Dependency And Policy Cleanup Checklist

Prepared: 2026-04-12
Scope: `crates/rustynet-backend-wireguard`, `third_party/boringtun`, `third_party/rustynet-tun`, and direct workspace `rand` dependencies
Objective: remove the `paste` supply-chain path, eliminate the current advisory and license-policy blockers, and keep the security model fail-closed without widening policy

## Checklist

- [x] The exact `paste` path was identified and removed from the active dependency graph
  Evidence:
  - previous path: `rustynet-backend-wireguard -> tun-rs -> netconfig-rs/route_manager/... -> paste`
  - code: `crates/rustynet-backend-wireguard/Cargo.toml`
  - code: `third_party/rustynet-tun/Cargo.toml`
  - code: `third_party/rustynet-tun/src/lib.rs`
  - code: `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs`

- [x] The repo no longer depends on `tun-rs` for the active Linux userspace-shared path
  Evidence:
  - code: `crates/rustynet-backend-wireguard/Cargo.toml`
  - code: `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs`
  - tests: `cargo test -p rustynet-backend-wireguard --offline`

- [x] License-policy blockers from the prior upstream `boringtun` dependency surface were removed without allowlists
  Evidence:
  - code: `third_party/boringtun/Cargo.toml`
  - code: `third_party/boringtun/src/lib.rs`
  - code: `third_party/boringtun/src/noise/handshake.rs`
  - code: `third_party/boringtun/src/noise/session.rs`
  - code: `third_party/boringtun/src/noise/rate_limiter.rs`
  - tests: `cargo test -p rustynet-backend-wireguard --offline`

- [x] The workspace direct `rand` dependency was upgraded out of `RUSTSEC-2026-0097`
  Evidence:
  - code: `Cargo.toml`
  - code: `crates/rustynet-cli/Cargo.toml`
  - code: `crates/rustynet-control/Cargo.toml`
  - code: `crates/rustynet-crypto/Cargo.toml`
  - code: `crates/rustynet-relay/Cargo.toml`
  - code: `crates/rustynetd/Cargo.toml`
  - code: `Cargo.lock`

- [x] OS randomness failure is now explicit where the new `rand` API requires it
  Evidence:
  - code: `crates/rustynet-cli/src/main.rs`
  - code: `crates/rustynet-cli/src/ops_e2e.rs`
  - code: `crates/rustynet-cli/src/ops_install_systemd.rs`
  - code: `crates/rustynet-cli/src/ops_phase9.rs`
  - code: `crates/rustynet-control/src/lib.rs`
  - code: `crates/rustynet-relay/src/session.rs`
  - code: `crates/rustynetd/src/traversal.rs`

- [x] Phase 3 rationale is written down with rejected alternatives
  Evidence:
  - rationale: this document, “Decision And Rationale”

## Decision And Rationale

### Exact `paste` path

The unmaintained `paste` crate was not coming from the Rustynet workspace directly. It entered through the Linux userspace-shared backend path:

- `rustynet-backend-wireguard`
- `tun-rs`
- `netconfig-rs` and its route-management helpers
- `paste`

That path was removed by replacing `tun-rs` with a narrow in-repo crate, `third_party/rustynet-tun`, which implements only the Linux `/dev/net/tun` behavior that the active backend actually needs.

### Chosen result

The accepted Phase 3 result has three parts:

1. Replace `tun-rs` with the in-repo `rustynet-tun` crate for the active Linux userspace-shared path.
2. Narrow the active `boringtun` dependency surface to an in-repo vendored copy that excludes the policy-blocking license set which was not needed for Rustynet’s active use.
3. Upgrade direct workspace `rand` usage from `0.8.5` to `0.9.3` and make `OsRng` failure explicit instead of treating it as infallible.

This is better for security and maintainability than the previous state because:

- it removes the unmaintained `paste` path entirely instead of tolerating it
- it preserves the single hardened userspace-shared execution path instead of adding a fallback
- it avoids policy exceptions, ignore files, or advisory allowlists
- it shrinks the active dependency surface to the minimum code Rustynet actually uses
- it improves failure semantics around OS entropy by making those failure points explicit

### Alternatives considered and rejected

- Keep `tun-rs` and add advisory or license exceptions.
  Rejected because it widens policy instead of fixing the dependency path.

- Keep upstream `boringtun` as-is and add license-policy exceptions.
  Rejected because the blocked crates were outside the minimal surface Rustynet actually needs, and an exception would preserve unnecessary exposure.

- Replace the full userspace-shared backend or the full WireGuard engine in Phase 3.
  Rejected because it is much higher-risk churn than needed to eliminate the actual blockers.

- Introduce a non-cryptographic or custom fallback RNG path to avoid `OsRng` failure handling changes.
  Rejected because it would soften the security model. The chosen implementation fails closed instead.

## Validation Evidence

- [x] `cargo fmt --all -- --check`
- [x] `cargo check -p rustynet-backend-wireguard --offline`
- [x] `cargo test -p rustynet-backend-wireguard --offline`
- [x] `cargo check --workspace --all-targets --all-features --offline`
- [x] `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`
- [x] `cargo test --workspace --all-targets --all-features --offline`
- [x] `cargo audit --deny warnings`
- [x] `cargo deny check advisories bans licenses sources`

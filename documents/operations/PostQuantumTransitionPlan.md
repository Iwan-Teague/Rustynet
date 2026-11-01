# Post-Quantum Transition and Hybrid Evaluation Plan

## Constraints
- No custom cryptography or custom VPN protocol is introduced in production paths.
- WireGuard remains default backend while migration planning is validated through modular backend boundaries.

## Goal
Prepare a controlled path for future PQ/hybrid adoption without destabilizing current proven cryptography.

## State In The Tree (re-checked 2026-11-01)
- `crates/rustynet-crypto/src/mlkem.rs` provides ML-KEM-768 (FIPS 203) encapsulation/decapsulation and the HKDF-SHA256 tunnel pre-shared-key derivation `derive_tunnel_psk` (pure Rust `ml-kem`, secrets zeroized; the raw KEM shared secret is a distinct type that cannot be used as a PSK directly).
- The backend crates carry a `PresharedKey` custody wrapper and the per-OS backends accept one.
- No daemon or CLI code path calls `derive_tunnel_psk` or the ML-KEM types yet (the only reference outside `rustynet-crypto` is a redaction-registry entry in `crates/rustynetd/src/secret_log_audit.rs`), so no hybrid/PQ mode is active in any production path. Treat the stages below as not yet started beyond the primitive.

## Hybrid Evaluation Stages
1. Lab-only hybrid candidate validation:
   - Evaluate candidate stacks from established libraries/protocols only.
   - Confirm compatibility with `TunnelBackend` abstraction and control-plane policy boundaries.
2. Interop test stage:
   - Validate negotiated fallback behavior with existing WireGuard default path.
   - Confirm fail-closed behavior when hybrid trust state is incomplete.
3. Canary stage:
   - Enable only under explicit feature flag and risk acceptance.
   - Collect latency, reconnect, and failure-mode metrics.
4. Decision gate:
   - Security review complete.
   - Performance regression within policy.
   - Operational runbooks updated.

## Decision Criteria
- No regression against Security Minimum Bar controls.
- No leakage of backend-specific types into control/policy domains.
- No unresolved high-risk findings from security review.

## Rollback Criteria
- Any trust-state validation error.
- Performance budget violation.
- Control-plane or data-plane availability degradation beyond SLOs.

## Ownership
- Engineering owner: backend modularity and rollout sequencing.
- Security owner: cryptographic review and risk acceptance governance.
- Operations owner: runbook/on-call readiness for staged rollout.

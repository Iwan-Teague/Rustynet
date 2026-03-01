# Rustynet Phase 1 Implementation (Production-Grade)

## 1) Objective and Exact Phase 1 Boundaries
Phase 1 delivers architecture and security foundations that are mandatory for safe implementation of all later features. Phase 1 is complete only when boundaries, contracts, security baselines, and quality gates are codified and testable.

### In Scope (Phase 1)
- Rust workspace and crate boundary enforcement for:
  - `crates/rustynet-control`
  - `crates/rustynetd`
  - `crates/rustynet-cli`
  - `crates/rustynet-relay`
  - `crates/rustynet-policy`
  - `crates/rustynet-crypto`
  - `crates/rustynet-backend-api`
  - `crates/rustynet-backend-wireguard`
- Protocol-agnostic backend abstraction contract (`TunnelBackend`) with explicit capability model.
- Hard separation rule: no WireGuard-specific types/config semantics in control-plane, policy, or domain crates.
- Security baseline artifacts:
  - key hierarchy and custody model
  - token model and revocation semantics
  - threat model v1 and trust boundaries
  - authentication abuse-control baseline
  - cryptographic allowlist/denylist and deprecation policy
- Engineering quality baseline:
  - CI command gates and failure criteria
  - backend contract test harness skeleton
  - performance harness skeleton and budget definitions

### Out of Scope (Not Phase 1 Delivery)
- Production enrollment/auth endpoint implementation.
- Linux/macOS/Windows production tunnel plumbing.
- Exit node, LAN toggle, Magic DNS runtime behavior.
- Multi-tenant, UI, SSO, compliance operations.

These features are intentionally excluded from Phase 1 implementation scope and are addressed by their owning phase documents without changing Phase 1 boundaries.

## 2) Normative References and Precedence Rules
### Normative References
1. [Requirements.md](./Requirements.md)
2. [SecurityMinimumBar.md](./SecurityMinimumBar.md)
3. [Phase1.md](./Phase1.md)
4. [Phase2.md](./Phase2.md) through [Phase9.md](./Phase9.md) (forward-compatibility constraints only)
5. Current workspace architecture:
   - `/Users/iwanteague/Desktop/Rustynet/Cargo.toml`
   - `/Users/iwanteague/Desktop/Rustynet/crates/*`

### Precedence Rules
1. `Requirements.md` is the source of truth for product/security requirements.
2. `SecurityMinimumBar.md` is release-blocking and cannot be weakened.
3. `Phase1.md` defines the required delivery slice for this phase.
4. This document defines executable implementation details for Phase 1 and cannot contradict items 1-3.
5. Phase 2-9 documents may influence interface extensibility decisions, but cannot alter Phase 1 requirements.

### Conflict Resolution
- If any implementation detail in this document conflicts with `Requirements.md`, update this document to match requirements immediately.
- If a security control in this document is weaker than `SecurityMinimumBar.md`, the control is invalid and must be replaced with the stronger requirement.
- If code behavior differs from this document, code is treated as non-compliant until corrected.

## 3) Final Architecture for Phase 1 (Crate Ownership and Responsibilities)
### Workspace Ownership Model
- `rustynet-backend-api`:
  - Owns protocol-agnostic transport domain contract.
  - Owns `TunnelBackend`, `BackendCapabilities`, backend errors, route/peer/runtime types.
  - Must not import any protocol adapter crate.
- `rustynet-backend-wireguard`:
  - Owns WireGuard adapter implementation only.
  - May translate generic backend contract into WireGuard-specific runtime behavior.
  - Must not leak WireGuard-specific types through public API outside adapter crate.
- `rustynetd`:
  - Owns client daemon orchestration.
  - Consumes `TunnelBackend` trait object; does not depend on WireGuard internals.
  - Owns runtime sequencing rules (start/configure/apply_routes/set_exit_mode/shutdown).
- `rustynet-control`:
  - Owns control-plane architecture baseline, signing-policy baseline, and policy decision integration contract.
  - Must remain protocol-agnostic.
- `rustynet-policy`:
  - Owns default-deny policy primitives and deterministic evaluation rules.
  - Must not know tunnel/backend internals.
- `rustynet-crypto`:
  - Owns crypto material handling primitives, key hierarchy model, algorithm policy enforcement.
  - Owns secure-memory handling requirements (zeroization) and key-custody interface baseline.
- `rustynet-cli`:
  - Owns operator/user command interface surface.
  - Must call daemon/control contracts; no backend-specific assumptions.
- `rustynet-relay`:
  - Owns ciphertext-forwarding service boundary definition only.
  - Must never require payload decryption capability.

### Enforced Dependency Direction
- Allowed:
  - `rustynetd -> rustynet-backend-api`, `rustynetd -> rustynet-policy`, `rustynetd -> rustynet-crypto`
  - `rustynet-backend-wireguard -> rustynet-backend-api`
  - `rustynet-control -> rustynet-policy`, `rustynet-control -> rustynet-crypto`
- Disallowed:
  - `rustynet-control -> rustynet-backend-wireguard`
  - `rustynet-policy -> rustynet-backend-wireguard`
  - `rustynet-backend-api -> rustynet-backend-wireguard`
  - Any crate importing WireGuard-specific symbols except `rustynet-backend-wireguard`

### Architectural Guardrails
- Rust-first implementation across all core components.
- `unsafe` remains forbidden at workspace level.
- Control/policy/domain models remain transport-protocol-agnostic.
- Adapter-specific behavior is isolated to adapter crate(s).

## 4) Backend Abstraction Contract Details (TunnelBackend Boundary, Capabilities, Invariants)
### Contract Surface (Phase 1 Baseline)
`TunnelBackend` methods are the only allowed control point for data-plane orchestration in Phase 1:
- `name()`
- `capabilities()`
- `start(context)`
- `configure_peer(peer)`
- `remove_peer(node_id)`
- `apply_routes(routes)`
- `set_exit_mode(mode)`
- `stats()`
- `shutdown()`

### Capability Contract
`BackendCapabilities` is authoritative for feature checks:
- `supports_roaming`
- `supports_exit_nodes`
- `supports_lan_routes`
- `supports_ipv6`

Fail-closed rule: unsupported capability requests must return an error and must not silently degrade behavior.

### Invariants
1. `start` may be called only once per running lifecycle; second call must fail.
2. `configure_peer`, `remove_peer`, `apply_routes`, `set_exit_mode`, and `stats` require running state.
3. `shutdown` clears in-memory peer/route/session state and resets exit mode.
4. `NodeId` and peer identifiers must be non-empty and canonicalized before insertion.
5. `apply_routes` is replace-all semantics for deterministic route state.
6. Backend errors must be typed (`InvalidInput`, `AlreadyRunning`, `NotRunning`, `Internal`) and non-ambiguous.
7. No method may expose protocol-specific internal representations to callers.

### Boundary Enforcement
- Enforcement point:
  - `crates/rustynet-backend-api/src/lib.rs` type system and public API boundary.
  - crate import policies in workspace review/CI checks.
- Verification method:
  - compile-time dependency checks.
  - grep-based boundary tests for protocol symbol leakage.
  - backend contract tests validating lifecycle/error invariants.

## 5) Security Baseline Implementation
### 5.1 Threat Model v1
### Assets
- Node private identity keys.
- Control-plane signing keys and trust state.
- Enrollment/auth tokens and one-time credentials.
- Policy definitions and route authority data.
- Audit trail integrity.

### Adversaries
- Internet attacker performing brute-force, replay, and abuse traffic.
- Malicious insider or compromised admin endpoint.
- Compromised node attempting lateral movement or privilege escalation.
- Attacker with temporary access to disk backups or host filesystem.
- Adversary attempting protocol confusion or weak-algorithm downgrade.

### Security Objectives
- Preserve confidentiality/integrity of mesh and control-plane operations.
- Enforce default-deny authorization and route policy.
- Prevent replay and abuse-driven state exhaustion.
- Prevent key/token leakage from logs/config surfaces.
- Preserve protocol modularity without reducing security controls.

### 5.2 Trust Boundaries
1. Client daemon (`rustynetd`) boundary:
- Crossing data: policy snapshots, peer maps, tokens, runtime commands.
- Enforcement: signature verification requirement, strict schema validation, redaction-safe logging.

2. Control-plane boundary (`rustynet-control`):
- Crossing data: enrollment/auth requests, node metadata mutations.
- Enforcement: TLS 1.3 only, abuse controls (rate limit/lockout/replay), RBAC baseline contract.

3. Backend boundary (`rustynet-backend-api` to adapter):
- Crossing data: generic peer/route/runtime instructions.
- Enforcement: trait invariants, capability checks, typed errors, no protocol leakage.

4. Key custody boundary (`rustynet-crypto` to OS/file system):
- Crossing data: encrypted key blobs, key metadata, memory-resident secrets.
- Enforcement: secure storage selection, permission checks, zeroization, fail-closed startup.

### 5.3 Auth Attack-Surface Controls (Baseline Spec)
These controls are mandatory Phase 1 baseline definitions and must be implemented through shared middleware contracts in Phase 2 without changing defaults.

1. Rate limiting:
- Default: per-IP token bucket (burst 20, refill 10/min), per-identity (burst 10, refill 5/15min).
- Enforcement point: `rustynet-control` auth middleware interface.
- Verification: negative tests must prove throttling under burst traffic.

2. Lockout/backoff:
- Default: exponential backoff starting at 30s, capped at 15m, reset only after successful auth + cooldown.
- Enforcement point: auth decision engine contract in `rustynet-control`.
- Verification: deterministic test cases for repeated failures and cooldown reset.

3. Anti-replay:
- Default token lifetime: 5 minutes; nonce/state required for all state-changing auth/enrollment operations.
- Clock skew tolerance: +/- 90 seconds; beyond this => reject.
- Enforcement point: token validation and nonce store interface.
- Verification: replay token reuse tests, stale token tests, skew boundary tests.

4. Abuse visibility:
- Baseline signal fields: source IP, identity handle, endpoint, failure class, limiter decision.
- Enforcement point: structured security event schema in `rustynet-control`.
- Verification: test asserts required fields exist and secrets are redacted.

Fail-closed rule: if abuse-control subsystem state cannot be read or updated, auth/enrollment operation is denied.

### 5.4 Key Custody Fallback Behavior
1. Primary storage:
- OS secure key storage APIs when available.

2. Fallback storage (when OS key store unavailable):
- Encrypted-at-rest key blob using AEAD (`AES-256-GCM` or `XChaCha20-Poly1305` via vetted library).
- Envelope key derived with `Argon2id` from operator-provided secret plus per-host salt.
- File permissions enforced at startup (`0700` directory, `0600` file, owner-only access).
- Automatic startup refusal on permission mismatch or encryption metadata mismatch.

3. Memory handling:
- Sensitive key material wrapped in zeroizing containers (`zeroize` semantics).
- Debug and log formatting for secret types must redact bytes by default.

4. Trust-state persistence:
- Signed-authorization trust state must be integrity-checked on load.
- Missing/corrupt/unwritable trust state => trust-required operations denied with explicit operator error.

Verification methods:
- permission-check unit/integration tests.
- corrupted-keystore negative tests.
- trust-state unavailable tests asserting fail-closed behavior.
- memory redaction tests for debug/log code paths.

### 5.5 Cryptographic Allowlist/Denylist and Deprecation Policy
### Allowlist (Phase 1 Baseline)
- Transport security:
  - TLS 1.3 only (`rustls`) for control-plane transport.
  - WireGuard protocol model for tunnel crypto (no custom protocol).
- Signatures:
  - `Ed25519` for control-plane signed artifacts.
- Hash/KDF:
  - `SHA-256`/`SHA-512`, `BLAKE2s/BLAKE2b` where applicable.
  - `HKDF-SHA256` and `Argon2id` for approved derivation contexts.
- AEAD (non-tunnel local storage contexts):
  - `AES-256-GCM` or `XChaCha20-Poly1305`.

### Denylist (Hard Rejection)
- `MD5`, `SHA-1` for security integrity/signing.
- `RC4`, `DES`, `3DES`, `BF-CBC`, and non-AEAD CBC tunnel/storage modes.
- Static/shared long-lived session keys without rekey model.
- Weak DH groups (< 2048-bit) and protocol downgrade paths.

### Deprecation and Exception Policy
- Insecure compatibility modes default to disabled.
- Any temporary exception requires:
  - documented risk owner
  - explicit expiry date
  - runtime auto-expiry behavior
  - explicit operator-visible warning
- After expiry, system returns to deny mode automatically.

Enforcement point:
- `rustynet-crypto` algorithm policy module and config validation at startup.

Verification:
- allowlist/denylist unit tests.
- configuration negative tests that must fail startup on denied algorithm.
- test that expired exception entries are rejected.

## 6) Data Model and State Strategy for Phase 1
### Phase 1 Canonical Domain Types
- Backend domain (`rustynet-backend-api`):
  - `NodeId`
  - `SocketEndpoint`
  - `PeerConfig`
  - `Route` + `RouteKind`
  - `RuntimeContext`
  - `BackendCapabilities`
  - `TunnelStats`
  - `BackendError` + `BackendErrorKind`
- Policy domain (`rustynet-policy`):
  - `PolicyRule`
  - `AccessRequest`
  - `Decision`
- Crypto domain (`rustynet-crypto`):
  - `PublicKey`
  - `SecretKey`
  - `NodeKeyPair`
  - `CryptoError`

### State Strategy
1. Runtime state:
- Backend lifecycle state in-memory only (`not running` or `running`).
- Peer/route state maintained by backend adapter with deterministic replace/clear semantics.

2. Security policy state:
- Cryptographic allowlist/denylist and abuse-control defaults are versioned configuration artifacts.
- Any invalid security policy load results in startup failure (fail-closed).

3. Trust and key state:
- Trust-required state cannot be treated as optional.
- Key custody must pass secure-store or encrypted-fallback checks before service start.

4. Schema/version strategy:
- All security-relevant config structures include explicit version field (`v1` baseline).
- Unknown major versions are rejected at load time.

## 7) CI/Security Gates for Phase 1 (Exact Commands and Pass Criteria)
All commands run from `/Users/iwanteague/Desktop/Rustynet`.

1. Formatting gate:
```bash
cargo fmt --all -- --check
```
Pass criteria: exit code `0`; no formatting diffs.

2. Lint gate:
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
Pass criteria: exit code `0`; zero warnings.

3. Build/type gate:
```bash
cargo check --workspace --all-targets --all-features
```
Pass criteria: exit code `0`.

4. Test gate:
```bash
cargo test --workspace --all-targets --all-features
```
Pass criteria: exit code `0`; all tests pass.

5. Dependency vulnerability gate:
```bash
cargo audit --deny warnings
```
Pass criteria: exit code `0`; no unresolved vulnerable dependencies without approved exception.

6. Dependency policy gate:
```bash
cargo deny check bans licenses sources advisories
```
Pass criteria: exit code `0`; policy-compliant dependency tree.

7. Protocol leakage boundary gate:
```bash
rg -n "(Wireguard|WireGuard|wg[-_]|wgctrl)" \
  crates/rustynet-control crates/rustynet-policy crates/rustynet-crypto \
  crates/rustynet-backend-api crates/rustynet-cli crates/rustynet-relay
```
Pass criteria: no matches.

8. Unsafe gate:
```bash
rg -n "\\bunsafe\\b" crates
```
Pass criteria: no `unsafe` blocks; workspace lint remains `forbid`.

9. Documentation hygiene gate:
```bash
rg -n "\\[\\[UNRESOLVED\\]\\]|\\{\\{UNRESOLVED\\}\\}" crates documents
```
Pass criteria: no matches.

Fail-closed CI rule: any gate failure blocks merge.

## 8) Performance Baseline Harness Requirements for Phase 1
Phase 1 requires a runnable benchmark/test harness skeleton that captures baseline metrics and encodes release budgets without relying on production data-plane completeness.

### Required Harness Components
1. Benchmark scaffolding:
- `crates/rustynetd/benches/phase1_runtime_baseline.rs`
- `crates/rustynet-backend-api/tests/backend_contract_perf.rs`

2. Runner script:
- `scripts/perf/run_phase1_baseline.sh`

3. Artifact output:
- JSON report at `artifacts/perf/phase1/baseline.json`
- Includes metric name, measured value, unit, threshold, pass/fail.

### Minimum Metrics Encoded in Harness
- Idle daemon CPU target: `<= 2%` of one core (Pi-class profile).
- Idle daemon memory target: `<= 120 MB RSS`.
- Reconnect target: `<= 5 s`.
- Route/policy apply target: `<= 2 s p95`.
- Throughput overhead target: `<= 15%` vs baseline WireGuard path.

### Phase 1 Pass Criteria
- Harness compiles and runs in CI.
- Report contains all required metric keys and thresholds.
- Every required metric must be measured and must pass thresholds.
- `not_measurable`, synthetic placeholders, and unavailable/invalid measurement reason codes are release-blocking failures.

Fail-closed rule: missing metric keys or any non-measured metric status fail CI.

## 9) Acceptance Test Plan for All Phase 1 Scope Items
| Test ID | Scope Item | Procedure | Pass Criteria |
|---|---|---|---|
| P1-AT-01 | Workspace/crate baseline | `cargo check --workspace` | All crates compile. |
| P1-AT-02 | Boundary ownership | Dependency and import review for disallowed edges | No disallowed crate dependency edges. |
| P1-AT-03 | Backend contract existence | Compile against `TunnelBackend` trait from `rustynet-backend-api` | Contract is consumable by daemon crate. |
| P1-AT-04 | Capability model | Unit tests for capability flags and unsupported-feature handling | Unsupported capabilities fail closed. |
| P1-AT-05 | Lifecycle invariants | Tests for start/restart/shutdown semantics in adapter | Invalid lifecycle calls return typed errors. |
| P1-AT-06 | No WireGuard leakage | `rg` boundary gate (Section 7.7) | No leakage matches outside adapter crate. |
| P1-AT-07 | Key hierarchy specification | Validate documented key hierarchy against crypto module interfaces | Documented hierarchy maps to crate ownership and type boundaries. |
| P1-AT-08 | Token/revocation baseline | Validate token/nonce/revocation schema contract in control-plane architecture docs | Required fields and fail-closed semantics defined and versioned. |
| P1-AT-09 | Threat model v1 | Review checklist for required threat classes | External abuse, replay, credential stuffing, and admin-surface threats all covered. |
| P1-AT-10 | Key custody fallback | Negative tests for permission mismatch/corrupt encrypted blob contract | Startup refusal and explicit errors confirmed. |
| P1-AT-11 | Crypto policy | Allowlist/denylist config tests | Denylisted algorithms rejected; allowlisted algorithms accepted. |
| P1-AT-12 | Deprecation exceptions | Expiry behavior tests for temporary compatibility exceptions | Expired exceptions rejected automatically. |
| P1-AT-13 | CI security gates | Execute all Section 7 commands in CI pipeline | All gates pass with zero warnings/errors. |
| P1-AT-14 | Integration harness skeleton | Run backend contract test harness | Harness executes and reports pass/fail. |
| P1-AT-15 | Performance harness skeleton | Run `scripts/perf/run_phase1_baseline.sh` | Report generated with required keys and all metrics measured/pass. |
| P1-AT-16 | Secret-handling baseline | Log redaction tests on crypto/debug surfaces | Secret bytes never emitted in plain text. |
| P1-AT-17 | TLS baseline policy | Control-plane transport config lint/test | TLS 1.3-only policy declared and validated. |
| P1-AT-18 | No custom crypto | Static review checklist + crypto module tests | No custom cryptographic construction in production path. |

## 10) Requirement-to-Implementation Traceability Matrix
Each Phase 1 requirement bullet is mapped to implementation approach, owner, and verification.

| Requirement ID | Requirement Bullet | Implementation Approach | Owning Crate/Module | Verification Method |
|---|---|---|---|---|
| P1-01 | Create Rust workspace and core crates | Keep all required crates registered in workspace manifest | `/Cargo.toml` + `crates/*` | `cargo check --workspace` |
| P1-02 | Define crate boundaries to avoid coupling | Enforce dependency direction and disallowed edges | Workspace dependency policy | Dependency review + CI checks |
| P1-03 | Create protocol-agnostic backend API crate | Maintain generic backend contract in dedicated crate | `rustynet-backend-api` | Trait import/use tests |
| P1-04 | Define `TunnelBackend` interface and capability model | Keep trait + `BackendCapabilities` as canonical control surface | `rustynet-backend-api/src/lib.rs` | Unit tests for lifecycle + capability behavior |
| P1-05 | No WireGuard types in control/policy/domain | WireGuard symbols only inside adapter crate | `rustynet-backend-wireguard` only | `rg` leakage gate (Section 7.7) |
| P1-06 | Define key hierarchy | Specify node identity, session, control signing key responsibilities | `rustynet-crypto` + this document | Security baseline review checklist |
| P1-07 | Define token model and revocation paths | Standardize short-lived token + nonce + revocation contract | `rustynet-control` architecture baseline | Contract schema tests |
| P1-08 | Define threat model v1 and trust boundaries | Capture assets, adversaries, boundaries, controls | this document + `rustynet-control` architecture | Threat coverage checklist |
| P1-09 | Define auth abuse controls | Baseline defaults for rate-limit, lockout/backoff, anti-replay | `rustynet-control` middleware contract | Negative abuse tests |
| P1-10 | Define endpoint key-custody fallback | OS keystore first; encrypted file fallback with strict perms | `rustynet-crypto` custody interfaces | Permission/corruption startup tests |
| P1-11 | Define allowlist and denylist | Enforce algorithm policy at config load/startup | `rustynet-crypto` algorithm policy | Allow/deny unit tests |
| P1-12 | Define formal/property assurance plan | Add contract/property tests for backend invariants and key lifecycle invariants | `rustynet-backend-api/tests`, `rustynet-crypto/tests` | Property/contract test suite |
| P1-13 | CI baseline (`fmt`, `clippy`, `test`, dependency checks) | Implement mandatory CI command chain | CI workflow + scripts | All Section 7 gates green |
| P1-14 | Integration test harness skeleton | Add backend contract integration test skeleton | `rustynet-backend-api/tests` | Harness runs in CI |
| P1-15 | Performance harness skeleton + budget definitions | Add benchmark scaffolding + JSON report schema + thresholds | `rustynetd/benches` + `scripts/perf` | Baseline report generated + validated |
| P1-16 | Deliverable: workspace and crate skeleton committed | Keep workspace crate set in repo root and buildable | `/Cargo.toml`, `crates/*` | `cargo check --workspace` |
| P1-17 | Deliverable: backend interface and capability flags defined | Preserve trait + capability flags in backend API | `rustynet-backend-api` | API compile/test validation |
| P1-18 | Deliverable: architecture/trust-boundary documentation | Keep this implementation doc authoritative for Phase 1 | `/documents/Phase1Implementation.md` | Doc review and sign-off |
| P1-19 | Deliverable: CI gates active | CI pipeline executes required commands on each merge | CI configuration | CI pass required for merge |
| P1-20 | Deliverable: crypto policy baseline approved | Maintain explicit allowlist/denylist/deprecation policy | `rustynet-crypto` + this document | Security sign-off + tests |
| P1-21 | Deliverable: protocol assurance strategy approved | Document and implement contract/property tests | Backend API + crypto tests | Test plan approval + passing tests |
| P1-22 | Security gate: no custom crypto design | Restrict to vetted primitives/protocols only | `rustynet-crypto`, architecture policy | Static review + module tests |
| P1-23 | Security gate: TLS 1.3 and key-management standards documented | Enforce TLS 1.3-only policy and key custody rules | `rustynet-control` transport policy + `rustynet-crypto` | Config lint/tests |
| P1-24 | Security gate: no secret/token logging | Redacted debug/log formats for secrets | `rustynet-crypto`, logging policy | Redaction tests |
| P1-25 | Security gate: threat model covers abuse/replay/admin threats | Threat model section includes required abuse classes | this document | Threat checklist audit |
| P1-26 | Security gate: weak-algorithm denylist + deprecation policy | Denylist hard rejection plus expiring exceptions | `rustynet-crypto` policy loader | Negative tests + expiry tests |
| P1-27 | Exit criterion: core crates compile and test harness runs | Build + run unit/integration harness | Entire workspace | `cargo check/test` + harness runs |
| P1-28 | Exit criterion: backend exists with no WireGuard coupling in core domains | Trait boundary + leakage checks | `rustynet-backend-api`, non-adapter crates | Boundary gate + architecture review |
| P1-29 | Exit criterion: security artifacts approved | Security baseline sections signed off by eng+security | this document + security review records | Approval checklist completion |
| P1-30 | Exit criterion: performance and attack-surface baselines documented and accepted | Budget and abuse-control defaults codified and tested | this document + harness config | Baseline report + review sign-off |

## 11) Risks and Mitigations for Phase 1 (Including Explicit Fail-Closed Decisions)
| Risk | Impact | Mitigation | Fail-Closed Decision | Verification |
|---|---|---|---|---|
| Protocol leakage from adapter into core domain | Breaks backend modularity; blocks future backend replacement | Enforce crate boundaries and leakage CI gate | Any leakage match blocks merge | Section 7.7 gate |
| Weak/legacy crypto enabled by config drift | Confidentiality/integrity regression | Allowlist/denylist enforcement at startup | Invalid/weak algorithm config aborts startup | Crypto policy tests |
| Key store unavailable or insecure permissions | Private key compromise risk | OS keystore-first and encrypted fallback with strict perms | If neither secure path available, daemon/control refuses to start | Permission/corruption tests |
| Abuse-control subsystem unavailable | Brute-force/replay exposure | Baseline middleware contract requires limiter + nonce state checks | Auth/enrollment request denied when control state unavailable | Negative integration tests |
| Trust/signing state missing or corrupt | Unauthorized peer-map/state acceptance risk | Integrity checks before trust-required operations | Trust-required operations blocked with explicit operator error | Trust-state load tests |
| Secret leakage in logs/debug output | Credential compromise | Redacted secret wrappers and log policy tests | Any secret redaction failure fails CI and blocks merge | Redaction tests + gate |
| CI dependency-vuln gate bypass | Known vulnerable dependency shipped | Mandatory `cargo audit` + `cargo deny` gates | Merge blocked on unresolved critical/high findings | CI gate enforcement |
| Performance harness schema drift | Missing regression signal | Fixed JSON schema with mandatory keys/reason codes | Missing key/invalid reason code fails CI | Perf harness validator |

## 12) Definition of Done Checklist (Phase 1)
- [ ] `documents/Phase1Implementation.md` exists and contains all 12 mandatory sections.
- [ ] All Phase 1 scope bullets (architecture, abstraction, security baseline, quality baseline) are mapped in Section 10.
- [ ] Workspace crate set matches Phase 1 required crates and compiles.
- [ ] `TunnelBackend` contract and capability model are implemented in protocol-agnostic crate.
- [ ] WireGuard-specific references are isolated to `rustynet-backend-wireguard`.
- [ ] Key hierarchy, token/replay model, trust boundaries, and abuse-control defaults are explicitly documented with enforcement points.
- [ ] Key custody fallback behavior includes encryption, strict permissions, zeroization, and startup refusal semantics.
- [ ] Cryptographic allowlist/denylist and deprecation/exception policy are explicitly documented and testable.
- [ ] CI gates in Section 7 are configured and required for merge.
- [ ] Integration and performance harness skeletons are runnable and produce deterministic pass/fail artifacts.
- [ ] Threat model v1 explicitly covers external abuse, credential stuffing, replay, and admin-surface threats.
- [ ] Secret-redaction baseline is enforced by testable controls.
- [ ] No custom cryptographic protocol/design is introduced in any Phase 1 path.
- [ ] Security and engineering owners sign off that Phase 1 exit criteria are met.

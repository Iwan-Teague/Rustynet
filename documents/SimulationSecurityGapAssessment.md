# Rustynet Simulation and Authenticity Security Gap Assessment

Date: 2026-03-01
Scope: Repository-wide findings on simulated/fake paths, non-authentic evidence generation, and permissive fallbacks that can mask real security or reliability failures.

## 1) Executive Summary
Rustynet currently contains multiple simulation and synthetic-evidence paths that can produce passing CI/reports without proving real secure dataplane behavior. This is a direct conflict with the project’s stated security-first and fail-closed principles.

If left unchanged, these gaps create a false sense of assurance:
- release signals can appear green while core security behavior is not actually exercised in real networking conditions,
- benchmark/performance artifacts can claim pass states from static values,
- operators can run non-production backends in live setups,
- custom signing logic exists where standard cryptographic primitives are required.

Given project intent ("real or it breaks"), these items must be treated as release blockers.

## 2) Normative Constraints Being Violated
Primary references:
- `documents/Requirements.md`
- `documents/SecurityMinimumBar.md`

Most relevant requirement/security controls:
- Requirements §4: security-first defaults.
- Requirements §5: use proven crypto only; no custom crypto/protocol design; signed control data and fail-closed trust behavior.
- Requirements §6.3: backend modularity without protocol leakage, but production behavior must remain real and verifiable.
- SecurityMinimumBar §3.1: no custom cryptographic protocol design in production paths.
- SecurityMinimumBar §3.2: signed control data validated before apply.
- SecurityMinimumBar §3.4: trusted authorization/signing state fail closed.
- SecurityMinimumBar §3.7: tunnel/DNS fail-close behavior validated.
- SecurityMinimumBar §6: required test evidence must be real and security-relevant, not only synthetic status files.

## 3) Findings (Severity-Ranked)
### F1 - Critical: Phase 10 gate passes on synthetic evidence generation
Evidence:
- `crates/rustynetd/src/main.rs` (`--emit-phase10-evidence`) uses `DryRunSystem` and synthetic peers/trust.
- `scripts/ci/phase10_gates.sh` accepts artifacts based on file presence and `"status": "pass"` strings.

Key references:
- `crates/rustynetd/src/main.rs:494`
- `crates/rustynetd/src/main.rs:499`
- `crates/rustynetd/src/main.rs:549`
- `scripts/ci/phase10_gates.sh:41`
- `scripts/ci/phase10_gates.sh:55`

Why this is an issue:
- CI can validate "production dataplane readiness" without exercising real Linux dataplane operations.
- This undermines trust in release gates and can allow shipping insecure/untested behavior.

Guideline conflict:
- Violates SecurityMinimumBar §6 evidence expectations and §3.7 fail-close validation intent.
- Violates Requirements §4 security-first defaults by allowing synthetic pass criteria.

### F2 - Critical: Phase 10 perf/soak report is hardcoded pass
Evidence:
- `write_phase10_perf_report` emits fixed metric values and fixed `soak_status: "pass"`.

Key references:
- `crates/rustynetd/src/phase10.rs:1376`
- `crates/rustynetd/src/phase10.rs:1382`
- `crates/rustynetd/src/phase10.rs:1416`

Why this is an issue:
- Produces unauthentic operational evidence.
- Masks performance regressions and can bypass release constraints.

Guideline conflict:
- Violates Requirements §4 performance budgets as verifiable targets.
- Violates SecurityMinimumBar §5 and §6 evidence integrity.

### F3 - High: Phase 1 baseline permits non-measurable synthetic outputs in pass pipeline
Evidence:
- Baseline metrics include `not_measurable` fields (`no_production_datapath`).
- Gate script explicitly permits these reason codes.

Key references:
- `crates/rustynetd/src/perf.rs:48`
- `crates/rustynetd/src/perf.rs:64`
- `crates/rustynet-backend-api/tests/backend_contract_perf.rs:205`
- `scripts/perf/run_phase1_baseline.sh:43`

Why this is an issue:
- Enables "green" baseline artifacts without real dataplane measurements.
- Reduces signal quality for security/perf readiness.

Guideline conflict:
- Conflicts with Requirements §12 testing/validation rigor and SecurityMinimumBar §5 performance bar.

### F4 - High: Custom peer-map signing construction in control plane
Evidence:
- Peer-map signing uses ad hoc `SHA256(secret || payload)` construction and equality checks.

Key references:
- `crates/rustynet-control/src/lib.rs:1449`
- `crates/rustynet-control/src/lib.rs:1474`
- `crates/rustynet-control/src/lib.rs:1665`

Why this is an issue:
- This is custom cryptographic construction rather than standard signature/HMAC API usage.
- Risk of subtle security flaws and non-interoperable trust semantics.

Guideline conflict:
- Direct conflict with Requirements §5 and SecurityMinimumBar §3.1 ("no custom cryptography/protocol design in production paths").

### F5 - High: Runtime supports in-memory backend mode in production entrypoints
Evidence:
- CLI/setup and daemon accept `in-memory` backend mode.
- In-memory backend does not execute real system dataplane operations.

Key references:
- `start.sh:654`
- `crates/rustynetd/src/main.rs:354`
- `crates/rustynetd/src/daemon.rs:368`
- `crates/rustynet-backend-wireguard/src/lib.rs:50`

Why this is an issue:
- Production operators can misconfigure into non-real dataplane mode.
- Can cause silent mismatch between expected security behavior and actual enforcement.

Guideline conflict:
- Conflicts with security-first defaults and real validation intent in Requirements §4/§5.

### F6 - High: Setup wizard offers direct manual peer/route programming path
Evidence:
- `start.sh` can directly run `wg set` and `ip route` with user-provided values.

Key references:
- `start.sh:533`
- `start.sh:548`

Why this is an issue:
- Bypasses centrally signed policy/assignment controls when used as operational path.
- Increases configuration drift and unauthorized route risk.

Guideline conflict:
- Conflicts with central policy enforcement and fail-closed control-plane governance intent.

### F7 - Medium: Membership CI evidence is synthetic scenario generation
Evidence:
- `--emit-membership-evidence` generates deterministic sample state/keys and emits pass/fail JSON.
- Gate validates presence/status fields.

Key references:
- `crates/rustynet-control/src/main.rs:64`
- `crates/rustynet-control/src/main.rs:75`
- `crates/rustynet-control/src/main.rs:212`
- `scripts/ci/membership_gates.sh:39`
- `scripts/ci/membership_gates.sh:52`

Why this is an issue:
- Good for unit-style conformance checks, but insufficient as sole operational security evidence.
- Can be mistaken for real environment validation.

Guideline conflict:
- Partially conflicts with SecurityMinimumBar §6 if used as substitute for real integration evidence.

### F8 - Medium: Weak/trivial tests that do not strongly prove security properties
Evidence examples:
- Persistence smoke test has no explicit assertions beyond no panic.
- Runtime baseline "skeleton" only asserts elapsed time > 0.

Key references:
- `crates/rustynet-control/src/persistence.rs:274`
- `crates/rustynetd/benches/phase1_runtime_baseline.rs:6`

Why this is an issue:
- Tests can pass while meaningful security invariants regress.

Guideline conflict:
- Weakens validation rigor expected by Requirements §12 and SecurityMinimumBar §6.

## 4) Why These Are High-Risk for Security
- False-positive assurance risk: release gates indicate "secure/pass" while real controls may be unverified.
- Operational misconfiguration risk: in-memory/manual paths can bypass intended policy/trust boundaries.
- Cryptographic assurance risk: custom constructions can invalidate threat assumptions.
- Incident response risk: fabricated or synthetic artifacts degrade forensic confidence.

In short: these are not only engineering quality issues; they materially weaken trust, auditability, and release integrity.

## 5) Recommended Remediation Strategy ("Real-or-Break")
### Phase R1 - Immediate release blockers
1. Remove synthetic Phase 10 evidence path from release gates.
2. Replace hardcoded perf/soak pass reports with measured outputs only.
3. Fail CI if required real measurements are unavailable.
4. Disable `in-memory` backend in production daemon startup paths (allow only explicit test-only compile feature or test binary).

### Phase R2 - Cryptographic correctness
1. Replace custom peer-map signing with standard Ed25519 signatures or approved MAC construction through vetted library APIs.
2. Add verifier key management and strict signature validation in consumers.
3. Add negative tests for tampering, replay, stale timestamps, and key rotation.

### Phase R3 - Control-plane integrity
1. Remove/bound manual peer programming from default setup workflow.
2. Enforce centrally signed assignment/policy path by default.
3. Require explicit break-glass mode with audit logging for any manual override.

### Phase R4 - Evidence hardening
1. Separate synthetic/unit evidence artifacts from release evidence directories.
2. Require signed, timestamped, environment-tagged integration evidence for release gates.
3. Add provenance checks binding evidence to real command executions and environment metadata.

### Phase R5 - Test quality uplift
1. Eliminate trivial tests or convert them to enforce concrete invariants.
2. Add assertion-rich tests for persistence semantics, fail-closed transitions, and ACL/dataplane behavior.
3. Fail gates on insufficient assertion coverage for critical modules.

## 6) Practical Implementation Policy
Adopt these repository-wide rules:
- If metric/evidence cannot be measured, gate fails.
- If real dataplane cannot be exercised for a release gate, release gate fails.
- If trust signature cannot be verified with approved cryptography, operation fails.
- If trusted state cannot be loaded, persisted, or validated, operation fails closed.

No synthetic pass output is allowed in release-critical artifacts.

## 7) Suggested Execution Order
1. Gate hardening first (prevent false green).
2. Remove custom signing construction and migrate to standard signatures.
3. Lock runtime defaults to production-safe backend modes.
4. Refactor setup wizard to policy/signed-control path.
5. Upgrade test and evidence rigor.

## 8) Exit Criteria for Remediation
Remediation is complete only when:
- Phase/membership gates cannot pass on synthetic status-only artifacts.
- All release evidence is generated from real measured execution paths.
- Custom cryptographic constructions are removed from production paths.
- Production defaults are secure/fail-closed and non-simulated.
- Security controls have explicit enforcement and verification coverage.


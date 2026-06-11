# Rustynet Agent Operating Contract

Use this file as mandatory execution guidance for AI implementation agents working in this repository.

`AGENTS.md` and `CLAUDE.md` are intentionally mirrored. Keep them aligned.

## 1) Mission
- Build Rustynet to production-grade quality.
- Keep security as the first priority.
- Keep architecture Rust-first and transport-backend modular.
- Prefer code, tests, gates, and evidence over design-only churn.

## 2) Read Order and Source of Truth
When documents disagree, apply this precedence:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. The active scope document for the task
4. Supporting design docs
5. `README.md` and operational runbooks

Read in this order before touching code:
1. `AGENTS.md`
2. `CLAUDE.md`
3. `README.md`
4. `documents/README.md`
5. `documents/Requirements.md`
6. `documents/SecurityMinimumBar.md`
7. The active scope document
8. Relevant runbooks under `documents/operations/`

Current primary execution ledgers:
- `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` for the cross-network dataplane track (D2-D13): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, service-hosting roles (nas, llm). Source of truth for "what are we building and why" when working on traversal, relay, gossip, enrollment, or cellular reliability.
- `documents/operations/active/MasterWorkPlan_2026-03-22.md` for repo-wide remaining work
- `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` for traversal, relay, and live-lab readiness (the defects it documents drive D2/D3/D4 in the dataplane execution plan)

Current lab-reference assets:
- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md` (includes probe-and-recover runbook for unsticking lab guests whose nft killswitch is blocking SSH after a network reconfig)
- `documents/operations/active/vm_lab_inventory.json`
- `scripts/vm_lab/probe_and_recover_local_utm.sh` — call before retrying a failed orchestrator run when one or more lab VMs show TCP/22 timeout but are visible in `arp -a`
- `documents/operations/LiveLabRunMatrix.md` and `documents/operations/live_lab_run_matrix.csv` — standard live-lab wrappers append a row automatically; verify the row exists after every run or focused live-lab stage used as evidence, including commit, dirty state, report directory, OS/role/stage statuses, node identity per role, and regression reference when applicable

Rules:
- If ambiguity exists, choose the strictest secure practical default and document that choice.
- Never weaken a higher-precedence requirement.
- Standalone prompt documents are not part of the repository source of truth. Use the active ledgers, runbooks, and index files instead.

## 3) Non-Negotiable Engineering Constraints
- Rust-first codebase. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography and no custom VPN protocol invention in production paths.
- WireGuard must remain an adapter behind stable backend abstractions and be easy to replace.
- No WireGuard-specific leakage into protocol-agnostic control, policy, or domain crates.
- Default-deny policy is mandatory across ACL, routes, and trust-sensitive flows.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.
- Do not defer in-scope requirements behind TODO/FIXME/placeholders in completed deliverables.
- Enforce one hardened execution path per security-sensitive workflow. No runtime fallback, downgrade, or legacy branch in production paths.

## 4) Security Baseline Requirements
- Enforce signed control/trust state validation before mutation.
- Enforce anti-replay and rollback protection where state freshness matters.
- Enforce strict key custody behavior:
  - use OS-secure key storage when available
  - otherwise use encrypted-at-rest fallback with strict permissions and startup permission checks
- Never log secrets or private key material.
- Preserve privileged-boundary hardening: argv-only exec for helpers, strict input validation, no shell construction with untrusted values.
- Preserve tunnel and DNS fail-closed behavior in protected modes.
- During shell-to-Rust migration, remove superseded shell implementations from active paths. Wrappers may only dispatch to the Rust command and must fail closed on error.

Each implemented security control must include:
1. an enforcement point in code
2. a verification method such as a unit test, integration test, negative test, or gate check

## 5) Required Working Style
- Before coding, read the relevant docs in precedence order.
- Build a concrete checklist from the scope requirements.
- Implement in small, verifiable increments.
- Run the closest relevant tests and gates during implementation, not only at the end.
- Keep the owning ledger or work document current. Do not maintain a hidden private checklist that diverges from repository state.
- Keep documentation synchronized with implementation changes.
- Remove dead links, stale index entries, and prompt-only guidance when you find them.

## 6) Documentation Rules
- `documents/README.md` is the top-level map of the docs tree.
- `documents/operations/README.md` is the operations/runbook map.
- `documents/operations/active/README.md` is the active-work map.
- If you add, remove, rename, archive, or materially repurpose docs, update the relevant index file in the same change.
- If a document becomes historical rather than active, move or classify it honestly.
- Do not reintroduce standalone prompt documents; keep execution guidance in the active ledgers themselves.

## 7) Validation and CI Gates
Run these as mandatory quality gates for substantial work:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Fast-fail convenience runner (recommended for local iteration):
- `cargo run -p rustynet-xtask -- gates` runs fmt → check → clippy → test in
  dependency order, stops at the first failure, streams output live, and wraps
  each stage in a timeout watchdog (kills the whole process group and prints the
  tail on a hang). Add `--skip-test` to gate without the slow test stage, or
  pass a cargo scope such as `-p rustynet-cli`. Per-stage timeouts are
  overridable via `XTASK_{FMT,CHECK,CLIPPY,TEST}_TIMEOUT` (seconds). The
  individual commands above remain the authoritative gate definitions.

Run scope-specific scripts when present:
- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- any active-phase gate script required by the scope document

If any gate fails:
1. stop phase progression
2. fix the root cause, not the symptom
3. re-run the impacted gates
4. record failure, fix, and proof in the relevant progress document when scope requires it

## 8) Architecture Boundary Rules
- Keep domain models and policy evaluation transport-agnostic.
- Keep backend-specific behavior in backend adapter crates.
- Expose capabilities via backend interfaces rather than leaking backend types.
- Maintain deterministic, testable state transitions for trust-sensitive systems.

## 9) Definition of Done
Work is complete only when all are true:
- in-scope requirements are implemented end-to-end
- security minimum bar controls are satisfied for that scope
- all mandatory gates pass, or the remaining blocker is explicitly documented and outside the claimed completion
- required artifacts exist and validate
- no unresolved in-scope blockers remain
- no TODO/FIXME/placeholders remain in completed deliverables

## 10) Common Patterns & How To Apply The Rules

This section translates the abstract rules above into concrete code patterns.
Agents should internalize these — they are the difference between code that
passes review and code that gets rejected.

### 10.1 Fail-Closed Pattern

Rule §3: "Fail closed when trust/security state is missing, invalid, stale,
or unavailable."

**Wrong:**
```rust
let state = load_trust_state().unwrap_or_default();
```

**Right:**
```rust
let state = match load_trust_state() {
    Ok(s) => s,
    Err(e) => {
        tracing::error!(%e, "trust state unavailable; failing closed");
        return Err(AdapterError::TrustStateUnavailable);
    }
};
```

Every path that reads trust/security state must handle the None/Err case
explicitly and return an error — never default, never silently continue.

### 10.2 Error Handling — No unwrap() or expect() in Production Paths

Rule §3: "One hardened execution path per security-sensitive workflow."

unwrap() and expect() are panics. In security-sensitive code, panics are
denial-of-service vectors. Use proper error propagation:

**Wrong:**
```rust
let key = load_key().unwrap();
let sig = verify(&key, &data).expect("signature verification failed");
```

**Right:**
```rust
let key = load_key().map_err(|e| AdapterError::KeyLoadFailed(e.to_string()))?;
let sig = verify(&key, &data).map_err(|e| AdapterError::SignatureInvalid(e.to_string()))?;
```

unwrap() is acceptable ONLY in:
- Unit tests
- Build scripts (build.rs)
- One-shot CLI entry points (not library code)
- Cases where the invariant is locally provable AND a comment explains why

### 10.3 Backend Abstraction Boundary

Rule §8: "Keep domain models and policy evaluation transport-agnostic.
Keep backend-specific behavior in backend adapter crates."

**Wrong:** importing wireguard types in rustynet-control or rustynet-policy.

**Right:** domain crates (control, policy, dns-zone) use abstract types.
Backend crates translate between abstract types and concrete WireGuard types.

Test with: scripts/ci/check_backend_boundary_leakage.sh

### 10.4 Default-Deny Always

Rule §3: "Default-deny policy is mandatory across ACL, routes, and
trust-sensitive flows."

**Wrong:** empty ACL → allow. Empty membership → allow. Missing context → allow.

**Right:** empty/missing/malformed → deny. The policy evaluator starts from
a deny-all posture and only adds allows for explicitly present entries.

When adding a new policy or ACL path, the first test you write should be:
"empty input produces deny."

### 10.5 Signed State — Verify Before Apply

Rule §4: "Enforce signed control/trust state validation before mutation."

**Wrong:** read a bundle, apply it, then check the signature.

**Right:** verify signature FIRST, check epoch/replay-watermark SECOND,
apply THIRD. Never apply unsigned or stale state.

### 10.6 Secrets Hygiene

Rule §4: "Never log secrets or private key material."

- Use tracing::Span with fields marked for redaction.
- Never Debug-print a type containing key material unless its Debug impl
  explicitly redacts.
- Test with: scripts/ci/secrets_hygiene_gates.sh

### 10.7 Role Transitions Are Not Just String Changes

When implementing a role transition, the side-effects matter more than the
role field. See get_role_transition in the MCP repo-context server.

Key rules:
- Adding serves_relay: deploy service BEFORE emitting signed bundle
- Removing serves_relay: undeploy service BEFORE revocation bundle
- Exit NAT: tear down BEFORE removing capability (residue = release-blocker)
- blind_exit is irreversible — requires factory reset
- All transitions emit append-only audit log entries

### 10.8 Test Location and Naming

- Unit tests: inline, #[cfg(test)] mod tests { ... }
- Integration tests: crates/<name>/tests/<scenario>.rs
- Names: descriptive_snake_case (e.g. gossip_three_peer_mesh)
- Every security control: 1 enforcement point + 1 verification test

### 10.9 Working With The Live Lab

- Check lab state first: ops vm-lab-discover-local-utm-summary
- If VMs stuck (SSH timeout): scripts/vm_lab/probe_and_recover_local_utm.sh
- Never hand-edit vm_lab_inventory.json — use --update-inventory-live-ips
- After every evidence run, verify the row in live_lab_run_matrix.csv

### 10.10 Commit Hygiene

- Small, verifiable increments — one logical change per commit
- Commit messages: imperative mood, what AND why
- Never commit generated files, build artifacts, or secrets
- Run at minimum: cargo fmt --all -- --check && cargo check -p <crate>

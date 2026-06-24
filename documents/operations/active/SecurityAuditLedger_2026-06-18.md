# Rustynet Security Audit Ledger — 2026-06-18 (review-only)

> **Engagement:** Full-repository, file-by-file security audit against
> `documents/SecurityMinimumBar.md` and the checklist in the audit charter.
> **Mode:** REVIEW-ONLY. No production code, crypto, or config is modified in
> this pass. Every finding is a *proposal* awaiting human approval.
> **Finding namespace:** `RSA-####` (this audit). Prior findings use `RN-*`
> (see `SecurityReview_2026-05-24.md`) and `HB-*`
> (`SecurityHardeningBacklog_2026-06-01.md`); this pass cross-references those
> rather than renumbering them.
> **Auditor of record:** automated security-audit agent until a human signs off.

## Executive Summary (live — updated as the pass proceeds)

**Status: COVERAGE COMPLETE (review-only).** Every tracked code/config file has a
dated ledger row — **594 / 594 audited, 0 pending** (528 `audited` + 66 `open`),
inventory grown from the seeded 581 by +13 (systemd unit files initially excluded by
the seed filter, added 2026-06-19). Deep audit ran highest-blast-radius-first across
8 multi-agent fan-out batches (Tiers 0→V) plus first-hand auditor verification of every
load-bearing finding, then an **adversarial re-verification pass (2026-06-19)** that
refuted each finding against the code, then further theme sweeps (truncation, `#[allow]`,
verification-bypass). **76 findings raised → 2 withdrawn as false-positive (RSA-0030,
RSA-0051) → 74 standing** (RSA-0001..0077; RSA-0062 retired, RSA-0030/0051 withdrawn).
All are review-only proposals awaiting human approval; **no
production code, crypto, or config was changed** (the one applied edit — a scratch-comment
cleanup in `daemon.rs` — was a separate, explicitly-authorised request, gates green).

| Severity | Count | Notes (post adversarial re-verification 2026-06-19) |
|---|---|---|
| Critical | 0 | none found |
| High | 2 | RSA-0009 (membership reducer non-determinism → revoke/rotate cannot apply; AUDIT-040), RSA-0063 (macOS bootstrap `NOPASSWD:ALL` sudoers residue → local privesc; AUDIT-045/RN-32). **Both survived adversarial re-verification.** |
| Medium | 15 | RSA-0001/0002/0007/0008/0023/0025/0026/0031/0037/0046/0047/0059/0064/0065/0068 (all 15 survived re-verification; RSA-0052/0053 downgraded to Low) |
| Low | 34 | RSA-0003/0004/0005/0006/0010/0012/0016/0017/0027/0028/0029/0032/0033/0038/0039/0040/0041/0042/0043/0048/0049/0050/0052/0053/0054/0055/0057/0060/0066/0067/0069/0074/0075/0077 (RSA-0077 = systemic verify_strict gap, generalizes RSA-0043) |
| Info | 19 | RSA-0011/0013/0015/0019/0020/0021/0022/0034/0035/0036/0044/0056/0058/0061/0070/0071/0072/0073/0076 (RSA-0034/0035 downgraded from Question, RSA-0056 from Low — all dormant/unreachable-today) |
| Question | 4 | RSA-0014, RSA-0018, RSA-0024, RSA-0045 (owner decisions / backlog carries) |
| ~~Withdrawn~~ | 2 | RSA-0030 (RN-09 test-gap — gating + test already exist, commit 1525cae), RSA-0051 (ops_e2e "shell injection" — argv-passed, no shell) — false-positives, verified first-hand |

**Top release-blockers:** **RSA-0009 (High)** remains the standout — the membership
reducer stamps `unix_now()` into the canonical state-root, so `RevokeNode`,
`RotateNodeKey`, `RestoreNode`, and `SetNodeCapabilities` can never apply or
replay: **node revocation and key rotation are non-functional** (re-confirms
AUDIT-040, verified first-hand; fails *closed* — harm is inability-to-revoke).
**No reachable Critical found in Tiers 0–1.** Batch 2 (rustynetd, 69 files) found
**0 Critical / 0 High new** and re-confirmed the daemon's core trust posture is
sound: RN-03/04/10/N1 fixed; all three trust ACL gates + every signed-bundle-apply
path use `evaluate_with_membership` (so **RSA-0008 has no daemon-side bypass**);
strong bounds-checked STUN/PCP/uPnP/gossip parsers; argv-allowlisted privileged
helper. The notable new Mediums are an enrollment one-time-consume **cross-process
race** (RSA-0023, no ledger lock — the §6 "concurrent consume" test is also missing)
and the **secret-log-audit gate's coverage gaps** (RSA-0026 — 3 of 4 guarded type
names are phantom; real secret types uncovered), which weakens the C6 control's
assurance. The revocation-blind `evaluate` pattern (RSA-0007 phase10, RSA-0008 CLI)
is confined and mitigated downstream. **Tier 2 (Batch 3) found 0 Critical/0 High**
and confirmed strong relay/backend posture (boringtun-only crypto, argv-only
adapters, 12-step relay hello check, `verify_strict`); **AUDIT-031 is largely
mitigated** (per-IP limiter + 4096-IP cap), with **RSA-0037** the one residual
pre-auth memory-DoS (an unpruned per-`node_id` map). **Tier 3 core (Batch 4) found
0 Critical/0 High** (both agent-proposed Highs downgraded to Medium on first-hand
reachability tracing): **AUDIT-006 is now REMEDIATED** (`lab_state` confines every
path via `confined_repo_path`); NAS at-rest AEAD + per-peer confinement, LLM
identity-from-tunnel/loopback-engine/E4-token-order, and windows-native DPAPI/WFP/
named-pipe FFI are all sound. The second **High, RSA-0063**, is in Tier 4: the macOS
bootstrap writes a `NOPASSWD: ALL` sudoers file then runs `curl|bash`, with no `trap`
to remove it — a failed/aborted bootstrap leaves passwordless root on the host
(re-confirms AUDIT-045/RN-32, verified first-hand). **Tier 3 cli bulk + Tier 4 scripts
(Batches 5/5b/6) and the vendored sub-tier (Batch 7) found 0 Critical and only the one
new Tier-4 High (RSA-0063):** the CI gate scripts are argv-array `exec` wrappers with
fail-closed zero-match gates, the 13 systemd units are strongly hardened, and **vendored
boringtun is clean** (standard Noise_IKpsk2, `ct_eq` MACs, AEAD-via-crate anti-replay,
no local weakening; device/ffi/jni uncompiled). Supply chain clean (`cargo audit`
0/210, `cargo deny` advisories+bans+sources OK). Recurring *themes* across the codebase
(each individually ≤Medium, but worth a systemic fix): (a) the non-unix permission-check
**no-op** pattern (RSA-0002/0025); (b) the **revocation-blind `evaluate`** vs
membership-aware path (RSA-0007/0008, mitigated downstream); (c) **unescaped
host/config values into PowerShell/bash/env-file** (RSA-0046/0051/0057/0059/0068); (d)
**`unsafe` without `// SAFETY:`** on production FFI (RSA-0032/0074); (e) **controls
built+tested but unwired** / asserted-but-unverified (RSA-0018/0024/0026/0049).

### SecurityMinimumBar — Critical-control trace (where each is enforced; gaps flagged)
| SecMinBar §3 Critical control | Primary enforcement (audited) | Status / gap |
|---|---|---|
| §3.1 Proven crypto only | `rustynet-crypto` (Argon2id/XChaCha20-Poly1305/Ed25519 `verify_strict`); vendored boringtun Noise | **PASS** (1 consistency gap: RSA-0043 dns-zone plain `verify`) |
| §3.2 Control-plane TLS 1.3 + signed-state verify-before-apply | `membership.rs` verify→freshness→replay→apply; daemon loaders | **PASS** on ordering; **gap RSA-0009 (High)** — signed updates for revoke/rotate can't apply (reducer non-determinism) |
| §3.3 Auth/enrollment hardening + atomic one-time creds | enrollment token HMAC `ct_eq`; relay 12-step; rate limiters | **gap RSA-0023 (Med)** one-time consume not cross-process atomic (no ledger lock); RSA-0037 (Med) relay pre-auth memory-DoS |
| §3.4 Secret/key custody + zeroize + redaction | OS keystore + AEAD fallback; `zeroize`; secret-log-audit gate | **PASS** core; **gaps** RSA-0002/0025 (Win perm no-op + `.enc` ACL), RSA-0026 (redaction-gate coverage), RSA-0039 (Win backend `Debug` key) |
| §3.5 Host-OS boundary enforcement | `rustynet-sysinfo` OS detect; platform path roots | **PASS** (gap RSA-0046 sysinfo PowerShell injection on Windows) |
| §3.6 Default-deny ACL + RBAC + MFA | `rustynet-policy` default-deny (21 tests); role RBAC; admin MFA/CSRF (`ct_eq`) | **PASS** at the evaluator; **gaps** RSA-0007/0008 revocation-blind callers (mitigated), RSA-0018/0024 unwired admin/service-exposure |
| §3.7 Privileged-helper argv-only + web/session | `privileged_helper` argv allowlist + RN-17 peer-cred; argv exec everywhere | **PASS** core; **gaps** RSA-0033 (kill any-pid), RSA-0063 (High, macOS sudoers residue), RSA-0046/0059/0068 shell-construction |
| §3.8 Dataplane leak prevention (tunnel/DNS fail-close, traversal) | killswitch pre-start (RN-04), `force_fail_closed` (RN-03), signed endpoint hints | **PASS** (re-verified RN-03/04 fixed); gaps RSA-0029 (post-restart replay), RSA-0031 (exit-NAT teardown verify fail-open), RSA-0045 (B.4.1 resolver filter, carry) |
| §3.9 Tamper-evident append-only audit | `role_audit` hash-chain (tamper tests) | **PASS** at the API; **gap RSA-0014** (CLI caller fail-open), RSA-0012 (append TOCTOU) |
| §3.10 Supply-chain integrity | `Cargo.lock` + `deny.toml` (unknown-registry=deny, crypto bans) | **PASS** — `cargo audit` 0/210, `cargo deny` OK; gaps RSA-0064/0065 (curl\|bash/unpinned downloads in bootstrap) |

**Most exposed files (by trust-boundary exposure, to be confirmed):** network
parsers (`rustynet-relay`, gossip/STUN/PCP/uPnP in `rustynetd`), the key
envelope (`rustynet-crypto`), enrollment/token paths (`rustynet-control`),
and the privileged-helper argv-exec surface.

### Reconciliation against existing security artifacts

This pass does **not** supersede prior work; it re-verifies and extends it.
- `documents/SecurityAnalysis_2026-06-12.md` — most recent verified analysis;
  RN-03/04/05/06/11/14/15 fixed, RN-08 partial (legacy v0 decode open),
  RN-02/09/10/16 + RN-N* open. Where this audit re-confirms one of those, the
  ledger row cites the RN-id instead of opening a duplicate RSA finding.
- `SecurityAndQualityAudit_2026-06-10.md` — prior full-repo pass, 53 findings
  (AUDIT-001..053; 0 Critical / 11 High / 19 Medium / 16 Low / 7 Info) with a
  claimed 100%-coverage ledger and a SecurityMinimumBar control trace. This
  pass independently re-verifies its load-bearing items (esp. AUDIT-006 unconfined
  `report_dir`, AUDIT-027 Windows ACL no-op, AUDIT-031 relay pre-auth DoS,
  AUDIT-040 non-deterministic reducer, AUDIT-045 NOPASSWD sudoers residue) and
  cites the AUDIT-id where it confirms one.
- `SecurityReview_2026-05-24.md` — 38-finding registry (RN-01..RN-24, RL-1..12).
- `SecurityHardeningBacklog_2026-06-01.md` — HB-1..7 low/info items.
- `SecurityMinimumBar.md` — the release-blocking control set this ledger maps to.

### Legend
- **Verdict:** `PASS` (no findings) · `FINDINGS` (one or more raised).
- **Status:** `pending` (seeded, not yet audited) → `audited` (done, no findings)
  / `open` (findings raised) → `proposed`/`accepted`/`applied`/`risk-accepted`.
- **Checks run:** checklist category IDs (C/K/F/E/V/I/N/W/A/S/T) from the charter.
- **Tier:** 0 crypto/key-custody · 1 trust/control/policy/privilege · 2 transport/dataplane
  · 3 service surfaces · 4 build/supply-chain/scripts · V vendored (`third_party/`).

---

## Coverage Tables (seeded — `pending` until a dated audit row replaces the placeholder)

_Inventory captured from `git ls-files` on 2026-06-18. 581 tracked code/config files across all tiers (docs, JSON evidence, and binary assets are out of scope for per-file rows)._

| Tier | Files seeded |
|---|---|
| 0 — Crypto & key custody | 4 |
| 1 — Trust / control / policy / privilege | 110 |
| 2 — Transport backends & dataplane | 40 |
| 3 — Service surfaces & interfaces | 216 |
| 4 — Build / supply chain / scripts | 176 |
| V — Vendored (`third_party/`) | 35 |
| **Total** | **581** |

### Tier 0 — Cryptography & key custody

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `crates/rustynet-crypto/Cargo.toml` | 2026-06-18 | 0 | C1,S1,S2 | PASS | none | none — vetted primitives only (argon2/chacha20poly1305/ed25519-dalek/subtle/zeroize/sha2/security-framework); no custom crypto; pinned via committed `Cargo.lock` (RustSec scan deferred to Tier 4 `cargo audit`) | Latacora Crypto Right Answers; SecMinBar §3.1 | audited |
| `crates/rustynet-crypto/src/lib.rs` | 2026-06-18 | 0 | C1,C2,C3,C4,C5,C6,E1,E3,F1,F4,I1,I2,V1,T1,T2 | FINDINGS | RSA-0001, RSA-0002, RSA-0003, RSA-0004 | unambiguous v0/v1 envelope framing + legacy-decode regression test; Windows ACL check in the file-fallback permission validator; fix inverted `with_exceptions` guard (or delete dead feature); document/contain macOS `-A` keychain exposure | RN-08/RL-12; HB-2; SecMinBar §3.4/§3.7; CWE-214/CWE-732; ANSSI; Latacora | open |
| `crates/rustynet-local-security/Cargo.toml` | 2026-06-18 | 0 | S1,S2 | PASS | none | none — zero external dependencies | SecMinBar §10 | audited |
| `crates/rustynet-local-security/src/lib.rs` | 2026-06-18 | 0 | C3,E1,F1,I3,V1,T2 | PASS | none | none — fail-closed on non-unix (returns Err, not Ok), default-deny permission posture, symlink rejection via `symlink_metadata`, parent-dir ownership mitigates check-then-use TOCTOU; strong negative tests | SecMinBar §3.7; ANSSI; CWE-367 | audited |

### Tier 1 — Trust, control plane, policy, privilege boundary

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `crates/rustynet-control/Cargo.toml` | 2026-06-18 | 1 | S1,S2,V2 | PASS | none | none needed — transport-agnostic deps (ed25519-dalek/subtle/hmac/hkdf/zeroize), no backend leak | CLAUDE.md §8; SecMinBar §10 | audited |
| `crates/rustynet-control/examples/perfprobe_membership.rs` | 2026-06-18 | 1 | T1,T2 | PASS | none | none needed | verified: Canonical-payload/state-root/decode roundtrip probe; synthetic membership state; no secrets; pubkey hex is fabricated test data. | audited |
| `crates/rustynet-control/src/admin.rs` | 2026-06-18 | 1 | W1,W2,W3,F2,I2,C7,T1,T2 | FINDINGS | RSA-0018 | wire AdminAuthorizer + validate_privileged_command into a prod enforcement point, or document as scaffold | SecMinBar §3.7; CLAUDE.md §4; CWE-1006 | open |
| `crates/rustynet-control/src/credential_unwrap.rs` | 2026-06-18 | 1 | C4,C6,F1,I1,I2,I3,E2,E3,V1,T1,T2 | PASS | none | none needed — argv-only OS custody, pinned helper paths, Zeroizing, fail-closed, no secret logging | SecMinBar §3.7; CLAUDE.md §4 | audited |
| `crates/rustynet-control/src/enrollment.rs` | 2026-06-18 | 1 | K1,F1,F4,E2,E3,V1,T1,T2 | FINDINGS | RSA-0015 | fail-loud on unrecognized role token (mirror RoleCapability::parse) instead of silent drop-to-Client | CLAUDE.md §3 default-deny; CWE-636 | open |
| `crates/rustynet-control/src/ga.rs` | 2026-06-18 | 1 | F1,F4,E1,T1,T2 | PASS | none | none needed — GA gates fail closed on any unmet condition; negative test present | SecMinBar §2; CLAUDE.md §3 | audited |
| `crates/rustynet-control/src/key_rotation.rs` | 2026-06-18 | 1 | K1,K2,K3,F1,E1,E3,V1,T1,T2 | PASS | none | none needed — monotonic epoch; dup-freeze/unknown-epoch/past-freeze fail closed; strong negative tests | SecMinBar §3.3; CLAUDE.md §10.5 | audited |
| `crates/rustynet-control/src/lib.rs` | 2026-06-18 | 1 | K1,K2,K3,F1,F2,F4,C1,C6,E1,E2,E3,I1,I4,V1,V2,N2,A1,T1,T2 | FINDINGS | RSA-0008, RSA-0010, RSA-0011 | membership-aware issuance gate; fail-closed relay-token mint (try_sign_at); anti-rollback generation floor | CLAUDE.md §3/§10.2; SecMinBar §3.6; CWE-863/248/294 | open |
| `crates/rustynet-control/src/main.rs` | 2026-06-18 | 1 | F2,E1,V1,T1 | PASS | none | none needed — one-shot scaffold printing a hardcoded demo decision; not a production authz path | CLAUDE.md §10.2 | audited |
| `crates/rustynet-control/src/membership.rs` | 2026-06-18 (+truncation sweep 2026-06-19) | 1 | K1,K2,F1,F2,E1,E3,I1,I4,C1,A1,T1,T2 | FINDINGS | RSA-0009, RSA-0075 | deterministic reducer: drop unix_now() from state-root so revoke/rotate apply; + use `usize::from(quorum_threshold)` not `count() as u8` for active-approver validate (RSA-0075) | AUDIT-040; CLAUDE.md §8; SecMinBar §3.3; CWE-197 | open |
| `crates/rustynet-control/src/operations.rs` | 2026-06-18 | 1 | C1,A1,A2,F1,I1,I4,T1,T2 | FINDINGS | RSA-0019 | classification-based (not denylist) redaction; reject/escape \| and newline in audit fields | AUDIT-041; CWE-117/532 | open |
| `crates/rustynet-control/src/persistence.rs` | 2026-06-18 | 1 | K3,F1,F2,I1,I4,E1,T1,T2 | FINDINGS | RSA-0017 | enforce/verify 0o600 on sqlite DB + -wal/-shm sidecars at open; fail closed | SecMinBar §3.5; CWE-732 | open |
| `crates/rustynet-control/src/role_audit.rs` | 2026-06-18 | 1 | A1,A2,E1,E2,K2,I4,T1,T2 | FINDINGS | RSA-0012, RSA-0013 | exclusive advisory lock around read-derive-index+append; propagate set_permissions error | SecMinBar §6.D ctrl 6; CWE-362/732 | open |
| `crates/rustynet-control/src/role_presets.rs` | 2026-06-18 | 1 | K1,F1,F2,E1,E2,T1,T2 | PASS | none | none needed — validate_transition fail-closed gatekeeper; BlindExit blocked/irrev+ack+owner-sig; exhaustive 8x8 matrix tests | SecMinBar §6.D ctrl 1/2/3; CLAUDE.md §10.7 | audited |
| `crates/rustynet-control/src/roles.rs` | 2026-06-18 | 1 | F1,F2,I1,I4,E2,V1,T1 | PASS | none | none needed — parse default-denies empty/unknown; canonicalize sorts+dedups; append-only ordering test-pinned | SecMinBar §6.D; CLAUDE.md §10.4 | audited |
| `crates/rustynet-control/src/scale.rs` | 2026-06-18 | 1 | C1,C7,W1,F1,F4,V1,T1,T2 | FINDINGS | RSA-0016 | constant-time (subtle) break-glass compare; redacting Debug for TrustHardeningConfig | SecMinBar §3.4; CLAUDE.md §10.6; CWE-208/532 | open |
| `crates/rustynet-operator/Cargo.toml` | 2026-06-18 | 1 | S1,S2,E2,V4 | PASS | none | none needed — zero external deps (std-only); inherits unsafe_code=forbid (RN-14) | SecMinBar §10; CLAUDE.md §8 | audited |
| `crates/rustynet-operator/src/args.rs` | 2026-06-18 | 1 | I1,E1 | PASS | none | none needed — strict argv parse; required-value + unknown-flag rejection; enum-validated | CWE-20; CLAUDE.md §10 | audited |
| `crates/rustynet-operator/src/config/keys.rs` | 2026-06-18 | 1 | I1,F2 | PASS | none | none needed — static allowlist of config keys; unknown rejected; negative test | CLAUDE.md §10.4 | audited |
| `crates/rustynet-operator/src/config/mod.rs` | 2026-06-18 | 1 | V1 | PASS | none | none needed — plain module re-exports | CLAUDE.md §8 | audited |
| `crates/rustynet-operator/src/config/parse.rs` | 2026-06-18 | 1 | I1,I4,E2,E3 | PASS | none | none needed — line-based allowlist parse; ASCII-quote slice provably in-bounds; no newline smuggling | CLAUDE.md §10 (I1) | audited |
| `crates/rustynet-operator/src/config/persist.rs` | 2026-06-18 | 1 | I3,C4,C6,E1,F1 | FINDINGS | RSA-0020 | fstat the open fd (check mode/owner on same handle that is read); verify parent-dir ownership | CWE-367; CLAUDE.md §4 | open |
| `crates/rustynet-operator/src/config/validate.rs` | 2026-06-18 | 1 | I1,I4,F1,F2,F4,E1,E4,K1 | FINDINGS | RSA-0021 | defense-in-depth: constrain interface-name/dataplane-mode shape at operator layer (re-validated downstream) | CLAUDE.md §10.4 (I1); CWE-20 | open |
| `crates/rustynet-operator/src/egress.rs` | 2026-06-18 | 1 | I1,E1,I3 | FINDINGS | RSA-0022 | if ever wired to a routing/trust decision, parse octets via Ipv4Addr; today a non-validating display extractor | CWE-20 | open |
| `crates/rustynet-operator/src/host.rs` | 2026-06-18 | 1 | E1,V1 | PASS | none | none needed — trivial cfg!-based OS-profile enum; no untrusted input | CLAUDE.md §8 | audited |
| `crates/rustynet-operator/src/launch.rs` | 2026-06-18 | 1 | I1,I2,F1,E1,T1 | PASS | none | none needed — is_valid_node_id blocks shell/path metachars before IPC; sanitize fails closed | CWE-78; SecMinBar §3.7 | audited |
| `crates/rustynet-operator/src/lib.rs` | 2026-06-18 | 1 | E2,V1 | PASS | none | none needed — module decls + #![forbid(unsafe_code)]; zero crate deps (no backend/crypto leak) | CLAUDE.md §8; RN-14 | audited |
| `crates/rustynet-operator/src/menu.rs` | 2026-06-18 | 1 | W1,V1,T1 | PASS | none | none needed — role-based menu RBAC (admin-only mutations hidden from client/blind-exit); tested | SecMinBar §3.6; CLAUDE.md §10.7 | audited |
| `crates/rustynet-operator/src/role.rs` | 2026-06-18 | 1 | F1,F3,E1,W1,V1,T1 | PASS | none | none needed — blind-exit locked posture + platform gating fail-closed; role coercion tested | SecMinBar §6.D ctrl 9; CLAUDE.md §3 | audited |
| `crates/rustynet-policy/Cargo.toml` | 2026-06-18 | 1 | S1,S2 | PASS | none | none — zero external dependencies (pure transport-agnostic domain crate, no backend leak) | CLAUDE.md §8; SecMinBar §10 | audited |
| `crates/rustynet-policy/src/lib.rs` | 2026-06-18 | 1 | F2,F4,V1,V2,I1,T1,T2 | FINDINGS | RSA-0005, RSA-0006 (+ caller finding RSA-0007 → `phase10.rs`) | remove/fix stale permissive-on-empty `is_populated()` doc+dead method; complete `validate_policy_safety` allow-all detection | CLAUDE.md §10.4; SecMinBar §3.6; FullRepoAnalysis_2026-05-24 | open |
| `crates/rustynetd/Cargo.toml` | 2026-06-18 | 1 | E2,S1,S2 | PASS | none | none needed | verified: Deps are workspace-path crates plus pinned audited crypto (ed25519-dalek 2, sha2, hmac, subtle, zeroize, nix, base64, OsRng via rand). No git/wildcard deps. unsafe_code=deny with d | audited |
| `crates/rustynetd/benches/phase1_runtime_baseline.rs` | 2026-06-18 | 1 | T1,T2 | PASS | none | none needed | verified: Deterministic XOR baseline bench; no security control, no secrets, no attacker input. | audited |
| `crates/rustynetd/src/daemon.rs` | 2026-06-18 (+verify sweep 2026-06-20) | 1 | C1,C6,E1,E2,E3,F1,F2,F3,F4,I1,K1,K2,V1 | FINDINGS | RSA-0077 | complete RN-22: the 5 signed-trust-state verifiers (`:6866/11253/12145/13170/13437`) use plain ed25519 `verify` (malleable) — migrate to `verify_strict` like `control`/`crypto`. (Fail-closed + secrets/panics/indexing lenses remain clean.) | RN-22/RL-3; CWE-347 | open |
| `crates/rustynetd/src/dataplane.rs` | 2026-06-18 | 1 | E1,E4,F1,F2,F3,F4,I3,RN-02 dead-code confirm,T1,V2 | PASS | none | none needed | verified: RN-02 confirmed: LinuxDataplane has zero production construction (only #[cfg(test)]); dead/unwired. forbid(unsafe). No net-new reachable bug. | audited |
| `crates/rustynetd/src/dataplane_candidates.rs` | 2026-06-18 | 1 | F2,I4,N3,V2 | PASS | none | none needed | verified: Untrusted STUN srflx filtered to Global/Private scope outbound (drops loopback/multicast/doc-prefix); getifaddrs fail-soft to empty; tested. | audited |
| `crates/rustynetd/src/enrollment_consume.rs` | 2026-06-18 | 1 | F1,F2,I1,K3,N3,V2 | FINDINGS | RSA-0023 | shares the enrollment-ledger lock fix | SecMinBar §3.3 (K3); CWE-362 | open |
| `crates/rustynetd/src/enrollment_token.rs` | 2026-06-18 | 1 | C1,C2,C6,E1,E3,F1,I1,I3,K3,T1 | FINDINGS | RSA-0023 | OS advisory file lock (flock) around ledger read-modify-write (mirror resilience.rs acquire_lock); concurrent-consume test | SecMinBar §3.3 (K3); CWE-362 | open |
| `crates/rustynetd/src/exit_codes.rs` | 2026-06-18 | 1 | A1,E1 | PASS | none | none needed | verified: Exit-code taxonomy. forbid(unsafe_code); const matches only; PolicyReject no-retry pinned by test; pairwise-distinct + sysexits alignment tests. | audited |
| `crates/rustynetd/src/fetcher.rs` | 2026-06-18 | 1 | E3,F1,I4,K1,K2,K3,N2 | PASS | none | none needed | verified: Verify->freshness->watermark order correct; 4MB body cap via take(cap+1); CRLF-reject in URL; strict int parse; clock<EPOCH fail-closed; replay rejects. | audited |
| `crates/rustynetd/src/gossip_runtime.rs` | 2026-06-18 | 1 | A1,C6,E1,F1,F2,F3,I4,K2,K3,T1 | FINDINGS | RSA-0028, RSA-0034 | per-peer inbound gossip token-bucket before Ed25519 verify; recheck current revocation status on ingest apply | RN-N4; CWE-770; CWE-285 | open |
| `crates/rustynetd/src/gossip_transport.rs` | 2026-06-18 | 1 | E1,F1,I1,N1,N3,T1 | PASS | none | none needed | verified: 4KiB cap enforced on send+recv; production drain uses Duration::ZERO single try_recv; deserialise delegated to strict path; Windows fails closed. | audited |
| `crates/rustynetd/src/ice_priority.rs` | 2026-06-18 | 1 | E3,F2,N3,V2 | PASS | none | none needed | verified: Pure RFC8445 prioritization; saturating math; MAX_CANDIDATE_PAIRS cap; priority informational, WG handshake authenticates; no trust bypass. | audited |
| `crates/rustynetd/src/ipc.rs` | 2026-06-18 | 1 | E1,E4,F2,I1,I4,K3,T1 | FINDINGS | RSA-0027 | structural CIDR parse (ipnet) at the boundary, not char-set only | RN-N7; CWE-20 | open |
| `crates/rustynetd/src/key_material.rs` | 2026-06-18 (re-verified 2026-06-19) | 1 | C1,C6,E1,E3,F1,F2,I1,I3,K3 | FINDINGS | RSA-0025 (RSA-0030 WITHDRAWN-FP) | apply restrictive ACL at .enc write on Windows (not just at check). RSA-0030 withdrawn: parent-dir gating + negative test already exist (`:628-658`/`:1418-1468`, commit 1525cae) | AUDIT-027/RN-33; CWE-732 | open |
| `crates/rustynetd/src/key_rotation.rs` | 2026-06-18 | 1 | A1,E1,E3,F1,I3,K1,K2,T1,T2 | PASS | none | none needed | verified: Ledger fails closed on corrupt/digest/monotonicity mismatch, atomic write+fsync+rename, 0o600, no secret logging (only pubkey hex), bounded read, broad fault-injection test coverag | audited |
| `crates/rustynetd/src/lib.rs` | 2026-06-18 | 1 | E2,V1 | PASS | none | none needed | verified: Module tree. #![deny(unsafe_code)] crate-wide; single documented #[allow(unsafe_code)] on cfg(macos) macos_utun_helper_unsafe (RN-14 scoped exception, not hiding a lint). | audited |
| `crates/rustynetd/src/linux_authenticode.rs` | 2026-06-18 | 1 | F1,K1,T1,T2 | PASS | none | none needed | verified: Honest non-applicability stub (applicable:false, overall_ok:true); orchestrator evaluator threads applicable separately, not fail-open. Snapshot-pinned. | audited |
| `crates/rustynetd/src/linux_dns_failclosed.rs` | 2026-06-18 | 1 | E1,F3,I4,T1 | PASS | none | none needed | verified: Pure verifier; non-loopback/unparseable/empty nameserver all = drift; advisory tool, not enforcement; strong negative-test coverage. | audited |
| `crates/rustynetd/src/linux_dns_protect.rs` | 2026-06-18 | 1 | E2,F3,I1,I2,I3 | PASS | none | none needed | verified: Fixed-selector privileged builtin; O_NOFOLLOW/O_EXCL+rename symlink-safe writes; argv-only redirect; phase10 apply fails closed per-step. | audited |
| `crates/rustynetd/src/linux_exit_dns_failclosed.rs` | 2026-06-18 | 1 | E1,F3,I2,T1 | PASS | none | none needed | verified: Read-only evidence producer; failed nft/getent capture -> empty -> rule 'missing'/overall_ok=false (fail-closed); inputs char-set validated before argv. | audited |
| `crates/rustynetd/src/linux_exit_nat_lifecycle.rs` | 2026-06-18 | 1 | E3,F3,I2,T1 | PASS | none | none needed | verified: Read-only snapshot/merge producer; as i64 cast on epoch secs harmless; proc-forwarding read defaults Disabled (conservative); argv-only nft. | audited |
| `crates/rustynetd/src/linux_key_custody.rs` | 2026-06-18 | 1 | A1,F1,F2,I4,T1 | PASS | none | none needed | verified: Default-deny evaluator: empty->reject, unknown requirement->reject, forbidden-at-rest->reject, symlink/owner/mode checks, serde unknown-tag fails closed, multi-drift aggregation te | audited |
| `crates/rustynetd/src/linux_killswitch_boot.rs` | 2026-06-18 | 1 | E1,E4,F3,I1,I2,T1 | PASS | none | none needed | verified: Boot killswitch installs policy-drop chain first, accept rules after (fail-closed window over-blocks); argv-only nft; CLI propagates apply error. | audited |
| `crates/rustynetd/src/linux_mesh_status.rs` | 2026-06-18 | 1 | E3,F1,I4,K2,T1,T2 | PASS | none | none needed | verified: Read-only snapshot verifier; fail-closed on Io/IntegrityMismatch/InvalidFormat; timestamp as-i64 cast in diagnostic path is fail-closed direction. Drift tests strong. | audited |
| `crates/rustynetd/src/linux_runtime_acls.rs` | 2026-06-18 | 1 | E2,E3,F1,F2,I3,T1,T2 | PASS | none | none needed | verified: Runtime-ACL evaluator rejects symlink-first, masks mode 0o7777, checks owner/group; uid/gid .ok() falls to Drifted (fail-closed). Strong negative tests. | audited |
| `crates/rustynetd/src/linux_runtime_nftables.rs` | 2026-06-18 | 1 | F1,F3,I1,V2 | PASS | none | none needed | verified: Pure verifier + service-scope renderer; correct default-deny/extra-chain reject logic, strict input validation, but entire module is unwired in production. | audited |
| `crates/rustynetd/src/linux_service_hardening.rs` | 2026-06-18 | 1 | E2,F1,F2,I2,T1,T2 | PASS | none | none needed | verified: argv-only systemctl show --all (no shell), overall_ok=probed&&empty-drift, empty-map deny, per-directive negative tests, pins killswitch ExecStartPre fail-closed. | audited |
| `crates/rustynetd/src/macos_authenticode.rs` | 2026-06-18 | 1 | F1,K1,T1,T2 | PASS | none | none needed | verified: Honest Gatekeeper non-applicability stub (applicable:false, overall_ok:true); parity with Linux stub. Drift tests pin shape. | audited |
| `crates/rustynetd/src/macos_blind_exit.rs` | 2026-06-18 | 1 | F1,F2,F3,I1,I2,T1,V1 | PASS | none | none needed | verified: blind_exit PF policy; FactoryReset-only removal (irreversible); terminal block-all + route-to/reply-to/dup-to bans; tunnel/mesh-only egress; default-deny. | audited |
| `crates/rustynetd/src/macos_dns_failclosed.rs` | 2026-06-18 | 1 | C1,E1,E3,F1,F3,I1,I4,T1 | PASS | none | none needed | verified: DNS-leak verifier; off-loopback/empty/missing/malformed all fail closed; parse().ok() surfaces None as drift; negative tests present. | audited |
| `crates/rustynetd/src/macos_exit_dns_failclosed.rs` | 2026-06-18 | 1 | E1,F3,I1,I2,I3,T1 | PASS | none | none needed | verified: Exit-DNS artefact producer; argv-only pfctl/tcpdump/dscacheutil; iface+hostname validated; missing rule/answer fails closed. | audited |
| `crates/rustynetd/src/macos_exit_killswitch_precedence.rs` | 2026-06-18 | 1 | E1,F1,F3,I1,I2,K1,T1 | PASS | none | none needed | verified: Killswitch-precedence proof; deliberate live flush+guaranteed restore via Result; empty rules fail closed; anchor name validated argv-only. | audited |
| `crates/rustynetd/src/macos_exit_nat_lifecycle.rs` | 2026-06-18 | 1 | E3,F1,F3,I1,I2,T1 | FINDINGS | RSA-0031 | fail-closed when pfctl exec fails during teardown verification (do not report forwarding_restored=true) | SecMinBar §6.D ctrl 7; CWE-636 | applied 2026-06-24 |
| `crates/rustynetd/src/macos_key_custody.rs` | 2026-06-18 | 1 | F1,F2,I4,T1 | PASS | none | none needed | verified: Default-deny evaluator with symlink+owner+mode probes, plaintext-key/passphrase forbidden-at-rest enforced, empty/unknown-requirement reject, serde unknown-tag fails closed; well t | audited |
| `crates/rustynetd/src/macos_mesh_status.rs` | 2026-06-18 | 1 | E3,F1,I4,K2,T1,T2 | PASS | none | none needed | verified: Read-only snapshot verifier reusing shared evaluator; fail-closed on all load-error variants; serde round-trips for every variant. | audited |
| `crates/rustynetd/src/macos_runtime_acls.rs` | 2026-06-18 | 1 | E2,E3,F1,F2,I3,T1,T2 | PASS | none | none needed | verified: Same ACL evaluator as Linux plus empty-roots fail-closed in evaluate_macos_runtime_acl_report. Symlink-first reject, mode mask, owner/group checks. | audited |
| `crates/rustynetd/src/macos_service_hardening.rs` | 2026-06-18 | 1 | C6,F1,F2,I2,I3,T1,T2 | PASS | none | none needed | verified: Read-only plist parse; evaluates scalars+ProgramArguments(backend pin)+env(keychain account allow-list charset); overall_ok=probed&&empty; empty deny. | audited |
| `crates/rustynetd/src/macos_utun_helper.rs` | 2026-06-18 | 1 | E1,I1,I4,V1 | PASS | none | none needed | verified: #![forbid(unsafe_code)]. validate_utun_interface_name enforces utun-prefix + all-digit suffix + len<=15, rejecting CWE-78 vectors (covered by negative tests). Client validates befo | audited |
| `crates/rustynetd/src/macos_utun_helper_server.rs` | 2026-06-18 | 1 | E1,F1,I1,I4 | PASS | none | none needed | verified: #![forbid(unsafe_code)]. RNUF frame parse validates magic/version/non-zero-len/UTF-8/no-trailing-bytes, then validate_utun_interface_name before device open. Errors surfaced via 0x | audited |
| `crates/rustynetd/src/macos_utun_helper_unsafe.rs` | 2026-06-18 | 1 | E1,E2,E4,F1,I1,I4 | FINDINGS | RSA-0032 | add // SAFETY: invariant comment to each unsafe block; run Miri where feasible | ANSSI Secure Rust (unsafe); CLAUDE.md §10.2 (E2) | open |
| `crates/rustynetd/src/main.rs` | 2026-06-18 | 1 | C1,C6,E1,E4,F1,I1,S1 | PASS | none | none needed | verified: Daemon CLI entry. Argv/env parsers all typed-parse+map_err, zero-guards on ports/durations, fail-closed on unknown flags; OsRng CSPRNG; key bytes zeroized; symlink_metadata+0o600 o | audited |
| `crates/rustynetd/src/peer_gossip.rs` | 2026-06-18 | 1 | C1,C7,E1,E3,F1,F4,I1,I4,K1,K2,K3,N3,T1,T2 | PASS | none | none needed | verified: Ed25519 verify->scope->freshness->monotonic ordering correct; decoder checked_add/mul + MAX_CANDIDATES bounds; expect() on locally-provable slices; thorough negative tests. | audited |
| `crates/rustynetd/src/perf.rs` | 2026-06-18 | 1 | E4,I1 | PASS | none | none needed | verified: Phase1 baseline metrics from env. forbid(unsafe_code); finite/>=0 parse guard, invalid/missing env => fail status (not silent pass); JSON values are numeric/static, no injection. | audited |
| `crates/rustynetd/src/phase10.rs` | 2026-06-18 | 1 | A1,E1,E2,E4,F1,F2,F3,I2,I3,K1,T1,V1 | FINDINGS | RSA-0007 | route set_exit_node/ensure_lan_route_allowed through evaluate_with_membership; add revoked-node negative test | RSA-0007; SecMinBar §3.6/§3.8; CWE-285 | applied 2026-06-24 |
| `crates/rustynetd/src/platform.rs` | 2026-06-18 | 1 | E1,F1 | PASS | none | none needed | verified: Platform parity validator. forbid(unsafe_code); validate_platform_parity returns Err on any missing hook / failed leak matrix (fail-closed); negative test present. | audited |
| `crates/rustynetd/src/port_mapper.rs` | 2026-06-18 | 1 | C1,C5,E3,I4,N3,T2 | FINDINGS | RSA-0035 | host-scope/allowlist the uPnP SSDP-supplied control URL (SSRF); add PCP/uPnP fuzz targets | CWE-918; RN-N6 | open |
| `crates/rustynetd/src/privileged_helper.rs` | 2026-06-18 | 1 | C6,E1,E2,E3,F1,F4,I1,I2,I3,T1,T2 | FINDINGS | RSA-0033 | scope the kill builtin to rustynet-owned PIDs (track spawned children) instead of any pid>1 | least-privilege; CWE-250 | open |
| `crates/rustynetd/src/relay_client.rs` | 2026-06-18 | 1 | C1,E1,F1,F4,I1,I3,K1,K3 | PASS | none | none needed | verified: try_sign fail-closed nonce; token bound (node/peer/relay/scope/nonce/ttl/expiry/skew) validated before I/O; preissued one-use+perms; ack source+port checked. | audited |
| `crates/rustynetd/src/resilience.rs` | 2026-06-18 | 1 | E1,F1,I1,I4,K1 | PASS | none | none needed | verified: SHA256 integrity verify-before-use; 128KiB cap; unknown line fails closed; atomic create_new+rename+fsync+0o600 under advisory lock. | audited |
| `crates/rustynetd/src/secret_log_audit.rs` | 2026-06-18 | 1 | C6,F1,I4,T1,T2 | FINDINGS | RSA-0026 | cover real secret types (SecretKey/EnrollmentToken/RelaySessionToken/SessionToken/...); multi-line scan; include control/relay/crypto crates | SecMinBar §3.4 (C6); ADR-001; CWE-532 | open |
| `crates/rustynetd/src/service_access_state.rs` | 2026-06-18 | 1 | A1,F2,F4,I3,T1 | PASS | none | none needed | verified: Default-deny grants via evaluate_with_membership + Active filter; atomic 0600 writes; teardown-before-revoke; force_deny_all backstop. Solid. | audited |
| `crates/rustynetd/src/service_exposure.rs` | 2026-06-18 | 1 | A1,A2,C6,E1,E2,E2-cast,E3,F1,F2,F3,I1,T1,T2,V1 | FINDINGS | RSA-0024 | wire ServiceExposureController into a production enforcement point, or document as scaffold (audit-catalog over-claim) | SecMinBar §6.E; CLAUDE.md §4; CWE-1006 | open |
| `crates/rustynetd/src/stun_client.rs` | 2026-06-18 | 1 | E3,I4,K1,N3,T1 | PASS | none | none needed | verified: STUN parser bounds-checked (20-byte hdr, length<=buf, attr_end<=end); txn-id+magic+type validated; padding loop advances; rich negative tests. | audited |
| `crates/rustynetd/src/traversal.rs` | 2026-06-18 | 1 | E1,E3,F1,F2,I1,K1,K2,K3,N3 | FINDINGS | RSA-0029 | persist coordination replay watermark across restart; bound coordination-record TTL | SecMinBar §3.8 (N3); CWE-294 | open |
| `crates/rustynetd/src/unix_shutdown_signals.rs` | 2026-06-18 | 1 | E1,F1 | PASS | none | none needed | verified: SIGTERM/SIGINT flag handler. forbid in cfg(unix); install failure propagated as startup error (no silent degrade); handler only touches AtomicBool (async-signal-safe); e2e raise-SI | audited |
| `crates/rustynetd/src/windows_authenticode.rs` | 2026-06-18 | 1 | C1,E3,F1,I4 | FINDINGS | RSA-0036 | implement the thumbprint extractor or document the stub as intentionally fail-closed (thumbprint-pinned policy currently can never pass) | net-new; SecMinBar §10 | open |
| `crates/rustynetd/src/windows_backend_gate.rs` | 2026-06-18 | 1 | E2,F1 | PASS | none | none needed | verified: forbid(unsafe_code); windows-unsupported label fails closed via require_supported_windows_backend; unknown label rejected. | audited |
| `crates/rustynetd/src/windows_backend_readiness.rs` | 2026-06-18 | 1 | F1,I2 | PASS | none | none needed | verified: Readiness probe; empty/unprobed/absent => drift, off-Windows probed=false (never fabricated pass); PowerShell/DPAPI via absolute path + argv arrays, netsh only file-probed (no bare | audited |
| `crates/rustynetd/src/windows_dns_failclosed.rs` | 2026-06-18 | 1 | E1,F1,F2,I1,I4,N3,T1,T2 | PASS | none | none needed | verified: Pure DNS verifier fails closed on schema/unparseable/non-loopback/missing-root; static argv-only PS script, System32-resolved binary, off-Windows Err; RN-07 covered via sibling+RA | audited |
| `crates/rustynetd/src/windows_exit_nat_lifecycle.rs` | 2026-06-18 | 1 | A1,F2,I1,I4,T1 | FINDINGS | RSA-0031 | fail-closed when forwarding-capture fails (do not count unknown as restored) | SecMinBar §6.D ctrl 7; CWE-636 | open |
| `crates/rustynetd/src/windows_ipc.rs` | 2026-06-18 | 1 | F2,I1,I4,N2,T1,V2 | PASS | none | none needed | verified: Pipe path pinned to RustyNet leaf; SDDL owner=SY + forbidden-principal allowlist + size bounds; PIPE_REJECT_REMOTE_CLIENTS kernel-enforced; serde bounded before decode. | audited |
| `crates/rustynetd/src/windows_key_custody.rs` | 2026-06-18 | 1 | F1,F2,I4,T1 | PASS | none | none needed | verified: Default-deny SDDL-based evaluator: required-present + forbidden-absent + ACL-drift + extension-drift + partial-rotation all fail closed; empty/unknown-requirement reject; rotation | audited |
| `crates/rustynetd/src/windows_killswitch_smoke.rs` | 2026-06-18 | 1 | E1,F1,F2,I1,T1,T2 | PASS | none | none needed | verified: Lab smoke verb, not daemon enforcement; conservative AND-of-all verdict, RN-06 SSH-CIDR scoping + RN-07/G8 IPv6 leak proven; Drop guard is documented dead-man's-switch backstop. | audited |
| `crates/rustynetd/src/windows_mesh_status.rs` | 2026-06-18 | 1 | F1,I3,K2 | PASS | none | none needed | verified: Read-only diagnostic; state path validated under reviewed root before FS access, integrity/format/future-timestamp => drift, default-deny on missing peers. | audited |
| `crates/rustynetd/src/windows_paths.rs` | 2026-06-18 | 1 | F1,F2,I3,V1 | PASS | none | none needed | verified: Reviewed-root + protected-DACL (D:P) enforcement, forbidden WD/AU/BU, deny-ACE detection, exact-token SDDL match, owner whitelist; daemon startup gate fails closed. No panics on at | audited |
| `crates/rustynetd/src/windows_registry_acls.rs` | 2026-06-18 | 1 | F2,V1 | PASS | none | none needed | verified: Registry-key ACL evaluator: empty=>deny, forbidden WD/AU/BU/AN allow ACEs, DACL-present required, allow-vs-deny discrimination; collector maps Invalid/Missing/Unobserved fail-close | audited |
| `crates/rustynetd/src/windows_runtime_boundary.rs` | 2026-06-18 | 1 | F1,I3,K3 | PASS | none | none needed | verified: Boundary self-check; secret blob path pinned, IPC server-error surfaced over transient races, cleanup runs before return on all paths. Self-check passphrase is a fixed non-secret c | audited |
| `crates/rustynetd/src/windows_service.rs` | 2026-06-18 | 1 | F1,I2,I3 | PASS | none | none needed | verified: SCM host; env-file path validated under reviewed root, env parser bounded+key-validated, backend resolution fails closed via blocker_reason; argv-only daemon dispatch. | audited |
| `crates/rustynetd/src/windows_service_hardening.rs` | 2026-06-18 | 1 | F1,I2,V1 | PASS | none | none needed | verified: Verifier: argv-only --windows-service/--env-file, install-root pinned binary, SID-type/account whitelist, non-interactive, recovery action, binary ACL via shared evaluator; off-Win | audited |
| `crates/rustynetd/src/windows_tunnel_smoke.rs` | 2026-06-18 | 1 | C1,F1 | PASS | none | none needed | verified: One-shot operator smoke; ephemeral key written 0600 then removed whether or not start succeeds. HB-1: cleanup uses let _ = (swallows error) so a failed remove leaves a throwaway ep | audited |
| `crates/rustynetd/tests/enrollment_token_audit.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Asserts raw-secret/tag absence, Debug redaction, AlreadyConsumed after ledger reload. Strong negative pins. | audited |
| `crates/rustynetd/tests/enrollment_trust_propagation.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Asserts SignatureInvalid/ThresholdNotMet, dup node_id, AlreadyConsumed negative paths. Genuine. | audited |
| `crates/rustynetd/tests/enrollment_two_peer_redeem.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: One-time redeem asserted (AlreadyConsumed); wrong secret leaves peers empty; rejected push leaves token intact. | audited |
| `crates/rustynetd/tests/gossip_three_peer_mesh.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Each negative asserts accepted_count unchanged AND the specific rejected_counts key. Real fail-closed pins. | audited |
| `crates/rustynetd/tests/ice_pair_race.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Asserts FailClosed reason when no direct pair + no relay; priority order and relay-armed fallback verified. | audited |
| `crates/rustynetd/tests/membership_replay_protection.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Asserts ReplayDetected for dup update_id and epoch<=max; PrevStateRootMismatch as durable rollback guard. | audited |
| `crates/rustynetd/tests/quorum_multi_approver.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Quorum=2 enforced: single sig rejected, revoked guardian not counted, misconfig caught at validate. | audited |
| `crates/rustynetd/tests/role_capability_enforcement.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Every illegal capability combo asserts InvalidFormat with expected message substring. Genuine deny pins. | audited |
| `crates/rustynetd/tests/state_fetcher.rs` | 2026-06-18 | 1 | T2 | PASS | none | none needed | verified: Asserts remote fetch disabled (always Skipped) and never overwrites local trust/bundle artifacts. | audited |

### Tier 2 — Transport backends & dataplane

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `crates/rustynet-backend-api/Cargo.toml` | 2026-06-18 | 2 | S1,S2 | PASS | none | none needed | verified: Zero external deps; version/lints workspace-pinned. No git/wildcard. | audited |
| `crates/rustynet-backend-api/src/lib.rs` | 2026-06-18 | 2 | C6,E1,E2,F1,F4,I1,V1,V2 | PASS | none | none needed | verified: TunnelBackend trait is fully transport-agnostic (no WireGuard/boringtun concrete types); NodeId::new rejects empty; default trait methods fail-closed; no unsafe/unwrap/secret-log. | audited |
| `crates/rustynet-backend-api/tests/backend_contract.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Conformance harness asserts fail-closed NotRunning pre-start, default-deny InvalidInput on unknown peers, double-start reject, route-replace determinism. Real assert | audited |
| `crates/rustynet-backend-api/tests/backend_contract_perf.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Perf report only, no security control. Deterministic peer keys local; report to temp/env path, no world-readable secret. | audited |
| `crates/rustynet-backend-stub/Cargo.toml` | 2026-06-18 | 2 | S1,S2 | PASS | none | none needed | verified: rustynet-backend-api duplicated in deps+dev-deps (harmless redundancy); all path-pinned. | audited |
| `crates/rustynet-backend-stub/src/lib.rs` | 2026-06-18 | 2 | E1,E2,F1,F4,V1 | PASS | none | none needed | verified: Pure in-memory test stub; ensure_running fail-closed NotRunning; no external input, crypto, or unsafe. Judged as test backend. | audited |
| `crates/rustynet-backend-stub/tests/stub_conformance.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Mirrors api contract suite against StubBackend; asserts NotRunning/InvalidInput/AlreadyRunning negative paths with real assert_eq. | audited |
| `crates/rustynet-backend-userspace/Cargo.toml` | 2026-06-18 | 2 | S1,S2 | PASS | none | none needed | verified: Path + exact-version deps (base64 0.22, tempfile 3). No git/wildcard. | audited |
| `crates/rustynet-backend-userspace/src/lib.rs` | 2026-06-18 | 2 | E1,E2,F4,V1,V2 | PASS | none | none needed | verified: Thin platform-delegating wrapper; unsupported platforms fail-closed with Internal error on every op, no cleartext fallthrough; no concrete-type leak. | audited |
| `crates/rustynet-backend-userspace/tests/userspace_conformance.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Asserts invalid-key-path -> InvalidInput, unsupported-platform -> Internal, pre-start configure -> NotRunning. TUN suite env-gated, skip explicit. | audited |
| `crates/rustynet-backend-wireguard/Cargo.toml` | 2026-06-18 | 2 | S1,S2 | PASS | none | none needed | verified: Path + exact-version deps; bench/example require opt-in test-harness; criterion default-features=false trims supply chain. No git/wildcard. | audited |
| `crates/rustynet-backend-wireguard/benches/dataplane_engine.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Criterion bench over bench_support seam; no sockets/keys/secrets; feature-gated test-harness path. No security surface. | audited |
| `crates/rustynet-backend-wireguard/examples/perfprobe_engine.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Fixed-work probe over handshaken engine pair via bench_support; counting allocator dev-only; no secrets persisted. | audited |
| `crates/rustynet-backend-wireguard/src/bench_support.rs` | 2026-06-18 | 2 | C7,E1,F4 | PASS | none | none needed | verified: cfg-gated test-harness only, never ships; drives real Noise via vendored boringtun (no custom crypto); expect() bench-only. | audited |
| `crates/rustynet-backend-wireguard/src/in_memory.rs` | 2026-06-18 | 2 | C6,E1,E2,E3,F4,I1,I2,T1 | PASS | none | none needed | verified: In-memory backend disabled in production (daemon fail-closed); wg show uses argv-only, 64KB cap, parse errors via ?, 32B pubkey check; as-casts bench/test-only. | audited |
| `crates/rustynet-backend-wireguard/src/lib.rs` | 2026-06-18 | 2 | F4,S1,V1 | PASS | none | none needed | verified: Module glue + re-exports; bench_support gated cfg(any(test, feature=test-harness)) so excluded from shipped binary. | audited |
| `crates/rustynet-backend-wireguard/src/linux_command.rs` | 2026-06-18 | 2 | C1-C7,E1-E4,F1-F4,I1-I4,T1-T2,V1-V4 | FINDINGS | RSA-0044 | factor macOS validate_peer_endpoint into a shared module; call it from the Linux configure/update paths for parity | CLAUDE.md §10 (I1); CWE-20 | open |
| `crates/rustynet-backend-wireguard/src/macos_command.rs` | 2026-06-18 | 2 | C1-C7,E1-E4,F1-F4,I1-I4,T1-T2,V1-V4 | PASS | none | none needed | verified: Argv-only wg/ifconfig/route/kill; utun name + CIDR validated; ps spawned with fixed argv; gateway parser rejects injection; rollback fail-closed; split-default correct. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs` | 2026-06-18 | 2 | C1,C4,C6,E1,E3,E4,F1,I1,V2 | FINDINGS | RSA-0038 | add cargo-fuzz target over process_inbound_ciphertext/inject_plaintext_packet/AllowedIpNetwork::parse | RN-N6 class; CWE-1286 | open |
| `crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs` | 2026-06-18 | 2 | A1,E1 | PASS | none | none needed | verified: Monotonic per-node handshake-unix telemetry map. No secrets, no unsafe, no untrusted-input parsing. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs` | 2026-06-18 | 2 | C1,E1,E3,F1,F4,I1,T1,T2,V2 | PASS | none | none needed | verified: Backend trait facade. No custom crypto, fail-closed start/recovery, CIDR validation, no boringtun type leak. Strong negative-test coverage incl malformed/unmatched packets. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs` | 2026-06-18 | 2 | E1,E4,F1,F4,N2 | PASS | none | none needed | verified: Single worker thread, channel command bus. Per-tick budgets (64) bound work; recording buffers cfg(test); round-trip single-flight gate; fail-closed on poll errors; no panic on wor | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs` | 2026-06-18 | 2 | E1,E4,F1,I1 | PASS | none | none needed | verified: std UdpSocket, nonblocking, recv-into scratch (no per-packet alloc), short-write detection, WouldBlock handled. No unsafe, no panic on hostile datagram. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs` | 2026-06-18 | 2 | E1,E4,I1,I2 | PASS | none | none needed | verified: argv-only ip-command exec (no shell), bounded recv scratch with overflow check, CIDR/iface validation, route/exit-mode reconcile with rollback. expect() only in cfg(test) state. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared_macos/mod.rs` | 2026-06-18 | 2 | C6,E1,E2,E3,E4,F1,F2,I1,I3,V1,V2 | PASS | none | none needed | verified: Backend facade: argv-only ifconfig/route, fail-closed start/recovery, CIDR/endpoint validation pre-mutation; all unwrap/expect/eprintln in test mod (>L755). | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared_macos/runtime.rs` | 2026-06-18 | 2 | C6,E1,E3,E4,F1,F2,I1,N2 | PASS | none | none needed | verified: Worker loop: bounded per-tick budgets (64), single round-trip slot via CAS, no panic on hostile bytes, recorded buffers cfg(test)-only, fails closed on poll error. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared_macos/socket.rs` | 2026-06-18 | 2 | C6,E1,E4,F1,I1 | PASS | none | none needed | verified: Authoritative UDP socket: scratch-based recv (no per-packet alloc), WouldBlock/TimedOut->None else error, send-truncation detected; no key/payload logging. | audited |
| `crates/rustynet-backend-wireguard/src/userspace_shared_macos/tun.rs` | 2026-06-18 | 2 | C6,E1,E2,E4,F1,F2,I1,I2,I3 | PASS | none | none needed | verified: utun lifecycle: utun<digits> name validation, argv route/ifconfig, truncation surfaced as error, fd-wrap fail-closed; expect() only on test-only state. | audited |
| `crates/rustynet-backend-wireguard/src/windows_command.rs` | 2026-06-18 | 2 | C1-C7,E1-E4,F1-F4,I1-I4,T1-T2,V1-V4 | FINDINGS | RSA-0039 | hand-write a redacting Debug for WindowsWireguardBackend (runtime_private_key => <redacted>); add a no-leak test | SecMinBar §3.4 (C6); CWE-532 | open |
| `crates/rustynet-backend-wireguard/tests/conformance.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Asserts injection-shaped allowed_ips and invalid endpoints rejected BEFORE state mutation, route/exit fail-closed-then-retryable, control-send to peer endpoint denie | audited |
| `crates/rustynet-dns-zone/Cargo.toml` | 2026-06-18 | 2 | S1-S3,V2 | PASS | none | none needed | verified: Only ed25519-dalek v2 + sha2 0.10 + std; transport-agnostic, no WireGuard/backend leak; workspace lints inherited; no custom crypto. | audited |
| `crates/rustynet-dns-zone/src/lib.rs` | 2026-06-18 | 2 | C1-C7,E1-E4,F1-F4,I1-I4,K1-K2,T1-T2,V1-V4 | FINDINGS | RSA-0042, RSA-0043 (→ RSA-0077 systemic) | use ed25519 verify_strict (one of 14 plain-`verify` sites — see RSA-0077); add a parse_signed_dns_zone_bundle_wire cargo-fuzz target | RN-22/RL-3; CWE-347; RN-N6 class | open |
| `crates/rustynet-relay/Cargo.toml` | 2026-06-18 | 2 | S1,S2,V2 | PASS | none | none needed | verified: subtle/ed25519-dalek v2 verify_strict, rand workspace; daemon=optional tokio/tracing/serde; windows-service cfg-gated off non-Windows; no custom crypto. | audited |
| `crates/rustynet-relay/benches/relay_forward.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Bench of forward path; deterministic [1u8;32] signing key is local bench material; RelaySessionToken::sign is real prod API. No leak. | audited |
| `crates/rustynet-relay/examples/perfprobe_relay.rs` | 2026-06-18 | 2 | T1,T2 | PASS | none | none needed | verified: Fixed-work relay forward probe; same local-only deterministic key; no secret persistence; no production downgrade branch. | audited |
| `crates/rustynet-relay/src/lib.rs` | 2026-06-18 | 2 | E1,F4,T1,V1 | PASS | none | none needed | verified: Relay-fleet selection domain logic only; no untrusted-input parse, no crypto, no backend leak, no panics in production paths. | audited |
| `crates/rustynet-relay/src/main.rs` | 2026-06-18 | 2 | C5,E1,E3,F1,F2,I1,I3,I4,K1,K2,N2,N3,T1,T2 | FINDINGS | RSA-0040, RSA-0041 | add cargo-fuzz for parse_relay_hello/parse_relay_token; suppress reject on the pre-auth-rate-limited path (kill the UDP reflector) | RN-N6; CWE-406 | open |
| `crates/rustynet-relay/src/rate_limit.rs` | 2026-06-18 | 2 | E1,E3,F1,F4,N2,T1,T2 | PASS | none | none needed | verified: Token-bucket per node_id; bits = len*8 safe (caller caps len at 64KiB first); retain_active_nodes prunes buckets; no panics, no overflow. | audited |
| `crates/rustynet-relay/src/session.rs` | 2026-06-18 | 2 | C1,E1,E2,E4,F1,T1 | PASS | none | none needed | verified: SessionId via OsRng CSPRNG, fail-closed (no fallback); try_generate returns Err not panic; pairing predicate symmetric; only test unwraps. | audited |
| `crates/rustynet-relay/src/transport.rs` | 2026-06-18 | 2 | A1,C1,C4,E1,E2,E3,F1,F2,F4,I1,I2,K1,K2,K3,N2,T1,T2 | FINDINGS | RSA-0037, RSA-0040 | prune+cap HelloLimiter.counts on the cleanup cadence (mirror PreAuthHelloLimiter::prune); add relay hello/token + state-machine cargo-fuzz target | AUDIT-031; RN-N6; CWE-770/CWE-400 | open |

### Tier 3 — Service surfaces & interfaces

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `crates/rustynet-cli/Cargo.toml` | 2026-06-18 | 3 | S1,S2 | PASS | none | none needed | verified: All deps pinned to registry versions, no git/wildcard/risky build-dep; live_signed_bundle_forger bin gated behind non-default chaos-forger feature so never ships. | audited |
| `crates/rustynet-cli/src/anchor_init.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Dry-run enforced; renders text plan only, never executes; no keys handled; operator self-runs printed cmds | audited |
| `crates/rustynet-cli/src/bin/active_network_security_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch with passthrough args | audited |
| `crates/rustynet-cli/src/bin/apply_cross_network_impairment_profile.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: sh -c command only with hardcoded ip/tc literals; iface validated alnum+._:- and passed as argv; profile allowlisted; fail-closed on unknown qdisc | audited |
| `crates/rustynet-cli/src/bin/bootstrap_ci_tools.rs` | 2026-06-18 | 3 | C6,I2 | PASS | none | none needed | verified: curl\\|sh of hardcoded official rustup URL via piped Stdio not shell string; all args argv/version-pinned; sudo argv-only | audited |
| `crates/rustynet-cli/src/bin/check_backend_boundary_leakage.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: rg argv-only with const LEAKAGE_PATTERN/SCAN_TARGETS; correctly handles rg exit 0/1/2 (match=PolicyReject, error=transient) | audited |
| `crates/rustynet-cli/src/bin/check_dependency_exceptions.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo; re-classifies bare GenericFailure to PolicyReject so retry loops can't mask reject | audited |
| `crates/rustynet-cli/src/bin/check_fresh_install_os_matrix_readiness.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: env-derived report path/age/profile/commit passed as discrete .arg() argv | audited |
| `crates/rustynet-cli/src/bin/check_no_unsafe_code.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/check_phase10_readiness.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: env-derived values passed as argv to cargo ops; argv-only | audited |
| `crates/rustynet-cli/src/bin/check_phase6_platform_parity.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/check_phase9_readiness.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/collect_linux_reconnect_bundle.rs` | 2026-06-18 | 3 | C4,C6,I2,I3 | PASS | none | none needed | verified: argv-only exec, env allowlist + secret exclusion, 0o600 atomic writes; format! display strings never executed | audited |
| `crates/rustynet-cli/src/bin/collect_network_discovery_info.rs` | 2026-06-18 | 3 | C4,I2,I3 | PASS | none | none needed | verified: argv-only incl sudo -n env; iface/node-id reach commands as argv; exports only public verifier keys | audited |
| `crates/rustynet-cli/src/bin/collect_phase1_measured_env.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: thin cargo dispatch, argv-only; env path passed via .env not shell | audited |
| `crates/rustynet-cli/src/bin/collect_phase9_raw_evidence.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch with passthrough args appended as argv | audited |
| `crates/rustynet-cli/src/bin/collect_platform_parity_bundle.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/collect_platform_probe.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/create_provenance.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/debian_two_node_clean_install_and_tunnel_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only rustynet ops dispatch; sh -c is constant string (no interpolation) | audited |
| `crates/rustynet-cli/src/bin/fresh_install_os_matrix_release_gate.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/fuzz_smoke.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/generate_phase10_artifacts.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/generate_phase9_artifacts.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/generate_platform_parity_report.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/generate_sbom.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/install_rustynetd_service.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: enforces hardened binary path (PolicyReject if RUSTYNET_BIN != /usr/local/bin/rustynet); argv-only | audited |
| `crates/rustynet-cli/src/bin/live_chaos_clock_attack_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper; delegates to live_chaos_support JSON scaffold; no remote exec/keys | audited |
| `crates/rustynet-cli/src/bin/live_chaos_crash_recovery_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper to live_chaos_support; report-only scaffold; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_daemon_fault_test.rs` | 2026-06-18 | 3 | E1,I2 | PASS | none | none needed | verified: Every interpolated value shell_quote'd + ensure_safe_token-validated; pid/const-only scripts; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_membership_adversarial_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper to live_chaos_support; report-only scaffold; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_network_impairment_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper to live_chaos_support; report-only scaffold; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_privileged_boundary_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper to live_chaos_support; report-only scaffold; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_resource_exhaustion_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Thin wrapper to live_chaos_support; report-only scaffold; clean | audited |
| `crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs` | 2026-06-18 | 3 | E1,I3 | PASS | none | none needed | verified: Offline fixture generation; no remote exec/keys; report fail-closed when stage lacks fixture | audited |
| `crates/rustynet-cli/src/bin/live_chaos_support/mod.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Writes only local report/log; fails closed when not dry-run; git invoked argv-only; no secrets handled. | audited |
| `crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | PASS | none | none needed | verified: All host-derived values shell_quote'd; pinned host-key + strict checking; secret-path env files (not key bytes); no production panics. | audited |
| `crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell.rs` | 2026-06-18 | 3 | C6,I2 | PASS | none | none needed | verified: Quote-by-construction on POSIX+Windows; EncodedCommand neutralizes shell layers; fail-closed validators; tmpfiles trap-cleaned. | audited |
| `crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell_tests.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Pure #[cfg(test)] verification harness; unwrap/expect acceptable test context; no production code. | audited |
| `crates/rustynet-cli/src/bin/live_lab_support/mod.rs` | 2026-06-18 | 3 | C6,E1,I2 | PASS | none | none needed | verified: argv-array remote exec, leak-proof single-quote, owner-only key/known_hosts perms enforced, no prod-path panics. | audited |
| `crates/rustynet-cli/src/bin/live_linux_anchor_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: sh -c uses positional $1..$N params; all interpolation via shell_quote/ps_quote_str; secrets 0600; rm -rf confined by is_safe_remote_dir | audited |
| `crates/rustynet-cli/src/bin/live_linux_control_surface_exposure_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: All guest reads via argv capture_root; report path operator-supplied (not escalation) | audited |
| `crates/rustynet-cli/src/bin/live_linux_endpoint_hijack_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only remote exec via context helpers; no shell string assembly | audited |
| `crates/rustynet-cli/src/bin/live_linux_enrollment_restart_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Token read then passed as discrete --token argv element; logged only as len=N | audited |
| `crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Every interpolated value wrapped in shell_quote incl passphrase path; cleanup rm via quoted path | audited |
| `crates/rustynet-cli/src/bin/live_linux_key_custody_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: 0644 chmod is deliberate negative custody test, reverted to 0600; argv on fixed KEY_FILE | audited |
| `crates/rustynet-cli/src/bin/live_linux_lan_toggle_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only via capture_root; report path operator-supplied | audited |
| `crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: sh -lc bodies interpolate only via shell_single_quote on config-derived fqdn/command; rest argv | audited |
| `crates/rustynet-cli/src/bin/live_linux_mixed_topology_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only via context helpers; ssh identity file from args parsed to PathBuf | audited |
| `crates/rustynet-cli/src/bin/live_linux_network_flap_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: All guest reads via argv capture_root_allow_failure; no shell assembly | audited |
| `crates/rustynet-cli/src/bin/live_linux_reboot_recovery_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only remote exec; reboot via systemctl argv on operator-targeted test VM | audited |
| `crates/rustynet-cli/src/bin/live_linux_relay_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only via context helpers; ssh identity from args | audited |
| `crates/rustynet-cli/src/bin/live_linux_role_switch_matrix_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: env_path/remote_env_path are compile-time constants; sudo sh -lc body via shell_quote | audited |
| `crates/rustynet-cli/src/bin/live_linux_secrets_not_in_logs_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Suspicious-match lines passed through redact_line before logging; journal read via argv | audited |
| `crates/rustynet-cli/src/bin/live_linux_server_ip_bypass_test.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only via context helpers; no shell string construction | audited |
| `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: cat/rm interpolation via shell_quote; install via scp_to + argv run_root | audited |
| `crates/rustynet-cli/src/bin/live_signed_bundle_forger.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Feature-gated (chaos-forger, non-default); mints only invalid placeholder sigs; never touches a node or real key. | audited |
| `crates/rustynet-cli/src/bin/live_signed_state_chaos/mod.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Fixtures carry deliberately-invalid sig strings; manifest stamps production_accepted=false; test asserts production_accepted=true is rejected. | audited |
| `crates/rustynet-cli/src/bin/membership_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/membership_incident_drill.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: output dir from arg confined under root_dir if relative, passed as argv; fail-closed on missing/non-measured/non-pass artifacts | audited |
| `crates/rustynet-cli/src/bin/no_leak_dataplane_gate.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only; fail-closed PolicyReject on non-Linux/non-root; report path from env passed as argv | audited |
| `crates/rustynet-cli/src/bin/perf_regression_gate.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/phase10_cross_network_exit_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: all env/arg values passed as discrete argv to cargo run --bin/ops; git rev-parse argv-only | audited |
| `crates/rustynet-cli/src/bin/phase10_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/phase10_hp2_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/phase1_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/phase3_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: run_command called only with hardcoded cargo + fixed args; argv-only | audited |
| `crates/rustynet-cli/src/bin/phase4_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: run_command argv-only with hardcoded program/args | audited |
| `crates/rustynet-cli/src/bin/phase5_gates.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only cargo/script exec, hardcoded args; report path operator-controlled, fail-closed gates | audited |
| `crates/rustynet-cli/src/bin/phase6_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: hardcoded scripts/ci/*.sh joined to root_dir, argv-only | audited |
| `crates/rustynet-cli/src/bin/phase7_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: hardcoded script paths, argv-only cargo/script exec | audited |
| `crates/rustynet-cli/src/bin/phase8_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: hardcoded scripts/ci/*.sh, argv-only | audited |
| `crates/rustynet-cli/src/bin/phase9_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/prepare_advisory_db.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/real_wireguard_exitnode_e2e.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | FINDINGS | RSA-0060 | create key dir 0700 + write ephemeral WG keys 0600 + secure-scrub on cleanup | HB-1; CWE-732 | open |
| `crates/rustynet-cli/src/bin/real_wireguard_no_leak_under_load.rs` | 2026-06-18 | 3 | C4,C6,E1,I2 | FINDINGS | RSA-0060 | create key dir 0700 + write ephemeral WG keys 0600 + secure-scrub on cleanup | HB-1; CWE-732 | open |
| `crates/rustynet-cli/src/bin/real_wireguard_rogue_path_hijack_e2e.rs` | 2026-06-18 | 3 | E1,I2 | FINDINGS | RSA-0061 | insert `--` before ssh user@host target + shape-validate host/user (mirror live_lab_bin_support::ssh_base_command) | RSA-0051/0057 class; CWE-88 | open |
| `crates/rustynet-cli/src/bin/real_wireguard_signed_state_tamper_e2e.rs` | 2026-06-18 | 3 | E1,I2 | FINDINGS | RSA-0061 | insert `--` before ssh user@host target + shape-validate host/user | RSA-0051/0057 class; CWE-88 | open |
| `crates/rustynet-cli/src/bin/release_readiness_gates.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: argv-only script exec, fail-closed PolicyReject on report mismatch/non-pass; writes operator-controlled paths | audited |
| `crates/rustynet-cli/src/bin/role_auth_matrix_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only; runs fixed list of required tests via run_required_test bin | audited |
| `crates/rustynet-cli/src/bin/run_phase1_baseline.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch, ignores user args | audited |
| `crates/rustynet-cli/src/bin/run_phase3_baseline.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo ops dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/run_required_test.rs` | 2026-06-18 | 3 | C6,E1,I2 | PASS | none | none needed | verified: package/test_filter from argv passed as discrete argv to cargo test (no shell); create_new temp w/ pid+nanos; passes through cargo exit | audited |
| `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs` | 2026-06-18 | 3 | C4,C6,E1,I3 | PASS | none | none needed | verified: no subprocess; ed25519 seed zeroized, Zeroizing decrypted material, encrypted-at-rest, symlink reject, abs-path passphrase; no secrets logged | audited |
| `crates/rustynet-cli/src/bin/secrets_hygiene_gates.rs` | 2026-06-18 | 3 | C6,I2 | PASS | none | none needed | verified: sh -c only with hardcoded REQUIRED_COMMANDS consts (cargo/git); rest argv-only; create_new temp, fail-closed PolicyReject | audited |
| `crates/rustynet-cli/src/bin/security_regression_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/supply_chain_integrity_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/bin/test_check_fresh_install_os_matrix_readiness.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Stale-child commit replay fixture MUST be rejected; harness fails (PolicyReject) if readiness gate accepts it. Control asserted. | audited |
| `crates/rustynet-cli/src/bin/test_cross_network_remote_exit_skeleton_validators.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Scripts run via argv array (no shell), asserts fail without lab prereqs; SSH identity is placeholder, hosts static literals. | audited |
| `crates/rustynet-cli/src/bin/test_validate_cross_network_nat_matrix.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Passes --require-pass-status to inner validator; argv-only cargo/git; subprocess fail surfaced as PolicyReject. | audited |
| `crates/rustynet-cli/src/bin/test_validate_cross_network_remote_exit_reports.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Same hardened pattern: --require-pass-status, argv-only exec, PolicyReject on inner fail. | audited |
| `crates/rustynet-cli/src/bin/test_validate_network_discovery_bundle.rs` | 2026-06-18 | 3 | T1,T2 | PASS | none | none needed | verified: Fails closed when no bundles found; passes --require-verifier-keys + daemon/socket flags; argv-only ops exec. | audited |
| `crates/rustynet-cli/src/bin/traversal_adversarial_gates.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch, ignores user args | audited |
| `crates/rustynet-cli/src/bin/verify_release_attestation.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: argv-only cargo dispatch wrapper | audited |
| `crates/rustynet-cli/src/env_file.rs` | 2026-06-18 | 3 | C6,I2 | PASS | none | none needed | verified: This IS the HB-6 hardening: quote-by-construction escapes backslash/quote/dollar/backtick, rejects NUL+newline, key charset [A-Z0-9_] | audited |
| `crates/rustynet-cli/src/live_lab_results.rs` | 2026-06-18 | 3 | E1,I3 | PASS | none | none needed | verified: Read-only TSV parse; path from arg+fixed components; rc parse fails safe to non-zero; expect() only in tests | audited |
| `crates/rustynet-cli/src/live_lab_run_matrix.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | FINDINGS | RSA-0055 | prefix-quote CSV cells beginning with =,+,-,@,tab (formula-injection neutralization) | CWE-1236; OWASP CSV-injection | open |
| `crates/rustynet-cli/src/llm_cli.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Strict node:/group: selector charset; records unsigned for owner signing; access-list default-deny on missing/empty file | audited |
| `crates/rustynet-cli/src/main.rs` | 2026-06-18 | 3 | A1,C4,C6,E1,E2,F1,F2,F4,I1,I2,I3,K1,K2,N1,T1,V2 | FINDINGS | RSA-0008, RSA-0014 | membership-aware bundle issuance (evaluate_with_membership); fail-closed durable audit before signed/irreversible role mutations | RSA-0008/RSA-0014; SecMinBar §3.6/A1; CWE-863/CWE-778 | open |
| `crates/rustynet-cli/src/ops_ci_release_perf.rs` | 2026-06-18 | 3 | C4,C6,I2,I3 | PASS | none | none needed | verified: SSH/script dispatch uses argv arrays only; no shell string assembly; tmp confined to repo artifacts. | audited |
| `crates/rustynet-cli/src/ops_cross_network_preflight.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Network-probe + JSON report only; no command construction, no secret material. | audited |
| `crates/rustynet-cli/src/ops_cross_network_reports.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: Report-validation only; git via argv; artifact values never reach exec or write path. | audited |
| `crates/rustynet-cli/src/ops_e2e.rs` | 2026-06-18 (re-verified 2026-06-19) | 3 | C6,E1,E3,F1,F4,I2,I3,K1,K3,N1,T1 | PASS | none (RSA-0051 WITHDRAWN-FP) | none needed — RSA-0051 withdrawn: `network_id` is passed as a discrete argv element via `Command::new/args` (bash `$2`), not a shell string; no injection | CWE-78 (refuted); SecMinBar §3.7 | audited |
| `crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs` | 2026-06-18 | 3 | I2,I3 | FINDINGS | RSA-0054 | confine report source_artifacts read paths (reject ../ + absolute; canonicalize under root) | CWE-22; SecMinBar §3.5 | open |
| `crates/rustynet-cli/src/ops_install_macos_exit.rs` | 2026-06-18 | 3 | C4,I2,I3 | PASS | none | none needed | verified: launchctl via argv; plist dest hardcoded; atomic write 0o644 (config, not secret). | audited |
| `crates/rustynet-cli/src/ops_install_macos_relay.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Mirror of macos_exit; launchctl argv, hardcoded reviewed dest, atomic write. | audited |
| `crates/rustynet-cli/src/ops_install_systemd.rs` | 2026-06-18 | 3 | C4,C6,I2 | PASS | none | none needed | verified: HB-1 cleanup scrubs-then-removes; env-line injection blocked; key perms 0o600; SSH allow fails closed. | audited |
| `crates/rustynet-cli/src/ops_install_systemd_exit.rs` | 2026-06-18 | 3 | C4,I2,I3 | PASS | none | none needed | verified: systemctl argv; hardcoded unit dest; atomic 0o644 write. | audited |
| `crates/rustynet-cli/src/ops_install_systemd_relay.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Mirror of systemd_exit; systemctl argv, hardcoded dest, atomic write. | audited |
| `crates/rustynet-cli/src/ops_install_systemd_service.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Unit name from fixed enum not free text; systemctl argv; Relay routed away fail-closed. | audited |
| `crates/rustynet-cli/src/ops_live_lab_failure_digest.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | PASS | none | none needed | verified: Pure read-parse-write digest generator; no exec, no secrets, prod panics absent. | audited |
| `crates/rustynet-cli/src/ops_live_lab_orchestrator.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | PASS | none | none needed | verified: Forensics/report engine; argv-only date+tcpdump, validated paths, secret redaction, no prod panics. | audited |
| `crates/rustynet-cli/src/ops_network_discovery.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: Pure bundle validation; guest JSON never reaches command/fs; rejects secret-like keys. | audited |
| `crates/rustynet-cli/src/ops_peer_store.rs` | 2026-06-18 | 3 | C3,I3 | PASS | none | none needed | verified: Strong confinement (abs+name+parent+canonicalize), uid check, 0700/0600 modes, field validation rejects pipe/newline/control | audited |
| `crates/rustynet-cli/src/ops_phase1.rs` | 2026-06-18 | 3 | C4,E1,I2 | PASS | none | none needed | verified: cargo via argv; tmp 0o600; line 2158 builds lint search-string, not a shell command. | audited |
| `crates/rustynet-cli/src/ops_phase9.rs` | 2026-06-18 | 3 | C4,C6,E1 | PASS | none | none needed | verified: Signing seed zeroized; keys 0o600 symlink-safe atomic; incomplete keypair fails closed. | audited |
| `crates/rustynet-cli/src/ops_security_audit.rs` | 2026-06-18 | 3 | C6,E1,E3,F1,F4,I2,I3,T1,T2 | PASS | none | none needed | verified: Audit-tooling: CLI-arg report paths walked/read/written unconfined, but local-operator-only (no priv gain). date exec is static argv. No secrets. | audited |
| `crates/rustynet-cli/src/ops_security_audit_workflows.rs` | 2026-06-18 | 3 | C6,E1,F1,I2,I3,N1,T1 | PASS | none | none needed | verified: All exec is argv-array; expect runs a fixed const remote command with passwords kept in files (log_user 0). Path args unconfined but local-CLI-only, not MCP-reachable. | audited |
| `crates/rustynet-cli/src/ops_write_daemon_env.rs` | 2026-06-18 | 3 | C6,E1,I2 | PASS | none | none needed | verified: Values via Command.env argv array (no shell); fail-closed policy forcing; 2 unwrap() provably safe (key inserted above) | audited |
| `crates/rustynet-cli/src/role_cli.rs` | 2026-06-18 | 3 | A1,A2,C6,E1,E3,F1,F4,I1,I2,I3,T1,T2,V1 | PASS | none | none needed | verified: Pure role-transition planner; no IPC/FS/exec. blind_exit confirmation + immutability correctly gated. No injection/secret surface. | audited |
| `crates/rustynet-cli/src/security_audit_catalog.rs` | 2026-06-18 | 3 | A1,A2,F1,I2,T1,T2,V1,V2 | FINDINGS | RSA-0049 | mark catalog entries 'covered' only when backed by a wired production enforcement point (not a test-only command_key) | RSA-0018; CLAUDE.md §4; CWE-1006 | open |
| `crates/rustynet-cli/src/vm_lab/bootstrap/mod.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: Pure phase-parse + provider dispatch; macOS path fails closed (not-implemented), no command/fs/secret logic. | audited |
| `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` | 2026-06-18 | 3 | E1,I2,I3 | PASS | none | none needed | verified: All host/guest values flow through powershell_quote + base64 EncodedCommand; SSH is argv-only; report parsers fail closed. No secrets/destructive/sudo logic. | audited |
| `crates/rustynet-cli/src/vm_lab/capability.rs` | 2026-06-18 | 3 | I2,I3 | PASS | none | none needed | verified: Sanitization + artifact rendering + capability scoring only; no command construction; fail-closed on empty | audited |
| `crates/rustynet-cli/src/vm_lab/mod.rs` | 2026-06-18 | 3 | C4,C6,E1,I2,I3 | FINDINGS | RSA-0058 | shell_quote the dest_dir_literal in the repo-sync printf script | CWE-78 | open |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/android.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: every method returns android_unsupported(); no command construction | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/factory.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: connection/platform validation then dispatch; unsupported platforms fail closed with security-bar message | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/ios.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: every method returns ios_unsupported(); no command construction | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pure dispatch; validator argv from fixed-string LinuxDaemonProbe builder; no untrusted interpolation | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs` | 2026-06-18 | 3 | I2,I3,C4,E1 | FINDINGS | RSA-0057 | escape/validate bootstrap env-file values (node_id/network_id/ssh_allow_cidrs) before the bootstrap script `source`s them (command-arg path is separately ok) | RSA-0051 class; CWE-78 | open |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_membership.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: all interpolated values pass shell_safe_arg (rejects quote/metachars) or hex validation before single-quote embedding | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_traffic.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: IP args validated; killswitch/probe commands compile-time constants; verify_no_key_material enforces *.priv/.pem/.key/keys exclusion | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pure dispatch; validator argv from fixed-string MacosDaemonProbe builder; no untrusted interpolation | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs` | 2026-06-18 | 3 | I2,I3,C4,E1 | FINDINGS | RSA-0057 | escape/validate bootstrap env-file values before the bootstrap script `source`s them (command-arg path is separately ok) | RSA-0051 class; CWE-78 | open |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: node_id/pubkey/capabilities validated before single-quote embedding; owner-approver-id from command substitution not interpolation | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: strongest IP validation of the three OSes (IpAddr parse); diag/cleanup paths are compile-time constants; tar listing fail-closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/mod.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pub mod declarations only; no logic | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: trait + fail-closed defaults; log-tail extractor is length-bounded and only feeds error strings, not commands | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/ssh.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: ssh/scp via argv arrays with `--` separators, BatchMode+StrictHostKeyChecking=yes, 0700 control dir, fail-closed validator parse | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/verifier_key.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: hex->32-byte decode rejects short and non-hex input (fail-closed); no shell interaction | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pure dispatch; validator argv from fixed-string DaemonProbe builder, binary ps_quote'd; no untrusted input reaches the script | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: all values ps_quote'd; -EncodedCommand defeats SSH-layer breakout; two independent RNG passphrases; ProtectedData + zero-on-delete tempfiles (HB-1 addressed) | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_membership.rs` | 2026-06-18 | 3 | I2 | FINDINGS | RSA-0059 | ps_quote (or drop) node_id in the PowerShell throw-literal, not just the --node-id arg | HB-6; CWE-78 | open |
| `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: IP args validated; rustynet_path/issue paths ps_quote'd; zip listing fails closed on unreadable archive; reset rule names compile-time | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/connection.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: known_hosts required at ctor; StrictHostKeyChecking=yes; no cmd strings | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: state struct + accessors only | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/error.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: error/outcome types; cascade fail-closed via runner | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/mod.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: module declarations only | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/parity.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pure-data diff; correct fail mapping; no fail-open | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: static plan builder; no untrusted input or cmd construction | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/remote_shell.rs` | 2026-06-18 | 3 | C4,C6,I2 | FINDINGS | RSA-0056 | reject shell metacharacters in env keys; build env via quoted KEY=val assignment | CWE-78; SecMinBar §3.7 | open |
| `crates/rustynet-cli/src/vm_lab/orchestrator/remote_shell_tests.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: cfg(test); strong negative coverage: empty/NUL path, argv, env =/NUL, mode allow-list, quote/PS-escape round-trips | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/report.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: serde report structs only | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pure role mapping; default-deny on unknown; strict parse | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/role_assignment.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: --node parse validated; alias is map key only | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/anchor.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: argv-only; token never shelled/logged (thumbprint only); fail-closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/mod.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: module declaration only | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: argv-only; PS -Command uses const-only values; lifecycle fail-closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/runner.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: skip-cascade fail-closed; failed/skipped deps block dependents | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/source_archive.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: archive path wrapper; fail-closed on absent | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/active_exit.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: activate+assert exit NAT; fail-closed each step | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: fail-closed missing adapter/node-id; named deferrals | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cleanup.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: reset+assert-clean; missing adapter fails closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/collect_pubkeys.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: collects guest values to ctx; no shell use; pubkey err fails | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: fail-closed missing adapter; named reported-skips | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: env-file content (not shell); values written to file; fail-closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_dns_zone.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: wrapper over distribute_bundle_kind | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_membership.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: signed public snapshot to temp; fail-closed; distributes via adapter | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_traversal.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: wrapper over distribute_bundle_kind | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/enforce_runtime.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: delegates to adapter; missing adapter fails closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/exit_handoff.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: owner-key + active-tunnels required; fail-closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/final_cleanup.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: per-node cleanup; missing adapter fails closed | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/install.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: rebuild-set predicate; fail-closed on no archive/adapter | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/membership_init.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: pubkey-hex + node_id validated; fail-closed; signed snapshot | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: stage trait + ids; no logic surface | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: argv ssh -V; fail-closed exit-count; writable-dir probe | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_validation.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: fail-closed; named reported-skips; lifecycle oracle | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/role_switch_matrix.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: fail-closed: empty/unverifiable tunnels => fail | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: git argv-only; stash-create non-destructive; no reset/clean | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: default-deny fails closed; inconclusive!=pass | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/validate_runtime.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: oracle: any non-pass/err fails stage; no fail-open | audited |
| `crates/rustynet-cli/src/vm_lab/orchestrator/stage/verify_ssh.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: delegates to adapter; missing adapter fails | audited |
| `crates/rustynet-cli/src/vm_lab/overnight/agent.rs` | 2026-06-18 | 3 | I2 | PASS | none | none needed | verified: Argv-only builder; prompt + paths passed as discrete args; test proves shell metachars stay inert | audited |
| `crates/rustynet-cli/src/vm_lab/overnight/backlog.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Pure data/parse; fail-closed classify ordering; no exec, no secrets, no path handling | audited |
| `crates/rustynet-cli/src/vm_lab/overnight/executor.rs` | 2026-06-18 | 3 | E1,I2 | FINDINGS | RSA-0052 | gate the live destructive/auto-commit path behind real branch-isolation (checkout dedicated branch) + dry-run default | AUDIT-017/018/019; CWE-77 | open |
| `crates/rustynet-cli/src/vm_lab/overnight/manifest.rs` | 2026-06-18 | 3 | I3 | PASS | none | none needed | verified: cell_slug sanitizes non-alphanumerics to underscore; dir from caller; no secrets serialized | audited |
| `crates/rustynet-cli/src/vm_lab/overnight/mod.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | FINDINGS | RSA-0052 | branch-isolation guard must verify the active checkout, not just the generated name | AUDIT-017/018/019; CWE-77 | open |
| `crates/rustynet-cli/src/vm_lab/overnight/safety.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | FINDINGS | RSA-0053 | pathspec-confine git clean (or scope to a worktree); never bare `git clean -fd` | AUDIT-017/018/019; CWE-77 | open |
| `crates/rustynet-cli/src/vm_lab/overnight/scheduler.rs` | 2026-06-18 | 3 | I2,I3,C6,E1 | PASS | none | none needed | verified: Pure scheduling; bounded loop; over-budget/parked/verified never selected; no exec or IO | audited |
| `crates/rustynet-cli/src/vm_lab/topology.rs` | 2026-06-18 | 3 | I3 | PASS | none | none needed | verified: serde_json deny_unknown_fields, strict [A-Za-z0-9._-] alias validation, fail-closed empty; values used as argv | audited |
| `crates/rustynet-llm-gateway/Cargo.toml` | 2026-06-18 | 3 | S1,S3 | PASS | none | none needed | verified: Minimal deps (ed25519-dalek, sha2, rustynet-policy); no build.rs; bin gated behind daemon feature; workspace lints inherited. | audited |
| `crates/rustynet-llm-gateway/src/enforce.rs` | 2026-06-18 | 3 | E3,N1,N2,T1 | PASS | none | none needed | verified: Deterministic per-peer quota/rate; saturating arith; empty allow-list denies; no-scope=unrestricted is by-design (grant already gated upstream). | audited |
| `crates/rustynet-llm-gateway/src/engine.rs` | 2026-06-18 | 3 | E1,F1,T1,V2 | PASS | none | none needed | verified: Loopback-only engine endpoint validated fail-closed; no engine-type leak through trait boundary; covered by negative tests. | audited |
| `crates/rustynet-llm-gateway/src/health.rs` | 2026-06-18 | 3 | F1,F2 | PASS | none | none needed | verified: Fail-closed health: any probe/list error => unhealthy; counts/reason only, no prompt or model internals leaked. | audited |
| `crates/rustynet-llm-gateway/src/lib.rs` | 2026-06-18 | 3 | C6,V1 | PASS | none | none needed | verified: forbid(unsafe_code); module surface documents tunnel-only/no-API-key/no-secret-logging contract; no code logic to exploit. | audited |
| `crates/rustynet-llm-gateway/src/main.rs` | 2026-06-18 | 3 | C6,E1,E2,F1,F2,I2,I3,T2 | FINDINGS | RSA-0048, RSA-0002 | add TCP read/write timeouts (slowloris); implement the non-unix session-key permission/ACL check | CWE-400; SecMinBar §3.4; RSA-0002 | open |
| `crates/rustynet-llm-gateway/src/protocol.rs` | 2026-06-18 | 3 | E1,E3,I1,I2,N1-N4,T1,T2 | PASS | none | none needed | verified: Length-bounded-before-alloc binary framing; unknown opcode/version + trailing bytes fail-closed; fuzz + negative tests; no panic, no unbounded alloc. | audited |
| `crates/rustynet-llm-gateway/src/session.rs` | 2026-06-18 | 3 | C1,C2,C6,F1-F4,T1 | FINDINGS | RSA-0024 | wire the §6.E session-token enforcement into the daemon service path, or document as scaffold | SecMinBar §6.E; CLAUDE.md §4; CWE-1006 | open |
| `crates/rustynet-mcp/Cargo.toml` | 2026-06-18 | 3 | S1,S2,S3 | PASS | none | none needed | verified: serde/serde_json pinned to 1; nix 0.29/socket2 0.6 used by lab_state bin; no git/path/build-script deps. | audited |
| `crates/rustynet-mcp/build.rs` | 2026-06-18 | 3 | E1,I2,S3 | PASS | none | none needed | verified: git/date spawned with fixed argv arrays, no untrusted input, no network/codegen. repo_root from CARGO_MANIFEST_DIR (build-time trusted). expect() acceptable in build.rs. | audited |
| `crates/rustynet-mcp/src/bin/gate_runner.rs` | 2026-06-18 | 3 | A1,C6,E1,E3,I2,I3,S2,T1,T2,V1 | PASS | none | none needed | verified: All exec is argv-array via run_with_timeout (no shell). Scripts confined to scripts/ci via canonicalize+starts_with. unsafe_scope_token blocks cargo RCE flags. forbid(unsafe_code). | audited |
| `crates/rustynet-mcp/src/bin/lab_state.rs` | 2026-06-18 | 3 | A1,C6,E1,E2,I2,I3,T1,T2,V1 | PASS | none | none needed | verified: AUDIT-006 remediated: all caller paths flow through confined_repo_path (lexical .. strip + canonicalize prefix + starts_with(repo) + symlink-escape check); exec argv-only; inventor | audited |
| `crates/rustynet-mcp/src/bin/repo_context.rs` | 2026-06-18 | 3 | A1,C6,E1,E3,I2,I3,N1,T1,T2,V1,V2 | PASS | none | none needed | verified: Caller path sink (get_document/read_resource) confined via read_safe (reject ..+abs, canonicalize, starts_with root). No exec. forbid(unsafe_code). Reads capped+truncated. Findings | audited |
| `crates/rustynet-mcp/src/lib.rs` | 2026-06-18 | 3 | A1,C6,E1,E3,I2,I4,N1,N4,T1,T2,V1,V2 | FINDINGS | RSA-0047 | cap JSON-RPC input line length (bounded read_line) — reject oversized before buffering | CWE-770; SecMinBar §6 | open |
| `crates/rustynet-nas/Cargo.toml` | 2026-06-18 | 3 | S1-S3,V2 | PASS | none | none needed | verified: Reviewed deps only (crypto/serde/sha2/zeroize); no build.rs supply-chain surface; workspace lints inherited (deny warnings). | audited |
| `crates/rustynet-nas/src/health.rs` | 2026-06-18 | 3 | C6,F1-F4 | PASS | none | none needed | verified: Diagnostics-only health signal; ids/booleans, no content or key bytes; failure produces fail-closed unhealthy report. | audited |
| `crates/rustynet-nas/src/lib.rs` | 2026-06-18 | 3 | V1,W1 | PASS | none | none needed | verified: Module wiring + tunnel port constant; forbid(unsafe_code); documents thin-wrapper / never-LAN/public posture. | audited |
| `crates/rustynet-nas/src/main.rs` | 2026-06-18 | 3 | A1-A2,C6,E2,F1-F4,I2,I3,W1-W3 | PASS | none | none needed | verified: Tunnel-only bind (rejects wildcard/loopback/multicast); per-frame re-auth default-deny; key from CREDENTIALS_DIRECTORY w/ perm check; forbid(unsafe); no secret logging. | audited |
| `crates/rustynet-nas/src/protocol.rs` | 2026-06-18 | 3 | E1,E3,I4,N1-N4,T1-T2 | PASS | none | none needed | verified: Bounded reader, per-field caps before allocation, deny-on-malformed (unknown opcode/version/trailing bytes/non-utf8); no-panic fuzz test. | audited |
| `crates/rustynet-nas/src/store.rs` | 2026-06-18 | 3 | A1-A2,C6,E1,E3,F1-F4,I3,I4,K1-K3,N1-N4,T1-T2 | PASS | none | none needed | verified: AEAD at-rest with location-binding AAD; strict peer/hash/snapshot charset confinement; symlink+mode fail-closed; size caps; key zeroized; cross-namespace replay tested-refused. | audited |
| `crates/rustynet-sysinfo/Cargo.toml` | 2026-06-18 | 3 | S1,S3 | PASS | none | none needed | verified: No dependencies, no build.rs, workspace lints inherited. Nothing to exploit. | audited |
| `crates/rustynet-sysinfo/src/lib.rs` | 2026-06-18 | 3 | C6,E1,E2,E3,I2,I4,N1,N2,T1,T2 | FINDINGS | RSA-0046, RSA-0050 | replace powershell -Command string interpolation with argv/typed APIs (no shell); bounds-check arp/tcp parser slices | CWE-78; CWE-125; SecMinBar §3.7 | open |
| `crates/rustynet-windows-native/Cargo.toml` | 2026-06-18 | 3 | S1,S2,S3 | PASS | none | none needed | verified: windows-sys 0.59 only, cfg(windows)-gated, feature list scoped to used APIs; no build.rs, no proc-macro, no risky deps. | audited |
| `crates/rustynet-windows-native/src/lib.rs` | 2026-06-18 | 3 | A1,C6,E1,E2,E3,E4,F1,F2,F3,I2,I3,N1,V1,V2,W1,W2,W3 | PASS | none | none needed | verified: Win32 FFI: all unsafe blocks check return/GetLastError and fail closed; no secret in log/Debug; SDDL from static policy + OS SID; argv-only; no path traversal. Solid. | audited |
| `tools/skills/install_rustynet_security_auditor.sh` | 2026-06-18 | 3 | I1,I2,S2 | FINDINGS | RSA-0070 | `shopt -s nullglob` (or compgen guard) before the globbed cp/chmod | CWE-754 (robustness) | open |
| `tools/skills/rustynet-security-auditor/agents/openai.yaml` | 2026-06-18 | 3 | I1,I2,S2 | PASS | none | none needed | verified: Config only; allow_implicit_invocation:false; no secrets, no executable surface | audited |

### Tier 4 — Build, supply chain, scripts, lab tooling

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `.github/workflows/cross-platform-ci.yml` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: All uses: SHA-pinned; --locked everywhere; read-only PR validation; sudo -E runs fixed repo script not untrusted input | audited |
| `.github/workflows/release-windows.yml` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Secrets via env vars not argv; PFX icacls-locked then scrubbed always(); fail-loud no unsigned fallback; SHA-pinned; --locked | audited |
| `Cargo.toml` | 2026-06-18 (+lint sweep 2026-06-19) | 4 | S1,S2,V2,V3 | FINDINGS | RSA-0076 | deps/`Cargo.lock` clean + `unsafe_code=forbid` (RN-14); but enable the clippy *restriction* security-lint family (truncation/indexing/unwrap/arithmetic) — currently no automated gate for the §10.2 panic class | cargo-deny; CLAUDE.md §10.2/§7; ANSSI; CWE-1006 | open |
| `crates/rustynet-xtask/Cargo.toml` | 2026-06-18 | 4 | S1,S2 | PASS | none | none needed | verified: nix 0.29 + serde_json 1 crates.io semver pins; publish=false; no git/wildcard/build-dep. | audited |
| `crates/rustynet-xtask/src/main.rs` | 2026-06-18 | 4 | T1,T2 | PASS | none | none needed | verified: argv-only spawns (no shell), killpg scoped to child's own process_group(0); CSV sanitized+tested; no secrets. | audited |
| `deny.toml` | 2026-06-18 | 4 | S1,S2 | PASS | none | none needed — unknown-registry=deny (S2), md5/sha1/des/rc4 banned (parity w/ source-import gate); note wildcards=allow | cargo-deny sources/bans; SecMinBar §10 | audited |
| `fuzz/Cargo.toml` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: publish=false; in-tree path deps only; three bounded bin targets | audited |
| `fuzz/fuzz_targets/ipc_parse_command.rs` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Wraps rustynetd::ipc::parse_command on lossy-utf8 input, discards result; no side effects | audited |
| `fuzz/fuzz_targets/membership_decode_signed_update.rs` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Wraps rustynet_control::membership::decode_signed_update; no side effects | audited |
| `fuzz/fuzz_targets/membership_decode_state.rs` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Wraps rustynet_control::membership::decode_membership_state; no side effects | audited |
| `rust-toolchain.toml` | 2026-06-18 | 4 | S2 | PASS | none | none needed — pins the toolchain channel (reproducible build) | Microsoft Rust supply-chain | audited |
| `scripts/bootstrap/linux/rn_bootstrap.sh` | 2026-06-18 | 4 | I1,I2,S2 | FINDINGS | RSA-0068 | parse the env-file with a strict key=value reader (reject non ^[A-Z_]+= lines); do not `source` an orchestrator-written file as root (RSA-0057 chain sink) | CWE-78; RSA-0057 | open |
| `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` | 2026-06-18 | 4 | S3 | FINDINGS | RSA-0063, RSA-0064 | trap-remove the NOPASSWD sudoers file on EXIT (any failure path); pin+verify the Homebrew installer (SHA/commit) not curl\|bash HEAD | AUDIT-045/RN-32; CWE-250; CWE-494 | open |
| `scripts/bootstrap/macos/Install-RustyNetMacosService.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Strong input validation before plist render; charset allowlists + integer checks on all interpolated values | audited |
| `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: cargo build uses --locked; argv arrays + ConvertTo-PowerShellSingleQuotedLiteral; no download-execute | audited |
| `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Read-only; explicitly omits env-file + private host key from snapshot; hashes only | audited |
| `scripts/bootstrap/windows/Install-RustyNetWindowsExitService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Reviewed-root validators; fail-closed forwarding enable; no injection surface | audited |
| `scripts/bootstrap/windows/Install-RustyNetWindowsRelayService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | FINDINGS | RSA-0067 | ensure the LocalMachine\Root code-signing cert key is non-exportable + removed on uninstall; constrain EKU/CA | CWE-732/CWE-295 | open |
| `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | FINDINGS | RSA-0067 | ensure the LocalMachine\Root code-signing cert key is non-exportable + removed on uninstall; constrain EKU/CA | CWE-732/CWE-295 | open |
| `scripts/bootstrap/windows/Invoke-RustyNetWindowsKillswitchSmoke.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Absolute netsh.exe path; argv-array daemon exec; dead-man restore armed before any block | audited |
| `scripts/bootstrap/windows/Invoke-RustyNetWindowsTunnelSmoke.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: argv-array exec via PSBoundParameters; admin-gated; bounded timeout | audited |
| `scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1` | 2026-06-18 | 4 | S3 | FINDINGS | RSA-0065 | verify Authenticode (valid + expected publisher) or pin SHA256 before executing rustup-init/vs_BuildTools | CWE-494 | open |
| `scripts/bootstrap/windows/RustyNetBootstrap.winget.yml` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Declarative winget package list; no executable payload or secrets | audited |
| `scripts/bootstrap/windows/Setup-RustyNetWindowsHost.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: winget install by package id; admin-gated; no raw download-execute | audited |
| `scripts/bootstrap/windows/Smoke-RustyNetWindowsServiceHost.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Charset/root validators; argv-array sc.exe; guaranteed cleanup in finally | audited |
| `scripts/bootstrap/windows/Uninstall-RustyNetWindowsExitService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Reviewed-root validators; fail-closed forwarding disable | audited |
| `scripts/bootstrap/windows/Uninstall-RustyNetWindowsRelayService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Reviewed-root validators; refuses to remove directory via file path; no injection | audited |
| `scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Validators pin Remove-Item targets; destructive purge is opt-in flag-gated | audited |
| `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Control-command allowlist; argv-array exec; read-only verification | audited |
| `scripts/ci/active_network_security_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper; args passed as quoted array, no injection | audited |
| `scripts/ci/anchor_downgrade_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Static rg pins + targeted cargo tests; clean | audited |
| `scripts/ci/anchor_live_lab_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: mktemp tmp dir, dry-run; rm -rf target is mktemp output, no unset-var hazard | audited |
| `scripts/ci/anchor_role_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: File-existence + rg pins + targeted tests; clean | audited |
| `scripts/ci/anchor_secret_redaction_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Negative-match gate fails closed on token-exposing log lines; sound | audited |
| `scripts/ci/bootstrap_ci_tools.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin; no curl\\|sh supply-chain risk | audited |
| `scripts/ci/chaos_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: umask 077, PID-suffixed workdir, dry-run only; reject path negatively tested | audited |
| `scripts/ci/check_backend_boundary_leakage.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper; backend-boundary enforcement is in the Rust binary | audited |
| `scripts/ci/check_dependency_exceptions.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/check_fresh_install_os_matrix_readiness.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/check_phase10_readiness.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/check_phase6_platform_parity.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/check_phase9_readiness.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/cross_platform_role_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: File + rg pins + hermetic cargo tests; clean | audited |
| `scripts/ci/fresh_install_os_matrix_release_gate.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/linux_exit_role_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: File + rg pins + targeted tests; clean | audited |
| `scripts/ci/llm_default_deny_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound run_required_test (zero-match=fail); api-key negative gate fails closed | audited |
| `scripts/ci/llm_exit_coexistence_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound zero-match-fail test helper; guard pins present | audited |
| `scripts/ci/membership_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Clippy + tests + Rust report verify that fails closed; clean | audited |
| `scripts/ci/nas_default_deny_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound zero-match-fail helper; enforcement-point pins present | audited |
| `scripts/ci/no_leak_dataplane_gate.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/perf_regression_gate.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase10_cross_network_exit_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase10_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase10_hp2_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase1_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase3_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase4_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase5_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase6_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase7_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase8_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/phase9_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/regression_coverage_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Floor-vs-count gate; mktemp logs; failure counts small enough no exit-code wrap | audited |
| `scripts/ci/release_readiness_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/role_auth_matrix_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/role_taxonomy_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound zero-match-fail helper; eight-preset pins; clean | audited |
| `scripts/ci/role_transition_audit_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound zero-match-fail helper; hash-chain integrity tests pinned | audited |
| `scripts/ci/run_required_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/secrets_hygiene_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper; secrets-hygiene logic is in the Rust binary | audited |
| `scripts/ci/security_regression_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | FINDINGS | RSA-0071 | extend the G2a grep to mirror deny.toml's ban list (add rc4/md4/md2/rc2/blowfish) or rely on G2b cargo-deny | defense-in-depth; deny.toml | open |
| `scripts/ci/service_hosting_role_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Sound helper; chains sub-gates with set -e propagation; clean | audited |
| `scripts/ci/supply_chain_integrity_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper; supply-chain logic is in the Rust binary | audited |
| `scripts/ci/test_check_fresh_install_os_matrix_readiness.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust test bin | audited |
| `scripts/ci/test_validate_cross_network_remote_exit_reports.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust test bin | audited |
| `scripts/ci/traversal_adversarial_gates.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Thin exec wrapper to Rust bin | audited |
| `scripts/ci/windows_compile_check.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Operator-only env vars; unquoted $CRATES is intentional word-split, self-controlled | audited |
| `scripts/ci/windows_cross_compile_gate.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Operator-run cross-compile; linker paths from which, no untrusted input | audited |
| `scripts/dev/cargo_watchdog.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Runs "$@" in own process group; mktemp log, kill -TERM/-KILL by group PID. set -u (no -e by design, polls manually). Dev-only. | audited |
| `scripts/dev/precheck.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Local lint heuristic; operates on repo file paths, quoted reads. Dev-only, not CI gate. No untrusted data. | audited |
| `scripts/dev/setup.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Writes single-quoted heredoc hooks (no interpolation), installs to .git/hooks. Dev-only, operator-run. | audited |
| `scripts/e2e/apply_cross_network_impairment_profile.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run --bin apply_cross_network_impairment_profile -- "$@"; argv-safe | audited |
| `scripts/e2e/capture_linux_exit_nat_lifecycle.sh` | 2026-06-18 | 4 | I2,I3 | PASS | none | none needed | verified: set -euo+umask 077; output validated absolute; mktemp -d + trap cleanup; python heredoc receives paths as argv | audited |
| `scripts/e2e/capture_macos_exit_dns_failclosed.sh` | 2026-06-18 | 4 | I3 | PASS | none | none needed | verified: set -euo+umask 077; output dir validated absolute; delegates to rustynetd with quoted --flags | audited |
| `scripts/e2e/capture_macos_exit_killswitch_precedence.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: array-based args (rustynetd "${args[@]}"); output validated absolute; optional pf-anchor quoted | audited |
| `scripts/e2e/capture_macos_exit_nat_lifecycle.sh` | 2026-06-18 | 4 | I2,I3 | PASS | none | none needed | verified: same hardened pattern as Linux variant; launchctl bootout/bootstrap with quoted args; absolute-path enforced | audited |
| `scripts/e2e/chaos_impair_link.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: valid_token regex + interface allow-list (rustynet0); mode/platform/direction/profile validated against fixed sets; tc/ip args quoted | audited |
| `scripts/e2e/clean_old_runs.sh` | 2026-06-18 | 4 | I3 | PASS | none | none needed | verified: rm -rf bound from find under fixed LAB_RUNS_DIR (-mindepth 1, null-delim); --older-than-days validated positive int; cannot be empty | audited |
| `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@"; argv-safe | audited |
| `scripts/e2e/diff_lab_runs.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo; arg-count guard; exec cargo run with "${1}/..." "${2}/..." quoted; no eval | audited |
| `scripts/e2e/live_chaos_clock_attack_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo; ROOT_DIR from BASH_SOURCE; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_crash_recovery_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" (clean dispatcher) | audited |
| `scripts/e2e/live_chaos_daemon_fault_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_membership_adversarial_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_network_impairment_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_privileged_boundary_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_resource_exhaustion_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_chaos_signed_state_adversarial_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_lab_common.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: argv-array ssh/scp, StrictHostKeyChecking=yes + pinned known_hosts, sudo -n only (no sudoers write), secret-hygiene checks presence not contents, mktemp -d | audited |
| `scripts/e2e/live_linux_anchor_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_control_surface_exposure_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_cross_network_controller_switch_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; mktemp -d WORK_DIR; local-only source; config-derived interpolation only | audited |
| `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; node-id interpolation is config-derived; trap cleanup EXIT | audited |
| `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; $CLIENT_ADDR (mesh IP) single-quoted into remote awk body; not remote-untrusted; mktemp -d cleanup | audited |
| `scripts/e2e/live_linux_cross_network_node_network_switch_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; sources only local common lib; rm -rf on mktemp -d WORK_DIR; interpolated values are config node-ids/IPs | audited |
| `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; LIVE_LAB_WORK_DIR staging via common lib; trap cleanup EXIT | audited |
| `scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; trap cleanup EXIT; helper-based remote exec via local common lib | audited |
| `scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; mktemp -d WORK_DIR; local-only source; helper-based remote exec | audited |
| `scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; mktemp -d WORK_DIR; local-only source | audited |
| `scripts/e2e/live_linux_endpoint_hijack_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_enrollment_restart_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_exit_handoff_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_key_custody_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_lab_orchestrator.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: set -euo+umask 077; profile parsed via key allow-list (not source); source archive built locally (tar/git archive), no network code fetch; rustup via distro pkg + to | audited |
| `scripts/e2e/live_linux_lan_toggle_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_managed_dns_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: set -euo; exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_network_flap_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_path_handoff_under_load_test.sh` | 2026-06-18 | 4 | I2 | FINDINGS | RSA-0066 | use StrictHostKeyChecking=yes + pinned known_hosts (route via live_lab_common.sh), not accept-new | SecMinBar §6.B; CWE-322 | open |
| `scripts/e2e/live_linux_reboot_recovery_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_relay_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_role_switch_matrix_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_secrets_not_in_logs_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_server_ip_bypass_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_linux_two_hop_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- "$@" | audited |
| `scripts/e2e/live_macos_anchor_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@"; literal platform flag, argv-safe | audited |
| `scripts/e2e/live_macos_exit_handoff_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_macos_lan_toggle_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_macos_managed_dns_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_macos_relay_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_macos_role_switch_matrix_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_macos_two_hop_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform macos "$@" | audited |
| `scripts/e2e/live_mixed_topology_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run --bin live_linux_mixed_topology_test -- "$@" | audited |
| `scripts/e2e/live_windows_anchor_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_exit_handoff_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_lan_toggle_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_managed_dns_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_relay_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_role_switch_matrix_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/live_windows_two_hop_test.sh` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: exec cargo run ... -- --platform windows "$@" | audited |
| `scripts/e2e/real_wireguard_exitnode_e2e.sh` | 2026-06-18 | 4 | I2,S3 | PASS | none | none needed | verified: Argv-only exec cargo run -p rustynet-cli -- "$@"; no injection/secret/sudo surface | audited |
| `scripts/e2e/real_wireguard_no_leak_under_load.sh` | 2026-06-18 | 4 | I2,S3 | PASS | none | none needed | verified: Argv-only exec cargo run wrapper; args forwarded as "$@" array, clean | audited |
| `scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh` | 2026-06-18 | 4 | I2,S3 | PASS | none | none needed | verified: Argv-only exec cargo run wrapper; no untrusted interpolation | audited |
| `scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh` | 2026-06-18 | 4 | I2,S3 | PASS | none | none needed | verified: Argv-only exec cargo run wrapper; clean | audited |
| `scripts/e2e/rn_bootstrap_macos.sh` | 2026-06-18 | 4 | I2,I3,S3 | PASS | none | none needed | verified: set -euo, strict allowlist validation, printf %q env escape, chmod 0600, quoted rm -rf on validated abs path, argv-only sudo bash; no NOPASSWD file created | audited |
| `scripts/e2e/rn_bootstrap_windows.ps1` | 2026-06-18 | 4 | C1,E2,V1 | PASS | none | none needed | verified: StrictMode+Stop+trap fail-closed; strict allowlist on all inputs before use; argv-bound child calls; no secrets, no Invoke-Expression. | audited |
| `scripts/e2e/test_live_lab_ssh_windows.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: CI unit harness; set -euo, mktemp temp file, bash -c uses fixed literal w/ trusted $0 path, no untrusted exec | audited |
| `scripts/fuzz/smoke.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". No untrusted interpolation. | audited |
| `scripts/mcp/install.sh` | 2026-06-18 | 4 | I2,S3 | PASS | none | none needed | verified: Local build+copy of MCP bins; args allowlisted, cargo build subshell, ad-hoc codesign. No remote fetch/exec. | audited |
| `scripts/operations/collect_linux_reconnect_bundle.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/operations/collect_network_discovery_info.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/operations/collect_phase9_raw_evidence.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/operations/generate_phase10_artifacts.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/operations/generate_phase9_artifacts.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/operations/membership_incident_drill.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/perf/collect_phase1_measured_env.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/perf/run_phase1_baseline.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/release/Sign-RustyNetWindowsBinary.ps1` | 2026-06-18 | 4 | C4,C6,S3 | PASS | none | none needed | verified: Exemplary: PFX pass via named env var not argv, Clear-Variable, post-sign verify, absolute signtool, fail-closed throws. | audited |
| `scripts/release/collect_platform_parity_bundle.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/release/collect_platform_probe.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/release/generate_platform_parity_report.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/release/generate_sbom.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: One-line exec to cargo bin with "$@". | audited |
| `scripts/systemd/install_rustynetd_service.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Wrapper exec to Rust bin with "$@" per §4 shell-to-Rust contract. | audited |
| `scripts/vm_lab/apply_nat_profile.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Profile allowlisted, interfaces validated via ip link show, args quoted, marker file fixed path. Root-only router VM. | audited |
| `scripts/vm_lab/nat_filter_probe.py` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: UDP probe; atomic write_text via os.replace temp, no shell/secret. Lab tooling. | audited |
| `scripts/vm_lab/nat_probe.py` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Pure STUN UDP probe, no shell, no secrets, argparse-validated. Lab tooling. | audited |
| `scripts/vm_lab/netns_internet_sim.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Profiles/impair allowlisted; netem $ne is allowlisted value; ns names prefix-confined for teardown. Root-only lab netns. | audited |
| `scripts/vm_lab/netns_nat_classify.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Lab gate; profiles fixed, tracks rc manually so -e omitted by design. mktemp temp dir, trap cleanup. No untrusted data. | audited |
| `scripts/vm_lab/netns_nat_filter.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Lab gate, fixed profile/scenario loops, mktemp temp dir, PID-tracked kill. No untrusted data; root-only netns. | audited |
| `scripts/vm_lab/probe_and_recover_local_utm.sh` | 2026-06-18 | 4 | I2 | FINDINGS | RSA-0072 | use absolute %SystemRoot%\System32\netsh.exe/sc.exe in the guest cmd string (HB-3 parity) | HB-3; CWE-426 | open |
| `scripts/vm_lab/stun_responder.py` | 2026-06-18 | 4 | I1,I2,S2 | PASS | none | none needed | verified: Minimal STUN responder, reflects source addr only, no shell/secret. Lab tooling. | audited |
| `scripts/vm_lab/vxlan_tier_b.sh` | 2026-06-18 | 4 | C4,I2 | PASS | none | none needed | verified: remote() single-quote-escapes cmd via sq(); StrictHostKeyChecking=yes, BatchMode, identity file. Hosts=operator env. Lab tooling. | audited |
| `scripts/vm_lab/windows/Collect-RustyNetWindowsDiagnostics.ps1` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Thin dispatcher to canonical bootstrap collector; Resolve-Path + argv arg, fail-closed trap. | audited |
| `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Dispatcher to canonical bootstrap; trims+length-checks key/path, passes as argv params, fail-closed trap. | audited |
| `scripts/vm_lab/windows/Install-RustyNetWindows.ps1` | 2026-06-18 | 4 | S3 | PASS | none | none needed | verified: Thin dispatcher to canonical bootstrap; $RepoUrl passed as argv arg, ErrorActionPreference Stop, trap exit 1. Validation in bootstrap (out of scope). | audited |
| `scripts/windows/Sign-RustyNetDevBuild.ps1` | 2026-06-18 | 4 | C4,C6 | FINDINGS | RSA-0069 | never run on a release/prod host; remove the Root-store cert on uninstall; non-exportable key | CWE-732/CWE-295 | open |
| `start.sh` | 2026-06-18 | 4 | I2 | PASS | none | none needed | verified: Hardened launcher; ROOT_DIR via BASH_SOURCE, exec argv with "$@", set -euo pipefail, fail-closed exit 127. | audited |
| `Cargo.lock` | 2026-06-18 | 4 | S1,S2 | PASS | none | none needed — committed lockfile; cargo audit clean (210 deps, 0/1134 advisories); cargo deny advisories+bans+sources OK | RustSec advisory-db; cargo-deny | audited |
| `scripts/systemd/rustynetd.service` | 2026-06-19 | 4 | W1,F1,C3,S2 | PASS | none | none needed — strong hardening: NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, ProtectKernel*, `CapabilityBoundingSet=`/`AmbientCapabilities=` (all caps dropped), LoadCredentialEncrypted for the WG passphrase, narrow ReadWritePaths | SecMinBar §3.7; systemd hardening | audited |
| `scripts/systemd/rustynetd-privileged-helper.service` | 2026-06-19 | 4 | W1,F1,I2,S2 | PASS | none | none needed — runs as root but with a scoped CapabilityBoundingSet (NET_ADMIN/NET_RAW/CHOWN/DAC_OVERRIDE/SYS_ADMIN), NoNewPrivileges, ProtectSystem=strict, minimal ReadWritePaths (least-privilege documented inline) | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynet-exit.service` | 2026-06-19 | 4 | W1,F1,S2 | PASS | none | none needed — NoNewPrivileges, ProtectSystem=strict, RestrictAddressFamilies=AF_UNIX, CapabilityBoundingSet=CAP_NET_ADMIN only | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynet-relay.service` | 2026-06-19 | 4 | W1,F1,S2 | PASS | none | none needed — hardened; CapabilityBoundingSet=CAP_NET_BIND_SERVICE only, RestrictAddressFamilies scoped, narrow ReadWritePaths | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynet-nas.service` | 2026-06-19 | 4 | W1,C3,F1,S2 | PASS | none | none needed — hardened; LoadCredentialEncrypted=nas_at_rest_key, RestrictAddressFamilies scoped, ReadWritePaths=/var/lib/rustynet-nas only | SecMinBar §3.7/§6.E | audited |
| `scripts/systemd/rustynet-llm-gateway.service` | 2026-06-19 | 4 | W1,F1,S2 | PASS | none | none needed — hardened; RestrictAddressFamilies scoped, ReadWritePaths=/var/lib/rustynet-llm only | SecMinBar §3.7/§6.E | audited |
| `scripts/systemd/rustynetd-anchor.service` | 2026-06-19 | 4 | W1,F1,S2 | PASS | none | none needed — hardened service unit (NoNewPrivileges/ProtectSystem=strict/scoped caps) per the family pattern | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynetd-managed-dns.service` | 2026-06-19 | 4 | W1,F1,F3,S2 | PASS | none | none needed — hardened DNS management unit (managed-DNS fail-close path) per the family pattern | SecMinBar §3.7/§3.8 | audited |
| `scripts/systemd/rustynetd-assignment-refresh.service` | 2026-06-19 | 4 | W1,K1,S2 | PASS | none | none needed — oneshot signed-assignment refresh; hardened unit, no secret in unit | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynetd-assignment-refresh.timer` | 2026-06-19 | 4 | S2 | PASS | none | none needed — timer schedule only; no secret/exec surface | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynetd-trust-refresh.service` | 2026-06-19 | 4 | W1,K1,S2 | PASS | none | none needed — oneshot signed-trust refresh; hardened unit | SecMinBar §3.7 | audited |
| `scripts/systemd/rustynetd-trust-refresh.timer` | 2026-06-19 | 4 | S2 | PASS | none | none needed — timer schedule only | SecMinBar §3.7 | audited |
| `scripts/bootstrap/windows/RustyNetBuildTools.vsconfig` | 2026-06-19 | 4 | S3 | PASS | none | none needed — VS Build Tools component manifest (declarative list); no exec/secret | S3 (build config) | audited |

### Tier V — Vendored code (third_party/) — audited for pinning, advisories, trust-path use only; not rewritten

| File | Date | Tier | Checks run | Verdict | Findings | Enforcement proposed | Source | Status |
|---|---|---|---|---|---|---|---|---|
| `third_party/boringtun/Cargo.toml` | 2026-06-18 | V | S1,S2,S3 | PASS | none | none needed | verified: Vendored fork; consumed via path dep by backend-wireguard. Deps version-pinned, no git/wildcard, no build-deps. | audited |
| `third_party/boringtun/benches/crypto_benches/blake2s_benching.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Blake2s throughput bench (zero buffers, ring RNG keys). Not compiled. Non-production. | audited |
| `third_party/boringtun/benches/crypto_benches/chacha20poly1305_benching.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Zero-nonce ChaCha20Poly1305 ring-vs-RustCrypto bench. Bench-only, not compiled. Not a production weakening. | audited |
| `third_party/boringtun/benches/crypto_benches/main.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: criterion group entry; autobenches=false + no [[bench]] → not compiled. Non-production. | audited |
| `third_party/boringtun/benches/crypto_benches/x25519_public_key_benching.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: x25519 pubkey-derivation bench (dalek vs ring). Not compiled. Non-production. | audited |
| `third_party/boringtun/benches/crypto_benches/x25519_shared_key_benching.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: x25519 shared-secret bench (dalek vs ring). Not compiled. Non-production. | audited |
| `third_party/boringtun/src/device/allowed_ips.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: IpNetworkTable longest-match wrapper w/ kernel-compat tests; not compiled. Unreachable. | audited |
| `third_party/boringtun/src/device/api.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard wg UAPI over /var/run/wireguard sock; not compiled. Unreachable. Input parsing matches upstream. | audited |
| `third_party/boringtun/src/device/dev_lock.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: parking_lot-based cooperative upgrade lock, no unsafe; not compiled. Unreachable. | audited |
| `third_party/boringtun/src/device/drop_privileges.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard privilege-drop with setgid(0)/setuid(0) re-check fail. Not compiled. Unreachable. | audited |
| `third_party/boringtun/src/device/epoll.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard Linux epoll event registry; not compiled. Unreachable. Unsafe is syscall-standard. | audited |
| `third_party/boringtun/src/device/integration_tests/mod.rs` | 2026-06-18 | V | T1,T2 | PASS | none | none needed | verified: #[ignore] docker integration tests gated cfg(test); not compiled (device unwired). argv-only exec, /tmp keys are ephemeral test keys. | audited |
| `third_party/boringtun/src/device/kqueue.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard BSD/macOS kqueue registry; not compiled. Unreachable. Unsafe is syscall-standard. | audited |
| `third_party/boringtun/src/device/mod.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard boringtun device event-loop; not compiled (no mod device). Unreachable from Rustynet. | audited |
| `third_party/boringtun/src/device/peer.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard peer struct; not compiled. Unreachable. No weakening. | audited |
| `third_party/boringtun/src/device/tun_darwin.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard macOS utun socket; not compiled. Unreachable. FFI matches upstream. | audited |
| `third_party/boringtun/src/device/tun_linux.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard Linux TUN socket; not compiled. Unreachable. FFI matches upstream. | audited |
| `third_party/boringtun/src/ffi/mod.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard C bindings; not compiled (no mod ffi). Unreachable. Zero nonces absent; no weakening. | audited |
| `third_party/boringtun/src/jni.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard Android JNI bindings; not compiled (no mod jni). Unreachable from Rustynet. No weakening. | audited |
| `third_party/boringtun/src/lib.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Declares only noise/x25519/serialization/(mock_instant\\|sleepyinstant). device/ffi/jni intentionally NOT wired. | audited |
| `third_party/boringtun/src/mock_instant.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Atomic mock clock gated behind mock-instant feature (test-only); not in production timer path. | audited |
| `third_party/boringtun/src/noise/errors.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: WireGuardError enum only (InvalidMac/InvalidAeadTag/Duplicate/InvalidCounter present). No logic. | audited |
| `third_party/boringtun/src/noise/handshake.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard Noise_IKpsk2. ct_eq on peer static key, AEAD tag via crate, TAI64N monotonic replay check, secrets redacted, no unsafe. | audited |
| `third_party/boringtun/src/noise/mod.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Tunn dispatch + length-checked packet parse. Attacker bytes route to WireGuardError, not panic. Standard boringtun. | audited |
| `third_party/boringtun/src/noise/rate_limiter.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: mac1/mac2 verified with ct_eq (constant-time), cookie via XChaCha20Poly1305. No == on MACs, no weakening. | audited |
| `third_party/boringtun/src/noise/session.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Per-packet ChaCha20Poly1305 via crate, sliding-window anti-replay bitmap, tag verified by AEAD. Replay test present. No weakening. | audited |
| `third_party/boringtun/src/noise/timers.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Standard WireGuard timer constants (REKEY/REJECT). Session expiry + key clear intact. No crypto logic, no weakening. | audited |
| `third_party/boringtun/src/serialization.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: KeyBytes hex/base64 parse; length-validated, dead_code-gated. No hardcoded keys, no weakening. | audited |
| `third_party/boringtun/src/sleepyinstant/mod.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: forbid(unsafe_code) wrapper over platform Instant; compiled and benign. No weakening. | audited |
| `third_party/boringtun/src/sleepyinstant/unix.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: CLOCK_BOOTTIME/MONOTONIC via nix; checked_duration_since saturates to ZERO. Standard. No unsafe. | audited |
| `third_party/boringtun/src/sleepyinstant/windows.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: One-line re-export of std::time::Instant. Benign. | audited |
| `third_party/rustynet-alloc-meter/Cargo.toml` | 2026-06-18 | V | S1,S2,S3 | PASS | none | none needed | verified: Zero dependencies. Dev-only crate, no external code, no build-deps. | audited |
| `third_party/rustynet-alloc-meter/src/lib.rs` | 2026-06-18 | V | C1,E2,V1 | PASS | none | none needed | verified: Dev-only counting allocator; pure System delegation, module-level unsafe rationale present; not on prod/trust path. | audited |
| `third_party/rustynet-tun/Cargo.toml` | 2026-06-18 | V | S1,S2,S3 | PASS | none | none needed | verified: Only dep libc="0.2", caret; Cargo.lock pins 0.2.182 from crates.io. No git/wildcard/build-dep. | audited |
| `third_party/rustynet-tun/src/lib.rs` | 2026-06-18 | V | C1,E2,V1 | FINDINGS | RSA-0074 | add // SAFETY: invariant comments to each FFI unsafe block (production dataplane TUN, called as root); run Miri where feasible | ANSSI Secure Rust; CLAUDE.md §10.2 (E2) | open |

---

## Running Findings Log (append-only)

> **Coverage status (2026-06-19): COMPLETE — 594/594 files audited, 0 pending.**
> All five tiers + the vendored sub-tier are done (Batches 1–7; Batches 5b/6/7 ran
> 2026-06-19 after the provider session limit reset). This pointer is retained as the
> audit history; there is no "next pending file."
>
> **Next phase = human-driven remediation tracking** (out of scope for this review-only
> pass). Suggested order by release-impact: (1) the 2 **High** — RSA-0009 (deterministic
> reducer so revoke/key-rotation apply) and RSA-0063 (EXIT-trap the macOS bootstrap
> sudoers file); (2) the 17 **Medium** (esp. RSA-0023 enrollment one-time-consume lock,
> RSA-0026 secret-log-audit gate coverage, RSA-0037 relay map cap, RSA-0046/0059
> PowerShell injection, RSA-0052/0053 overnight-driver guards, RSA-0068 bootstrap
> env-file `source`); (3) the 5 systemic *themes* listed in the executive summary;
> (4) the 6 **Question** items need an owner decision (RSA-0014/0018/0024/0034/0035/0045).
> As fixes land, flip the relevant rows `open → proposed/accepted/applied` with a dated
> status line (append-only). Reusable audit workflow scripts live under `.git/secaudit_*.js`.

### RSA-0001 — Encrypted-key envelope v0/v1 byte-detection is ambiguous; legacy v0 blobs are misclassified as v1 and fail to decrypt
- File: `crates/rustynet-crypto/src/lib.rs:1601-1608` (`decode_encrypted_blob`), with `decode_encrypted_blob_v0/v1` at `:1610-1660`, framing at `encode_encrypted_blob:1582-1599`
- Date: 2026-06-18
- Severity: **Medium** (availability / upgrade-correctness; fail-closed direction — not a confidentiality weakening)
- Bar mapping: SecurityMinimumBar §3.4 (secret/key handling); High-control §4.6 (patch/availability SLA). Re-confirms **RN-08 / RL-12 (partial — "legacy v0 decode open")** and `SecurityAnalysis_2026-06-12.md §2.2`.
- Reachability / attacker: not attacker-driven. Triggers on any node that wrote a **v0** key blob (`[salt:16][nonce:24][len:4][ct]`, no version byte) before the v1 framing landed, then upgrades. `decode_encrypted_blob` picks v1 whenever `bytes.len() >= 45 && bytes[0] != 0`; a v0 blob's first byte is `salt[0]`, nonzero with probability 255/256, so ~99.6% of legacy v0 files are routed to `decode_encrypted_blob_v1`, which reads `version = salt[0]` and shifts the salt/nonce/length window by one byte → wrong Argon2 salt → wrong key → AEAD tag failure → `DecryptionFailed`. The daemon then fails its WG-key / trust-passphrase load at startup and fail-closes (no leak, but no service).
- Observation: detection is a length+first-byte heuristic, not an unambiguous frame tag. v0 (min 44B) and v1 (min 45B) share a near-identical layout, so the discriminator is fragile. The struct-level `decrypt_private_key_envelope` correctly handles both versions once `blob.version` is set — the defect is purely in the on-disk framing/auto-detection.
- Risk: fleet-wide daemon key-load failure on upgrade for nodes carrying v0 key files; recovery requires manual re-enrollment / key re-write. AEAD integrity is preserved (no wrong-key decrypt success), so confidentiality is intact.
- Proposed enforcement (review-only — do NOT apply): introduce an unambiguous, self-describing frame — e.g. a fixed magic prefix (`b"RNK1"`) for v1 with explicit version, and treat any blob lacking the magic as v0; or migrate v0→v1 on first successful read. The fix MUST guarantee every legacy v0 blob still decodes. Per `SecurityAnalysis_2026-06-12.md §2.2`, add the missing regression test that hand-builds a v0 `[salt][nonce][len][ct]` blob and asserts `read_encrypted_key_file` / `decode_encrypted_blob` decrypt it, plus negative tests that v1 rejects tampered version/AAD framing (the version-tamper test at `:1878` covers the struct layer but not the on-disk detection).
- Justification / source: Latacora "Cryptographic Right Answers" (versioned, self-describing message framing) — https://www.latacora.com/blog/cryptographic-right-answers/ (accessed 2026-06-18); SecurityMinimumBar §3.4. Doc-precedence: re-confirms existing RN-08 rather than opening a new defect.
- Verification method: unit regression test (v0 round-trip decode) + negative tests (v1 version/AAD tamper rejection at the on-disk layer); `cargo test -p rustynet-crypto`.
- Status: **open** (re-confirms RN-08/RL-12; 2026-06-18)

### RSA-0002 — `validate_key_custody_permissions` no-ops on non-Unix, so the encrypted-file-fallback startup permission check is not enforced on Windows
- File: `crates/rustynet-crypto/src/lib.rs:1712-1717` (`#[cfg(not(unix))]` branch returns `Ok(())`)
- Date: 2026-06-18
- Severity: **Medium** (fail-open on a Critical-control sub-requirement; mitigated by AEAD-at-rest). Prior art (`SecurityAnalysis_2026-06-12.md §5`) tracks this as **HB-2 (Low)**; this pass raises it to Medium on the fail-closed-pattern violation, while noting the AEAD compensating control.
- Bar mapping: SecurityMinimumBar §3.4 ("Encrypted-at-rest fallback with strict permissions and **startup permission checks**") and §5 (host-OS boundary — non-Linux must enforce platform-safe storage fail-closed); CLAUDE.md §10.1 (fail-closed pattern: a path that cannot verify must return Err, never Ok).
- Reachability / attacker: reachable on Windows. `read_encrypted_key_file` / `write_encrypted_key_file` call `validate_key_custody_permissions`, which on `cfg(not(unix))` returns `Ok(())` without inspecting the ACL ("Windows ACL validation not yet implemented; defer to OS enforcement"). These functions are invoked directly from `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs` and the CLI/daemon mains (grep-confirmed callers). The daemon's primary WG-key path uses `OsStoreFallbackPolicy::RequireOsSecureStore` + DPAPI (`key_material.rs:590/592`), which bypasses the file fallback — but the direct callers and any DPAPI-root-absent fallback do hit the unchecked path. Attacker = local non-admin user reading a key-custody file whose ACL was never validated at startup.
- Observation: the Unix branch enforces exact `0o700` dir / `0o600` file modes, symlink rejection, and type checks; the non-Unix branch is a verified no-op. The DPAPI custody paths *do* validate SDDL (`validate_windows_dpapi_root/file`), so the gap is specifically the **generic encrypted-file fallback** custody, not the DPAPI custody.
- Risk: a key-custody file with over-broad ACLs passes the startup "permission check" on Windows. The file is still XChaCha20-Poly1305-sealed under an Argon2-stretched passphrase, so this is a defense-in-depth/at-rest-permission gap rather than direct key disclosure — an attacker still needs the passphrase to use a leaked blob.
- Proposed enforcement (review-only — do NOT apply): implement the non-Unix branch using the existing `rustynet_windows_native::inspect_file_sddl` (already used by `validate_windows_dpapi_root/file`) to require a `D:P` protected DACL excluding `WD`/`AU`/`BU`, reject symlinks/reparse points, and fail closed (`Err(PermissionValidationUnavailable)`) where the ACL cannot be read — never `Ok`.
- Justification / source: CLAUDE.md §10.1 fail-closed pattern; SecurityMinimumBar §3.4/§5; CWE-732 "Incorrect Permission Assignment for Critical Resource" — https://cwe.mitre.org/data/definitions/732.html (accessed 2026-06-18). Re-confirms HB-2.
- Verification method: Windows-target unit/integration test asserting an over-broad-ACL file fails `validate_key_custody_permissions`; gate via `windows-runtime-acls-check`.
- Status: **open** (re-confirms HB-2, severity raised to Medium; 2026-06-18)
- Status update (2026-06-18, Batch 4): reachability **confirmed on Windows** — `bin/rustynet-windows-trust-cli.rs` (trust ed25519 signing-key custody, `:280/:330`) and `rustynet-llm-gateway/src/main.rs:175-205` (`validate_signing_key_material`) both reach the non-unix permission-check no-op. The most sensitive instance is the **trust signing key** (the trust root) — RSA-0025 (write-time DACL) + this read-side no-op together leave that key's at-rest custody unenforced on Windows. The no-op pattern recurs across: `rustynet-crypto::validate_key_custody_permissions` (origin), the llm-gateway session-key check, and the windows-trust-cli custody. Remains **Medium**.

### RSA-0003 — `AlgorithmPolicy::with_exceptions` guard is inverted; the compatibility-exception feature is dead and its tests enshrine the inversion
- File: `crates/rustynet-crypto/src/lib.rs:188-199` (`with_exceptions`), tests at `:1816-1853`
- Date: 2026-06-18
- Severity: **Low** (currently **fails closed / stricter**; not wired into any production crypto decision; latent fail-open risk only if naively "fixed"). `FullRepoAnalysis_2026-05-24.md` rated this **critical (inverted guard)**; this audit **downgrades it with explicit reasoning** (below) rather than inheriting the label.
- Bar mapping: SecurityMinimumBar §3.1 (proven-crypto / algorithm governance); CLAUDE.md §10.4 default-deny.
- Reachability / attacker: **not reachable as a weakening today.** `with_exceptions` does `if !exceptions.is_empty() { return Err(InvalidException); }` — so it rejects *every* non-empty exception list and the subsequent denylist-validation loop is dead code. Therefore no `AlgorithmPolicy` constructed via the public API can ever carry an active exception; `validate()` always denies non-allowlisted algorithms (default-deny holds). Grep confirms `AlgorithmPolicy` is referenced **only in `rustynet-control` tests** (`lib.rs:4279/4527/4533`), not in any production crypto-selection path — the live crypto choices are hardcoded vetted primitives (XChaCha20-Poly1305 / Ed25519 / Argon2id), so even `validate()` itself gates nothing in production.
- Observation: the empty-check is inverted (it should *permit* validated non-empty exception lists and reject only invalid ones); and the unit tests (`denylisted_algorithm_exceptions_are_rejected`, `invalid_exception_for_allowlisted_algorithm_is_rejected`) were written to match the broken behavior, so they would block a correct fix and give false confidence.
- Risk: latent. If a future change "repairs" `with_exceptions` to allow denylisted-algorithm exceptions *and* wires `validate()` into a production path, weak algorithms (MD5/SHA1/RC4/DES/3DES) could be temporarily permitted. Today the bug is protective, so the risk is purely forward-looking + maintainability.
- Proposed enforcement (review-only — do NOT apply): either (a) **delete** the unused compatibility-exception facility (nothing consumes it; least surface, safest), or (b) correct the guard to `if exceptions.is_empty() { return Err(InvalidException); }`-style validation that accepts only denylisted-algorithm exceptions, and rewrite the tests to assert the intended semantics (accept a denylisted exception within TTL; reject allowlisted-algo exceptions; reject expired). The human owner should decide whether the feature is wanted at all — strict default-deny argues for deletion.
- Justification / source: CLAUDE.md §10.4 (default-deny; first test for a policy path is "empty ⇒ deny"); least-privilege/strictest-secure-default doc-precedence rule (charter). NIST SP 800-131A algorithm-transition governance — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final (accessed 2026-06-18).
- Verification method: tests asserting the intended (or absent) exception semantics; `cargo test -p rustynet-crypto`.
- Status: **open** (severity diverges from FullRepoAnalysis_2026-05-24 with stated reasoning; 2026-06-18)

### RSA-0004 — macOS `-A` (allow-any-application) keychain store path exposes a secret in argv and stores it under an over-broad item ACL
- File: `crates/rustynet-crypto/src/lib.rs:574-582` (`store_macos_generic_password_allow_any_app`), `:631-697` (`..._via_security_cli`, `-w <secret>` argv at `:686-687`, `-A` at `:681`)
- Date: 2026-06-18
- Severity: **Low** (both facets carry strong compensating controls; the code documents the trade-off extensively)
- Bar mapping: SecurityMinimumBar §3.4 (secret handling) / §3.7 (privileged-helper argv discipline). 
- Reachability / attacker: used to store the **trust signing-key passphrase** (read cross-binary by `rustynet ops refresh-signed-trust`). Two facets: (1) **CWE-214 argv exposure** — the passphrase is passed as `security add-generic-password -w <secret>`, visible via `ps`/`/proc` to other processes for the ~50 ms exec; mitigated because the call runs as root in a single-shot bootstrap and only same-or-higher-privileged (root) processes can observe it. (2) **CWE-732 over-broad ACL** — `-A` lets any local application read the stored item; mitigated because the passphrase alone is useless without the separately stored XChaCha20-Poly1305 ciphertext, whose file ACL is restrictively enforced, and reading that ciphertext requires owner/root who already hold full access.
- Observation: the modern, tighter path (`store_macos_generic_password_system_keychain_owned`, `:803-847`) uses `SecItemAdd` with **no argv secret** and an identity-scoped ACL, and is correctly preferred where the same binary reads back. The `-A` CLI path is the documented fallback for the cross-binary reader; the trade-off and single-tenant assumption are spelled out in-code (`:646-664`).
- Risk: on a genuinely multi-tenant macOS host (contrary to the documented single-tenant assumption), a non-owner local account could read the passphrase item; still not sufficient for key recovery without the restricted ciphertext.
- Proposed enforcement (review-only — do NOT apply): prefer the `SecItemAdd` owned path wherever cross-binary read is not required; for the cross-binary case, document the residual risk in the operator runbook and add a startup assertion that the install layout is single-tenant (or migrate the cross-binary reader to share the storing binary's identity). No change to crypto.
- Justification / source: CWE-214 "Invocation of Process Using Visible Sensitive Information" — https://cwe.mitre.org/data/definitions/214.html ; CWE-732 — https://cwe.mitre.org/data/definitions/732.html (both accessed 2026-06-18); NIST SP 800-57 Pt 1 Rev 5 §5 (restrict key/secret access) — https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf.
- Verification method: source-pin test that the owned path carries no `-w` argv secret already exists (`:2557`); add an operator-runbook note + (optional) single-tenant startup assertion.
- Status: **open** (informational; documented trade-off — candidate for `risk-accepted`; 2026-06-18)

### RSA-0005 — `MembershipDirectory::is_populated()` is dead code whose doc advertises permissive-on-empty (the exact RN-11 fail-open posture)
- File: `crates/rustynet-policy/src/lib.rs:112-118`
- Date: 2026-06-18
- Severity: **Low** (stale/dangerous documentation + dead API; the *enforced* behavior is fail-closed, so no current weakening)
- Bar mapping: SecurityMinimumBar §3.6 (default-deny); CLAUDE.md §10.4. Adjacent to **RN-11** (empty membership = allow-all), which was fixed at the daemon/`phase10` layer.
- Reachability / attacker: not currently reachable as a weakening. `is_populated()` has **zero callers** anywhere in the workspace (grep-confirmed) — the live enforcement path (`selector_membership_allowed`, `:412-429`) denies `node:`/`user:`/`group:`/`tag:` selectors when the directory is empty (status resolves to `Unknown` ≠ `Active`), proven by the test `membership_aware_policy_denies_node_selectors_when_directory_empty` (`:714`).
- Observation: the method's doc comment states "When the directory is unpopulated (empty) the membership enforcement gate treats nodes as pre-membership and **skips the check** so that deployments that have not yet adopted governance are not broken." That describes precisely the RN-11 fail-open that was supposedly removed. The method survives as an attractive-nuisance helper: a future caller that re-introduces `if membership.is_populated() { enforce } else { allow }` would resurrect RN-11.
- Risk: latent fail-open if the dead helper is wired into a gate. No present exploit.
- Proposed enforcement (review-only — do NOT apply): delete `is_populated()` (no callers), or, if kept for diagnostics, rewrite the doc to remove any "skip the check" semantics and add a comment that membership enforcement is unconditional + fail-closed on empty.
- Justification / source: CLAUDE.md §10.4 (default-deny; empty ⇒ deny); SecurityMinimumBar §3.6; CWE-1188/CWE-636 (fail-open default) — https://cwe.mitre.org/data/definitions/636.html (accessed 2026-06-18).
- Verification method: `cargo clippy` dead-code surfacing + a doc/test asserting empty-directory denial (already exists at `:714`).
- Status: **open** (2026-06-18)

### RSA-0006 — `validate_policy_safety` only blocks the literal `Protocol::Any` allow-all; a protocol-enumerated allow-all evades the canary safety net
- File: `crates/rustynet-policy/src/lib.rs:369-380` (`validate_policy_safety`), called by `PolicyRolloutController::stage_revision` (`:335-344`)
- Date: 2026-06-18
- Severity: **Low** (a safety tripwire, not the enforcement boundary; bypass requires an owner-signed policy, and default-deny still holds at evaluation time)
- Bar mapping: SecurityMinimumBar §3.6 (default-deny / policy governance); §10 (staged rollout). Re-confirms `FullRepoAnalysis_2026-05-24.md` "rollout validation bypass."
- Reachability / attacker: the guard rejects a rule only when `src=="*" && dst=="*" && protocol==Any && action==Allow`. A staged revision containing `* * Tcp Allow` (+ `* * Udp Allow`, `* * Icmp Allow`) is *effectively* allow-all but each rule has a concrete protocol, so `validate_policy_safety` returns `Ok`. Attacker = whoever authors/stages a policy revision; because revisions must be owner-signed to apply, the practical actor is a careless or compromised policy author, and the tripwire's job is to catch exactly that mistake.
- Observation: the check is an exact-shape match, not a semantic allow-all analysis. It also does not consider broad group/tag selectors that resolve to "everyone."
- Risk: an effectively-open policy can be staged/promoted without the intended "UnsafeAllowAll" rejection. Mitigated because (a) per-request default-deny is unaffected, and (b) signing is still required.
- Proposed enforcement (review-only — do NOT apply): broaden the detection to flag any `*`→`*` Allow regardless of protocol (iterate protocols), and consider flagging a set of protocol-specific `*`→`*` Allow rules that together cover all protocols. Document that this is a tripwire, not a substitute for review of signed policy.
- Justification / source: SecurityMinimumBar §3.6 default-deny; OWASP ASVS 5.0 V4 access-control (deny-by-default, no broad grants) — https://github.com/OWASP/ASVS (accessed 2026-06-18); CLAUDE.md §10.4.
- Verification method: unit tests that `stage_revision` rejects `* * Tcp Allow` and a protocol-spanning set; `cargo test -p rustynet-policy`.
- Status: **open** (re-confirms FullRepoAnalysis_2026-05-24 "rollout validation bypass"; 2026-06-18)

### RSA-0007 — Dataplane controller gates exit-node/LAN-route ACLs with the revocation-blind `evaluate`, while the daemon uses the membership-aware `evaluate_with_membership`
- File: `crates/rustynetd/src/phase10.rs:4729` (`set_exit_node`), `:4799` (`ensure_lan_route_allowed`). Contrast: `crates/rustynetd/src/daemon.rs:4001/4023/4038` use `evaluate_with_membership`.
- Date: 2026-06-18
- Severity: **Medium** (defense-in-depth / consistency; mitigated by upstream membership-gated peer provisioning and explicit default-deny ACL maps — not an open revocation bypass)
- Bar mapping: SecurityMinimumBar §3.6 (default-deny ACL across mesh/routes/exit) and §3.8 (failover cannot bypass trust-state); CLAUDE.md §10.4. Same revocation-bypass *class* as RN-05.
- Reachability / attacker: `Phase10Controller::set_exit_node` and `ensure_lan_route_allowed` call `self.policy.evaluate(ContextualAccessRequest{..})` — the plain `ContextualPolicySet::evaluate`, which performs **no** membership/revocation check. If a `node:`/`user:` selector that matches an Allow rule belongs to a *revoked* node, this layer alone would still return `Allow`. Today this is contained because (a) revoked peers are not provisioned as WG peers (the RN-11 `check_peer_membership_active` gate runs before provisioning, per `SecurityAnalysis_2026-06-12.md §1.4`), and (b) `ensure_lan_route_allowed` first requires `lan_access_enabled`, an advertised route, and an explicit `lan_route_acl` entry defaulting to `false` (`:4790-4797`). Residual exposure is a revocation-vs-selection race and the inconsistency itself.
- Observation: the daemon's auto-tunnel/CIDR/via decisions (`daemon.rs:4001/4023/4038`) correctly use `evaluate_with_membership`; the dataplane controller's two ACL gates do not. The membership-aware variant exists and is the established secure pattern (RN-05/RL-10 wired the signed membership directory into `Phase10Controller`).
- Risk: a revoked node could pass these two control-plane ACL gates if the upstream provisioning gate is ever bypassed or races a concurrent revocation; and the divergence makes the security posture depend on a second, weaker code path (CLAUDE.md §3 "one hardened path").
- Proposed enforcement (review-only — do NOT apply): route both `phase10` ACL checks through `evaluate_with_membership` using the signed membership directory already held by `Phase10Controller`, so revocation is enforced at this layer too; add a negative test that a revoked exit-node / LAN-route requester is denied at `set_exit_node` / `ensure_lan_route_allowed`.
- Justification / source: SecurityMinimumBar §3.6/§3.8; CLAUDE.md §3 (one hardened path, no weaker parallel branch) and §10.5; CWE-285 "Improper Authorization" — https://cwe.mitre.org/data/definitions/285.html (accessed 2026-06-18).
- Verification method: revoked-node negative tests on both `phase10` entry points; `cargo test -p rustynetd phase10`.
- Status: **applied** (2026-06-24). Both `set_exit_node` (`set_exit_node:5066`) and `ensure_lan_route_allowed` (`:5136`) now call `self.policy.evaluate_with_membership(&req, &self.membership)` using the signed `MembershipDirectory` the controller already holds, so a revoked exit node / revoked requester selector is denied at this control-plane ACL layer too (one hardened path — the revocation-blind `evaluate` branch is gone here). Negative tests added: `set_exit_node_denies_revoked_exit_node`, `ensure_lan_route_allowed_denies_revoked_requester`. The CLI issuance generator RSA-0008 remains the only revocation-blind `evaluate` site (separate finding). (130 phase10 tests pass.)
- Prior status: **open** — File row: `phase10.rs` remains `pending` (full `rustynetd` audit in a later increment will complete its row and cite RSA-0007). Also carried for verification: `rustynet-control/src/lib.rs:3377` and `:main.rs:31` use plain `evaluate` — confirmed in Batch 1 (lib.rs:3377 → RSA-0008; main.rs:31 → benign scaffold, see file row). (2026-06-18)
- Status update (2026-06-18, Batch 2): `phase10.rs` audited — row now `open` citing RSA-0007 (`set_exit_node:4729`, `ensure_lan_route_allowed:4799` confirmed revocation-blind, no negative test). Containment strengthened: the daemon-trust lens confirmed the daemon's own three trust ACL gates (`daemon.rs:4001/4023/4038`) and all signed-bundle-apply paths DO use `evaluate_with_membership`, so the revocation-blind `evaluate` is confined to these two `phase10` control-plane methods + the CLI issuance generator (RSA-0008). Remains **open** (Medium).

---

## Findings Log — Batch 1 (rustynet-control + rustynet-operator, multi-agent fan-out 2026-06-18)

> 8 read-only agents swept all 28 files; **every load-bearing finding below was
> re-verified first-hand by the auditor against the cited code** before logging
> (the two High candidates were read line-by-line; the agent's High #1 → Medium
> here after reachability verification). Positive controls confirmed:
> `validate_transition` is a fail-closed 8×8-matrix-tested gatekeeper with
> BlindExit irreversibility + owner-sig-for-capabilities (`role_presets.rs`);
> `credential_unwrap.rs` is clean (argv-only custody, Zeroizing, no secret logs);
> `key_rotation.rs` monotonic-epoch fail-closed; RN-01 membership-decoder bounds
> re-confirmed sound (`membership.rs`).

### RSA-0009 — Membership reducer stamps `unix_now()` into the canonical state-root, so Revoke / RotateKey / Restore / SetCapabilities can never be applied or replayed (revocation + key-rotation non-functional)
- File: `crates/rustynet-control/src/membership.rs:1149,1168,1180,1193` (reducer), `:285` (canonical payload includes `updated_at_unix`), `:718-724` (`apply_signed_update` re-derives + compares root)
- Date: 2026-06-18
- Severity: **High** (re-confirms **AUDIT-040**; release-blocker class — a Critical security operation, node revocation, cannot be performed). Fails closed (op is rejected), so no unauthorized access is *granted*; the harm is that authorization *cannot be withdrawn*.
- Bar mapping: SecurityMinimumBar §3.3 (credential/membership lifecycle), §6.D (role/capability transitions must apply), §6.B (signed-state trust chain); CLAUDE.md §8 ("deterministic, testable state transitions for trust-sensitive systems").
- Reachability / attacker: operator/admin (or the daemon applying a quorum-signed update) attempting to revoke a compromised node or rotate a node key. Verified first-hand: `reduce_membership_state` sets `node.updated_at_unix = unix_now()` for `SetNodeCapabilities`/`RevokeNode`/`RestoreNode`/`RotateNodeKey`; `updated_at_unix` is serialized into `canonical_payload` (`:285`) and therefore into `state_root_hex()`. The producer computes `record.new_state_root` from the reducer at proposal-build time T1 (`main.rs:6206` `preview_next_state`); `apply_signed_update` re-runs the reducer at apply time T2 (`:718`) and rejects with `NewStateRootMismatch` (`:722-723`) whenever T1 and T2 fall in different unix seconds — i.e. essentially always, since proposal→sign→transport→apply spans more than one second. **Replay always fails** (re-derivation time ≠ recorded second). The other four ops (`AddNode`/`RemoveNode`/`SetQuorum`/`RotateApprover`) do not call `unix_now()` and so apply correctly — which is why existing apply tests pass and the defect went unnoticed.
- Risk: a compromised or rogue enrolled node cannot be revoked via the signed-update path; a leaked node key cannot be rotated. Historical-log replay (disaster recovery) is also broken for any log containing one of the four ops. This is a fail-closed *inability to act* on the most security-critical transitions.
- Proposed enforcement (review-only — do NOT apply): make the reducer deterministic for state-root purposes — derive `updated_at_unix` from the signed record (e.g. `record.created_at_unix`), or carry the new timestamp explicitly in the operation, or exclude `updated_at_unix` from `canonical_payload`/`state_root`. Add success-path `apply_signed_update` + `replay` tests for `RevokeNode`/`RestoreNode`/`RotateNodeKey`/`SetNodeCapabilities` asserting the signed `new_state_root` matches (the missing negative-coverage that hid this).
- Justification / source: CLAUDE.md §8 (deterministic trust-sensitive state transitions); SecurityMinimumBar §3.3/§6.D; CWE-664 "Improper Control of a Resource Through its Lifetime" — https://cwe.mitre.org/data/definitions/664.html (accessed 2026-06-18). Re-confirms AUDIT-040.
- Verification method: success-path apply + replay tests for the four affected ops; `cargo test -p rustynet-control membership`.
- Status: **open** (re-confirms AUDIT-040, verified first-hand; 2026-06-18)

### RSA-0008 — Operator-side control-plane bundle generator (`ControlPlaneCore`) gates all signed-artifact issuance with the revocation-blind `evaluate`
- File: `crates/rustynet-control/src/lib.rs:2229` (`policy: PolicySet`, no `MembershipDirectory` field), `:3371-3389` (`policy_allows_node_pair` → `self.policy.evaluate`), callers at `:2567/2600/2706/2798/2986/3064` (peer-map, auto-tunnel, DNS-zone, endpoint-hint, relay-fleet bundles + relay-session token)
- Date: 2026-06-18
- Severity: **Medium** (defense-in-depth / consistency — same class as RSA-0007 at the *issuance* layer; **downgraded from the agent's High** after reachability verification: `ControlPlaneCore` is the operator-run CLI generator, not a daemon runtime gate, and the daemon consumer re-checks membership).
- Bar mapping: SecurityMinimumBar §3.6 (default-deny / membership-gated access via `evaluate_with_membership`), §3.2 (signed control data); CLAUDE.md §3 (fail-closed on trust state). Same class as RSA-0007; CWE-863.
- Reachability / attacker: verified that `ControlPlaneCore::new(...)` is constructed in production only by the **CLI** (`rustynet-cli/src/main.rs:5522/5629/5720`, operator-run bundle generation) — every `rustynetd/src/traversal.rs` construction is under `#[cfg(test)]`. `policy_allows_node_pair` calls the plain `PolicySet::evaluate`, which never consults `MembershipDirectory`; `ControlPlaneCore` holds none. So a **revoked** node whose ACL selector still matches an Allow rule is still included when the operator regenerates auto-tunnel/peer-map/endpoint-hint/relay-fleet bundles. **Mitigated** because the daemon-side consumer gates peer provisioning on `check_peer_membership_active` + `evaluate_with_membership` (the RN-11/RL-10 fix), so a revoked node named in a bundle is not actually provisioned. (Note: revocation itself is currently broken by RSA-0009, compounding the analysis.)
- Risk: signed connectivity artifacts can name a revoked peer; a real bypass would require a downstream consumer that trusts a bundle's node-list without re-checking membership. **Carry:** verify no such consumer exists when auditing the daemon bundle-application paths (Batch 2).
- Proposed enforcement (review-only — do NOT apply): give `ControlPlaneCore` a signed `MembershipDirectory` and route `policy_allows_node_pair` through `PolicySet::evaluate_with_membership` (mirroring `daemon.rs:4001/4023/4038`), so empty/missing/Revoked/Unknown ⇒ Deny. Add a negative test: a revoked source/dest node is denied issuance of each signed bundle and the relay-session token.
- Justification / source: SecurityMinimumBar §3.6/§3.2; CLAUDE.md §3 (one hardened path, fail-closed on trust state); CWE-863 "Incorrect Authorization" — https://cwe.mitre.org/data/definitions/863.html (accessed 2026-06-18).
- Verification method: revoked-node negative tests on each `signed_*_bundle` issuer + `issue_relay_session_token`; `cargo test -p rustynet-control`.
- Status: **open** (RSA-0007 class at the issuance layer; severity adjusted with reasoning; 2026-06-18)
- Status update (2026-06-18, Batch 2): the "Carry" question is **resolved — no daemon-side bypass**. The Batch-2 daemon-trust lens verified that no daemon consumer applies a signed auto-tunnel/peer-map/endpoint-hint/relay-fleet bundle's node-list without re-checking membership (`daemon.rs:6648-6792/8060-8245`). So a revoked peer named in an operator-generated bundle is still dropped by the daemon's `check_peer_membership_active` provisioning gate. RSA-0008 stays **Medium** as a defense-in-depth/consistency gap at the CLI generator (it can still *emit* artifacts naming revoked peers), but the worst-case end-to-end bypass is foreclosed.
- Status update (2026-06-18, Batch 4): the CLI generator confirmed first-hand — `execute_assignment Issue`/`execute_dns_zone_issue`/`execute_traversal_issue` build a fresh `ControlPlaneCore::new(signing_secret, policy)` from operator `--nodes`/`--allow-pairs` (`main.rs:5522/5629/5720`) with no revocation list at issue time. A Batch-4 agent proposed **High**; kept **Medium** because (a) the daemon consumer re-checks membership (above) and (b) the actor is the operator already wielding the owner signing key they hold (no privilege gain). `cli/main.rs` row now `open` citing RSA-0008.

### RSA-0010 — `issue_relay_session_token` mints via the panicking `sign_at` instead of the fail-closed `try_sign_at` on CSPRNG failure
- File: `crates/rustynet-control/src/lib.rs:2953-2999` (`issue_relay_session_token`), `:2992` (calls `sign_at`), `:1742-1764` (panic at `:1762`), `:1776-1804` (`try_sign_at`/`RelayTokenMintError` exists)
- Date: 2026-06-18 · Severity: **Low** (latent — `production_path: false`)
- Bar mapping: CLAUDE.md §10.2 (no panic in production paths — DoS vector), §3 (fail-closed on entropy). CWE-248.
- Reachability: the `Result`-returning public `issue_relay_session_token` calls `sign_at`, which `panic!`s on `OsRng` failure, although the fail-closed `try_sign_at` exists and the daemon's real issuer (`relay_client.rs:138` `LocalRelaySessionTokenIssuer::issue_token`) already uses the fail-closed path. Verified: the panicking variant has **no non-test caller today** (callers at `lib.rs:7383+` are `#[cfg(test)]`) — so it is a latent footgun on a public API, not a live DoS.
- Proposed enforcement: switch `:2992` to `try_sign_at(...).map_err(ControlPlaneError::…)`; gate `sign_at` to `#[cfg(test)]`. Add a CSPRNG-failure-returns-Err test.
- Source: CLAUDE.md §10.2; mirrors the crate's own `try_random_nonce_hex` (`:3494`) fail-closed pattern; CWE-248 — https://cwe.mitre.org/data/definitions/248.html (accessed 2026-06-18).
- Status: **open** (net-new; 2026-06-18)

### RSA-0011 — `TrustState` is MAC-integrity-protected but has no monotonic anti-rollback floor, and the MAC key is co-located with the protected file
- File: `crates/rustynet-control/src/lib.rs:1009-1153` (`load_trust_state`/persist/MAC), MAC key at `<path>.integrity.key` (`:1118`)
- Date: 2026-06-18 · Severity: **Info** (defense-in-depth; local-write attacker)
- Bar mapping: SecurityMinimumBar §3.2/§3.3 (signed-state freshness / anti-rollback); CLAUDE.md §4. CWE-294 (replay).
- Reachability: `load_trust_state` verifies an HMAC-SHA256 MAC and fails closed on every error (good), but `TrustState.generation` is never compared against a previously-seen floor, so an attacker with filesystem write to the state dir can roll back to an older *validly-MAC'd* generation. The MAC key sits beside the file with the same `0o600`, so write-access generally implies key-access — the MAC mainly defends against a read-only attacker.
- Proposed enforcement: persist/compare a monotonic highest-generation-seen floor (or bind `generation` to OS-secure storage / a separate key-custody domain); reject loads below the floor; add a downgrade negative test.
- Source: CLAUDE.md §4 (anti-replay/rollback where freshness matters); CWE-294 — https://cwe.mitre.org/data/definitions/294.html (accessed 2026-06-18).
- Status: **open** (net-new; 2026-06-18)

### RSA-0012 — Role-audit append is a read-then-append TOCTOU; concurrent appends can produce duplicate-index entries that break the hash-chain verifier
- File: `crates/rustynet-control/src/role_audit.rs:237-289` (`append_role_audit_entry`; no `flock`/`O_EXCL`)
- Date: 2026-06-18 · Severity: **Low**
- Bar mapping: SecurityMinimumBar §6.D ctrl 6 (tamper-evident transition audit); A1; CWE-362.
- Reachability: two concurrent `rustynet role set` invocations both read `existing.last()`, compute the same `next_index = N` + `previous_hash`, and both append `index=N`; `verify_role_audit_chain` then fails (`index != position`). Integrity is preserved (no forged-passing chain — `entry_hash` binds index|prev|payload); the risk is availability/auditability (a benign concurrent append makes the chain unverifiable). Operator-initiated one-shot CLI action, so genuine concurrency is unusual.
- Proposed enforcement: exclusive advisory lock spanning read-derive-index + append (or reject a duplicate trailing index); mirror `membership.rs:1462` `create_new`. Add a concurrent-append negative test.
- Source: SecurityMinimumBar §6.D ctrl 6; CWE-362 — https://cwe.mitre.org/data/definitions/362.html (accessed 2026-06-18).
- Status: **open** (net-new; 2026-06-18)

### RSA-0013 — Role-audit log `set_permissions(0o640)` result is discarded on create
- File: `crates/rustynet-control/src/role_audit.rs:271-277` (`let _ = file.set_permissions(...)`)
- Date: 2026-06-18 · Severity: **Info** (log holds no secrets — role names/outcomes/hash fields only)
- Bar mapping: CLAUDE.md §4 (strict perms on at-rest files); A1; CWE-732.
- Reachability: if the chmod fails the log keeps umask-derived (possibly group/other-readable) mode with no error surfaced. Minimal impact given non-secret content.
- Proposed enforcement: propagate the error as `RoleAuditError::Io`, or document best-effort tightening as acceptable for non-secret content.
- Source: CLAUDE.md §4; CWE-732. Status: **open** (net-new; 2026-06-18)

### RSA-0014 — `emit_role_audit` (CLI) is fail-open by design: a role transition proceeds even if the durable audit append fails
- File: `crates/rustynet-cli/src/main.rs:17327-17337` (caller of the fail-closed `append_role_audit_entry`)
- Date: 2026-06-18 · Severity: **Question** (caller-policy decision; the audited `role_audit.rs` API is correctly fail-closed)
- Bar mapping: SecurityMinimumBar A1 ("every transition emits an entry") vs CLAUDE.md §3 (fail-closed when security state unavailable). CWE-778.
- Reachability: the sole production caller downgrades any append error to an `eprintln` warning and lets the transition (including capability-bearing SignedMembership changes) complete — documented rationale: audit is operator-visible evidence, not a gate. A transition can complete with no durable audit record if the log path is unwritable (local operator, full disk).
- Proposed enforcement (owner decision): if SecMinBar requires durable audit *before* mutation, make `emit_role_audit` fail closed for SignedMembership/Irreversible transitions. No change needed in `role_audit.rs`.
- Source: SecurityMinimumBar A1; CLAUDE.md §3; CWE-778 — https://cwe.mitre.org/data/definitions/778.html (accessed 2026-06-18).
- Status: **open** — File row: `rustynet-cli/src/main.rs` remains `pending` (Tier 3); cited here as raised. (2026-06-18)
- Status update (2026-06-18, Batch 4): **confirmed first-hand** at `cli/main.rs:17321-17337` — `emit_role_audit` calls `append_role_audit_entry` and on `Err` only `eprintln!`s a `[warn]`; `execute_role_plan` (`:17269-17306`) applies all actions and returns `Ok` regardless (reached from PresetTransition `:17258/17283/17299` and CapabilityMutation `:17620`). `cli/main.rs` row now `open` citing RSA-0008 + RSA-0014. Owner decision still required (fail-closed durable audit before signed/irreversible mutations).

### RSA-0015 — Enrollee role-string mapping silently drops unrecognized roles (defaults to Client)
- File: `crates/rustynet-control/src/enrollment.rs:185-210` (`enrollee_capabilities_from_roles`, `_ => {}` at `:203`)
- Date: 2026-06-18 · Severity: **Info** (fail-safe — can only *drop* privilege; produced record is unsigned and capability grant is gated by approver-quorum signing)
- Bar mapping: CLAUDE.md §3 (default-deny / fail-loud); CWE-636.
- Reachability: operator typo / future role name produces a client-only node with no error. No escalation (mapping is fail-safe toward Client; actual grant requires quorum signature).
- Proposed enforcement: return a typed error on unrecognized role tokens (mirror `roles.rs::RoleCapability::parse`) instead of silent drop. Add a negative test for the unknown-role path.
- Source: CLAUDE.md §3; CWE-636 — https://cwe.mitre.org/data/definitions/636.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0016 — `disable_trust_hardening` compares the break-glass secret with non-constant-time `!=`; `TrustHardeningConfig` derives `Debug` over a plaintext secret
- File: `crates/rustynet-control/src/scale.rs:264-273` (`!=` compare), `:221-225` (`#[derive(Debug)]` over `break_glass_secret: String`)
- Date: 2026-06-18 · Severity: **Low** (`production_path: false` — `scale.rs` is not wired into any binary today)
- Bar mapping: SecurityMinimumBar §3.4 (constant-time secret compare; never log secrets); CLAUDE.md §10.5/§10.6; CWE-208/CWE-532.
- Reachability: `String !=` short-circuits on the first differing byte (timing oracle) — unlike `admin.rs` which correctly uses `subtle::ConstantTimeEq` for its CSRF token; and any `{:?}`/tracing of the config leaks the plaintext break-glass secret. If wired, recovering the secret disables trust-hardening (re-enabling unsigned/unauthorized-key acceptance). No wired caller today.
- Proposed enforcement: `subtle::ConstantTimeEq` over byte slices (mirror `admin.rs`); hand-written redacting `Debug`. Add a redacted-Debug negative test.
- Source: SecurityMinimumBar §3.4; CLAUDE.md §10.6; CWE-208 — https://cwe.mitre.org/data/definitions/208.html, CWE-532 — https://cwe.mitre.org/data/definitions/532.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0017 — `SqliteStore::open` performs no permission check on the control-plane DB (pubkeys, MFA flags, enrollment credential state)
- File: `crates/rustynet-control/src/persistence.rs:74-82` (`Connection::open(path)`, no perm validation)
- Date: 2026-06-18 · Severity: **Low**
- Bar mapping: SecurityMinimumBar §3.5 (encrypted-at-rest fallback with strict permissions + startup permission checks); CLAUDE.md §4; CWE-732.
- Reachability: the file-based `TrustState` gates access via `validate_secure_file` (0o077 mask, symlink reject); the sqlite path has no equivalent, and WAL mode creates `-wal`/`-shm` sidecars under default umask. On a multi-user host the DB (credential single-use state, node pubkeys, user MFA posture) could be group/world-readable → local info disclosure / credential-state tampering. Distinct from RN-09 (integrity-key path).
- Proposed enforcement: enforce/verify `0o600` on the DB + sidecars at `open()`, reject group/other-accessible files, fail closed; add a group-readable-DB negative test.
- Source: SecurityMinimumBar §3.5; CWE-732. Status: **open** (net-new; 2026-06-18)

### RSA-0018 — Privileged-command argv validation in `admin.rs` is `#[cfg(test)]`-only and the whole module is unwired (asserted-but-unverified control)
- File: `crates/rustynet-control/src/admin.rs:207-263` (`validate_privileged_command`/`contains_shell_meta`/… all `#[cfg(test)]`)
- Date: 2026-06-18 · Severity: **Question** (assurance-drift; `production_path: false`)
- Bar mapping: SecurityMinimumBar §3.7 (argv-only privileged exec); CLAUDE.md §4 (control needs an enforcement point AND a verification); CWE-1006.
- Reachability: the RBAC/MFA/CSRF `AdminAuthorizer` logic is non-test, but the whole `admin` module has no production importer (no `rustynetd`/bin uses `rustynet_control::admin`), and the argv-validation fns are `#[cfg(test)]`-gated — so the privileged-exec hardening the `rustynet-cli` security_audit_catalog cites as satisfied does not run in any shipped build. No reachable privileged-exec wired through this code today.
- Proposed enforcement: wire `AdminAuthorizer` + `validate_privileged_command` into the real admin API/IPC enforcement point and drop the `#[cfg(test)]` gate, OR document these as design-reference scaffolding so the audit catalog does not over-claim.
- Source: CLAUDE.md §4; SecurityMinimumBar §3.7; CWE-1006 — https://cwe.mitre.org/data/definitions/1006.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0019 — `operations.rs`: denylist-based log redaction can miss unnamed secrets; tamper-evident audit log accepts unvalidated `|`/newline delimiters
- File: `crates/rustynet-control/src/operations.rs:50-56` (redaction allow-list), `:162-178/214-237` (`|`-delimited audit append/restore)
- Date: 2026-06-18 · Severity: **Info** (`production_path: false` — module referenced only by the CLI audit catalog/tests)
- Bar mapping: SecurityMinimumBar §3.4 (never log secrets); CLAUDE.md §10.6; CWE-117/CWE-693. Reconciles **AUDIT-041**.
- Reachability: `looks_sensitive_value`/`is_sensitive_key` match a fixed substring set — a secret under an unlisted key passes cleartext (redaction false-negative). `TamperEvidentAuditLog::append` takes `actor`/`action` verbatim into a `|`-delimited line; restore splits on `|`/newline with no field validation. The delimiter issue is fail-closed in practice (the SHA-256 hash chain breaks on mis-parse → `IntegrityMismatch`), so it denies rather than forges. No production caller today.
- Proposed enforcement: classification-based redaction (not substring guessing); reject/escape `|` and control chars before hashing. Add an embedded-delimiter negative test.
- Source: SecurityMinimumBar §3.4; CWE-117 — https://cwe.mitre.org/data/definitions/117.html (accessed 2026-06-18); reconciles AUDIT-041. Status: **open** (2026-06-18)

### RSA-0020 — Operator `assert_config_file_secure` has no parent-directory TOCTOU guard and re-opens the file after the check
- File: `crates/rustynet-operator/src/config/persist.rs:77-109`
- Date: 2026-06-18 · Severity: **Info**
- Bar mapping: CLAUDE.md §4 (startup permission checks); CWE-367.
- Reachability: `lstat`-based checks correctly reject symlinks / group-world-writable / untrusted owners, but the file is re-opened separately in the CLI loader (check-then-use window) and parent-dir writability is not checked. Low impact: config is `0o600` owner-restricted, parents are root-owned system paths, and the file holds only paths/flags (no secrets).
- Proposed enforcement: open once and `fstat` the open handle (check mode/owner on the same fd that is read); optionally verify parent-dir ownership.
- Source: CLAUDE.md §4; CWE-367. Status: **open** (net-new; 2026-06-18)

### RSA-0021 — Operator layer stores `WG_INTERFACE`/`EGRESS_INTERFACE`/`DATAPLANE_MODE`/keychain-account without syntactic validation
- File: `crates/rustynet-operator/src/config/validate.rs:247,263,266,278`
- Date: 2026-06-18 · Severity: **Info** (defense-in-depth — re-validated at the daemon boundary)
- Bar mapping: CLAUDE.md §10 (parse-then-reject-early, bounded sizes); CWE-20.
- Reachability: these fields are assigned from parsed values without charset/length checks (unlike node-id/enum fields). No injection on round-trip (`lines()`-split values carry no newline; emitted as `KEY=value`, never a shell; passed via `command.env()`), and downstream consumers re-validate (`validate_managed_dns_interface_name`, `BootSshCidr::parse`, daemon `DATAPLANE_MODE` match). Defense-in-depth gap only.
- Proposed enforcement: constrain interface names to `^[A-Za-z0-9._-]{1,15}$` and `DATAPLANE_MODE` to the known enum at the operator layer.
- Source: CLAUDE.md §10 (I1); CWE-20 — https://cwe.mitre.org/data/definitions/20.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0022 — `endpoint_host_from_value` accepts out-of-range IPv4 octets (non-validating display extractor)
- File: `crates/rustynet-operator/src/egress.rs:17-27`
- Date: 2026-06-18 · Severity: **Info** (`production_path: false` — no non-test caller; CLI uses its own `split_endpoint_host_port`)
- Bar mapping: CLAUDE.md §10.4 (input validation); CWE-20.
- Reachability: the IPv4 branch checks only 4 non-empty all-digit octets, not 0–255, so `999.1.1.1:80` returns `Some(host)`. The helper feeds no exec/policy/trust decision and has zero external callers. ASCII-delimiter byte-slicing is in-bounds (no panic).
- Proposed enforcement: if ever wired to a routing/trust decision, parse via `std::net::Ipv4Addr::from_str`; otherwise document as a non-validating display extractor.
- Source: CLAUDE.md §10.4; CWE-20. Status: **open** (net-new; 2026-06-18)

---

## Findings Log — Batch 2 (rustynetd, 20-agent multi-agent fan-out 2026-06-18)

> 20 read-only agents swept all 69 source files of the daemon (the 28k-line
> `daemon.rs` across three concern lenses). **Verdict: 0 Critical / 0 High new.**
> Load-bearing findings re-verified first-hand (enrollment ledger lock absence,
> kill-arg scope, secret-log-audit phantom type names).
>
> **Positive controls confirmed (re-verified, not findings):** RN-03 (no discarded
> `force_fail_closed` Results), RN-04 (killswitch before backend start), RN-10
> (corrupt rotation ledger fails closed, absent ⇒ genesis), RN-N1 (relay_client
> double-take no longer panics), RN-14 (`unsafe` forbidden crate-wide bar one
> documented macos_utun exception), RN-24 (secrets logged only as thumbprints,
> zeroized), RN-N8 (gossip `SeenSequenceState` bounded by membership not attacker).
> **RSA-0008 daemon-side bypass: ABSENT** — the daemon applies no signed-bundle
> node-list without re-checking membership; all three trust ACL gates
> (`daemon.rs:4001/4023/4038`) use `evaluate_with_membership`; auto-tunnel loader
> ordering is verify→future→stale→replay→build. Strong parsers: STUN/PCP/NAT-PMP/
> uPnP/gossip decoders are bounds-checked (`checked_add`/`checked_mul`,
> `MAX_CANDIDATES`, 4MB/4KiB caps); `privileged_helper` argv-allowlist + RN-17
> peer-cred; Windows named-pipe `PIPE_REJECT_REMOTE_CLIENTS` + SDDL.

### RSA-0023 — Enrollment one-time-token ledger has no file lock; concurrent (cross-process) consume can redeem the same single-use token twice
- File: `crates/rustynetd/src/enrollment_token.rs:436-572` (`load_ledger`/`write_ledger`), consume path in `crates/rustynetd/src/enrollment_consume.rs`
- Date: 2026-06-18 · Severity: **Medium**
- Bar mapping: SecurityMinimumBar §3.3 ("One-time credential consumption is atomic and race-safe under concurrent requests"), §6.C ctrl 3 (shared single-use ledger for bundle-pull + redemption), §6 Required Evidence ("Concurrent one-time-key consume race tests"); CWE-362.
- Reachability / attacker: verified first-hand — `load_ledger` reads the file with no lock; `write_ledger` does an atomic temp+rename but there is **no `flock`/advisory lock spanning the read→check-consumed→record→write** sequence (grep confirms zero `flock`/`FileExt`/`lock_exclusive`/`Mutex` in either module). The sibling `resilience.rs` *does* serialize via `write_atomic_locked`/`acquire_lock` (`:96/185/226`), so the safe pattern exists in-repo and was simply not applied here. Two redemption attempts for the same token that interleave (the §6.C anchor bundle-pull endpoint and the enrollment redemption endpoint share one ledger, and may run as separate processes/tasks) can both observe "not consumed," both register the peer, and both write — last-write-wins drops one consume record → the single-use token is honored twice. Attacker = a holder of one enrollment token racing two redemptions to onboard two nodes (or replay across the two endpoints).
- Risk: violates the one-time-credential guarantee; a single enrollment token could admit more than one node. Fails *open* under the race (the second consume is not rejected).
- Proposed enforcement (review-only — do NOT apply): take an exclusive OS advisory lock (flock / `FileExt::lock_exclusive`, mirroring `resilience.rs::acquire_lock`) around the entire read-modify-write, OR move consumption to an atomic compare-and-set. Add the §6-mandated concurrent-consume race test (two threads/processes, assert exactly one success).
- Justification / source: SecurityMinimumBar §3.3/§6.C/§6; CWE-362 "Concurrent Execution using Shared Resource with Improper Synchronization" — https://cwe.mitre.org/data/definitions/362.html (accessed 2026-06-18).
- Verification method: concurrent-consume integration test asserting single redemption; `cargo test -p rustynetd enrollment`.
- Status: **applied** (2026-06-24). Added `enrollment_token::acquire_ledger_lock` (Unix: exclusive `flock(LOCK_EX)` on `<ledger>.lock`, auto-released on fd close incl. process death, mirroring `resilience.rs::acquire_lock`; non-Unix: O_EXCL lock file removed on drop). The daemon consume path (`daemon.rs` enrollment redeem) now holds the guard across the ENTIRE `load_ledger → verify_and_consume → register → write_ledger` sequence, so an interleaved second redemption re-loads under the lock, observes the recorded consume, and is rejected. Test `concurrent_consume_under_lock_redeems_token_exactly_once` (8 threads racing the same token → exactly 1 success, `consumed_count == 1`).

### RSA-0026 — `secret_log_audit` (the C6 "no secret logging" enforcement gate) has coverage gaps that produce false assurance
- File: `crates/rustynetd/src/secret_log_audit.rs:254-270` (forbidden type-name lists), `:41-57/132-167` (denylist + single-line scanners), `:71-76` (crate scope)
- Date: 2026-06-18 · Severity: **Medium**
- Bar mapping: SecurityMinimumBar §3.4 ("Secret redaction verified across MDM/env/CLI/API/UI"; never log secrets); `documents/operations/adr/ADR-001-secret-log-audit.md`; CWE-532.
- Reachability / attacker: not attacker-driven — this is an *assurance* defect in the control that is supposed to catch secret logging. Verified first-hand: `FORBIDDEN_DEBUG_SECRET_TYPES`/`FORBIDDEN_DISPLAY_SECRET_TYPES` list `PassphraseMaterial`, `WrappedKeyMaterial`, `RuntimePrivateKey`, `SigningKeyMaterial` — but grep shows **3 of the 4 do not exist anywhere in the workspace** (`WrappedKeyMaterial`/`RuntimePrivateKey`/`SigningKeyMaterial` = 0 definitions; only `PassphraseMaterial` exists). Meanwhile real secret-bearing types (`SecretKey`, `EnrollmentToken`, `RelaySessionToken`, `SignedTokenClaims`, `SessionToken`, `TokenClaims`) are **not** in the forbidden lists. Additionally (agent-reported, consistent with the code shape) the scanners are single-line only (multi-line `format!`/log calls evade detection) and scope is limited to `rustynetd` + `rustynet-cli`, excluding the secret-handling `control`/`relay`/`crypto` crates.
- Risk: the gate reports "no secret Debug/Display exposure" while guarding mostly phantom types and skipping the real ones — a `Debug`/`Display`/`format!` leak of an actual secret type would pass the gate. False confidence in a Critical (§3.4) control.
- Proposed enforcement (review-only — do NOT apply): enumerate the *real* secret-bearing types (derive the list from `#[derive(Zeroize)]`/`Zeroizing<_>` fields or a `#[secret]` marker), make scanners multi-line-aware, and extend coverage to `control`/`relay`/`crypto`. Add a self-test that fails if a known secret type is omitted from the forbidden list.
- Justification / source: SecurityMinimumBar §3.4; ADR-001; CWE-532 "Insertion of Sensitive Information into Log File" — https://cwe.mitre.org/data/definitions/532.html (accessed 2026-06-18).
- Verification method: a meta-test asserting every `Zeroizing`/zeroize-deriving type appears in the forbidden lists; `cargo test -p rustynetd secret_log`.
- Status: **open** (net-new, verified first-hand; 2026-06-18)

### RSA-0025 — Windows encrypted-key `.enc` backup is written with no file-level ACL hardening at write time
- File: `crates/rustynetd/src/key_material.rs:545-573` (write path; `:565`)
- Date: 2026-06-18 · Severity: **Medium** (re-confirms **AUDIT-027 / RN-33**; write-side complement to RSA-0002's read-side permission no-op)
- Bar mapping: SecurityMinimumBar §3.4 (encrypted-at-rest fallback with strict permissions), §5 (host-OS boundary); CWE-732.
- Reachability / attacker: on Windows the `.enc` fallback key file is created without applying a restrictive DACL at write time (the Unix path sets `0o600`; the Windows path relies on inherited ACLs). Combined with RSA-0002 (the read-side `validate_key_custody_permissions` no-op on non-unix), the encrypted-file fallback custody on Windows has neither a write-time ACL nor a startup ACL check. Mitigated: the blob is XChaCha20-Poly1305-sealed under an Argon2 passphrase, so this is an at-rest-permission gap, not plaintext key exposure; attacker = local non-admin user reading the `.enc` file (still needs the passphrase).
- Proposed enforcement (review-only — do NOT apply): apply an explicit SYSTEM/Administrators-only DACL (via `rustynet_windows_native`) at `.enc` creation, and verify it (closes the RSA-0002 read-side too). Fail closed if the ACL cannot be set.
- Justification / source: SecurityMinimumBar §3.4/§5; CWE-732 — https://cwe.mitre.org/data/definitions/732.html (accessed 2026-06-18). Re-confirms AUDIT-027/RN-33.
- Verification method: Windows test asserting the created `.enc` rejects non-admin read / has the expected DACL.
- Status: **open** (re-confirms AUDIT-027/RN-33; 2026-06-18)

### RSA-0031 — Exit-NAT teardown verification is fail-open: pfctl/forwarding-capture exec failure is reported as teardown-succeeded, masking residual exit NAT
- File: `crates/rustynetd/src/macos_exit_nat_lifecycle.rs:94-111,181-201`; `crates/rustynetd/src/windows_exit_nat_lifecycle.rs:58-72,118-120,172-183`
- Date: 2026-06-18 · Severity: **Medium** (touches a §6.D release-blocking control — NAT residue after revocation)
- Bar mapping: SecurityMinimumBar §6.D ctrl 7 ("Forwarding/NAT residue after revocation is a release-blocking defect"); CLAUDE.md §10.1 (fail-closed); CWE-636.
- Reachability / attacker: not attacker-driven. On macOS, `after_stop`'s NAT snapshot treats a `pfctl` spawn/exec **failure** as "anchor-absent ⇒ teardown succeeded"; on Windows, a failed/unknown forwarding-state capture counts as `forwarding_restored = true`. So if the verification command itself errors during exit-capability revocation, the daemon reports the NAT/forwarding was torn down when it could not actually confirm it — the RN-03 fail-open *class* applied to teardown verification.
- Risk: residual exit NAT/forwarding after `serves_exit` revocation could persist undetected (the bar calls this a release-blocking defect), because the proof-of-teardown silently passes on exec error.
- Proposed enforcement (review-only — do NOT apply): on macOS/Windows, a failed `pfctl`/forwarding-capture during teardown verification MUST return an error (fail closed), never `restored=true`/`anchor-absent`. Add a negative test injecting an exec failure and asserting the teardown is reported as *unverified*, not succeeded.
- Justification / source: SecurityMinimumBar §6.D ctrl 7; CLAUDE.md §10.1; CWE-636 "Not Failing Securely" — https://cwe.mitre.org/data/definitions/636.html (accessed 2026-06-18).
- Verification method: exec-failure injection tests on both OS NAT-lifecycle verifiers.
- Status: **applied** (2026-06-24). macOS: `capture_pf_anchor_state` exec failure now interpreted as anchor-PRESENT (`interpret_pf_anchor_capture`), `capture_sysctl_forwarding` returns `Option` (None on exec error → `"Unknown"` via `interpret_forwarding_capture`), and `parse_sysctl_forwarding` maps empty/malformed to `"Unknown"` (not `"Disabled"`). Windows: `Get-NetNat` capture failure now interpreted as NAT-PRESENT (`interpret_netnat_capture`), and `merge_windows_exit_nat_lifecycle_artifact` requires both forwarding flags to be an EXPLICIT `"Disabled"` (was the fail-open `!= "Enabled"`). Net effect: an unverifiable teardown capture reports the anchor/NAT as still present and forwarding NOT restored, so the validator fails the teardown stage instead of passing it. Tests added: `pf_anchor_capture_failure_fails_closed_as_present`, `forwarding_capture_failure_fails_closed_as_unknown`, `merge_artifact_does_not_report_teardown_when_forwarding_unverifiable` (macOS); `netnat_capture_failure_fails_closed_as_present`, `merge_artifact_does_not_report_teardown_on_unverifiable_forwarding`, `merge_artifact_does_not_report_teardown_when_nat_residue_present` (Windows). Merged-artifact schema unchanged (only fail-closed values differ), so the orchestrator-side validators are unaffected. Live-lab re-proof on macOS/Windows exit teardown still pending (human-only).

### RSA-0024 — `service_exposure` (§6.E tunnel-only-bind + default-deny + teardown-before-revoke) is correct and unit-tested but not wired into a production enforcement point
- File: `crates/rustynetd/src/service_exposure.rs:169-213,234-245,363-55x`
- Date: 2026-06-18 · Severity: **Question** (assurance-drift; `production_path: false`)
- Bar mapping: SecurityMinimumBar §6.E (E1 tunnel-only bind, E2 default-deny per-peer, E3 teardown-before-revoke); CLAUDE.md §4 (control needs an enforcement point AND a verification); CWE-1006.
- Reachability: the `ServiceExposureController` logic (tunnel-only bind validation, `evaluate_with_membership` default-deny, session severance before capability release, thumbprint-only audit) is implemented and unit-tested, but the agent found no production caller wiring it into the daemon's service lifecycle. The sibling `service_access_state.rs` *is* wired (default-deny grants confirmed), so the per-session enforcement may live there; this finding flags that the §6.E controller itself appears to be scaffold. Needs owner confirmation of whether `nas`/`llm` service hosting (D13) ships with this as the enforcement point.
- Proposed enforcement (review-only — do NOT apply): wire `ServiceExposureController` into the daemon's nas/llm service start/stop path, or document it as design-reference so the audit catalog does not over-claim §6.E enforcement.
- Justification / source: SecurityMinimumBar §6.E; CLAUDE.md §4; CWE-1006 — https://cwe.mitre.org/data/definitions/1006.html (accessed 2026-06-18).
- Verification method: confirm a production call path constructs/uses `ServiceExposureController`; otherwise reclassify as scaffold.
- Status: **open** (net-new, reachability/severity pending owner confirmation; 2026-06-18)
- Status update (2026-06-18, Batch 4): the same unwired pattern was found in `rustynet-llm-gateway/src/session.rs` — the §6.E E4 session-token verification (verify order exact, well-tested) is **never wired into the daemon binary** (dormant defence-in-depth). RSA-0024 now covers both §6.E enforcement modules (`service_exposure` controller + llm-gateway `session`): both are built+tested but not on a production enforcement path. Owner confirmation needed on whether D13 service-hosting ships with these wired.

### RSA-0034 — Gossip ingest applies state from any registered peer without re-checking current membership/revocation status
- File: `crates/rustynetd/src/gossip_runtime.rs:352-427` (`ingest_inbound_*`)
- Date: 2026-06-18 · Severity: **Question** (relates to the RSA-0007 revocation-blind class on the gossip path)
- Bar mapping: SecurityMinimumBar §3.6 (default-deny / revocation), §3.8 (gossip is signed but must not bypass trust state); CWE-285.
- Reachability: gossip ingest verifies Ed25519 signature + known-peer + monotonic-sequence + freshness, but (per the agent) does not re-check whether the source peer is *currently* `Active` vs `Revoked` before applying its gossiped state. A revoked-but-still-registered peer's gossip could be applied until the registry drops it. Distinct from the bundle-apply path (which the daemon-trust lens confirmed *does* re-check membership). Severity pending confirmation of whether the registry is pruned on revocation and what gossiped state can actually influence (endpoint hints vs trust).
- Proposed enforcement (review-only — do NOT apply): gate gossip ingest-apply on current `MembershipStatus::Active` for the source peer (consistent with the bundle-apply path); add a revoked-peer-gossip-ignored test.
- Justification / source: SecurityMinimumBar §3.6/§3.8; CWE-285 — https://cwe.mitre.org/data/definitions/285.html (accessed 2026-06-18).
- Verification method: confirm registry pruning on revocation + a revoked-peer gossip-rejection test.
- Status: **open** (net-new, Question; 2026-06-18)
- Status update (re-verification 2026-06-19): **Question → Info (downgraded).** First-hand: the gossip subsystem is **dormant in the shipped daemon** — `gossip_node` is `None` (`daemon.rs:3847`), the sole setter `attach_gossip_runtime` is `#[allow(dead_code)]` with no caller, and enrollment-consume fails closed when gossip is unattached. Even if wired, ingest applies **endpoint hints only** (`applied_endpoints`), not trust/policy — so a revoked-but-registered peer could at most inject stale connect-hints, not gain authorization. Reachability currently zero; fix before wiring gossip.

### RSA-0035 — uPnP follows the SSDP-supplied `LOCATION`/`controlURL` with no host-scope restriction (SSRF)
- File: `crates/rustynetd/src/port_mapper.rs:1855-1871,1331-1395,16xx`
- Date: 2026-06-18 · Severity: **Question** (SSRF to LAN; uPnP is inherently gateway-directed)
- Bar mapping: OWASP ASVS V5 (SSRF / URL validation); CWE-918.
- Reachability: the uPnP IGD flow follows the `LOCATION` URL and `controlURL` returned by an SSDP responder with no restriction that the host be the discovered gateway / on-link. A malicious SSDP responder on the LAN could point the daemon's HTTP client at an arbitrary host:port (SSRF). Bounded by: the daemon runs the request as itself on the LAN, body cap + CRLF-reject already exist (`fetcher`), and uPnP is opt-in. Attacker = a host on the same LAN spoofing SSDP.
- Proposed enforcement (review-only — do NOT apply): restrict the `LOCATION`/`controlURL` host to the SSDP responder's source IP (or the known default gateway) and to private/on-link address space; reject off-subnet/public targets.
- Justification / source: CWE-918 "Server-Side Request Forgery" — https://cwe.mitre.org/data/definitions/918.html (accessed 2026-06-18); OWASP ASVS 5.0 V5.
- Verification method: a test that an SSDP `LOCATION` pointing off-subnet/public is rejected.
- Status: **open** (net-new, Question; 2026-06-18)
- Status update (re-verification 2026-06-19): **Question → Info (downgraded).** First-hand: there is **no production enablement path** for uPnP — the daemon always builds the supervisor with `upnp_enabled: false` (`port_mapper.rs:2218`, `daemon.rs:5045`), both SSDP entry points are gated `if self.upnp_enabled` (`:2266/2275`), and `with_upnp_enabled` has **no caller** outside the crate. So `ssdp_discover_igd`/`discover_one` never run in the shipped binary. The SSRF (LOCATION/controlURL host followed with no on-link/responder-IP scope) is a **real latent defect to fix before uPnP ships**; current reachability is zero, attacker must be an on-link SSDP spoofer, and body-cap + CRLF-reject already exist.

### RSA-0027 — `ipc.rs` `validate_cidr` is character-set-only, not structural (re-confirms RN-N7)
- File: `crates/rustynetd/src/ipc.rs:272-282`
- Date: 2026-06-18 · Severity: **Low** (re-confirms **RN-N7**)
- Bar mapping: CLAUDE.md §10 (parse-then-validate at boundary); CWE-20. Reachability: `validate_cidr` checks only hex/dot/colon/slash chars + length, so `999.999.999.999/33` passes the pre-filter; the OS networking stack rejects it downstream, so this is a weak pre-filter, not a security gate. Proposed: parse with `ipnet` to validate structure before any privileged use. Source: RN-N7; CWE-20 — https://cwe.mitre.org/data/definitions/20.html (accessed 2026-06-18). Status: **applied** (2026-06-24) — `validate_cidr` now structurally parses `base` as `IpAddr` + a family-appropriate `prefix` (≤32 v4 / ≤128 v6), rejecting `999.999.999.999/33`, over-range prefixes, and missing/empty parts; test `cidr_validation_is_structural_not_just_charset`.

### RSA-0028 — No per-peer inbound gossip rate limit (re-confirms RN-N4)
- File: `crates/rustynetd/src/gossip_runtime.rs:321-427`, `crates/rustynetd/src/peer_gossip.rs`
- Date: 2026-06-18 · Severity: **Low** (re-confirms **RN-N4**)
- Bar mapping: SecurityMinimumBar High-control §1 (abuse detection); CWE-770. Reachability: inbound gossip has signature + freshness + monotonic-sequence + replay checks but no per-source token-bucket, so a single authenticated (enrolled) peer can flood forged/stale bundles and monopolize the per-iteration Ed25519-verify CPU budget. Bounded to authenticated peers. Proposed: token-bucket per source node (e.g. 10 bundles/s), drop above-limit before signature verification. Source: RN-N4; CWE-770 — https://cwe.mitre.org/data/definitions/770.html (accessed 2026-06-18). Status: **open** (re-confirms RN-N4; 2026-06-18)

### RSA-0029 — Traversal coordination replay window is in-memory only; 24h TTL allows post-restart replay of a captured coordination record
- File: `crates/rustynetd/src/traversal.rs:765-766,837-856,1231-12xx`
- Date: 2026-06-18 · Severity: **Low**
- Bar mapping: SecurityMinimumBar §3.8 (traversal endpoint-hint state must be replay-protected, freshness-bounded — N3); CWE-294. Reachability: the coordination-record replay cache is in-memory; on daemon restart it is empty, so a coordination record captured before restart can be replayed within its (up to 24h) TTL. Endpoint-hint records are signed + freshness-bounded, so impact is bounded to re-presenting a still-valid signed hint after restart. Proposed: persist the replay watermark/seen-set across restart (mirror the membership/fetcher watermark spool) and/or shorten the coordination TTL. Source: SecurityMinimumBar §3.8; CWE-294 — https://cwe.mitre.org/data/definitions/294.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0030 — RN-09 systemd-credential group-read mask (`0o037`) has no negative test (asserted-but-unverified)
- File: `crates/rustynetd/src/key_material.rs:596-648,755-757`
- Date: 2026-06-18 · Severity: **Low** (test-gap on the open **RN-09**)
- Bar mapping: SecurityMinimumBar §3.4 (startup permission checks); CLAUDE.md §10.8 (every control needs a negative test). Reachability: the credential-permission check uses a wider `0o037` mask for the `/run/credentials/` prefix (the RN-09 concern) and there is no negative test proving a group-readable credential is rejected (or that the wider mask is gated by verified systemd-tmpfs parentage). Proposed: add the parent-ownership/tmpfs verification RN-09 calls for, plus a negative test for a group-readable credential. Source: RN-09; SecurityMinimumBar §3.4; CLAUDE.md §10.8. Status: **WITHDRAWN — false-positive (re-verified first-hand 2026-06-19).** The claimed-missing controls **exist**: `key_material.rs:628-658` gates the wider `0o037` mask on parent-dir verification (root-or-owner-owned via `parent_uid == 0 || effective`, rejects world-access + group-write via `parent_mode & 0o027 != 0`, symlink-rejected, systemd-tmpfs rationale documented at `:636-646`), and the negative test (`world-/group-write parent rejected`) is at `:1418-1468` — both added by commit `1525cae` (2026-06-18). The RN-09 wider-mask concern is mitigated, not an open test-gap. (2026-06-19)

### RSA-0032 — `macos_utun_helper_unsafe` unsafe blocks lack `// SAFETY:` invariant comments
- File: `crates/rustynetd/src/macos_utun_helper_unsafe.rs:96,188,198-211,235,250,2xx`
- Date: 2026-06-18 · Severity: **Low**
- Bar mapping: CLAUDE.md §10.2 / ANSSI Secure Rust (E2: every `unsafe` block minimal + `// SAFETY:` proving the invariant); CWE-1006. Reachability: this file holds the only `unsafe` in `rustynetd/src` (the documented RN-14 exception). The buffers are bounded and `MSG_CTRUNC`/truncated-cmsg is handled (positive), but the individual `unsafe` blocks lack the mandated `// SAFETY:` comments justifying each invariant — an E2 rigor/auditability gap. Proposed: add a `// SAFETY:` comment to each `unsafe` block; run Miri on the module where feasible. Source: ANSSI Secure Rust Guidelines — https://anssi-fr.github.io/rust-guide/ ; CLAUDE.md §10.2 (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0033 — Privileged-helper `kill` builtin permits SIGTERM to any pid > 1, not scoped to rustynet-owned processes
- File: `crates/rustynetd/src/privileged_helper.rs:1841-1846` (`validate_kill_args`)
- Date: 2026-06-18 · Severity: **Low** (least-privilege; bounded by the helper's peer-cred allowlist)
- Bar mapping: SecurityMinimumBar §3.7 (privileged-boundary hardening, least privilege); CWE-250. Reachability: verified — `validate_kill_args` accepts `["-TERM", pid]` for any `pid > 1`, so an IPC client that passes the helper's RN-17 peer-credential check can have the root helper `SIGTERM` *any* process. If the authorized caller is non-root (the rustynet service uid), this widens its capability to terminate arbitrary processes (incl. other users'/root) → local DoS / privilege widening. Bounded because the caller must already be on the peer-cred allowlist. Proposed: scope the kill to PIDs the daemon spawned/owns (track child PIDs), reject others. Source: CWE-250 "Execution with Unnecessary Privileges" — https://cwe.mitre.org/data/definitions/250.html (accessed 2026-06-18); SecurityMinimumBar §3.7. Status: **open** (net-new, verified first-hand; 2026-06-18)

### RSA-0036 — Windows Authenticode thumbprint extractor is a permanent stub (thumbprint-pinned policy can never pass)
- File: `crates/rustynetd/src/windows_authenticode.rs:358-371`
- Date: 2026-06-18 · Severity: **Info** (fails closed — non-functional feature, not a weakening)
- Bar mapping: SecurityMinimumBar §10 (signed-artifact verification); CWE-1006. Reachability: the thumbprint extractor returns a stub even on Windows, so any policy that pins to a certificate thumbprint can never be satisfied — fail-closed (the verification denies rather than accepts). The concern is a non-functional control presented as available. Proposed: implement the extractor or document the stub as intentionally fail-closed so callers do not rely on thumbprint pinning. Source: net-new; SecurityMinimumBar §10. Status: **open** (net-new; 2026-06-18)

---

## Findings Log — Batch 3 (Tier 2: backends + relay + dns-zone, 7-agent fan-out 2026-06-18)

> 7 read-only agents swept all 31 files. **Verdict: 0 Critical / 0 High; 1 Medium.**
> Load-bearing items re-verified first-hand (relay `HelloLimiter` unbounded map,
> Windows backend `Debug` private-key leak, dns-zone plain `verify`).
>
> **Positive controls confirmed:** every userspace WireGuard backend delegates
> per-packet crypto to vendored **boringtun — no custom crypto**; key material is
> `Zeroizing`+zeroized with redacting `Debug` (except RSA-0039); all command
> adapters are **argv-only** (no shell) with iface/CIDR/endpoint validation; the
> `Backend`/`TunnelBackend` trait is transport-agnostic (no boringtun type leak,
> V2 clean); stub/in-memory backends are test-only and the daemon fail-closes
> rather than using them in production. **Relay (public pre-auth surface):** the
> 12-step ordered hello check (rate-limit→sig→TTL→freshness→replay→`ct_eq`
> bindings→scope→capacity), `verify_strict`, durable replay store, `OsRng`
> session ids (fail-closed), and **AUDIT-031 pre-auth DoS mitigations** (per-IP
> 50/s limiter, 4096-IP cap, serial control loop) are present and effective —
> the residual is the documented design ceiling **plus RSA-0037** below.

### RSA-0037 — Relay `HelloLimiter` per-`node_id` map is never pruned or capped → unauthenticated remote memory-exhaustion DoS
- File: `crates/rustynet-relay/src/transport.rs:1005-1034` (`HelloLimiter`), validation order at `:330-345`
- Date: 2026-06-18 · Severity: **Medium** (remote, pre-auth, public-internet surface; reconciles the **AUDIT-031** pre-auth-DoS theme — a residual the per-IP limiter does not cover)
- Bar mapping: SecurityMinimumBar §4.7 (relay abuse/capacity controls under churn), High-control §1 (abuse detection); CWE-770 / CWE-400.
- Reachability / attacker: verified first-hand — `HelloLimiter::check` does `self.counts.entry(node_id.to_owned()).or_insert(...)` keyed on the **attacker-controlled `node_id`**, and is invoked as validation Check 1 **before** the Ed25519 signature check. The map `counts: HashMap<String,(u32,Instant)>` is never pruned or size-capped (contrast `rate_limit.rs::retain_active_nodes`, which prunes per-node token buckets, and `PreAuthHelloLimiter::prune`, which prunes the per-IP table). The per-IP `PreAuthHelloLimiter` (50 hellos/IP/s, 4096-IP cap) bounds *IP* cardinality but not *node_id* cardinality: a pre-auth attacker rotating `node_id` strings can insert ~50 new entries/s/IP × 4096 IPs ≈ 2×10⁵ permanent entries/s, growing the map without bound. Attacker = remote unauthenticated peer(s) hitting the public relay.
- Risk: unbounded relay memory growth → OOM / availability loss of the relay (which brokers traffic for the mesh). No auth required.
- Proposed enforcement (review-only — do NOT apply): prune `counts` on the `cleanup_idle_sessions` cadence (drop entries whose 1s window elapsed, mirroring `PreAuthHelloLimiter::prune`) AND hard-cap `counts.len()`, rejecting new node_ids above the cap. Add a test asserting bounded map size under a flood of distinct node_ids.
- Justification / source: SecurityMinimumBar §4.7; CWE-770 "Allocation of Resources Without Limits or Throttling" — https://cwe.mitre.org/data/definitions/770.html (accessed 2026-06-18). Reconciles AUDIT-031 (residual).
- Verification method: flood test (distinct node_ids) asserting `counts.len()` stays bounded; `cargo test -p rustynet-relay`.
- Status: **applied** (2026-06-24). `HelloLimiter` now carries `max_entries = MAX_HELLO_LIMITER_ENTRIES` (16384): when a NEW node_id arrives at capacity the limiter prunes elapsed-window entries (`prune_elapsed`) and, if still full, rejects the new node_id (fail closed — never allocated above the cap). `cleanup_idle_sessions` also calls `prune_elapsed` on its cadence (mirroring `PreAuthHelloLimiter::prune` / `retain_active_nodes`). Tests: `hello_limiter_caps_distinct_node_ids_under_flood`, `hello_limiter_prune_drops_elapsed_windows`. Existing tracked node_ids are never rejected on the cap path, so no false-reject of an in-window peer.

### RSA-0039 — `WindowsWireguardBackend` derives `Debug` while holding the live runtime private key → `{:?}` leaks the key
- File: `crates/rustynet-backend-wireguard/src/windows_command.rs:25` (`#[derive(Debug)]`), `:38` (`runtime_private_key: Option<Zeroizing<String>>`)
- Date: 2026-06-18 · Severity: **Low** (defense-in-depth — requires a future caller to Debug-log the backend; `Zeroizing` zeroizes on drop but its `Debug` forwards to the inner `String`)
- Bar mapping: SecurityMinimumBar §3.4 (never log private key material); CLAUDE.md §10.6; CWE-532.
- Reachability / attacker: verified — the struct derives `Debug` and holds the daemon-decrypted plaintext WireGuard private key in `Zeroizing<String>`; `Zeroizing`'s `Debug` is transparent, so `format!("{:?}", backend)` (e.g. tracing the backend on an error path) writes the plaintext key to logs. The userspace `engine.rs` correctly redacts its key in `Debug`; this Windows backend is the outlier.
- Proposed enforcement (review-only — do NOT apply): hand-write a `Debug` impl that prints `runtime_private_key` as `Some(<redacted>)`/`None`; add a unit test asserting the formatted backend never contains the key bytes.
- Justification / source: SecurityMinimumBar §3.4; CLAUDE.md §10.6; CWE-532 — https://cwe.mitre.org/data/definitions/532.html (accessed 2026-06-18).
- Verification method: a test that `format!("{:?}", backend)` excludes the key; `cargo test -p rustynet-backend-wireguard`.
- Status: **open** (net-new, verified first-hand; 2026-06-18)

### RSA-0043 — `dns-zone` bundle signature uses plain ed25519 `verify()`, not `verify_strict` (the sole divergence from the repo's RN-22 malleability standard)
- File: `crates/rustynet-dns-zone/src/lib.rs:284-285` (`verifying_key.verify(...)`)
- Date: 2026-06-18 · Severity: **Low** (signature malleability without payload forgery; consistency regression vs the repo-wide RN-22/RL-3 `verify_strict` standard)
- Bar mapping: SecurityMinimumBar §3.1 (proven crypto, no malleability); CWE-347. Reconciles the **RN-22** standard.
- Reachability / attacker: verified — `verify_signed_dns_zone_bundle` calls `verifying_key.verify(...)`, while `rustynet-control` (`lib.rs:1575/3160/3313`, `membership.rs:1022/1116`) and `rustynet-crypto` (`lib.rs:1174`) all use `verify_strict`, which rejects non-canonical S and small-order/torsion components. Plain `verify` accepts malleable signature encodings of the *same* signed payload — no payload forgery (the signature still binds the payload), so impact is limited to alternate-encoding acceptance; it matters only if bundle signature bytes are ever used as a replay/dedup key.
- Proposed enforcement (review-only — do NOT apply): replace `verify` with `verify_strict` (matching the rest of the repo); add a negative test that a malleated/non-canonical signature is rejected.
- Justification / source: RN-22/RL-3 (repo standard); CWE-347 "Improper Verification of Cryptographic Signature" — https://cwe.mitre.org/data/definitions/347.html (accessed 2026-06-18); WireGuard/Ed25519 RFC 8032 strict verification.
- Verification method: malleated-signature negative test; `cargo test -p rustynet-dns-zone`.
- Status: **open** (net-new, verified first-hand; 2026-06-18)
- Status update (verification-bypass sweep 2026-06-20): **scope correction** — this entry's "the sole divergence" claim was WRONG. A repo-wide map of `verify` vs `verify_strict` shows dns-zone is **one of 14** plain-`verify` sites; `verify_strict` is applied only in `control`+`crypto` (10 sites), and the *entire* daemon/llm/cli trust-verification surface uses plain `verify`. Generalized into **RSA-0077** (the systemic finding); fix dns-zone as part of that RN-22-completion migration.

### RSA-0041 — Relay control-plane `reject` reply is a UDP reflection/amplification primitive
- File: `crates/rustynet-relay/src/main.rs:430-435,452-456` (`serialize_relay_reject` to `from_addr`)
- Date: 2026-06-18 · Severity: **Low** (low amplification factor ~9×; bounded by the same per-IP limiter)
- Bar mapping: OWASP/CWE-406 (amplification); SecurityMinimumBar §4.7. Reachability: on the rate-limited and validation-failure paths the relay sends a ~9-byte reject to the (UDP-spoofable) `from_addr`. A spoofing attacker can use the relay as a low-factor reflector against a third party; sustained volume to one victim is bounded by the `PreAuthHelloLimiter`. Proposed: drop silently on the pre-auth-rate-limited path (as the dataplane does), or only reply after at least one field authenticates; keep replies ≤ request size. Source: CWE-406 "Insufficient Control of Network Message Volume" — https://cwe.mitre.org/data/definitions/406.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0040 — No cargo-fuzz target for the relay hello/token wire parsers + hello validation state machine (re-confirms RN-N6)
- File: `crates/rustynet-relay/src/main.rs:669-827` (`parse_relay_hello`/`parse_relay_token`), `crates/rustynet-relay/src/transport.rs:330-436` (`validate_hello` state machine)
- Date: 2026-06-18 · Severity: **Low** (re-confirms **RN-N6**)
- Bar mapping: SecurityMinimumBar §6 Required Evidence (hostile-input parser coverage); CLAUDE.md §10.8. Reachability: these decode untrusted UDP bytes on the public-internet pre-auth surface; all length reads are bounds-checked under current review (no panic/over-read found), but there is no continuous fuzzing, so a future refactor could reintroduce a panic/over-read undetected. Proposed: add cargo-fuzz targets for `parse_relay_hello`, `parse_relay_token`, and the `validate_hello` state machine; run ≥1h/commit in CI. Source: RN-N6; SecurityMinimumBar §6. Status: **open** (re-confirms RN-N6; 2026-06-18)

### RSA-0038 — No cargo-fuzz target for the userspace WireGuard inbound-ciphertext / plaintext / allowed-ip framing wrappers
- File: `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs:238-339,569-601`
- Date: 2026-06-18 · Severity: **Low** (RN-N6 class)
- Bar mapping: SecurityMinimumBar §6 (hostile-input parser coverage); CLAUDE.md §10.8. Reachability: `process_inbound_ciphertext`/`inject_plaintext_packet`/`AllowedIpNetwork::parse` are the thin Rust framing wrappers around boringtun decapsulate/encapsulate; they have unit+negative tests but no fuzz target (workspace `fuzz/` has only ipc + membership targets). Attacker-controlled wire bytes from a configured peer endpoint reach these wrappers. Proposed: add a cargo-fuzz target driving the wrappers over arbitrary byte slices against a fixed two-peer engine, asserting no panic. Source: RN-N6 class; SecurityMinimumBar §6. Status: **open** (net-new; 2026-06-18)

### RSA-0042 — No cargo-fuzz target for `parse_signed_dns_zone_bundle_wire` (untrusted-bundle parser)
- File: `crates/rustynet-dns-zone/src/lib.rs:290-511`
- Date: 2026-06-18 · Severity: **Low** (RN-N6 class)
- Bar mapping: SecurityMinimumBar §6; CLAUDE.md §10.8. Reachability: parses attacker-influenced signed-bundle bytes (256KB/16K-line/1024-record bounded); no fuzz target exists (only ipc + membership targets in `fuzz/`). Structured-output reconstruction (`split_once`, `record_count*8+8` field arithmetic) is asserted by unit tests only. Proposed: add `fuzz/fuzz_targets/dns_zone_parse_bundle.rs` over arbitrary `&str`, asserting no panic + bounded work. Source: RN-N6 class; SecurityMinimumBar §6. Status: **open** (net-new; 2026-06-18)

### RSA-0044 — Linux WireGuard `configure_peer`/`update_peer_endpoint` skip the zero-port/unspecified endpoint validation macOS enforces
- File: `crates/rustynet-backend-wireguard/src/linux_command.rs:351-406` (vs `macos_command.rs:119-141` `validate_peer_endpoint`)
- Date: 2026-06-18 · Severity: **Info** (no security boundary crossed — `wg` errors/no-ops on a bad endpoint; inconsistent error surface only)
- Bar mapping: CLAUDE.md §10 (parse-then-reject parity); CWE-20. Reachability: Linux formats `{addr}:{port}` into `wg set ... endpoint` without the non-zero-port / not-unspecified/multicast/broadcast checks the macOS backend applies. A caller-supplied `0.0.0.0:0` reaches `wg` on Linux where macOS rejects it; impact is an inconsistent error surface, not a security gap. Proposed: factor `validate_peer_endpoint` into a shared module and call it from the Linux paths; add a parity negative test. Source: CLAUDE.md §10; CWE-20. Status: **open** (net-new; 2026-06-18)

### RSA-0045 — B.4.1 resolver-output RFC1918 answer filter is not enforced (by design in dns-zone; still pending in the daemon DNS responder)
- File: daemon DNS responder (carry) — `dns-zone/src/lib.rs:655-710` documents the intentional scoping; the filter belongs in the daemon protocol-level resolver
- Date: 2026-06-18 · Severity: **Question** (carry of the known **B.4.1** backlog item; not a defect in `rustynet-dns-zone`)
- Bar mapping: SecurityMinimumBar §3.8 (DNS leak prevention); CWE-350. Reachability: `parse_expected_ip` deliberately permits RFC1918 (10/8, 172.16/12, 192.168/16) at the zone-bundle layer (documented universally-true-invariants-only posture), rejecting only loopback/link-local/RFC5737. The B.4.1 control — rejecting RFC1918 *resolver answers* for tailnet-internal names (DNS-rebinding-style protection) — is a resolver-output concern that must live in the daemon's loopback DNS responder, not this crate. Confirm whether the daemon resolver enforces it; if not, B.4.1 remains open there. Proposed: no change in `rustynet-dns-zone`; track B.4.1 against the daemon DNS responder. Source: B.4.1 (`SecurityAnalysis_2026-06-12.md §5`); CWE-350 — https://cwe.mitre.org/data/definitions/350.html (accessed 2026-06-18). Status: **open** (carry to daemon resolver; 2026-06-18)

---

## Findings Log — Batch 4 (Tier 3 service surfaces + CLI security core, 12-agent fan-out 2026-06-18)

> 12 read-only agents swept 32 files. Agents proposed 2 High; **first-hand
> verification downgraded both to Medium** (see RSA-0046 reasoning + the RSA-0008
> status update). Net: 0 Critical / 0 High new.
>
> **Headline positive — AUDIT-006 is REMEDIATED:** `rustynet-mcp/bin/lab_state.rs`
> now routes every caller-supplied path through `confined_repo_path` (lexical `..`
> strip → canonicalize → `starts_with(repo_root)` → symlink-escape check); the
> prior arbitrary-host read/delete is closed. **Other positives:** all three MCP
> binaries are argv-only exec with path-confinement; `gate_runner` blocks cargo-RCE
> flags; **NAS** at-rest AEAD with location-binding AAD + per-peer namespace
> confinement + cross-namespace-replay-refused tests + tunnel-only bind; **LLM
> gateway** identity-from-tunnel (no API key), loopback-only engine, E4 token verify
> order exact (sig→window→audience→peer→current policy), length-bounded framing;
> **windows-native** Win32 FFI unsafe all check GetLastError + fail closed, SDDL
> from static policy + OS SID, no secret logging — DPAPI backend is sound (underpins
> RSA-0002/0025); cli `main.rs` binary-path validation + argv-only + passphrase-by-file
> + OsRng all PASS.

### RSA-0046 — `rustynet-sysinfo` builds `powershell -NoProfile -Command` scripts by single-quote-interpolating untrusted path/host (Windows command-injection sink)
- File: `crates/rustynet-sysinfo/src/lib.rs:4903` (cert path), `:5200` (TLS host), `:6265/6273` (dir-size path)
- Date: 2026-06-18 · Severity: **Medium** (operator-CLI reachability today — self-injection, no privilege gain; rated Medium as a CWE-78 sink that violates the project's explicit argv-only/no-`-Command`-interpolation control and sits one caller away from an untrusted boundary). **Downgraded from the agents' High** after reachability tracing.
- Bar mapping: SecurityMinimumBar §3.7 (no shell construction with untrusted values; argv-only); CLAUDE.md §4; CWE-78. Same class as the DnsFailclosed lesson (NRPT moved to `reg.exe` argv precisely because `powershell -Command "script"` is unsafe param-binding for metacharacter values).
- Reachability / attacker: verified first-hand — four Windows fns wrap an untrusted string in PowerShell single quotes (`'{}'`); a `'` in the input terminates the quoted string (PowerShell escapes `'` by doubling, not `\`), so input like `'; <cmd>; '` executes arbitrary PowerShell. Tracing callers: these fns are reached ONLY via `rustynet-cli/main.rs:16714/16786` (`execute_tls_cert_expiry`/cipher), whose `path`/`host` are **operator-supplied CLI args** — sysinfo is not exposed via any MCP tool (grep-confirmed), so the agent's MCP/untrusted vector does not exist. Today this is operator self-injection on their own host (no privilege boundary crossed). The risk is the latent escalation: a future caller (config-sourced path, orchestrator, scheduled job, or new untrusted input) turns this into RCE, and it already violates a stated control on shipped Windows code.
- Risk: CWE-78 command execution if any untrusted value ever reaches these diagnostics; today bounded to operator self-injection.
- Proposed enforcement (review-only — do NOT apply): replace `-Command` string interpolation with argv/typed invocation — pass the path/host via a parameterized PowerShell `-File` script with `param()` binding, or use a native Rust API (e.g. read the cert via `schannel`/`windows-sys`), so no untrusted value is concatenated into a script. Mirror the DnsFailclosed `reg.exe`-argv remediation pattern.
- Justification / source: CLAUDE.md §4 / SecurityMinimumBar §3.7 (argv-only, no untrusted shell construction); CWE-78 "OS Command Injection" — https://cwe.mitre.org/data/definitions/78.html (accessed 2026-06-18).
- Verification method: a test that a path/host containing `'` is rejected or safely parameterized (no injected execution); `cargo test -p rustynet-sysinfo` (note: this crate currently has zero tests — see RSA-0050).
- Status: **open** (net-new, verified first-hand; severity adjusted from agent High; 2026-06-18)

### RSA-0047 — MCP server reads JSON-RPC requests with unbounded `BufRead::lines()` → memory-exhaustion DoS
- File: `crates/rustynet-mcp/src/lib.rs:706-727` (`run_server`)
- Date: 2026-06-18 · Severity: **Medium** (the MCP server runs with the developer/host's full privileges; a single oversized line OOM-kills it)
- Bar mapping: SecurityMinimumBar §6 (bounded input); CWE-770. Reachability: `run_server` does `for line in BufReader::new(stdin.lock()).lines()`, which buffers an entire line into a `String` with no size cap before any parse/truncation (the output side is capped, the input side is not). A malicious or buggy MCP client driving the server over stdio can send an arbitrarily large line and exhaust host memory. The MCP servers are agent-facing tools running with full host privilege.
- Proposed enforcement (review-only — do NOT apply): replace `.lines()` with a bounded `read_line`/`take(MAX)` loop that rejects (or errors) on a line exceeding a sane cap (e.g. a few MB) before buffering.
- Justification / source: CWE-770 "Allocation of Resources Without Limits or Throttling" — https://cwe.mitre.org/data/definitions/770.html (accessed 2026-06-18); SecurityMinimumBar §6.
- Verification method: a test feeding an oversized line and asserting bounded memory / rejection.
- Status: **applied** (2026-06-24). `run_server` replaced unbounded `BufRead::lines()` with `read_bounded_line` (cap `MAX_MCP_REQUEST_LINE_BYTES` = 4 MiB): an over-cap line is reported `TooLong` (JSON-RPC parse error to the client) and the rest of the line is STREAM-drained to the next newline (never buffered) so the stream resyncs. Tests: `read_bounded_line_rejects_oversized_then_resyncs`, `read_bounded_line_oversized_unterminated_is_too_long_then_eof`, `read_bounded_line_accumulates_across_small_chunks`, `read_bounded_line_reads_lines_then_eof`.

### RSA-0048 — LLM gateway accepts TCP connections with no read/write timeout (slowloris DoS; per-connection thread)
- File: `crates/rustynet-llm-gateway/src/main.rs:71-89,296-312`
- Date: 2026-06-18 · Severity: **Low** (intra-mesh: attacker must be an enrolled, policy-allowed peer)
- Bar mapping: SecurityMinimumBar High-control §1 (abuse); CWE-400. Reachability: accepted streams get no `set_read_timeout`/`set_write_timeout`, and each connection is handled on its own thread, so a slow/idle peer can hold connections/threads open indefinitely (slowloris-style resource exhaustion). Bounded because the LLM service is tunnel-only and default-deny, so the attacker must already be an authorized peer. Proposed: set read/write timeouts on accepted streams and cap concurrent connections. Source: CWE-400 "Uncontrolled Resource Consumption" — https://cwe.mitre.org/data/definitions/400.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0049 — `security_audit_catalog` marks controls `covered` whose production enforcement point is unwired (assurance over-claim feeding an ops report)
- File: `crates/rustynet-cli/src/security_audit_catalog.rs:740-753,832-848,916-943`
- Date: 2026-06-18 · Severity: **Low** (`production_path: false` — reporting integrity, not a runtime vuln; reconciles the **RSA-0018** assurance-drift theme)
- Bar mapping: CLAUDE.md §4 (a control needs an enforcement point AND a verification); CWE-1006/CWE-684. Reachability: `COMPARATIVE_CATALOG` entries assert `coverage_status:'covered'` backed only by `command_keys` pointing at unit tests (e.g. route-hijack/protocol-filter TS-2024-005/TS-2025-006, the NetBird/OpenVPN privileged-helper rows), and the catalog drives `execute_ops_generate_comparative_exploit_coverage`. So an operator-facing coverage report renders "covered" for control classes whose enforcement is scaffold-only (cf. RSA-0018 admin.rs, RSA-0024 service_exposure). Proposed: gate `covered` on a wired production enforcement point, not a test-only `command_key`; surface "test-only" as a distinct status. Source: CLAUDE.md §4; CWE-684 "Incorrect Provision of Specified Functionality" — https://cwe.mitre.org/data/definitions/684.html (accessed 2026-06-18). Status: **open** (net-new, RSA-0018 theme; 2026-06-18)

### RSA-0050 — `rustynet-sysinfo` arp/tcp parsers have off-by-one slice-index panics on malformed system-command output (and the crate has zero tests)
- File: `crates/rustynet-sysinfo/src/lib.rs:4576-4580` (ARP: guard `>=5`, indexes `parts[5]`), `:3801-3808` (macOS TCP: guard `<4`, indexes `fields[4]/[5]`)
- Date: 2026-06-18 · Severity: **Low** (panic/DoS on unexpected `arp`/`netstat` output; not attacker-controlled in normal operation)
- Bar mapping: CLAUDE.md §10.2 (no panic on production paths); CWE-125 (out-of-bounds read → panic). Reachability: the ARP parser guards `parts.len() >= 5` then indexes `parts[5]` (needs ≥6); the macOS TCP parser guards `< 4` then indexes `fields[4]`/`fields[5]` (needs ≥6) — both panic on output with exactly the boundary field count. Triggered by unexpected OS-tool output (locale/format variation), a local DoS of the sysinfo diagnostic. The crate has no tests (T1/T2 gap). Proposed: use `.get(n)` with fail-soft handling; add parser unit tests with malformed fixtures. Source: CLAUDE.md §10.2; CWE-125 — https://cwe.mitre.org/data/definitions/125.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0051 — `ops_e2e` passes a plist-extracted `network_id` to bash without `ensure_safe_token`
- File: `crates/rustynet-cli/src/ops_e2e.rs:810,840,856`
- Date: 2026-06-18 · Severity: **Low** (lab/e2e orchestration; value is plist-extracted, not directly remote — shell-hygiene gap)
- Bar mapping: SecurityMinimumBar §3.7 (no untrusted shell construction); CWE-78. Reachability: the macOS enforce path interpolates a `network_id` read from a plist into a bash invocation without the crate's own `ensure_safe_token` sanitizer (applied elsewhere). If the plist content is attacker-influenced (a compromised lab guest), this is a shell-injection vector on the orchestrating host. Bounded to the lab/e2e flow. Proposed: run `ensure_safe_token(network_id)` before any shell use (consistent with the crate's other call sites), or pass via argv. Source: SecurityMinimumBar §3.7; CWE-78 — https://cwe.mitre.org/data/definitions/78.html (accessed 2026-06-18). Status: **WITHDRAWN — false-positive (re-verified first-hand 2026-06-19).** The stated "shell-injection" mechanism does not exist: `run_status` (`ops_e2e.rs:5042-5049`) is `Command::new(program).args(args)` — `network_id` is passed as a **discrete argv element** to `/bin/bash <script> --network-id <value>` (positional `$2`), not concatenated into a shell command line, so there is no shell to inject into at the Rust boundary; the consuming script additionally re-validates via `case`. (No residual injection; if anything an Info "value not shape-validated as a positional arg.") (2026-06-19)

---

## Findings Log — Batch 5 (rustynet-cli orchestrator/lab/e2e bulk, multi-agent fan-out 2026-06-18)

> **Partial batch: 8/11 agents completed; 3 hit the provider session limit** and
> their scope remains `pending` (see resume pointer): orchestrator `stage/` +
> `role_validation/` + `plan`/`factory`; `bin/live_lab_support` + `live_lab_bin_support`
> + `real_wireguard_*` + `live_chaos_*`; `bin/collect_*` + `phase*_gates` + misc `bin/`.
> Of the 66 files covered: 0 Critical / 0 High. Positives: the systemd/launchd
> installers (`ops_install_*`) are argv-only with hardcoded reviewed dests + atomic
> `0o600`/`0o644` writes + HB-1 secure-scrub cleanup + `0o600` key perms + fail-closed
> SSH-allow; `ops_phase9` zeroizes the provenance signing seed; `ops_live_lab_orchestrator`
> redacts PRIVATE KEY/passphrase/token from forensics. Two folded Info notes (not
> RSA-numbered): `vm_lab/bootstrap/windows.rs:2031/2157` guarded `.expect()` in a
> non-test path (invariant locally provable — acceptable, recommend `?`); orchestrator
> `ssh.rs:318-337` `wait_for_remote_socket` interpolates `socket_path` unquoted into
> `test -S` (currently **dead code** — fix or delete before wiring).

### RSA-0052 — Overnight driver's live path runs destructive git ops + agent auto-commits with an ineffective branch-isolation guard
- File: `crates/rustynet-cli/src/vm_lab/overnight/mod.rs:200-232`, `crates/rustynet-cli/src/vm_lab/overnight/executor.rs` (live execute path)
- Date: 2026-06-18 · Severity: **Medium → Low** (re-verified 2026-06-19 — downgraded; see status update). Re-confirms **AUDIT-017/018/019**; destructive lab automation; LiveExecutor implemented but never run per project memory.
- Bar mapping: CLAUDE.md §3 (fail-closed; one hardened path), SecurityMinimumBar §9 (don't commit generated artifacts/secrets); CWE-77/CWE-78.
- Reachability / attacker: not attacker-driven — operator-run automation. The live path (no `--dry-run`) generates `branch = overnight_branch_name(...)` then calls `assert_safe_target_branch(&branch)` — but that guard only inspects the freshly-generated *name string*; there is no `git checkout` to a dedicated isolated branch, so the per-work-unit agent's auto-commits land on whatever branch the live checkout is currently on (potentially `main`). Combined with RSA-0053, each no-progress unit also wipes untracked files. The OvernightAutonomousBugHunt design explicitly requires a dedicated `overnight/<date>` branch never `main`/pushed — the implementation's guard does not enforce that at the git level.
- Risk: an unattended overnight run could commit agent-generated changes to `main` (or the active branch) and destroy untracked working-tree state, on a security-sensitive repo, without a human in the loop.
- Proposed enforcement (review-only — do NOT apply): before any work-unit, actually `git checkout -B overnight/<date>` (verify `git rev-parse --abbrev-ref HEAD` matches and is never `main`) and refuse to proceed otherwise; default to `--dry-run`; never `git push`. Add a test asserting the live path aborts when the active branch is `main`/unexpected.
- Justification / source: CLAUDE.md §3/§10; AUDIT-017/018/019 (`SecurityAndQualityAudit_2026-06-10.md`); CWE-77 "Command Injection (argument)" — https://cwe.mitre.org/data/definitions/77.html (accessed 2026-06-18).
- Verification method: branch-isolation unit test (active branch = `main` ⇒ abort); dry-run-default test.
- Status: **open** (re-confirms AUDIT-017/018/019; 2026-06-18)
- Status update (re-verification 2026-06-19): **downgraded Medium → Low.** First-hand re-read shows the safety envelope the original framing called missing is substantially present, so "auto-commits to main, no isolation" over-stated it: `run_overnight` short-circuits on `dry_run` (`mod.rs:194` — dry-run is the safe default path); `assert_safe_target_branch` **fail-closed refuses `main`/`master`/`release`/`production`/`prod`** (`safety.rs:86-99`, unit-tested); `classify_touched_paths` is **fail-closed** (denylisted crypto/control/policy/local-security/dns-zone crates AND an empty/unknown path-set ⇒ `NeedsAdversarialReview`, never auto-committed — `safety.rs:63-82`); and the executor **never `git push`** (commits stay local) and reverts both security-sensitive (`executor.rs:113-114`) and uncommitted (`:146-147`) residue. The **valid residual (Low)** is the narrower one this entry already identified: nothing enforces that the **active git checkout** is the isolated branch (only the name string is validated), so a live run started on `main` would land *local* commits on `main`. Fix unchanged (`git rev-parse --abbrev-ref HEAD` assert / `checkout -B` before work).

### RSA-0053 — Overnight clean-tree revert uses bare `git clean -fd` (no pathspec) — wipes all untracked files in the worktree
- File: `crates/rustynet-cli/src/vm_lab/overnight/safety.rs:115-125` (`revert_to_clean_argv`, `:123`)
- Date: 2026-06-18 · Severity: **Medium → Low** (re-verified 2026-06-19 — downgraded; data-loss, not a security bypass). The bare `git clean -fd` is the *intentional, documented* between-units clean-tree reset (`safety.rs:111-114` comment, argv-only) on an isolated throwaway branch; its real data-loss risk only materializes via RSA-0052's active-checkout gap (running on the wrong branch). On the intended `overnight/<date>` branch it is by-design. Coupled to RSA-0052; both now Low.
- Bar mapping: CLAUDE.md §3 (don't take irreversible destructive action without confinement); CWE-77. Reachability: `revert_to_clean_argv` emits `['git','clean','-fd']` with no pathspec; combined with RSA-0052's unguarded checkout, every no-progress work-unit removes ALL untracked files anywhere in the worktree (incl. operator scratch, uncommitted evidence, the audit ledger if untracked). Proposed: confine `git clean` to a pathspec/subdir the driver owns, or run the whole unit in a dedicated `git worktree` so cleanup cannot touch the operator's tree; never bare `git clean -fd`. Source: CLAUDE.md §3; AUDIT-017/018/019; CWE-77 — https://cwe.mitre.org/data/definitions/77.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0056 — Orchestrator `remote_shell` interpolates env KEY unquoted into the POSIX command line; `validate_env` permits shell metacharacters in keys
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/remote_shell.rs:238-257` (`validate_env`), `:726-734` (`posix_run_argv` env prefix)
- Date: 2026-06-18 · Severity: **Low** (env keys are orchestrator-internal today, not attacker-supplied)
- Bar mapping: SecurityMinimumBar §3.7 (no untrusted shell construction); CWE-78. Reachability: `validate_env` rejects empty/`=`/NUL in keys and NUL in values but NOT space/`;`/`$`/`` ` ``/`&`/newline in the KEY; `posix_run_argv` builds the env prefix as `KEY=val ...` interpolating the key unquoted into the remote shell line. If a caller ever passes an attacker-influenced env key, it injects into the remote command. Bounded because keys are currently hardcoded by the orchestrator. Proposed: reject shell metacharacters in env keys (allow `[A-Za-z_][A-Za-z0-9_]*` only) and quote/`env`-prefix the assignment. Source: SecurityMinimumBar §3.7; CWE-78. Status: **open** (net-new; 2026-06-18)
- Status update (re-verification 2026-06-19): **Low → Info (downgraded).** The unquoted-env-KEY defect is real, but **no production caller of `posix_run_argv` passes any env** (let alone a dynamic/attacker-influenced key), so attacker-influence reachability is currently nil — it is a latent footgun for a future caller, not a present vector.

### RSA-0057 — Bootstrap env-file values (node_id/network_id/ssh_allow_cidrs) embedded unescaped into a file the bootstrap script `source`s
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:361-370` (`build_bootstrap_env`), macOS counterpart in `adapter/macos_install.rs`
- Date: 2026-06-18 · Severity: **Low** (same class as RSA-0051; lab/bootstrap flow, values are config/inventory-derived)
- Bar mapping: SecurityMinimumBar §3.7; CWE-78. Reachability: `build_bootstrap_env` formats `NODE_ID={node_id}\nNETWORK_ID={network_id}\nSSH_ALLOW_CIDRS={ssh_allow_cidrs}` with raw ctx values and no escaping; `install_daemon` scps the file to the guest and the bootstrap script `source`s it, so a value containing a newline + shell command injects when sourced. Bounded to config/inventory-controlled values (a compromised lab guest or config). Proposed: validate/escape these values (reject newline/shell metachars; or emit via a quoted-by-construction writer). Source: SecurityMinimumBar §3.7; CWE-78. Status: **open** (net-new, RSA-0051 class; 2026-06-18)

### RSA-0054 — `ops_fresh_install_os_matrix` reads report-JSON `source_artifacts` paths without `../`/absolute confinement
- File: `crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs:173-238` (`canonicalize_report`)
- Date: 2026-06-18 · Severity: **Low** (operator-self-scope; the copy *dest* is confined via `file_name()`, only the *source* read path is not)
- Bar mapping: SecurityMinimumBar §3.5; CWE-22. Reachability: each `source_artifacts` string is taken `raw` from report JSON and joined under `root` (or used absolute) with no `..`/absolute rejection, then read+copied — a crafted report could read an arbitrary file into the matrix output. Operator runs it on their own report. Proposed: reject `..`/absolute and canonicalize-confine the source under the report root. Source: CWE-22 "Path Traversal" — https://cwe.mitre.org/data/definitions/22.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0055 — `live_lab_run_matrix` CSV cells are not neutralized against spreadsheet formula injection
- File: `crates/rustynet-cli/src/live_lab_run_matrix.rs:1633-1639` (`csv_escape`)
- Date: 2026-06-18 · Severity: **Low**
- Bar mapping: OWASP CSV Injection; CWE-1236. Reachability: `csv_escape` applies only RFC-4180 quoting (comma/quote/CR/LF) and does NOT prefix-escape values beginning with `=`/`+`/`-`/`@`/tab; cells include `git_branch` and `USER`-derived values, so a crafted branch name (`=cmd|...`) becomes a live formula when the matrix CSV is opened in a spreadsheet. Proposed: prefix-quote (`'`) or wrap any cell starting with a formula trigger. Source: CWE-1236 "Improper Neutralization of Formula Elements in a CSV File" — https://cwe.mitre.org/data/definitions/1236.html (accessed 2026-06-18). Status: **open** (net-new; 2026-06-18)

### RSA-0058 — `vm_lab/mod.rs` repo-sync script interpolates `dest_dir` unquoted into a single-quoted `printf` literal
- File: `crates/rustynet-cli/src/vm_lab/mod.rs:21725-21750` (`build_repo_sync_script`)
- Date: 2026-06-18 · Severity: **Info** (every command-token interpolation IS `shell_quote`d; only a `dest_dir_literal` inside a single-quoted `printf` is raw — a `'` in `dest_dir` could break the literal)
- Bar mapping: SecurityMinimumBar §3.7; CWE-78. Reachability: `dest_dir` is an orchestrator-configured path (not remote-attacker-controlled), and the command-token uses are properly quoted; the raw `printf` literal is a latent quoting gap. Proposed: `shell_quote` the `dest_dir_literal` too (consistency). Source: SecurityMinimumBar §3.7; CWE-78. Status: **open** (net-new, Info; 2026-06-18)

---

## Findings Log — Batch 5b (rustynet-cli bulk finish: orchestrator + bin/ + top-level, 6-agent fan-out 2026-06-19)

> Completed the 3 session-limited Batch-5 scopes + 6 top-level files (130 files
> covered; 116 net-new). **0 Critical / 0 High; 1 Medium, 1 Low, 1 Info.** Strong
> positives: the orchestrator adapters consistently use `ps_quote` / `shell_safe_arg` /
> `hex_32_safe_arg` / `validate_ip_arg` before interpolation, ship the relay verifier
> key as **bytes** (not interpolated), `ssh`/`scp` via argv arrays with `--` separators
> + `BatchMode` + `StrictHostKeyChecking=yes` + `known_hosts` required at connect (fail
> closed), Windows uses `-EncodedCommand` (UTF-16+base64, defeats SSH-layer breakout) +
> DPAPI key separation + zero-on-delete tempfiles (**HB-1 addressed** on Windows);
> iOS/Android adapters fail closed (`UnsupportedPlatform`). **Cross-check note:** the
> Batch-5b adapter agent rated `linux_install.rs`/`macos_install.rs` PASS (the install
> *command args* are single-quote-escaped); first-hand re-read confirmed that is a
> *narrower* view than RSA-0057 — `build_bootstrap_env` (`linux_install.rs:367`) still
> interpolates `node_id`/`network_id`/`ssh_allow_cidrs` **raw** into the env file the
> bootstrap script `source`s, so **RSA-0057 stands** and those rows are restored to FINDINGS.

### RSA-0059 — `windows_membership` interpolates a host-derived `node_id` raw into a PowerShell throw-literal (PS-literal breakout)
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_membership.rs:93-118` (esp. `:107`)
- Date: 2026-06-19 · Severity: **Medium** (lab orchestration; `node_id` is inventory/topology-derived, not remote-attacker-supplied — same PowerShell-interpolation class as RSA-0046)
- Bar mapping: SecurityMinimumBar §3.7 (no untrusted shell construction); CWE-78. Reconciles the HB-6 PowerShell-string-assembly class.
- Reachability / attacker: in `init_membership_snapshot` each peer's `node_id` is correctly `ps_quote`d for the `--node-id {node_id_q}` argument, but the SAME `node_id` is ALSO substituted raw at Rust `format!`-time into a single-quoted PowerShell string literal (a `throw '...'` error message, `:107`). A `node_id` containing a `'` breaks out of that PS literal. `node_id` is host/inventory-derived (a compromised lab guest or crafted inventory), so it is not pure operator-self-injection — hence Medium, matching the project's treatment of the other PS-`-Command` sinks.
- Proposed enforcement (review-only — do NOT apply): `ps_quote` (or omit) the `node_id` in the throw-literal too — never interpolate a host-derived value raw into any PowerShell string, even an error message. Add a test with a `'`-containing node_id asserting no breakout.
- Justification / source: SecurityMinimumBar §3.7; CWE-78 — https://cwe.mitre.org/data/definitions/78.html (accessed 2026-06-19).
- Verification method: unit test feeding a quote-bearing node_id; assert it is quoted/rejected.
- Status: **applied** (2026-06-24). The per-peer script is now built by a pure `build_add_peer_script`, which `ps_quote`s `node_id` everywhere — including the `throw` error-message literal (concatenated as `+ {node_id_q} +` instead of raw `format!` interpolation). Tests: `add_peer_script_quotes_node_id_in_throw_literal_no_breakout` (a `'`-bearing node_id is doubled in BOTH the `--node-id` arg and the throw message; no raw breakout) and `add_peer_script_rejects_control_chars_in_node_id` (CR/LF/NUL fail closed via `ps_quote`).

### RSA-0060 — `real_wireguard` e2e harnesses write ephemeral WireGuard private keys world-readable (no chmod/umask), clean up with plain remove (HB-1)
- File: `crates/rustynet-cli/src/bin/real_wireguard_exitnode_e2e.rs:150,552-556`; `crates/rustynet-cli/src/bin/real_wireguard_no_leak_under_load.rs:151,471-475`
- Date: 2026-06-19 · Severity: **Low** (standalone e2e TEST-HARNESS binaries; ephemeral keys; reconciles **HB-1**)
- Bar mapping: SecurityMinimumBar §3.4 (key custody / strict perms); CWE-732. Reachability: `key_dir` is created via `fs::create_dir_all` with no mode, and `generate_wg_key` writes the `wg genkey` output to `client.key`/`exit.key` via plain `fs::write` (no `PermissionsExt`/chmod, no `umask`); `Cleanup::drop` removes via plain `fs::remove*` (no secure scrub). On a multi-user host another local user could read the ephemeral private keys during the test window. Test-harness scope. Proposed: create the key dir `0700`, write keys `0600`, secure-scrub on cleanup (mirror the Windows harness's zero-on-delete and `ops_install_systemd`'s `secure_remove_file`). Source: HB-1; CWE-732 — https://cwe.mitre.org/data/definitions/732.html (accessed 2026-06-19). Status: **open** (net-new, HB-1 class; 2026-06-19)

### RSA-0061 — `real_wireguard` rogue-path / signed-state-tamper harnesses build the `ssh user@host` argv without a `--` separator and don't shape-validate host/user
- File: `crates/rustynet-cli/src/bin/real_wireguard_rogue_path_hijack_e2e.rs:80-86,221-239`; `crates/rustynet-cli/src/bin/real_wireguard_signed_state_tamper_e2e.rs:79-93,200-218`
- Date: 2026-06-19 · Severity: **Info** (operator-self-injection only — host/user are operator CLI args; test harnesses)
- Bar mapping: SecurityMinimumBar §3.7; CWE-88 (argument injection). Reachability: `remote_exec`/`capture_remote_root` build the ssh argv as `Command::new(base[0]).args(base[1..]).arg(target).args(args)` with **no `--` before `target`**, unlike the shared `live_lab_bin_support::ssh_base_command` which inserts `--`; and `parse_args` validates `ssh_port`/`identity` but not the exit-host/user shape. A `target` beginning with `-` could be parsed as an ssh option (option injection). Operator supplies the target, so it's self-injection (no privilege gain), but it diverges from the safe in-repo pattern. Proposed: insert `--` before the `user@host` target and shape-validate host/user (mirror `live_lab_bin_support::ssh_base_command`). Source: CWE-88 "Argument Injection" — https://cwe.mitre.org/data/definitions/88.html (accessed 2026-06-19); RSA-0051/0057 class. Status: **open** (net-new, Info; 2026-06-19)

---

## Findings Log — Batch 6 (Tier 4 scripts / CI / fuzz / tools, 6-agent fan-out 2026-06-19)

> 193 files swept. **0 Critical; 1 High, 3 Medium, 3 Low, 3 Info** (this auditor
> re-rated the agents' set: `rn_bootstrap.rs source-as-root` ↑ to Medium as the
> RSA-0057 chain sink; the auditor-skill nullglob ↓ to Info as robustness). Strong
> positives: the `scripts/ci/` gate scripts are thin `exec` wrappers to Rust bins
> (args passed as quoted `"$@"` arrays — no word-split injection), use `set -euo
> pipefail` + `mktemp` + `umask 077` + PID-suffixed workdirs + EXIT traps, and the
> default-deny / secret-redaction / api-key gates **fail closed on zero match**
> (`run_required_test`); the **13 systemd units are well-hardened** (NoNewPrivileges,
> ProtectSystem=strict, dropped/scoped `CapabilityBoundingSet`, `LoadCredentialEncrypted`
> for secrets, RestrictAddressFamilies, narrow ReadWritePaths) — see the Tier-4 rows.

### RSA-0063 — macOS bootstrap leaves a `NOPASSWD: ALL` sudoers file on disk if the Homebrew install fails (local privilege-escalation residue)
- File: `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:243-250` (write `:246`, curl|bash `:248-249`, late `rm` `:250`)
- Date: 2026-06-19 · Severity: **High** (re-confirms **AUDIT-045/RN-32**; local privesc on the bootstrapped host)
- Bar mapping: SecurityMinimumBar §3.7 (privilege boundary), CLAUDE.md §3 (fail-closed / don't leave a weaker state on error); CWE-250/CWE-279.
- Reachability / attacker: verified first-hand — `ensure_homebrew()` writes `${REAL_USER} ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers.d/rustynet-bootstrap-tmp` (`:246`, chmod 0440), runs the Homebrew installer via `as_user … /bin/bash -c "$(curl -fsSL …/install.sh)"` (`:248-249`), then `rm -f` the file (`:250`). There is **no `trap … EXIT`**, so if the curl|bash fails (network error, upstream change, `set -e` abort) or the operator interrupts, the script exits before `:250` and the `NOPASSWD: ALL` sudoers file persists. Any local process running as `${REAL_USER}` then has passwordless root. Attacker = any local code running as the install user after a failed/aborted bootstrap.
- Risk: persistent local privilege escalation to root on the bootstrapped macOS host.
- Proposed enforcement (review-only — do NOT apply): register `trap 'rm -f "${sudoers_tmp}"' EXIT` **immediately after** creating the file (before the curl|bash), so it is removed on every exit path. Prefer scoping the temporary grant to the specific brew command rather than `ALL=(ALL) NOPASSWD: ALL`.
- Justification / source: AUDIT-045/RN-32; CWE-250 "Execution with Unnecessary Privileges" — https://cwe.mitre.org/data/definitions/250.html ; CWE-279 (insecure file perms on critical resource) (accessed 2026-06-19).
- Verification method: a test/lint asserting the EXIT trap is registered before the sudoers write; bootstrap-failure simulation leaves no `/etc/sudoers.d/rustynet-*`.
- Status: **open** (re-confirms AUDIT-045/RN-32, verified first-hand; 2026-06-19)

### RSA-0064 — macOS bootstrap fetches the Homebrew installer with `curl|bash` and no checksum/signature pin (supply-chain RCE)
- File: `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:248-249`
- Date: 2026-06-19 · Severity: **Medium**
- Bar mapping: SecurityMinimumBar §10 (supply-chain integrity); CWE-494. Reachability: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` fetches the **HEAD** of the upstream installer over the network and executes it as the install user — a MITM, CDN/repo compromise, or upstream change yields RCE on the bootstrapping host. Proposed: pin the installer to a specific commit-SHA URL and verify a known SHA-256 before executing, or vendor the installer. Source: CWE-494 "Download of Code Without Integrity Check" — https://cwe.mitre.org/data/definitions/494.html (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0065 — Windows lab-image provisioning downloads `rustup-init.exe` / `vs_BuildTools.exe` and executes them with no hash/signature pin
- File: `scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1:214-234,267-283` (`Invoke-WebDownload` `:136-146`)
- Date: 2026-06-19 · Severity: **Medium**
- Bar mapping: SecurityMinimumBar §10; CWE-494. Reachability: `Invoke-WebDownload` uses `Invoke-WebRequest` with no hash verification; the script downloads `rustup-init.exe` from `win.rustup.rs` and `vs_BuildTools.exe` from Microsoft, then `Start-Process` them. No Authenticode/SHA check → MITM/upstream-compromise RCE during image provisioning. Proposed: `Get-AuthenticodeSignature` (require Valid + expected publisher) or pin a known SHA-256 before `Start-Process`. Source: CWE-494 (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0068 — `rn_bootstrap.sh` `source`s an arbitrary env-file argument as root (the RSA-0057 chain sink)
- File: `scripts/bootstrap/linux/rn_bootstrap.sh:9` (`source "$1"`)
- Date: 2026-06-19 · Severity: **Medium** (root code-exec sink; this is where RSA-0057's raw-written env file is consumed)
- Bar mapping: SecurityMinimumBar §3.7; CWE-78. Reachability: `source "$1"` interprets the env-file (first arg) as bash, so any shell code in it executes with the script's privileges; the script runs commands as root via `sudo -n` throughout. The env file is written by the orchestrator's `build_bootstrap_env` (**RSA-0057**) with raw `node_id`/`network_id`/`ssh_allow_cidrs` — so a crafted inventory/config value containing a newline + command becomes root code-exec on the guest. Together RSA-0057 (raw write) + RSA-0068 (`source` as root) form the full injection-to-root chain; gated by control of the orchestration inputs (lab/config). Proposed: parse the env-file with a strict `^[A-Z_]+=` key=value reader (reject anything else) instead of `source`, and require the file be root-owned `0600`. Source: CWE-78 — https://cwe.mitre.org/data/definitions/78.html (accessed 2026-06-19); chains with RSA-0057. Status: **open** (net-new; 2026-06-19)

### RSA-0066 — One e2e script uses `StrictHostKeyChecking=accept-new` (TOFU), diverging from the suite's pinned-known_hosts model
- File: `scripts/e2e/live_linux_path_handoff_under_load_test.sh:68-72` (`ssh_cmd`)
- Date: 2026-06-19 · Severity: **Low** (lab e2e; man-in-the-middle on first connect)
- Bar mapping: SecurityMinimumBar §6.B (trust-anchor / host-key pinning); CWE-322. Reachability: `ssh -o StrictHostKeyChecking=accept-new …` trusts the host key on first use, unlike `live_lab_common.sh` (`live_lab_ssh_via_ssh`) which uses `StrictHostKeyChecking=yes` + a pinned `UserKnownHostsFile`. A first-connect MITM could intercept. Lab-only. Proposed: route this test through `live_lab_common.sh` or set `=yes` against a pinned known_hosts. Source: CWE-322 "Key Exchange without Entity Authentication" — https://cwe.mitre.org/data/definitions/322.html (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0067 — Windows service installers mint a self-signed code-signing cert and add it to `LocalMachine\Root` (machine-wide trust expansion)
- File: `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1:893-938`; `scripts/bootstrap/windows/Install-RustyNetWindowsRelayService.ps1` (same pattern)
- Date: 2026-06-19 · Severity: **Low** (constrained cert; install-time; but widens machine root trust)
- Bar mapping: SecurityMinimumBar §10 (artifact signing); CWE-295/CWE-732. Reachability: `install-release` mints a self-signed CodeSigning cert (`New-SelfSignedCertificate`) and imports it into `Cert:\LocalMachine\Root` so `WinVerifyTrust` accepts the locally re-signed `rustynetd.exe`/`rustynet.exe`. The cert is constrained (code-signing EKU, non-CA, hostname-scoped) and signing skips timestamping. If the cert's private key is exportable / weakly protected, an attacker could sign malware the machine trusts. Proposed: ensure the key is non-exportable, remove the Root-store entry on uninstall, keep the EKU/CA/hostname constraints. Source: CWE-295 "Improper Certificate Validation" / CWE-732 — https://cwe.mitre.org/data/definitions/295.html (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0069 — Dev-build signing script adds a self-signed cert to `LocalMachine\Root`
- File: `scripts/windows/Sign-RustyNetDevBuild.ps1:65-78`
- Date: 2026-06-19 · Severity: **Low** (`production_path: false` — dev script; but machine-root trust expansion)
- Bar mapping: SecurityMinimumBar §10; CWE-295/CWE-732. Reachability: creates a self-signed `CN=RustyNet Lab Dev` code-signing cert and imports it into `LocalMachine\Root` so `WinVerifyTrust` returns Verified for `rustynetd.exe`; reuses any existing same-CN cert with >30d validity. Same machine-root trust-expansion concern as RSA-0067, dev-scoped. Proposed: document/enforce never-on-prod, remove the Root entry on uninstall/cleanup, non-exportable key. Source: CWE-295/CWE-732 (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0070 — Auditor-skill installer aborts on an empty `scripts/` dir (unmatched `*.py` glob under `set -e`)
- File: `tools/skills/install_rustynet_security_auditor.sh:21,23`
- Date: 2026-06-19 · Severity: **Info** (robustness, not security; `production_path: false`)
- Bar mapping: CWE-754 (improper check of unusual condition). Reachability: `cp "$SKILL_SRC/scripts/"*.py …` / `chmod … *.py` with zero `.py` files present + `set -e` aborts the install. Proposed: `shopt -s nullglob` or a `compgen -G` guard before the globbed `cp`/`chmod`. Source: CWE-754 (accessed 2026-06-19). Status: **open** (net-new, Info; 2026-06-19)

### RSA-0071 — `security_regression_gates.sh` G2a deprecated-crypto grep is narrower than the `deny.toml` ban list (defense-in-depth drift)
- File: `scripts/ci/security_regression_gates.sh:34-40`
- Date: 2026-06-19 · Severity: **Info** (not an enforcement hole — G2b `cargo-deny` is the real gate)
- Bar mapping: SecurityMinimumBar §10; defense-in-depth. Reachability: the G2a fast-fail grep matches only `sha1|md-5|md5|des|des3|3des|triple-des` in `Cargo.lock`, while `deny.toml [[bans.deny]]` now also bans `rc4|md4|md2|rc2|blowfish` (12 names vs 7) — so G2a alone would miss a newly-introduced rc4/blowfish dep, but G2b (`cargo deny check bans`, verified clean) catches it. Proposed: mirror the `deny.toml` list in G2a, or drop G2a and rely on G2b as the single source of truth. Source: deny.toml (in-repo); defense-in-depth. Status: **open** (net-new, Info; 2026-06-19)

### RSA-0072 — VM recovery uses bare `netsh`/`sc`/`nft` in the guest command chain (HB-3-style PATH reliance)
- File: `scripts/vm_lab/probe_and_recover_local_utm.sh:143-180`
- Date: 2026-06-19 · Severity: **Info** (re-confirms **HB-3**; defense-in-depth, not attacker-controlled)
- Bar mapping: SecurityMinimumBar §3.7; CWE-426 (untrusted search path). Reachability: recovery dispatches guest commands via `utmctl exec "$name" --cmd …`; the VM name is passed as a single argv arg (not shell-interpolated), and the Windows guest command (`:170`) uses bare `netsh` (PATH-resolved). HB-3 guidance prefers an absolute `%SystemRoot%\System32\netsh.exe`. Proposed: use absolute system-binary paths in the guest cmd for PATH-hijack resistance. Source: HB-3; CWE-426 — https://cwe.mitre.org/data/definitions/426.html (accessed 2026-06-19). Status: **open** (net-new, Info, HB-3; 2026-06-19)

---

## Findings Log — Batch 7 (vendored `third_party/` + crate tests/benches + cli test-bins, 7-agent fan-out 2026-06-19)

> 67 files swept — **completes 100% coverage (594/594).** **0 Critical/High/Medium/Low
> new; 2 Info → 1 reclassified Low.** Vendored **boringtun is clean**: standard
> `Noise_IKpsk2` handshake (peer static key compared with `ct_eq`, AEAD tag via the
> crate, TAI64N monotonic anti-replay), per-packet ChaCha20-Poly1305 with a
> sliding-window replay bitmap, mac1/mac2 verified constant-time, cookie via
> XChaCha20-Poly1305 — **no local weakening, no hardcoded keys/nonces, no `==` on MACs**;
> `device/`, `ffi/`, `jni.rs` are **intentionally not compiled** (no `mod device/ffi/jni`
> in `lib.rs`) so their `unsafe`/raw-FFI is unreachable from Rustynet (which consumes
> boringtun as a noise/x25519 library behind its own backends). `Cargo.lock`/advisories
> clean (S1/S2). The rustynetd integration tests (`membership_replay_protection`,
> `enrollment_two_peer_redeem`, `quorum_multi_approver`, `role_capability_enforcement`,
> `gossip_three_peer_mesh`, …) assert their negative paths — confirmed T1/T2 evidence;
> `live_signed_bundle_forger` is a test-only adversarial minter.

### RSA-0074 — Vendored `rustynet-tun` FFI `unsafe` blocks lack `// SAFETY:` rationale comments (production dataplane, called as root)
- File: `third_party/rustynet-tun/src/lib.rs:28-43,50-63,68-78,82-…`
- Date: 2026-06-19 · Severity: **Low** (E2 rigor gap on a production FFI path; same class as RSA-0032)
- Bar mapping: CLAUDE.md §10.2 / ANSSI Secure Rust (E2: every `unsafe` minimal + `// SAFETY:` proving the invariant); CWE-1006. Reachability: `rustynet-tun` IS on the production dataplane — `rustynet-backend-wireguard` `userspace_shared{,_macos}/tun.rs` call `SyncDevice::open/recv/send/from_raw_fd`, and `rustynetd/macos_utun_helper_unsafe.rs:228` calls it as root. The `unsafe` ioctl/fd FFI blocks have no `// SAFETY:` comments justifying the pointer/fd/length invariants. (Vendored — per charter, audit not rewrite; this is a documentation/rigor proposal.) Proposed: add `// SAFETY:` to each `unsafe` block; run Miri on the buffer paths where feasible. Source: ANSSI Secure Rust Guidelines — https://anssi-fr.github.io/rust-guide/ ; CLAUDE.md §10.2 (accessed 2026-06-19). Status: **open** (net-new; 2026-06-19)

### RSA-0073 — Vendored boringtun ships upstream `device/` + `ffi/` + `jni.rs` (unused `unsafe`/raw-FFI surface) on disk although not compiled
- File: `third_party/boringtun/src/device/**`, `src/ffi/mod.rs`, `src/jni.rs` (declared nowhere in `lib.rs`)
- Date: 2026-06-19 · Severity: **Info** (`production_path: false` — not compiled, unreachable; attack-surface-on-disk only)
- Bar mapping: charter vendored sub-tier (trust-path-use review). Reachability: `lib.rs` declares only `noise`/`x25519`/`serialization`/feature-gated clocks — there is no `mod device/ffi/jni`, so the upstream device main-loop, C ABI, and Android JNI (with their syscall `unsafe`) are dead on disk and cannot be reached from Rustynet. No weakening; purely a smaller-surface hygiene note. Proposed (optional, do NOT rewrite vendored crypto): strip the unused `device/ffi/jni` files from the vendored copy to shrink the on-disk surface, or document that they are intentionally retained from upstream and uncompiled. Source: charter vendored-code rule; RN-02 (dead-code) class. Status: **open** (net-new, Info; 2026-06-19)

---

## Findings Log — Targeted sweep: numeric-truncation `as` casts (2026-06-19)

> Post-coverage thematic sweep (CWE-197 / CWE-681) over all 136 narrowing integer
> `as` casts in production crate src, concentrating on the untrusted-wire parsers
> (relay, gossip, STUN, PCP/uPnP, dns-zone, membership, nas/llm protocols). **Result:
> the codebase casts safely** — every parser cast is either encode-side on a value
> already bounded by a `MAX_*` cap, intentional masked byte-extraction (`& 0xff … as u8`),
> a constant high-bits extraction (`STUN_MAGIC_COOKIE >> 16`), or a `cfg(test)` LCG —
> **one genuine truncation found (RSA-0075), fail-closed.** Scope note: `as usize`
> narrowing was excluded as it only truncates on a 32-bit target, which is not a declared
> Rustynet platform (targets are 64-bit Linux/macOS/Windows).

### RSA-0075 — Active-approver count is narrowed to `u8` (`count() as u8`); wraps at 256 in the membership `validate()` quorum sanity check
- File: `crates/rustynet-control/src/membership.rs:212-216` (`active_approvers`), consumed at `:232` and `:237`
- Date: 2026-06-19 · Severity: **Low** (CWE-197 numeric truncation; **fail-closed direction** — can only over-reject; impractical scale)
- Bar mapping: SecurityMinimumBar §3.3 (membership/quorum integrity); ANSSI Secure Rust (integer casts); CWE-197 / CWE-681.
- Reachability / attacker: in `MembershipState::validate()`, `active_approvers = self.approver_set.iter().filter(Active).count() as u8` — the count of Active approvers truncated to `u8`, so it wraps modulo 256. Consumers: `:232` `if active_approvers == 0 { reject }` and `:237` `if self.quorum_threshold > active_approvers { reject }` (`quorum_threshold` is `u8`, max 255). Because `count() as u8` can only *reduce* the value (real ≥256 ⇒ reported `= real mod 256` `<` real), the check becomes **stricter**, never weaker: a config that should fail (`threshold > real_active`) cannot be made to pass by the truncation, and the one hard edge is **exactly 256 active approvers ⇒ reported 0 ⇒** spurious "at least one active approver is required" rejection. Verified first-hand that the **authoritative quorum enforcement is truncation-free**: `verify_membership_signatures` (`:1004`) gates on `signer_ids.len() < usize::from(state.quorum_threshold)` (`usize::from` widens the `u8`) — so the truncation does **not** reach signature-count enforcement and is **not** a quorum bypass.
- Risk: an organisation with ≥256 active approvers gets a confusing/incorrect membership-validation rejection (availability/correctness), not a trust bypass. Attacker gains nothing (truncation is fail-closed).
- Proposed enforcement (review-only — do NOT apply): keep the count as `usize` and compare via `usize::from(self.quorum_threshold)` (mirroring the correct enforcement at `:1004`), or `u16`; drop the `as u8`. Add a test with 256 active approvers asserting `validate()` succeeds when `quorum_threshold ≤ 256`.
- Justification / source: ANSSI Secure Rust Guidelines (integer conversions) — https://anssi-fr.github.io/rust-guide/ ; CWE-197 "Numeric Truncation Error" — https://cwe.mitre.org/data/definitions/197.html (accessed 2026-06-19); SecurityMinimumBar §3.3.
- Verification method: `validate()` unit test at the 255/256/257-active-approver boundaries; `cargo test -p rustynet-control membership`.
- Status: **open** (net-new; 2026-06-19)
- Sweep coverage (benign, labelled): encode-side length prefixes bounded by `MAX_*` — `nas/protocol.rs:207/319/542`, `llm-gateway/protocol.rs:207/274/282`, `peer_gossip.rs:307-310/549-552`; constant/attr lengths — `peer_gossip.rs:302/796`, `stun_client.rs:378/559/563/878/920`; constant high-bits — `stun_client.rs:275/351/362/432/546/858/911`; count/masked-byte — `relay/main.rs:2115/3502-3504`; `cfg(test)` LCG + `(MAX_* as u32)+1` fixtures — `nas/protocol.rs:544/566/658`, `llm-gateway/protocol.rs:470/526/547/553/568`, `peer_gossip.rs:978/1219/1222-1223`. (`port_mapper.rs:1190` is text in an error string, not a cast.)

---

## Targeted sweep: untrusted-length allocation / unbounded read (2026-06-19) — CLEAN (no new finding)

> Thematic sweep for **CWE-789 / CWE-130 / CWE-400** — `Vec::with_capacity(n)` /
> `vec![x; n]` / `.reserve(n)` / `read_to_end` / `read_to_string` where `n` (or the read)
> is an attacker-influenced count/length used to size an allocation **before** it is
> bounded. This directly generalizes the project's own fixed **RN-01** (membership
> decoder `with_capacity` from an attacker count) and the open **RSA-0047** (MCP
> unbounded JSON-RPC line read). Swept all 263 sizing-allocation sites; read every
> decode-side site fed by a non-literal size in the untrusted parsers/IPC.
>
> **Verdict: the bound-before-allocate control is consistently enforced — no new finding.**
> Every untrusted-length-driven allocation is capped *before* the alloc, first-hand verified:
> - `rustynetd/privileged_helper.rs:641` — `arg_count` gated by `MAX_ARGS` at `:638` (root IPC).
> - `rustynetd/peer_gossip.rs:656/662/668/675` — candidate counts gated by `MAX_CANDIDATES_PER_BUNDLE` (`:632`) **and** an exact wire-length match (`:649`).
> - `rustynet-dns-zone/lib.rs:410` — `record_count` validated against the parsed field count (`:399-408`).
> - `rustynetd/daemon.rs:12190` (`peer_count` ≤ `MAX_AUTO_TUNNEL_PEER_COUNT` `:12184`), `:13209` (`candidate_count` field-count match `:13202`), `:12287` (route_count, same pattern).
> - `rustynet-nas/protocol.rs:371` / `rustynet-llm-gateway/protocol.rs:316` — `count.min(64)`.
> The unbounded `with_capacity(len)` sites (`llm-gateway/protocol.rs:551/565`,
> `nas/protocol.rs:656/672`) are `#[cfg(test)]` LCG fuzz harnesses; the `*.len()*2` sites
> are hex encoders over locally-bounded data; `args.len()+1` is over a fixed argv.
> Unbounded reads: `rustynetd/fetcher.rs` explicitly caps `read_to_end` at 4 MB
> (`:189-196`); the macOS utun-helper socket reads are owner-only-socket bounded. **The
> one open gap in this class remains RSA-0047 (MCP `run_server` line read) — already
> logged**; `fetcher.rs` is the positive model for its fix.

---

## Targeted sweep: `#[allow(...)]` lint suppression (V3) (2026-06-19)

> Enumerated **every** `#[allow]`/`#![allow]` in production crate src (286 total) and
> classified each by the lint it suppresses. **V3 verdict: CLEAN** — no `#[allow]` hides a
> *security* lint without justification. Breakdown: 191 `dead_code` (scaffolding /
> future-track accessors, esp. the crate-level `#![allow(dead_code)]` on every
> `vm_lab/orchestrator/*` module), 28 `clippy::result_large_err`, 27
> `clippy::too_many_arguments`, 8 `unreachable_code` (cfg-platform early-returns), 8
> `deprecated` (all in `bin/live_*` TEST harnesses), and assorted clippy style lints
> (`uninlined_format_args`, `collapsible_if`, `type_complexity`, …). The lone
> **`unsafe_code`** allow (`rustynetd/src/lib.rs:44`) is the **documented** macos_utun
> exception (RN-14). None suppress `indexing_slicing`, `unwrap_used`,
> `cast_possible_truncation`, `arithmetic_side_effects`, or `as_conversions`.
>
> **But that clean result has a flip side — RSA-0076 below:** nothing security-relevant is
> suppressed because the clippy *restriction* security-lint family is not enabled anywhere.

### RSA-0076 — The clippy restriction security-lint family is not enabled; the panic / truncation / indexing / arithmetic bug classes have no automated gate (defense-in-depth)
- File: `Cargo.toml:34-35` (`[workspace.lints.rust]` — only `unsafe_code = "forbid"`; no `[workspace.lints.clippy]`); no crate opts in
- Date: 2026-06-19 · Severity: **Info** (absent defense-in-depth / shift-left control; not itself a vulnerability — but it is why several of this pass's findings had to be caught by manual audit)
- Bar mapping: CLAUDE.md §7 (CI gates) + §10.2 ("no `unwrap()`/`expect()`/`panic!`/panicking index/unchecked arithmetic in production paths") — the rule exists in prose but has **no lint enforcing it**; ANSSI Secure Rust Guidelines (recommends these clippy lints). CWE-1006 (use of an inappropriate/weak coding standard enforcement).
- Reachability / attacker: not attacker-driven. Verified the workspace enables only `unsafe_code = "forbid"`; grep finds **no** `[workspace.lints.clippy]`, no `deny(clippy::…)`, no `clippy::all`/`pedantic`/`restriction` in any crate. The mandatory gate `cargo clippy --workspace --all-targets --all-features -- -D warnings` (and `membership_gates.sh`'s `clippy -p rustynet-control -- -D warnings`) deny the *default* clippy groups (correctness/style/complexity/perf/suspicious) but **not** the *restriction* group, which is off by default and is where the memory-safety/panic lints live: `clippy::cast_possible_truncation` (would flag RSA-0075's `count() as u8`), `clippy::indexing_slicing` (RSA-0050's arp/tcp slice panics), `clippy::unwrap_used`/`expect_used` + `clippy::panic` (the §10.2 panic class, e.g. RSA-0010/RN-N1 historically), `clippy::arithmetic_side_effects`, `clippy::as_conversions`. So these classes have **no automated gate** and depend entirely on manual review.
- Risk: a whole family of CLAUDE.md-§10.2-prohibited constructs can be (re)introduced without any CI signal; this audit's RSA-0075 / RSA-0050 and the historical panic findings would have been caught at compile time had the lints been on. Regression-prevention gap.
- Proposed enforcement (review-only — do NOT apply): add a `[workspace.lints.clippy]` (or per-crate `#![…]`) enabling the security subset — at minimum `cast_possible_truncation`, `cast_sign_loss`, `indexing_slicing`, `arithmetic_side_effects`, `unwrap_used`, `expect_used`, `panic` — as `warn` workspace-wide and `deny` in the trust-critical crates (`rustynet-crypto`, `-control`, `-policy`, `-dns-zone`, and the `rustynetd`/`-relay` wire parsers), with narrowly-scoped `#[allow(…)] // <reason>` at the legitimate sites (tests, one-shot CLI, provably-bounded indexes). Stage with `warn` first to size the backlog, then ratchet to `deny`.
- Justification / source: ANSSI Secure Rust Guidelines (recommended clippy lints) — https://anssi-fr.github.io/rust-guide/ ; Rust Secure Code WG — https://github.com/rust-secure-code ; CLAUDE.md §10.2/§7; CWE-1006 — https://cwe.mitre.org/data/definitions/1006.html (accessed 2026-06-19).
- Verification method: CI shows the new lints active (`clippy` fails on a deliberately-introduced `x as u8`/`v[i]`/`.unwrap()` in a gated crate); the backlog from the initial `warn` run is triaged.
- Status: **open** (net-new, Info — high-value process improvement; would auto-catch RSA-0075/RSA-0050; 2026-06-19)

---

## Targeted sweep: disabled / bypassed verification (2026-06-20) — CWE-295 / CWE-347 / CWE-296

> Swept for the highest-impact trust-bypass class: TLS cert-verification disabled, custom
> verifiers that unconditionally return `Ok`, signature checks that don't fail closed, and
> insecure download / host-key flags. **Mostly CLEAN, with one systemic finding (RSA-0077).**
>
> **Clean (strong positives):** (a) **no TLS-verification-disable patterns anywhere** — and
> in fact **no TLS client/server stack at all** (no rustls/native-tls/openssl/reqwest/ureq):
> the control plane's integrity/authenticity anchor is the **Ed25519 signature on the
> bundle**, not transport TLS, so SecurityMinimumBar §3.2 is satisfied by signed-state
> verification rather than a TLS API (TLS would add only confidentiality of already-signed
> state). (b) **No fail-open verifier** — every signature verifier returns `Err` on a bad
> signature (spot-read `fetcher.rs:224`, `traversal.rs:576-606`, `daemon.rs:12144`,
> `peer_gossip.rs:390`, `llm-gateway/session.rs:152`). (c) **No insecure download / host-key
> flags** in scripts — no `curl -k`/`--insecure`, no `wget --no-check-certificate`, no
> `StrictHostKeyChecking=no`, no `UserKnownHostsFile=/dev/null`, no `GIT_SSL_NO_VERIFY` (the
> one host-key relaxation is RSA-0066's single e2e `accept-new`, already logged). (d) Bonus:
> `fetcher.rs:231-245` `check_freshness` explicitly treats an attacker-rolled-back host clock
> (pre-`UNIX_EPOCH`) as fail-closed — the wall-clock-freshness hardening is present.

### RSA-0077 — Ed25519 `verify_strict` (the RN-22 malleability standard) is applied only in `control`+`crypto`; the entire daemon/dns-zone/llm/cli trust-signature surface (14 sites) uses malleable plain `verify()`
- File: plain `verify()` at `rustynetd/src/daemon.rs:6866,11253,12145,13170,13437` (signed trust-state / assignment / auto-tunnel / traversal / dns-zone artifacts), `rustynetd/src/fetcher.rs:227`, `rustynetd/src/traversal.rs:606`, `rustynetd/src/peer_gossip.rs:401`, `rustynet-llm-gateway/src/session.rs:167`, `rustynet-dns-zone/src/lib.rs:285` (= RSA-0043), `rustynet-cli/src/ops_phase9.rs:2813,3000,3389,3687`. Contrast `verify_strict` at `rustynet-control/src/lib.rs:1575/1856/2497/3160/3228/3313/3416`, `membership.rs:1022/1116`, `rustynet-crypto/src/lib.rs:1174` (10 sites).
- Date: 2026-06-20 · Severity: **Low** (signature malleability without payload forgery; verifying keys are pinned and replay is epoch/watermark-based — so no practical forgery or replay-bypass — **but a systemic, repo-wide deviation from the project's own landed RN-22 standard across the core trust-verification path**). Supersedes/generalizes RSA-0043 (which mis-stated dns-zone as the *sole* divergence; it is one of 14).
- Bar mapping: SecurityMinimumBar §3.1 (proven crypto, no malleability) / §3.2 (signed control data validated before application); RN-22/RL-3 (the landed verify_strict migration); CWE-347.
- Reachability / attacker: `verify_strict` (RFC 8032 strict / ZIP-215) rejects non-canonical `S` and small-order/torsion components; plain `verify` accepts them. So an attacker holding a *valid* signed bundle can mint an alternate signature-bytes encoding that still verifies for the **same payload** — no payload forgery. Verified that the daemon verifies **all** its signed trust state this way (e.g. `daemon.rs:12144` auto-tunnel bundle: `verifying_key.verify(payload, &sig)` fail-closed-but-non-strict), while the `control` crate that mints them uses `verify_strict`. Practical impact is bounded to Low because (1) verifying keys are pinned (membership-owner / assignment / endpoint-hint / dns-zone / node-session keys loaded from the out-of-band trust anchor, not attacker-supplied — so small-order-key attacks don't apply), and (2) anti-replay is epoch/`update_id`-watermark-based, not signature-byte-based — so a malleated re-encoding does not bypass replay. The concern is the **incomplete RN-22 application** (a landed security hardening that covers only 2 of the ~6 crates that verify signatures) and the integrity-standard inconsistency on the trust path.
- Risk: alternate-signature-encoding acceptance on every daemon-side signed trust artifact; latent escalation if any consumer ever keys replay/dedup or audit on signature bytes, or ever accepts a verifying key from the wire.
- Proposed enforcement (review-only — do NOT apply): complete the RN-22 migration — replace plain `verifying_key.verify(...)` with `verify_strict(...)` at all 14 sites (daemon/dns-zone/llm/cli + fetcher/traversal/gossip), matching `control`/`crypto`; add a workspace lint/grep gate forbidding `\.verify\(` on a `VerifyingKey` so it cannot regress (ties to RSA-0076). Add a malleated-signature negative test on the daemon auto-tunnel / trust-state verifiers.
- Justification / source: RN-22/RL-3 (in-repo standard); ed25519-dalek `verify_strict` docs (RFC 8032 strict / ZIP-215); CWE-347 "Improper Verification of Cryptographic Signature" — https://cwe.mitre.org/data/definitions/347.html (accessed 2026-06-20).
- Verification method: grep shows all 14 plain-`verify` sites migrated to `verify_strict`; malleated-signature negative tests on `daemon.rs` trust-state verifiers + `fetcher`/`traversal`/`gossip`; `cargo test --workspace`.
- Status: **open** → **applied** (verify_strict migration landed `6e0d0f0`, 2026-06-21 — all 14 sites migrated; unused `Verifier` trait imports pruned; an RN-22 regression-gate leg added to `scripts/ci/security_regression_gates.sh` (fails closed if a non-strict `.verify(` reappears anywhere in `crates/`); validated by 203 daemon verification tests + the dns-zone/llm-gateway suites + `cargo clippy -D warnings`. This also closes **RSA-0043**.)

---

## Targeted sweep: post-baseline commit delta (`576401e..HEAD`, 2026-06-21)

> The audit baseline was `576401e`; the live-lab track has since landed 11 commits
> (`444a1a6..bde69a9`, HEAD now `57586be`) touching security-sensitive surfaces:
> `rustynetd/src/resilience.rs` (state-lock rewrite), the macOS/Windows bootstrap
> scripts (fresh-enroll signed-state reset, trust-passphrase ACL, offline build), the
> vm-lab orchestrator shell (SSH transport / sudo-prime / stage-watchdog), and the
> cross-OS signed-bundle distribution to Windows. Audited the two **production**-path
> deltas first (daemon persistence + the anti-rollback control). The `bde69a9`
> trust-passphrase ACL fix was independently re-read and **confirmed correct + secure**
> (strips inherited `BU`, grants only Admin+SYSTEM, fail-closed on `icacls` error; the
> sibling WG-passphrase write at `Install-RustyNetWindowsService.ps1:1016` is written
> into a pre-hardened dir and consumed by the Rust key-custody pair — **no sibling
> gap**). Two net-new findings below; the lab-only shell/transport deltas and the
> `57586be` Windows bundle-distribution wiring remain to audit.

### RSA-0078 — State-lock cross-UID recovery (`PermissionDenied` ⇒ unlink+recreate) is liveness-blind; safe only under an undocumented single-writer precondition
- File: `crates/rustynetd/src/resilience.rs:255` (`#[cfg(unix)] acquire_lock`, the `PermissionDenied ⇒ fs::remove_file + recreate` arm) and `StateLockGuard::drop` (`:357`, unlink-on-release); writer `write_atomic_locked:188`; sole production caller `crates/rustynetd/src/daemon.rs:7921` (`persist_session_snapshot(&snapshot, &self.state_path)`)
- Date: 2026-06-21 · Severity: **Info** (latent hazard / undocumented precondition — **not currently reachable**: the protected file is single-writer)
- Bar mapping: SecurityMinimumBar (state-persistence integrity / fail-closed); CLAUDE.md §3 (fail closed on state); CWE-667 (improper locking) / CWE-367 (TOCTOU) — latent.
- Reachability / attacker: not attacker-driven. The unix `acquire_lock` rewrite (984f756/3ff6605) replaces the `O_EXCL` lockfile-as-mutex with advisory `flock` plus two recovery behaviors: (a) unlink the lock file on clean release (`Drop`), (b) on `PermissionDenied` opening the lock file, `fs::remove_file` + recreate under the daemon UID. Verified first-hand that the protected resource is the **session/reconnect snapshot** (`SessionStateSnapshot` = timestamp / peer_ids / selected_exit_node / lan_access_enabled), written by the single non-root daemon process only (sole production caller `daemon.rs:7921`); root-run ops persist a *different* file via `persist_membership_snapshot` (`main.rs:3153`). So this lock has **one writer-UID**, and the cross-UID branch fires only for a *stale* root-owned file (dead holder) — where unlink+recreate is correct. **The hazard is that the recovery is liveness-blind**: `PermissionDenied` is a pure permission condition, indistinguishable between a *dead* root holder (stale file) and a *live* one; `flock` is per-inode, so if a different-UID process ever concurrently holds this lock, the unconditional unlink+recreate produces a *second* inode that both parties can lock → two writers hold "the lock" at once → torn/lost write. Safe today **only** by the single-writer invariant, which is neither enforced nor documented as a precondition.
- Risk: a future caller that persists the session snapshot from a different UID (a root-run diagnostic/refresh, or a daemon that runs privileged setup then drops UID while a second instance is live) would silently lose mutual exclusion on the state-persist path — integrity corruption, not a confidentiality break.
- Proposed enforcement (review-only — do NOT apply): (1) document the single-writer precondition at `acquire_lock`/`write_atomic_locked` and assert the session snapshot is only ever written by the daemon UID; (2) make the `PermissionDenied` recovery liveness-aware without needing to open the file (stat-able sidecar pid/heartbeat, or a staleness-age threshold before unlink) so a *live* foreign holder is never displaced; (3) add a concurrency negative test (two acquirers, one holding while the other is forced down the unlink path) asserting mutual exclusion holds across an unlink.
- Justification / source: CWE-667 "Improper Locking" — https://cwe.mitre.org/data/definitions/667.html ; CWE-367 "TOCTOU Race Condition" — https://cwe.mitre.org/data/definitions/367.html (accessed 2026-06-21); flock(2) per-inode advisory semantics; CLAUDE.md §3.
- Verification method: the concurrency negative test above; a code comment recording the precondition. `cargo test -p rustynetd resilience`.
- Status: **open** (net-new, Info — latent / not currently reachable; 2026-06-21)

### RSA-0079 — Fresh-enroll bootstrap wipes the anti-replay watermark; safe only if re-enrollment rotates the genesis (a same-genesis redeploy opens a rollback window)
- File: `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:688` (`clear_residual_state` — wipes `membership/`+`trust/`+`rustynetd.state`), invoked in both the full and `SKIP_BUILD` paths (`:1226`); embedded into the lab adapter via `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs:34` (`include_str!`); Linux analogue is the cleanup's `rm -rf /var/lib/rustynet`; consumed-against `crates/rustynet-control/src/membership.rs` (`network_id` bind `:696`, epoch chain `:710`, `PerEpochReplayWatermark`)
- Date: 2026-06-21 · Severity: **Low / Question** (transient anti-rollback reset; high exploitation bar — operator-root-gated trigger + privileged delivery + same-genesis redeploy; mirrors pre-existing Linux behavior). Severity rests on the re-enroll genesis-rotation policy (the Question).
- Bar mapping: SecurityMinimumBar §3/§4 (anti-replay / rollback protection where freshness matters); CWE-294 (capture-replay) / CWE-693 (protection-mechanism failure).
- Reachability / attacker: `clear_residual_state` (52e7463) deletes the `membership/`+`trust/` signed-state and `rustynetd.state` on operator bootstrap, **including the `SKIP_BUILD` redeploy-onto-a-prior-enrollment path** (the test `bootstrap_script_clears_stale_signed_state_on_fresh_enroll` asserts it runs in both paths), which resets the per-epoch anti-replay watermark to 0. This is **correct** for a genuine fresh enrollment (a new genesis legitimately resets the epoch — the comment is explicit that the *running* daemon's between-enrollment anti-rollback is unchanged). Verified the binding model: membership *updates* are bound to `network_id` (mismatch rejected, `membership.rs:696`) and strictly chained (`epoch_prev == state.epoch`, `:710`), but the **genesis snapshot** ingested after the wipe is accepted at face value (no surviving watermark to compare). So the reset is safe-by-construction **only if re-enrollment rotates the genesis** (new `network_id` + new authority verifier key — as the lab does: `NetworkId=rn-live-lab-<ts>`). If a redeploy **reuses** the same `network_id`+authority key, the watermark was the sole rollback guard, and between the wipe and the legitimate re-distribution there is a window in which a captured, still-validly-signed *older* membership snapshot (e.g. one listing a since-revoked node as Active) would be accepted, advancing the daemon to that lower epoch. Exploitation bar is high: (1) the wipe needs operator root to trigger; (2) delivery needs write access to the daemon's signed-state ingestion path (local privilege) or defeating the authenticated SSH distribution; (3) the window closes once the current bundles re-establish the watermark; (4) it mirrors the pre-existing Linux `rm -rf /var/lib/rustynet`.
- Risk: a re-provision/redeploy that reuses the genesis transiently disables rollback protection on trust/membership state — a narrow replay/rollback window (e.g. re-activating a revoked node).
- Proposed enforcement (review-only — do NOT apply): make the reset safe-by-construction rather than safe-by-timing — guarantee re-enroll/redeploy mints a **fresh genesis** (rotate `network_id` + authority verifier key) so pre-reset bundles are cryptographically rejected after the wipe regardless of watermark; OR persist a minimal monotonic "highest-epoch-ever-seen for this `network_id`" floor *outside* the wiped dirs so a same-genesis redeploy cannot ingest a lower epoch; document which guarantee the production re-enroll flow provides. **Owner question:** does production re-enrollment/redeploy always rotate the genesis, or can it reuse `network_id`+authority key (the `SKIP_BUILD` case)? If always-rotate ⇒ downgrade to Info.
- Justification / source: SecurityMinimumBar §3/§4 (anti-replay/rollback); CWE-294 "Authentication Bypass by Capture-replay" — https://cwe.mitre.org/data/definitions/294.html ; CWE-693 "Protection Mechanism Failure" — https://cwe.mitre.org/data/definitions/693.html (accessed 2026-06-21).
- Verification method: confirm the production re-enroll flow rotates `network_id`+authority key (then safe-by-construction); else a negative test that a lower-epoch snapshot is rejected after a same-genesis redeploy.
- Status: **open** (net-new, Low/Question; 2026-06-21)

### RSA-0080 — macOS bootstrap deletes the WireGuard passphrase with `rm -f` (no secure-erase); fails the secrets-hygiene gate in HEAD and reflects no actual secure-deletion of key material
- File: `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:899` (`rm -f "${KEYS_DIR}/wireguard.passphrase"`, the Phase-E stale-copy cleanup); sibling un-flagged sensitive `rm -f` at `:1048` (`${runtime_key}`), `:1120` (`${passphrase_file}`), `:942` (trap on `${passphrase_tmp}`); scanner rule `crates/rustynet-cli/src/ops_phase1.rs:2147-2183`
- Date: 2026-06-21 · Severity: **Low** (insecure deletion of key material — CWE-459 — **plus a live mandatory-gate failure in HEAD**: `secrets_hygiene_gates.sh` exits 78). Real-world recoverability is bounded by APFS copy-on-write + FileVault.
- Bar mapping: SecurityMinimumBar §4 (key custody / secret hygiene); CLAUDE.md §7 (mandatory gates must pass); CWE-459 (incomplete cleanup) / CWE-212 (improper removal of sensitive information).
- Reachability / attacker: a post-baseline commit's Phase-E migration (moving `wireguard.passphrase` from `keys/` to `bootstrap/`) added `rm -f "${KEYS_DIR}/wireguard.passphrase"` at `:899`. The secrets-hygiene scanner (`ops_phase1.rs:2147`) textually flags any `rm -f` line containing a literal sensitive filename (`wireguard.passphrase`) and prescribes the shell helper `secure_remove_file`. Verified first-hand: (1) the gate **fails closed in HEAD** — `security_regression_gates.sh` → `secrets_hygiene_gates.sh` exits 78 citing `:899`; (2) the prescribed helper `secure_remove_file` is **not defined anywhere** under `scripts/`; (3) the sibling sensitive-material removals at `:1048/:1120/:942` use shell *variables*, so they evade the textual scanner while being equally non-secure — i.e. the macOS bootstrap performs **no actual secure deletion** of passphrase/key material, it only avoids the literal-name match. Not externally reachable (operator-root provisioning); the harm is plaintext key material left recoverable in freed disk blocks + a red release gate. **Note: switching `:899` to a variable would *game* the scanner without improving security — explicitly NOT the fix.**
- Risk: a WireGuard key passphrase (and the plaintext runtime key) may remain recoverable after bootstrap; the secrets-hygiene release gate is red, blocking a clean mandatory-gate run.
- Proposed enforcement (review-only — owner design decision): define a real `secure_remove_file` shell helper (`ops secure-remove --path` once the daemon binary is present; else best-effort overwrite with an honest comment that APFS copy-on-write + FileVault bound its efficacy) and apply it consistently at **all** sensitive-material removals (`:899/:1048/:1120/:942`), not only the literally-named one; OR, if `rm -f` is accepted on FileVault/APFS, document that decision and tighten the scanner so it cannot be silently evaded by variable indirection. Either way, restore the gate to green honestly.
- Justification / source: CWE-459 "Incomplete Cleanup" — https://cwe.mitre.org/data/definitions/459.html ; CWE-212 "Improper Removal of Sensitive Information Before Storage or Transfer" — https://cwe.mitre.org/data/definitions/212.html (accessed 2026-06-21); Apple APFS copy-on-write (secure-erase efficacy); CLAUDE.md §7.
- Verification method: `bash scripts/ci/security_regression_gates.sh` exits 0; scanner self-test covers the helper; no un-secure `rm -f` on sensitive material remains (or documented, scanner-enforced exceptions).
- Status: **open** (net-new, Low; gate-blocking in HEAD; owner decision on helper-vs-accept; 2026-06-21)

### RSA-0081 — macOS service-hardening check still expects the WG passphrase at `keys/`, but Phase-E moved it to `bootstrap/`; the posture check now validates a stale path (degraded assurance + false-drift on a correct install)
- File: `crates/rustynetd/src/macos_service_hardening.rs:260` (`evaluate_macos_launchd_environment` hardcodes expected `RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH == "/usr/local/var/rustynet/keys/wireguard.passphrase"`), reinforced by the reviewed fixture at `:376/:399/:429-431`; diverged from `scripts/bootstrap/macos/Install-RustyNetMacosService.sh` (444a1a6) which now emits `${STATE_ROOT}/bootstrap/wireguard.passphrase` (or omits the var entirely in the keychain-only case). Same Phase-E root cause as RSA-0080.
- Date: 2026-06-21 · Severity: **Low** (security-*assurance* drift, not runtime enforcement — `rustynetd macos-service-hardening-check` is an operator/CI subcommand `main.rs:232`, not a startup gate, so the daemon does not brick. Rises toward Medium if that check is wired into a release/live-lab gate.)
- Bar mapping: SecurityMinimumBar §4 (key-custody verification); CLAUDE.md §6 (keep validators synced with implementation); CWE-684 (incorrect behaviour of a protection mechanism) / CWE-1059 (insufficient verification).
- Reachability / attacker: not attacker-driven. The Phase-E key-custody change (444a1a6) deliberately relocated the WG decrypt passphrase `keys/`→`bootstrap/` (so the `keys/`-only `macos-key-custody-check` does not flag it) and re-pointed the plist's `RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH` accordingly — but `evaluate_macos_launchd_environment` (`macos_service_hardening.rs:259-266`) still hardcodes `.../keys/wireguard.passphrase` and pushes a drift reason → `overall_ok=false` (`:328`) otherwise. Verified `macos_service_hardening.rs` was **not** touched in the post-baseline delta (`git log 576401e..HEAD` empty for it). Net effect on a canonical `/usr/local/var/rustynet` install: (a) **false-positive failure** — the check reports drift on a correctly Phase-E-installed node (whether the credential path is set to `bootstrap/...`, → drift, or omitted in the keychain-only case, → "missing"); (b) **degraded assurance** — the check validates a path (`keys/wireguard.passphrase`) that by design no longer holds the passphrase, so it would not detect a real custody problem at the true location (`bootstrap/wireguard.passphrase`); the golden fixture (`:376/:399/:429`) is self-consistent with the stale expectation, so the self-tests don't catch the drift.
- Risk: a key-custody posture-verification control silently checks the wrong location → false confidence that WG passphrase custody is verified, plus a check that fails on correctly-installed nodes (gate breakage if wired into CI/live-lab).
- Proposed enforcement (review-only — do NOT apply): update `macos_service_hardening.rs` (the `:260` expectation + the `:376/:399/:429-431` fixture) to the Phase-E reality — accept the `bootstrap/wireguard.passphrase` credential path AND the keychain-only case (absence of `CREDENTIAL_PATH` when the daemon relies on the keychain account/service must not be "drift"); add a parity test pinning the validator's expected paths to the install script's emitted paths so they cannot diverge again.
- Justification / source: CWE-684 — https://cwe.mitre.org/data/definitions/684.html ; CWE-1059 — https://cwe.mitre.org/data/definitions/1059.html (accessed 2026-06-21); CLAUDE.md §6 (validator/impl sync); macOS keychain custody model (SecurityMinimumBar §4).
- Verification method: `rustynetd macos-service-hardening-check` reports `overall_ok=true` on a Phase-E install (file-fallback AND keychain-only); a parity test asserts the validator's expected credential path equals the install script's emitted path.
- Status: **open** (net-new, Low; assurance drift, shares Phase-E root cause with RSA-0080; 2026-06-21)

---

## Supply-chain evidence (Tier 4, live gates — 2026-06-18)

Read-only gates run on the working tree (commit per `git rev-parse HEAD`):
- `cargo audit` — fetched the RustSec advisory DB (1134 advisories), scanned **210
  crate dependencies** from the committed `Cargo.lock` → **0 vulnerabilities** (exit 0). Satisfies **S1** (no unaddressed RustSec advisory).
- `cargo deny check advisories bans sources` → **advisories ok, bans ok, sources ok**
  (exit 0). `[sources] unknown-registry = "deny"` passes (no untrusted registry/git
  source); the `[bans]` denylist for md5/sha1/des/rc4 holds (none present). Satisfies
  **S2** + the no-banned-crate control.
- **Info note (S1 duplicates):** the dep graph carries duplicate `windows-sys`
  versions (`0.59` and `0.61.2`), tolerated by `deny.toml`'s `wildcards = "allow"`.
  Not a vulnerability — a build-bloat / larger-surface observation; consider tightening
  to `wildcards = "deny"` and de-duplicating once upstream crates converge.
- **Not yet run this pass:** `cargo deny check licenses` (the `[licenses]` allow-list
  exists; defer to the Tier-4 completion), and `cargo audit --deny warnings` (the plain
  `cargo audit` was clean). `cargo geiger` (S4 unsafe inventory) not run.

---

## Appendix A — Sources cited in this audit (with access date 2026-06-18)

**Repo-internal authorities (precedence per CLAUDE.md):** `documents/Requirements.md`;
`documents/SecurityMinimumBar.md` (§3.1–3.9, §4, §5, §6.B–6.E, §10); `documents/
SecurityAnalysis_2026-06-12.md`; `documents/operations/active/SecurityReview_2026-05-24.md`
(RN-01..RN-24, RL-1..12); `SecurityAndQualityAudit_2026-06-10.md` (AUDIT-001..053);
`SecurityHardeningBacklog_2026-06-01.md` (HB-1..7); `FullRepoAnalysis_2026-05-24.md`;
`documents/operations/adr/ADR-001-secret-log-audit.md`; `CLAUDE.md`/`AGENTS.md` §3/§4/§8/§10.

**Cryptography:** Latacora "Cryptographic Right Answers" — https://www.latacora.com/blog/cryptographic-right-answers/ ;
NIST SP 800-131A Rev 2 (algorithm transitions) — https://csrc.nist.gov/pubs/sp/800/131/a/r2/final ;
NIST SP 800-57 Pt 1 Rev 5 (key management) — https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf ;
RFC 8032 (Ed25519 strict verification).

**Rust secure coding:** ANSSI Secure Rust Guidelines — https://anssi-fr.github.io/rust-guide/ ;
CLAUDE.md §10.2 (no panic/unwrap on production paths).

**Supply chain:** RustSec Advisory Database — https://rustsec.org/ ; cargo-deny —
https://github.com/EmbarkStudios/cargo-deny ; Microsoft Rust supply-chain guidance —
https://microsoft.github.io/RustTraining/engineering-book/ch06-dependency-management-and-supply-chain-s.html .

**Weakness taxonomies (CWE — https://cwe.mitre.org/):** CWE-20 (input validation),
CWE-22 (path traversal), CWE-77/78 (command/argument injection), CWE-117 (log injection),
CWE-125 (out-of-bounds read), CWE-190 (integer overflow), CWE-208 (timing), CWE-214
(argv secret exposure), CWE-248 (uncaught exception/panic), CWE-250 (unnecessary
privilege), CWE-285/863 (improper authorization), CWE-294 (replay), CWE-347 (improper
signature verification), CWE-350 (DNS-based trust), CWE-362 (race), CWE-367 (TOCTOU),
CWE-400/770 (resource exhaustion), CWE-406 (amplification), CWE-532 (secret in log),
CWE-636/684/693/1006 (fail-open / protection-mechanism failure / control-not-in-prod),
CWE-664 (improper lifecycle), CWE-732 (incorrect permission), CWE-778 (insufficient
logging), CWE-918 (SSRF), CWE-1236 (CSV formula injection); CWE-88 (argument injection),
CWE-279 (insecure file perms on critical resource), CWE-295 (improper certificate
validation), CWE-322 (key exchange without entity authentication), CWE-426 (untrusted
search path), CWE-494 (download of code without integrity check), CWE-754 (improper check
of unusual condition). OWASP ASVS 5.0 — https://github.com/OWASP/ASVS ; OWASP CSV Injection.

**Finding-ID note:** IDs run RSA-0001..RSA-0074 with **RSA-0062 retired** (renumber during
synthesis — its two file rows now cite RSA-0061, which covers the same two harnesses), so
the corpus is **74 standing findings** (76 raised, RSA-0030/0051 withdrawn). Post-coverage theme sweeps added RSA-0075 (numeric-truncation), RSA-0076 (clippy-lint-config), RSA-0077 (verify_strict scope, 2026-06-20); the post-baseline commit-delta sweep (`576401e..HEAD`, 2026-06-21, **now complete**) added RSA-0078 (state-lock cross-UID recovery, Info), RSA-0079 (fresh-enroll watermark reset window, Low/Question), RSA-0080 (macOS bootstrap insecure passphrase deletion, Low — gate-blocking in HEAD), and RSA-0081 (macOS service-hardening check stale `keys/` path, Low — assurance drift). **CLEAN** in the same sweep (no finding): the `57586be` Windows signed-bundle distribution (`live_lab_common.sh` — ACL re-harden correct + fail-closed, preserves verify-before-apply), `bde69a9` trust-passphrase ACL fix, the `56363c8` Windows `--offline` build fallback (fail-closed), and the orchestrator-shell platform-dispatch SSH probes (no eval/injection in added lines). **RSA-0077 landed as applied** (`6e0d0f0`, 2026-06-21), which also **closes RSA-0043**. **Running corpus: 83 raised** (RSA-0077 applied; RSA-0043 closed; RSA-0030/0051 withdrawn; RSA-0062 retired).

_(Each finding entry cites the specific rule/section it invokes; this appendix is the
consolidated index of sources actually cited. Audit pass COMPLETE — 594/594 files.)_

---

## Adversarial re-verification pass (2026-06-19)

Findings were re-checked against the code with a *refute* mandate ("prove this is NOT a
weakness / is over-rated / is unreachable").

**Manual re-read of the highest-stakes Mediums** (the must-patch findings not already
read first-hand): **RSA-0025** (Win `.enc` written via `KeyCustodyPermissionPolicy::default()`
+ non-unix no-op — **CONFIRMED**), **RSA-0047** (`reader.lines()` genuinely unbounded —
**CONFIRMED**), **RSA-0059** (`peer_id`=`node_id` interpolated raw into the PS `throw`
literal at `windows_membership.rs:107` while `--node-id` is `ps_quote`'d — **CONFIRMED**),
**RSA-0031** (`capture_pf_anchor_state(...).unwrap_or((false,…))` conflates pfctl exec-failure
with anchor-absent — **CONFIRMED** fail-open primitive; severity retained Medium with the
caveat that impact depends on whether the snapshot *gates* revocation vs. is telemetry).
**Two over-statements corrected → downgraded Medium → Low:** **RSA-0052** and **RSA-0053**
(overnight driver) — first-hand re-read found the safety envelope the original framing
called missing is substantially present (dry-run default, trunk-name refused fail-closed,
fail-closed denylist classification, no `git push`); the valid residual (active-checkout
not enforced; bare `git clean -fd` coupled to it) is Low. No outright false-positives in
the Medium set. Severity tallies updated (Medium 17→15, Low 34→36; total unchanged at 75).
The 2 Highs (RSA-0009, RSA-0063) were re-confirmed first-hand earlier and stand.

**Multi-agent adversarial sweep (8 agents, refute-mandate) over the remaining ~52
Low/Info/Question/unverified-Medium findings — verdicts: 42 CONFIRM · 3 DOWNGRADE ·
2 FALSE_POSITIVE · 4 NEEDS_HUMAN (the already-Question items, unchanged).** Every
non-CONFIRM was then **re-verified first-hand by the auditor** before changing the ledger:

- **WITHDRAWN as false-positive (2)** — verified against the code:
  - **RSA-0030** (RN-09 systemd-credential test-gap) — the claimed-missing control **exists**:
    `key_material.rs:628-658` gates the wider `0o037` mask on parent-dir verification
    (root-or-owner-owned, no world access, no group-write, symlink-rejected, systemd-tmpfs
    rationale documented), and the negative test is at `:1418-1468` (added by commit `1525cae`).
    My test-gap claim was incorrect.
  - **RSA-0051** (ops_e2e `network_id`→bash "shell injection") — `run_status` (`ops_e2e.rs:5042-5049`)
    is `Command::new(program).args(args)`; `network_id` is a discrete **argv** element (bash
    positional `$2`), not concatenated into a shell string, and the script re-validates it via
    `case`. The stated injection mechanism does not exist.
- **DOWNGRADED (3)** — real but over-rated:
  - **RSA-0034** gossip-ingest revocation-recheck: Question → **Info** — the gossip subsystem is
    **dormant in the shipped daemon** (`gossip_node` is `None` at `daemon.rs:3847`; `attach_gossip_runtime`
    is `#[allow(dead_code)]` with no caller), and the only applied state is endpoint hints, not trust.
  - **RSA-0035** uPnP SSRF: Question → **Info** — **no production enablement path** (`upnp_enabled` is
    always `false`; `with_upnp_enabled` has no caller), so the SSDP/uPnP fetch never runs in the shipped
    binary. Real latent defect to fix before uPnP ships; reachability currently zero.
  - **RSA-0056** remote_shell env-key injection: Low → **Info** — the unquoted-KEY defect is real but
    **no production caller passes any env**, so attacker-influence reachability is nil.
- **NEEDS_HUMAN (4 = RSA-0014, RSA-0018, RSA-0024, RSA-0045)** — all re-confirmed as genuine
  Question-class (owner decisions / backlog carries), already classified as such. No change.
- **42 CONFIRM** — re-verified at the stated severity (the bulk of the corpus stands as written).

**Net after the full re-verification (manual + sweep): 75 raised → 2 withdrawn (FP) →
73 standing findings** as of 2026-06-19. (A subsequent 2026-06-20 verification-bypass
sweep added **RSA-0077** → **76 raised, 74 standing**: 0 Critical · 2 High · 15 Medium ·
34 Low · 19 Info · 4 Question.) The 2 Highs and all 15 Mediums survived adversarial
re-verification.

---

## Ledger self-consistency QA (2026-06-19)

Definition-of-Done verification run programmatically over this ledger:
- **Coverage:** 594/594 tracked code/config files have a dated row — **0 `pending`**
  (528 `audited` + 66 `open`).
- **Findings ↔ rows (refreshed 2026-06-20):** 76 detailed `### RSA-####` entries (74
  standing + 2 withdrawn-but-retained); 67 coverage-table `FINDINGS` rows citing 73 distinct
  ids. **0 dangling references** (every id cited by a row has a detailed entry) and **0
  `PASS` rows leaking an RSA id** in the findings column.
- **Intentionally row-less entries (cross-cutting / withdrawn, by design):** **RSA-0045**
  (B.4.1 resolver RFC1918 answer-filter — carry to the daemon DNS responder) and **RSA-0073**
  (vendored boringtun `device/`/`ffi/`/`jni` dead-code — spans many uncompiled files), both
  deliberate; plus **RSA-0051** (withdrawn FP — its row reverted to PASS so it is correctly no
  longer cited as a finding). None are dangling.
- **Numbering:** range RSA-0001..RSA-0077 with **RSA-0062 retired** and **RSA-0030/0051
  withdrawn** (entries retained, marked WITHDRAWN) → **74 standing**, no other gaps.
- **No-change guarantee:** the audit modified only this ledger + the `active/README.md`
  index (plus the separately-authorised `daemon.rs` scratch-comment cleanup). No
  production code, crypto, or config was changed by the audit; all 74 standing findings are
  review-only proposals awaiting human approval.

**Verdict: the review-only audit pass is complete and internally consistent.** Release
posture per SecurityMinimumBar §2: **2 High controls are unmet on reachable paths**
(RSA-0009 revocation/rotation non-functional; RSA-0063 macOS bootstrap privesc residue) —
each requires documented risk-acceptance or a fix before the next security milestone; no
unmet **Critical** control was found.


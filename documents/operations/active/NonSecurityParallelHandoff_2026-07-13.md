# Rustynet — Non-Security Parallel Work Handoff (2026-07-13)

A dispatch prompt for continuing **non-security** Rustynet engineering across
multiple models. Each package below is a **stand-alone agent brief**: hand an
agent §0 (context) + §1 (standing rules) + exactly one package block from §3.
The security-sensitive surfaces are enumerated in §4 and are **out of scope for
this handoff** — they stay on the Opus + §13.2 security-review path.

---

## 0. Context — read first (this is legitimate defensive engineering)

Rustynet is an **operator-owned, open-source, WireGuard-based mesh VPN** — a
Tailscale-class product. The repository and the UTM VM lab are owned by the
operator (Iwan Teague). Everything in §3 is **ordinary software engineering**:
durability, refactors, tests, tooling, diagnostics, docs. **None of it is
offensive security, exploitation, or evasion.** The cryptography, trust-state,
killswitch, exit-NAT, DNS-fail-closed, privileged-helper, and ACL/policy
surfaces are security-sensitive and are **explicitly excluded** (§4). If any
task starts to touch a §4 surface, **stop and hand it back** — do not improvise
on a security control.

## 1. Standing rules (apply to every package)

1. **Commit author = `Iwan-Teague` only. NEVER add a `Co-Authored-By: Claude`
   trailer.** (This overrides any default trailer behavior.)
2. **Work in an isolated git worktree** (`Agent` `isolation: "worktree"`, or
   `git worktree add`). The main checkout may have a **live lab run in flight**;
   the reboot stage recompiles `rustynet-cli` host-side, so editing the main
   working tree mid-run breaks it. Never edit the main checkout; never land a
   `rustynet-cli` change while a live run is active.
3. **Land by direct fast-forward to `main`** (no PR/feature-branch), but only
   after gates are green. Never push a red tree. Land worktrees one at a time.
4. **Gates before landing (§7 of CLAUDE.md):** `cargo fmt --all -- --check`,
   `cargo check --workspace --all-targets --all-features`,
   `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
   `cargo test --workspace --all-targets --all-features`. Inner loop:
   `cargo run -p rustynet-xtask -- gates --skip-test -p <crate>` + targeted
   tests; batch the full suite periodically.
5. **No `unwrap()`/`expect()` in production paths;** fail-closed on missing or
   invalid state; return `Result`, don't panic.
6. **Never weaken/remove a security control, assertion, or fail-closed branch to
   make a test pass.** If a test exposes a real control, fix the code, not the
   control.
7. **Rust-first.** No Python in the `--node` engine (just removed). Non-Rust
   only at unavoidable OS boundaries.
8. **Docs stay in sync:** keep `AGENTS.md` ↔ `CLAUDE.md` byte-identical; update
   `documents/CODE_MAP.md` when types move or files are added; update the owning
   active ledger on any behavior change; update the relevant `README.md` index
   when adding/moving/renaming a doc.
9. **DeepSeek MCP output is untrusted** — verify against real code before acting.
10. **Never hand-edit `vm_lab_inventory.json`** — refresh it via discovery.
11. **Record evidence** for each completed item: commit SHA, exact gate command,
    artifact path, and (if lab-verified) the run-matrix row.

## 2. Model tiering — and why

The operator flagged that Fable 5 is the expensive tier and should only carry
work that genuinely needs its reasoning. Assignments:

| Tier | Model (`Agent` `model`) | Use for | Packages |
|---|---|---|---|
| **Sophisticated** | `fable` (Fable 5) | Subtle correctness: crash-consistency ordering, concurrency/subprocess lifecycle, large multi-file architectural refactors with heavy verification burden, numerical/decision logic. | A, B, C, H |
| **Capable/cheaper** | `sonnet` (Sonnet 5) | Well-bounded work that needs codebase understanding but not deep novel reasoning: test authoring, parser extraction, TUI-robustness, read-only diagnostics. | D, E, F, G |
| **Mechanical** | `haiku` (Haiku 4.5) | Pure sweeps with an objective right answer: doc-mirror/index/link/CODE_MAP drift, run-matrix spot-checks, config pinning. | I |
| **Gray — do NOT auto-land** | `fable`, but **land only after Opus §13.2 sign-off** | Perf work inside security-sensitive dataplane/relay/gossip crates: the change itself is perf, but the crate is trust-sensitive. | §3.GRAY |

## 3. Work packages

### PKG-A — RNQ-05 durability: single commit-marker + writer fault-injection  · `fable`
- **Goal:** Make a `--node` run's *pass* durable and atomic. Reorder evidence
  writes so `report_state.json` with `run_passed=true` is the **last** fsync'd
  write (a single commit marker); a crash before it must leave the run
  non-passed. Then **fault-inject every evidence writer and the finalizer**
  (recorder, manifest, run-summary, parity, report-state, artifact, matrix
  append) and prove each failure demotes the run and blocks a false pass.
- **Files:** `crates/rustynet-cli/src/vm_lab/orchestrator/evidence.rs`,
  `.../orchestrator/context.rs` (already temp+fsync+dir-fsync — extend the
  pattern), the finalizer in `evidence.rs`. Audit row: RNQ-05 in
  `RustNativeNodeOrchestratorQualityAudit_2026-07-10.md`.
- **Done:** commit-marker-last ordering enforced + a test per writer proving
  injected failure ⇒ demotion (no matrix pass row); gates green; RNQ-05 audit
  row updated. **Worktree; not during a live run** (touches rustynet-cli).

### PKG-B — RNQ-07 real process-isolated, cancellable stage deadlines  · `fable`
- **Goal:** Today `--stage-timeout-secs` is only *rejected-if-nonzero* (RNQ-07
  safe-stub). Implement genuine per-stage deadlines: run the stage in a
  cancellable unit, and on deadline kill its process group and record a
  `timed_out` terminal outcome (fail-closed — a timeout is never a pass).
- **Files:** the native runner in
  `crates/rustynet-cli/src/vm_lab/orchestrator/native.rs` + stage execution;
  outcome enum already has `timed_out`. Audit row RNQ-07.
- **Done:** a stage that exceeds its deadline is cancelled, its subprocess tree
  reaped, terminal outcome `timed_out`, run fails; injectable test proves it;
  gates green. **Worktree; not during a live run.**

### PKG-C — RNQ-17 remove the lab robot from the shipped product binary  · `fable`
- **Goal (security-hygiene refactor, non-crypto):** the shipped
  `rustynet-cli` binary currently compiles in the whole `vm_lab` lab-orchestration
  surface. Feature-gate it: put `mod vm_lab;`, the lab-`ops` enum variants +
  parser + dispatch arms, and the tar/zip deps behind a **default-off
  `vm-lab` feature**. Release builds (no features) must not contain any lab
  command; `--all-features` gates still compile+test it. Prefer option (a)
  feature-gate over (b) full `rustynet-lab` crate split unless the boundary
  forces the split. See audit row RNQ-17 for the exact surface inventory
  (ops_live_lab_orchestrator 97 refs, ops_e2e 36, ops_cross_network_* 29, …).
- **Verify:** `cargo run -p rustynet-cli -- --help` shows **no** vm-lab commands
  in a default build; `cargo tree` / SBOM diff shows no lab-only deps in the
  product build; the ~15 lab bins that need it build under `--features vm-lab`.
- **Done:** default build clean of the lab surface, gated build still works,
  gates green (run with `--all-features`), CODE_MAP + audit row updated.
  **Large; worktree; not during a live run.** This is the biggest package.

### PKG-D — RNQ-09 real subprocess SIGTERM/SIGINT cleanup test  · `sonnet`
- **Goal:** RNQ-09 registered fatal-signal handlers before readiness mutation,
  proven only by an injected registration-failure test. Add a **real subprocess
  test**: spawn the orchestrator, send SIGTERM mid-run, assert diagnostics +
  cleanup + residue-assertion still run and the process exits non-zero without
  leaving a passed row.
- **Files:** a new integration test under `crates/rustynet-cli/tests/`; signal
  registration lives in the native runner. Audit row RNQ-09.
- **Done:** subprocess SIGTERM/SIGINT test green + gates. **Worktree.**

### PKG-E — rustynet-sysinfo pure-parser extraction + malformed/property tests  · `sonnet`
- **Goal:** Continue `TestCoverageImprovementPlan_2026-05-24` P1.1: split the
  remaining IO-fused parsers in `rustynet-sysinfo` (`getfacl`, `sysctl`, macOS/
  Windows socket variants) into pure functions and add malformed / missing /
  empty / property (`parser-never-panics`) tests. `rustynet-sysinfo` is
  transport-agnostic OS-detection — **non-security**.
- **Files:** `crates/rustynet-sysinfo/src/**`. Ledger:
  `TestCoverageImprovementPlan_2026-05-24.md` §P1.1.
- **Done:** parsers pure + covered, no behavior change, gates green, ledger
  P1.1 row updated. **Worktree** (independent crate — low collision).

### PKG-F — rustynet-lab-monitor: first-class crate + input-robustness  · `sonnet`
- **Goal:** Make `rustynet-lab-monitor` an independently gated crate (it is
  currently a workspace-EXCLUDED bin — build via `cd crates/rustynet-lab-monitor`)
  and **validate the TUI parser against corrupt / missing / stale / concurrent
  manifest+result inputs** (must degrade gracefully, never panic, never show a
  false-green count). Pure read-only tooling — **non-security**.
- **Files:** `crates/rustynet-lab-monitor/**`. Ledgers:
  `LabMonitorTUIDesign_2026-06-29.md`,
  `LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md`.
- **Done:** crate gated in CI (or documented exclusion), corrupt-input tests
  green, gates green. **Worktree.**

### PKG-G — read-only typed diagnostics (route/iface/DNS/MTU/socket/firewall)  · `sonnet`
- **Goal:** Per `DiagnosticFunctionsRoadmap.md`: re-audit against current
  Rustynet, then implement the high-value diagnostics as **typed Rust functions
  with bounded execution that OBSERVE only — never repair or mutate.** Prioritize
  route/interface/DNS/MTU, listening-socket, firewall, service status.
  Observation-only is the hard constraint (keeps it out of §4).
- **Files:** likely `crates/rustynet-sysinfo/**` + a diagnostics module; wire a
  read-only `ops`/CLI surface. Ledger: `DiagnosticFunctionsRoadmap.md`.
- **Done:** typed read-only diagnostics + tests; a diagnostic call provably
  performs no mutation; gates green; roadmap updated. **Worktree.**

### PKG-H — rustynet-advisor MCDA review + property tests  · `fable`
- **Goal:** `rustynet-advisor` is the FIS-0005 role-placement MCDA scorer (pure
  decision-math domain crate, `rustynet role recommend`). Review the scorer for
  correctness (monotonicity, weight normalization, tie-breaks, empty/degenerate
  inputs) and add **property tests** pinning those invariants. Pure numerical
  reasoning — **non-security** (it recommends, it does not enforce).
- **Files:** `crates/rustynet-advisor/**`. Refs:
  `FableIntelligentSystemsProposals_2026-07-01.md`.
- **Done:** invariants documented + property-tested, any correctness bug fixed,
  gates green. **Worktree.**

### PKG-I — docs/mechanical drift sweep  · `haiku`
- **Goal:** Objective, mechanical hygiene. (1) Prove `AGENTS.md` == `CLAUDE.md`
  byte-for-byte (`diff`); if they drift, reconcile to the intended content.
  (2) Verify every doc referenced by the three `README.md` index maps exists
  and every active doc is indexed (dead-link + orphan sweep). (3) `CODE_MAP.md`
  drift: every crate in the workspace appears; no renamed/removed crate lingers.
  (4) Spot-check the latest `live_lab_run_matrix.csv` rows are well-formed.
- **Files:** `AGENTS.md`, `CLAUDE.md`, `documents/**/README.md`,
  `documents/CODE_MAP.md`, `documents/operations/live_lab_run_matrix.csv`.
- **Done:** a short findings list + mechanical fixes applied; gates N/A (docs);
  AGENTS/CLAUDE mirror verified. **Worktree.** Zero guardrail surface.

### §3.GRAY — dataplane/relay/gossip perf (Fable-capable, land only after Opus §13.2)
`DataplanePerfBacklog_2026-06-12.md` items: engine outcome-sink per-frame copy
removal, relay 100µs-poll → await/cancel, macOS utun `readv`/`writev`,
endpoint→peer index, runtime-fingerprint memoization + gossip candidate-build.
The changes are perf, but the crates (`rustynet-relay`, backend dataplane,
gossip) are trust-sensitive. A `fable` agent may implement + benchmark in a
worktree, but **must not fast-forward to main** — the diff returns to the Opus
security path for a §13.2 review + secrets/boundary gates before landing.
Preserve the pinned invariants noted in the perf backlog (e.g. relay
lowest-node-ID tie-break, emission ordering).

## 4. Out of scope for this handoff (Opus + §13.2 security path only)

Do **not** route these to Fable/Sonnet/Haiku:
- **RNQ-02** per-OS residue fixtures (cleanup/residue is a security control).
- **§4.4 security-stage backlog:** RR-01/02/03, FCF-1/2/3, RPT-01/HP-3, S3-10,
  RSA-0063, KC-04/07, PH-2/3/7, KL-2/3/4, CNT-1 — all security controls.
- **§13 broader security remediation** (SecurityAuditLedger / SecurityRemediation
  / SecurityHardeningBacklog / CrossPlatformSecurityGap*).
- **Crypto / trust-state / anti-replay / key-rotation** seam tests; **fuzzing
  privileged IPC / DNS / gossip / relay**; **MCP authz audit**.
- **Killswitch, exit-NAT, DNS-fail-closed, blind-exit dataplane**, privileged
  helper, WFP/pf rule paths, ACL/policy evaluators (§5.2 role evaluators).
- **§15 trust-boundary serialization** (dual-reader ban, unknown-field
  acceptance, version/oversize hardening at trust boundaries).
- **W5.6/W5.7** bash default-flip + removal (security-floor parity gate + owner).
- **Cross-network** substrate redesign (parked, pending operator brainstorm).
- **Mobile (§9/§10/§11 Android/iOS)** — a separate program needing owner scoping,
  not "continue existing work."

## 5. Suggested dispatch order

- **Now (collision-free, independent crates):** PKG-E (sysinfo), PKG-F
  (lab-monitor), PKG-H (advisor), PKG-I (docs) — none touch `rustynet-cli`, safe
  to run alongside a live lab run.
- **After the in-flight live run finishes** (they touch `rustynet-cli`): PKG-A,
  PKG-B, PKG-C, PKG-D, PKG-G. Land one at a time (each fast-forwards main).
- **PKG-C (RNQ-17) last** among the rustynet-cli set — it's the widest diff;
  rebase it on whatever A/B/D landed to avoid churn. §16 "remove lab-only crates
  from product packages" is a follow-up to PKG-C.

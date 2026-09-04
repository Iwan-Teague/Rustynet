# FullTodoInventory Adversarial Review — 2026-09-04

## Status

**UNTRUSTED adversarial audit** of `documents/operations/active/FullTodoInventory_2026-07-28.md` (994 lines) against the actual tree, performed 2026-09-04 in worktree `state/edit-worktrees/edit-1788542026681-26537-8` on branch `ai-edit/edit-1788542026681-26537-8` (HEAD `a67fcbfc`). Every classification below was re-derived from the live tree by grep/read and, for commit claims, `git cat-file -t` + `git merge-base --is-ancestor`. Purely planning/subjective sections were skipped as not code-verifiable. This review does not modify the audited document; it records discrepancies for the inventory's owner to apply.

## Method

- SHA claims verified with `git cat-file -t <sha>` (existence) and `git merge-base --is-ancestor <sha> HEAD` (landed on this branch's history).
- Symbol/file claims verified with grep/read at exact paths; where the cited line number drifted but the mechanism is present, the finding is classified WRONG-CITE (minor) rather than stale.
- Ledger claims parsed with a quote-aware Python `csv` reader (per the repo's own warning about `awk -F,` misreads), against both `documents/operations/live_lab_node_run_matrix.csv` (the live Rust `--node` ledger) and `documents/operations/live_lab_run_matrix.csv` (the frozen bash archive).

## Findings table

Classification key: **CONFIRMED** (claim matches tree), **STALE-DONE** (doc claims open/planned; actually landed), **REGRESSED-CLAIM** (doc claims a done/never state the tree now contradicts), **WRONG-CITE** (right idea, wrong file:line/number), **UNVERIFIABLE** (not decidable from the tree).

| # | Inventory claim (line) | Tree reality | Classification |
|---|---|---|---|
| 1 | `--node` never passed `linux_stage_two_hop` (L68-70, repeated L937) | Live ledger: `linux_stage_two_hop` = **62 pass** / 35 fail / 136 skip / 39 not_run over 272 rows | **REGRESSED-CLAIM** — the single most misleading stale claim in the doc; two_hop has been passing on `--node` since the bad-alias fix landed |
| 2 | Bash archive records 52 `two_hop` passes (L68-70) | Bash archive: 56 pass / 17 fail / 76 skip / 392 not_run over 550 rows | WRONG-CITE (count drifted from 52 → 56; direction of the claim still holds for the archive) |
| 3 | ParityRefresh: `--node` ledger 88 rows, zero fully passing (L71-73) | Ledger now has 272 rows with 62 two_hop passes. The 88-row figure was a 2026-07-23 snapshot | Date-scoped snapshot, now superseded — needs refresh |
| 4 | `live_lab_run_matrix.rs:922` + `:2293` hold `acquire_append_lock` (§2a a) | Lock present at `crates/rustynet-cli/src/live_lab_run_matrix.rs:872` and `:2632`; shared `crates/rustynet-cli/src/append_lock.rs` | CONFIRMED (lines drifted; WRONG-CITE on line numbers only) |
| 5 | `MACOS_LAUNCHD_STOP_COMMAND` at `macos_traffic.rs:27-28` bootouts label + plist (§2a b) | Present at `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:68`; boots `system/com.rustynet.daemon` | CONFIRMED (line drifted) |
| 6 | iproute2 6.19 FIB fix at `phase10.rs:1091-1101`, tests `:11728-:11776` (§2a c) | Fix present: `crates/rustynetd/src/phase10.rs` narrow match + comments at :1789/:1806; tests at :17143/:17154/:17191 | CONFIRMED (file is in `rustynetd`, lines drifted) |
| 7 | Revoke stages `validate_linux_membership_revoke_applies` / `validate_linux_revoked_peer_denied_e2e` wired (§2a d) | Registered at `live_lab_stage_registry.rs:1779`/`:1789`; mapped in `live_lab_run_matrix.rs:3250`/`:3257`/`:4974`; stage fns at `vm_lab/mod.rs:23684` | CONFIRMED |
| 8 | Lock in `live_lab_stage_triage.rs` append path at `:228` (§2a e) | `use crate::append_lock::{acquire_append_lock, lock_path_for}` at `:60`; lock taken before the ledger critical section (~:225) | CONFIRMED (line drifted) |
| 9 | T2 wired at `live_lab_run_matrix.rs:710` (§2a f) | Triage stub wiring at `live_lab_run_matrix.rs:644-662` (`append_stubs_for_failed_stages`) | CONFIRMED (line drifted) |
| 10 | T4 write-half landed at `fd8c5d04` (§2a f) | `git cat-file -t fd8c5d04` = commit; ancestor of HEAD = yes | CONFIRMED |
| 11 | `fill_patch` defect fixed in `fd8c5d04` (L166-171) | SHA verified as landed (see #10); fix content not independently re-derived | CONFIRMED (SHA), fix-body UNVERIFIABLE from grep alone |
| 12 | Six harness items verified at SHA `2e742929` (L149) | `2e742929` is a commit and an ancestor of HEAD | CONFIRMED |
| 13 | `e0cc8e5` merged to main (AnchorBundlePull..., L183) | Commit exists, ancestor of HEAD | CONFIRMED |
| 14 | FIS-0015 blocker cleared at `16de276f` (L307) | Commit exists, ancestor of HEAD | CONFIRMED |
| 15 | G1 satisfied at `a414ceb` (NodeEngineFlipDispositions, L510) | Commit exists, ancestor of HEAD | CONFIRMED |
| 16 | Phase 4 groundwork `e6144250`, `PathMtuConfig::for_bringup_mtu` (L797) | `crates/rustynetd/src/path_mtu.rs:189` `pub fn for_bringup_mtu`; SHA landed | CONFIRMED |
| 17 | chaos_* stages exist on `--node`, `--enable-chaos-suite` in 0/178 runs (L189) | 43 chaos references in `live_lab_stage_registry.rs` (stages exist); dispatch count not re-derived (ledger grew) | Stage existence CONFIRMED; run-count date-scoped |
| 18 | HP-3: validator body exists at `vm_lab/mod.rs:13841`, no `--node` StageId; `linux_relay_forwards_frame` not_run in all rows (L428) | Validator present (`exercise_linux_relay_forwards_frame`, `vm_lab/mod.rs:14073`) **and now registered**: `live_lab_stage_registry.rs:1920-1922` (`validate_linux_relay_forwards_frame`, special `linux_relay_forwards_frame`) | **STALE-DONE** — the missing StageId gap has been closed |
| 19 | `relay_validation` lifecycle-only framing (`role_validation/relay.rs:142-145`, L555) | `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/relay.rs` carries the lifecycle-only doc framing | CONFIRMED (framing present) |
| 20 | BashRetirementPlan: "W5.7 not started... delete not started" (L211) | Bash orchestrator deleted: `BashOrchestratorRetirementProgram_2026-08-22.md` and `BashRetirementPlan_2026-07-24.md` both moved to `documents/operations/done/`; no `orchestrate-live-lab` bash scripts remain under `scripts/vm_lab/`; AGENTS.md records the bash engine as deleted in W5.7 | **STALE-DONE** — second-most misleading claim; W5.7 is complete |
| 21 | `--node` cross-OS 0/88; Windows never bootstrapped on `--node` (L71-73) | Snapshot-era claim; cannot be re-derived from the current 272-row ledger without per-row join | Date-scoped — needs refresh or explicit as-of stamp |
| 22 | LlmNodeRoleDesign: "entire build plan open: D13.d.1 rustynet-llm-gateway crate" (L472) | `crates/rustynet-llm-gateway/` exists with `[[bin]] rustynet-llm-gateway` (Cargo.toml:17-19) and a session-token module (`src/session.rs`) | **STALE-DONE** |
| 23 | NasNodeRoleDesign: "entire build plan open: D13.c.1 rustynet-nas crate" (L502) | `crates/rustynet-nas/` exists with `[[bin]] rustynet-nas` (Cargo.toml:19-21) | **STALE-DONE** |
| 24 | NonSecurityParallelHandoff PKG items "presumed open": RNQ-17 vm_lab feature-gate, sysinfo extraction, lab-monitor crate, advisor MCDA property tests (L527) | All four artifacts exist: default-OFF `vm-lab` feature (AGENTS.md §11.2), `crates/rustynet-sysinfo/`, `crates/rustynet-lab-monitor/`, `crates/rustynet-advisor/` (HEAD itself is a merge adding advisor MCDA test coverage) | **STALE-DONE** (per-item; the entry's "presumed open" posture is wrong for at least these) |
| 25 | QualityHardeningTodo QH-16 CLOSED via `scripts/ci/gate_exit_code_gates.sh` (L596-602) | `scripts/ci/gate_exit_code_gates.sh` exists | CONFIRMED |
| 26 | QH-18 CLOSED: per-guest flock at execute_ops chokepoint (L596-602) | QH-18 flock contract documented and enforced at `crates/rustynet-cli/src/vm_lab/mod.rs:30863-30932` | CONFIRMED |
| 27 | QH-14 CLOSED: provision-toolchain os-release distro detection (L596-602) | os-release parsing present in `crates/rustynet-cli/src/vm_lab/script_template.rs` and `orchestrator/adapter/linux.rs` | CONFIRMED (essence; exact script lines not re-derived) |
| 28 | QH-21 sibling StrictMode site at `script_template.rs:1281` (L596-602) | `Set-StrictMode` sites now at `crates/rustynet-cli/src/vm_lab/script_template.rs:1526` (plus :1675, :3229) | CONFIRMED (line drifted) |
| 29 | QH-07: ledger two_hop column pass for a stage that never passed, "0/379" (L596-602) | The underlying stage now has 62 `--node` passes; the 0/379 arithmetic predates that | **REGRESSED-CLAIM** — same root cause as #1 |
| 30 | Untracked file literally named `-` at repo root (QualityHardeningTodoReview, L606) | No `./-` at the real repo root (`/Users/iwan/Desktop/Rustynet/-` absent) | **STALE-DONE** (resolved or removed) |
| 31 | SecurityAuditCatalogStalePathsTodo OPEN: `security_audit_catalog.rs:279` cites deleted `dataplane.rs`; 0 of 11 paths guarded (L664) | `dataplane.rs` now appears only inside a comment ("removed dead `dataplane.rs` module") at `crates/rustynet-cli/src/security_audit_catalog.rs:414`; the stale citation is gone | **STALE-DONE** (at minimum the dataplane.rs half; the 11-path guard count not re-derived) |
| 32 | SecurityMinimumBar §6.D: `scripts/ci/blind_exit_irreversibility_gates.sh` doesn't exist (L863) | No such file under `scripts/ci/` (grep for `blind_exit` in that dir: no hit) | CONFIRMED (still missing) |
| 33 | §6.E E1/E3/E4 "not wired": ServiceExposureController never constructed (L864) | `ServiceExposureController` referenced only inside `crates/rustynetd/src/service_exposure.rs` — no construction site elsewhere | CONFIRMED |
| 34 | §6.E: session-token verify/issue never called from LLM gateway binary (L864) | `crates/rustynet-llm-gateway/src/session.rs` exists (session-token module present); end-to-end call-chain not re-derived | PARTIALLY STALE / UNVERIFIABLE — module exists, wiring unproven either way |
| 35 | Phase1/Phase1Implementation: TLS 1.3 (rustls) not implemented / declared-not-enforced (L824, L830) | `crates/rustynetd/Cargo.toml:41` now depends on `rustls = "0.23"` ("Anchor control-plane TLS (QH-26 item 4 / DA-01)") | **STALE-DONE** — rustls landed after those entries were written |
| 36 | SecurityAnalysis RN-N1: production `expect()` panic at `daemon.rs:5908` (double `.take()` on relay_client) (L848) | `crates/rustynetd/src/daemon.rs:5908` now holds unrelated code (`verified_traversal_index.insert`); the two `relay_client.take()` sites (:7419, :8044) are guarded (`if let` / `ok_or_else`), not panics | **STALE / WRONG-CITE** — the named panic site no longer exists at that line and neither current take-site panics |
| 37 | OsAgnosticOrchestrator: `verify_signed_auto_tunnel_bundle` weakness (L543) | `rustynet-control/src/lib.rs:3399` `pub fn verify_signed_auto_tunnel_bundle` exists | Symbol CONFIRMED; weakness verdict UNVERIFIABLE (needs protocol review) |
| 38 | Relay `NonceStore::insert` clones the entire map per hello (L546) | `crates/rustynet-relay/src/transport.rs:3680` comment: "NonceStore::insert **no longer** clones the entire map per accepted hello" | **STALE-DONE** |
| 39 | PlatformSupportMatrix: `rustynet anchor pull-bundle` "Planned (D11), doesn't exist yet" (L962) | `pull-bundle` subcommand dispatched at `crates/rustynet-cli/src/main.rs:6163` (with docs at :461) | **STALE-DONE** |
| 40 | LinuxMtuPrivilegedHelperAllowlistGap: fix NOT implemented (re-export SAFE_BRINGUP_TUNNEL_MTU + validate_ip_args allowlist) (L375) | Re-export landed: `crates/rustynet-backend-wireguard/src/lib.rs:18`; MTU bounded by `..=SAFE_BRINGUP_TUNNEL_MTU` at `crates/rustynetd/src/privileged_helper.rs:1994` and referenced at :5276 | **STALE-DONE** (Steps 1-2 evidence present) |
| 41 | LinuxBlindExitDataplane: broken test helper line-JSON vs framed client (L372) | Not re-derived (helper shape not inspected) | UNVERIFIABLE this pass |
| 42 | HostObservabilityStabilityPlan §7.9.1 digests are 64-zero placeholders (L364) | Not re-derived (doc-internal claim) | UNVERIFIABLE this pass |
| 43 | BackendAgilityValidation: only WireGuard + simulated stub (L902) | Crates `rustynet-backend-wireguard`, `-userspace`, `-stub` all present | PARTIALLY CONFIRMED (three backend crates exist; the "userspace is not a second real backend" judgment not re-derived) |
| 44 | "Zero real TODO/FIXME/XXX markers; only 3 grep hits" (L53) | Raw grep returns ~11 hits, all benign (`mktemp XXXXXX` patterns, doc quotes, test placeholder strings); no real deferred-work markers found | CONFIRMED (essence; hit count drifted 3 → 0 real markers / ~11 raw) |
| 45 | RN-03: of 44 `force_fail_closed` sites, 10 discarded (L815) | `force_fail_closed` now appears ~100 times in `crates/**` | Date-scoped count drift — not misleading, needs restamp |
| 46 | `--node` ledger "178 runs" figures (chaos 0/178, not_run in all 178 rows) (L189, L428) | Ledger is now 272 rows | Date-scoped — refresh arithmetic |

## Confirmed correct (summary)

The §2a "verified against code, ALREADY DONE" addendum table is accurate in substance: all six of its mechanisms are present in the tree (items #4-#11), with only line-number drift. All six commit SHAs the inventory cites (`2e742929`, `fd8c5d04`, `e0cc8e5`, `16de276f`, `e6144250`, `a414ceb`) exist and are ancestors of this branch's HEAD — no fabricated SHAs. The QH-14/QH-16/QH-18 closure claims (#25-#27), the missing `blind_exit_irreversibility_gates.sh` (#32), and the unwired `ServiceExposureController` (#33) all check out. The doc's core discipline — no real TODO/FIXME markers in the workspace — still holds (#44).

## Most misleading items (highest priority to fix)

1. **#1/#29** — "`--node` never passed two_hop" is now false by 62 passes. Any consumer of the inventory inherits a wrong model of the engine's core capability. The Per-ParityRefresh caution in AGENTS.md §12.3 (0 passes at `9cdd660f`) is itself historical; the alias fix landed and the stage is green at scale.
2. **#20** — Bash retirement "not started" contradicts the completed W5.7 program (its plan and program docs are already in `operations/done/`).
3. **#22/#23/#24** — nas/llm crates and binaries, the vm-lab feature gate, sysinfo/lab-monitor/advisor crates all exist while their inventory entries say "entire build plan open" / "presumed open".
4. **#18** — the HP-3 "no `--node` StageId" gap is closed in the registry.
5. **#35** — rustls is a real dependency now; "TLS not implemented" entries predate it.
6. **#38/#39/#40** — NonceStore clone, `anchor pull-bundle`, and the MTU allowlist gap are each fixed/landed.

## Verdict

The inventory's §2a addendum and its SHA citations are solid, but roughly **17 findings need a status refresh** (items #1, #3, #18, #20, #21, #22, #23, #24, #29, #30, #31, #35, #36, #38, #39, #40, #46), of which **2 are actively misleading in the dangerous direction** (#1/#29: a proven capability recorded as never-proven; #20: a finished program recorded as unstarted). Classification spread: 13 CONFIRMED, 17 stale/regressed, 5 date-scoped drift, 4+ UNVERIFIABLE.

## Self-verification

Per the full-mode self-verify requirement, five key findings were re-grepped after drafting: the nas/llm crate+`[[bin]]` existence (#22/#23), the 62-pass `linux_stage_two_hop` count (#1), the `pull-bundle` dispatch at `main.rs:6163` (#39), the rustls dependency line (#35), and the `acquire_append_lock` call sites at `live_lab_run_matrix.rs:872`/`:2632` (#4). All five held on re-check.

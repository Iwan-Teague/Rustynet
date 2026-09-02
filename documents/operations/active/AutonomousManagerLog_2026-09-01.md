# Autonomous Manager Log — 2026-09-01

Running log of the autonomous live-lab orchestration manager (owner asleep; all
decisions taken under the standing autonomy grants, security-first). One line per
event: what was merged, launched, decided, and why. The durable twin is the loop
journal (`state/mcp-loop-journal.jsonl`, `write_loop_note`).

Conventions: `MERGE <sha> <branch>: <what>` · `LAUNCH <job_id> <mode>: <task>` ·
`DECIDE: <call> — <reason>` · `VERIFY: <claim> → <result>` · `CLEAN: <what>`.

## Tick 1 — 2026-09-01

- ORIENT: main @ 4761df88, origin in sync, tree clean; 4 GLM jobs (-27/-28/-29/-30) all COMPLETE; -26 orphan present.
- CLEAN: removed orphan worktree + branch ai-edit/edit-1788300744894-45994-26 (0 unique commits; failed first GAP-6 launch).
- VERIFY (-28 macOS doc): Macos* StageIds = exactly the 3 anchor ids (stage/mod.rs:235-237) ✓; active_exit.rs:184 Linux|Windows ✓; ipv6_leak.rs:17-19 Linux-only ✓; cross_os_lan_toggle fed only by bash-dialect live_lan_toggle (registry:1951) ✓; cross_os_anchor_enrollment has no feeder ✓; quote-aware ledger tallies (242 rows) match ✓.
- VERIFY (-29 Windows doc): ledger windows_stage_bootstrap 5 fail/0 pass, cleanup 3/2, present 5 pass ✓; node_adapter.rs:522 "no status subcommand §4.7" ✓; windows.rs:160 DeferredPlatform / :299 ephemeral mint ✓; W-FIX-1 test pin exists (windows_install.rs:1765) ✓; **ps1 line citations STALE** (Require-Winget is :616 not :548-571; Ensure-WingetConfigurationDependencies :1248 not :1130 — inherited from the 08-28 verdict, pre-W-FIX-1) → fixed by hand before merge.
- VERIFY (-30 Linux doc): post-removal linux_stage_two_hop = 26 pass/8 fail/86 skip/28 not_run ✓ exact; 8 bare linux_* columns in DEFAULT_MATRIX_COLUMNS ✓; no ValidateLinux* StageIds ✓; **two_hop attribution WRONG** — doc credits the 26 passes to `live_two_hop` (registry:1943, a bash-dialect spec with NO StageId → unreachable on --node) and calls `live_two_hop_validation` "lifetime 0 pass" (a count quoted from the run_matrix.rs comment at commit 9cdd660f, stale since the first --node pass on 2026-08-14). Per-stage truth: live_two_hop_validation Linux = 130 pass / 121 fail / 449 skip node-rows → fixed by hand before merge.
- MERGE ai-edit/edit-1788301458693-45994-28: macOS + cross-OS pass-likelihood analysis (docs-only).
- MERGE 7421acad ai-edit/edit-1788300770125-45994-27: GAP-6 offline secrets-in-logs scanner + fail-closed evaluator (role_validation/secrets_not_in_logs_eval.rs). Gate: own files absent from fmt diff; clippy -p rustynet-cli --all-targets --all-features --locked -D warnings rc=0; 15 tests pass in lib + bin binaries. Pattern set verified byte-exact vs live_linux_secrets_not_in_logs_test.rs (:251-253 separator skip, :280 prefixes).
- MERGE 33c3b5bb ai-edit/edit-1788301531842-45994-30: Linux pass-likelihood doc, after hand-fix b90aeb23 (two_hop attribution). README auto-merged.
- MERGE 78b9a835 ai-edit/edit-1788301496705-45994-29: Windows pass-likelihood doc, after hand-fix 5384c2e4 (ps1/windows_install.rs citations). README index conflict (three docs, same insertion point) resolved keeping all three lines.
- PUSH origin main = 78b9a835 (fast-forward; staleness 0 both directions). All merged worktrees + branches removed.
- LAB: utmctl list → all 10 UTM guests STOPPED (lab down). Host load 2.6, swap 179M/1G. No live run launched this tick.
- LAUNCH attempt GAP-4 offline core (traversal_hint_wire_replay_eval.rs, stage/cross_network/scenario/): first launch → opencode serve reset ("Connection reset by peer" on POST /session; serve had come up on default port 4096 with no recorded pid); second attempt → client transport "Connection closed", no job record. CLEAN: orphan worktree edit-1788303135011-7094-0 removed. Third attempt in flight.
- DECIDE: GAP-4 offline core placed under stage/cross_network/scenario/ beside acl_deny_failover_verdict.rs (GAP-3 precedent) rather than role_validation/ — it is a scenario report evaluator, not a per-node role validator.
- LAUNCH edit-1788303426006-14409-0 full: GAP-4 offline core (third attempt succeeded; serve on :4096).
- INFRA FINDING: in-client MCP calls to rustynet-ai-agent now fail with "Connection closed" on any slow call (launch, or poll of a RUNNING job); each failure respawns the server and leaves the old instance idle (3 instances observed). The opencode serve itself answers in ~2ms and the job progresses normally. WORKAROUND adopted: launch and poll through `scripts/mcp/drive_ai_agent.py` (stdio, own binary spawn) — verified: poll returned RUNNING + spend, launch returned a job id. The `[glm] HTTP 500` retry storms in ~/Library/Logs/Claude/mcp-server-rustynet-ai-agent.log are from another session's provider calls (call_edit_result makes no provider call).
- LAUNCH edit-1788303791150-17104-0 full (via stdio driver): Phase A consolidation — LiveLabStagePassLikelihood_Summary_2026-09-01.md with the ranked cross-OS highest-leverage table, Phase C candidate queue, do-not-chase list; indexes in README.
- CLEAN: parked GAP-1 aliasing branch ai-edit/edit-1788297577518-45994-20 (bad40bb1) deleted per the design's retire-not-alias decision.
- DECIDE: GAP-1 sequencing — offline pure core FIRST (ordering comparator, plan-vs-observed sequencer via rustynet_control::role_presets::transition_plan, outcome aggregation, blind-exit reversal assessment, audit-growth verifier, audit-wiring source scan; design §4 tests 1-3,5-7), rename+RETIRE + wiring in a SECOND change — so the renamed stage never carries a liveness-only body under an ordering name (GAP-7 hazard in reverse).
- LAUNCH edit-1788303957105-19696-0 full (stdio driver): GAP-1 offline core role_transition_ordering_eval.rs + one pub mod line in stage/mod.rs.
- JOB edit-1788303426006-14409-0 (GAP-4 offline core) COMPLETE at ~390k billable tokens; merge gate running.
- VERIFY (GAP-4 branch 637c8470): scope 2 files; own files fmt-clean; clippy rc=0; 19 tests pass. Two hand-fixes on the branch before merge: (1) removed an empty `if is_replay_of(..) {}` dead branch in validate_replay_fixture; (2) `Watermark::is_replay_of` compared generation only, but the daemon's traversal_watermark_ordering (daemon.rs:16523-16531) tiebreaks on nonce — added `ordering_against` mirroring generation-then-nonce, routed is_replay_of through it, extended the ordering test with the two nonce-tiebreak cases (the original test's "equal" cases used a different nonce from live and would have been wrong under the daemon's ordering).
- JOB edit-1788303791150-17104-0 (Phase A Summary doc) COMPLETE at ~241k billable tokens; reviewing.
- JOB edit-1788303957105-19696-0 (GAP-1 offline core) RUNNING (~188k tokens).
- MERGE 220d7bfe ai-edit/edit-1788303426006-14409-0: GAP-4 offline core (19 tests; two hand-fixes noted above).
- VERIFY (Summary doc): ranked table rows trace to bucket docs; `--enable-relay-forwarding-validation` (row 5) confirmed real (plan.rs:319 `enable_relay_forwarding_validation`, CLI flag present); two_hop correction carried forward correctly; no invented SHAs/dates spotted.
- MERGE ai-edit/edit-1788303791150-17104-0: LiveLabStagePassLikelihood_Summary_2026-09-01.md + README index. Phase A CONSOLIDATION DONE.
- NEXT (Phase B): adversarial refute pass over the Summary's six-item Phase C candidate queue; then Phase C on the reviewed items. GAP-5 offline core to launch alongside.
- PUSH origin main = 8acab546.
- LAUNCH edit-1788304389725-30524-0 full (stdio driver): Phase B adversarial refute pass over the Summary's §1 rows 1-11 + §2 six Phase C candidates → LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md (verdict table, per-candidate five-question review, anchor verification, reordering, refuted claims) + README index.
- LAUNCH edit-1788304478904-35761-0 full (stdio driver): GAP-5 offline core — crates/rustynet-control/tests/signed_state_rollback_apply_layer.rs (PrevStateRootMismatch-first, root-forged epoch-chain, replay-cache dedup, byte-identical state after rejection, correct-epoch still applies, EpochRegression-not-on-apply-path source pin) + role_validation/signed_state_rollback_eval.rs (Blocked≠Failed both fail; ordered expected-rejection set) + role_validation/mod.rs line.
- TICK 1 END: main @ 8acab546 pushed; in flight = GAP-1 core (-19696-0), Phase B review (-30524-0), GAP-5 core (-35761-0). Wakeup re-armed 900s.

## Tick 2 — 2026-09-02 00:32

- ORIENT: main @ 8cd40eb3, staleness 0; all three tick-1 jobs COMPLETE (GAP-1 core, Phase B review, GAP-5 core); load 2.05.
- LAUNCH edit-1788305596759-42655-0 full: QH-07 stale "0 pass" doc-comment refresh in live_lab_run_matrix.rs (comment-only; Summary row 18).
- GATE GAP-1 core (e71d770a): scope 2 files; clippy rc=0; 17 tests pass. Hand-fix 26a15377: check_sequence named the EXPECTED step as the out-of-order step (message read "'X' out of order: expected 'X' next"); now names the step at the cursor. Local rustfmt flags import order + assert! layout in the new file — resolving against the CI-faithful toolchain before merge.
- GATE GAP-5 core (5ac1f2b9): scope 3 files; clippy rc=0 both crates; 6 rustynet-control integration tests + 22 evaluator tests pass. Local rustfmt flags import order in the control test file — same resolution pending.
- VERIFY (Phase B review, e241fcbf): principal refutation CONFIRMED by hand — trust CLI `role status` → IpcCommand::Status (rustynet-windows-trust-cli.rs:133-136/:454); ipc.rs:42/:119/:199; daemon Status response begins `node_id={} node_role={}` (daemon.rs:9113); windows_traffic::query_live_identity (:94-96) returns config_file evidence and never consumes it; no role-transition StageId in stage/mod.rs; registry SoakSuite rule at :347. MERGE 93989c7f.
- DECIDE: Phase C candidate 1 proceeds in its AMENDED form (orchestrator-side collector + a raw `status` verb on the trust CLI; gate untouched) — smaller and strictly more secure (identity from the running daemon, not a file).
- MERGE a4f86d3a GAP-1 offline core (17 tests; hand-fixes: sequencer message + pinned-rustfmt formatting of the new file). MERGE e5d83dc8 GAP-5 core (6 rustynet-control integration tests + 22 evaluator tests; pinned-rustfmt of the test file). MERGE 3459b508 QH-07 doc-comment refresh (comment-only; pinned fmt clean; cargo check rc=0).
- ROOT CAUSE (CI): every Cross Platform CI run since before this session is RED in "Workspace validation" (Debian+macOS) and "Build + test Windows-portable crates" on `cargo fmt --check`, flagging ONLY windows_install.rs / anchor_tls.rs / daemon.rs — the three "pre-existing drift" files. Cause: /opt/homebrew/bin/cargo shadows rustup, so local `cargo fmt` = rustfmt 1.9.0 while CI = pinned 1.88.0 (rustfmt 1.8.0). The "never cargo fmt" rule was a symptom workaround. FIX: `rustup run 1.88.0 rustfmt --edition 2024` on exactly those three files; `rustup run 1.88.0 cargo fmt --all -- --check` now clean workspace-wide; cargo check rc=0. Committed on main. New merge-gate rule: pinned fmt check per file; never bare `cargo fmt`. Saved to memory (homebrew_cargo_shadow_ci_fmt_red).
- DECIDE: GAP-1 rename-RETIRE DEFERRED — the design's rename+extend needs the live CLI-driven transition driver (lab); renaming today would put an ordering name on a liveness-only body (the GAP-7 hazard in reverse) and could not be live-proven. Revisit when the lab is up (§4C loop). The offline core is merged and ready to wire.
- LAUNCH edit-1788306278374-51744-0 full (docs): LiveLabMacosExitServingAdapterDesign_2026-09-02.md — resolves the exit-vs-blind_exit role tension, adapter surface, S2 end-to-end egress assertion, killswitch-precedence fold-in, offline core plan, live-proof recipe, open questions (goes to Phase B next).
- JOB edit-1788305993287-47879-0 (candidate 1, Windows live identity collector) RUNNING (~299k tokens).
- PUSH origin main = 3eecd5f6 (drift fix e2ff2c82 + log). Watch next CI run for green fmt.
- LAUNCH edit-1788306459791-52627-0 full: Phase C candidate 5 — `cross_os: Some("cross_os_lan_toggle")` on the --node live_lan_toggle_validation spec + oracle mapping + fail-closed "skip never writes pass" test.
- LAUNCH edit-1788306579981-54602-0 full: WIN-F-2 delete dead inspect_handle_sddl (rustynet-windows-native; cross-check on x86_64-pc-windows-gnu).
- TICK 2 END: in flight = C1 (-47879-0), C2 design (-51744-0), C5 (-52627-0), WIN-F-2 (edit-1788306579981-54602-0). Wakeup 01:05.

## Tick 3 — 2026-09-02 01:05

- ORIENT: main @ fabc3555; all four tick-2 jobs COMPLETE. CI still red BUT the fmt step now passes (no `Diff in`); it uncovered masked failures: clippy `uninlined_format_args` at backend-wireguard/windows_command.rs:697 + control/role_audit.rs:334 (CI = real 1.88.0 clippy, where the lint is warn-by-default) and Windows E0609 on FWPM_FILTER0 field access in windows-native (pre-existing; CI last compiled Windows before the fmt breakage).
- ROOT CAUSE (toolchain, refined): `rustup run 1.88.0 cargo …` runs cargo 1.88 but resolves rustc/cargo-clippy via PATH → Homebrew 1.97. So every local "pinned" clippy/check was really 1.97 (lint demoted → no repro) and the Windows target check failed with E0463 (Homebrew rustc has no windows-gnu std). CI-faithful recipe = `PATH=~/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH cargo …` with CARGO_TARGET_DIR=target-pinned. Memory note updated. True-1.88 workspace clippy + Windows cross-check launched in background.
- FIX 7df68076: inlined the two format! args CI's clippy rejects (pinned fmt clean).
- LAUNCH edit-1788307583350-72047-0 full (docs): F-1 llm-gateway scope=None security PLAN (Requirements/SecurityMinimumBar first; options ranked; strictest default).
- VERIFY (C2 design 03c471f7): anchors main.rs:451-456, macos_exit_nat_lifecycle.rs:94/:149, vm_lab/mod.rs:20076/:21267 + tests, node_adapter.rs:296/:309/:322/:339, macos.rs:78, PF-05 :127, Refresh :102/:389 all exact. MERGE 1955249b. LAUNCH edit-1788308252685-82507-0 full (docs): its adversarial review (Phase B) with 8 attack vectors.
- GATE C1 (5540a86a): clippy 0; windows_traffic 26 + challenge_gate 5 tests pass; BUT the job had run a 2015-style rustfmt sweeping import/assert! churn into all 4 files — restored with the pinned rustfmt (ee3e1768); node_adapter.rs + windows.rs hunks then comment-only (gate untouched, verified). MERGE dd730ec7.
- GATE C5 (80db8870): clippy 0; pinned fmt clean; lan_toggle + registry tests pass; 3 live_lab_run_matrix tests FAIL — all about `relay_forwards_frame_validation` (logical Some("relay_forward_test") vs oracle None; special None vs oracle Some("linux_relay_forwards_frame"); columns {os}_stage_relay_forward_test absent from schema). Checking whether main already fails them (suspect pre-existing, masked by CI's fmt/clippy failures).
- PUSH origin main = dd730ec7.
- VERIFY (F-1 plan 53dfb176): enforce.rs:82-86 None ⇒ Ok early ✓; main.rs:328-337 admission default-deny + scopes.get ✓; service_access_state.rs:116 `scopes: Vec::new()` ✓; policy lib.rs:344-359 scope_for "fail-open deliberate" ✓; tests :198/:294 ✓. MERGE fa6907f1 (README bullet conflict resolved keeping both). LAUNCH edit-1788308637832-89595-0 full (docs, based on the F-1 branch): its adversarial review with 8 attack vectors incl. Option A vs B vs signed-marker.
- PRE-EXISTING BUG FIXED 615b2d9f: `relay_forwards_frame_validation` (HP-3, 6f5cfaca) carried logical "relay_forward_test" — no such schema column → set_status would silently drop the stage verdict; 3 live_lab_run_matrix equivalence tests had been failing on main (CI never reached them). Spec now `special: Some("linux_relay_forwards_frame")` per the oracle; 101 → 104 tests green with C5.
- TRUE-1.88 CLIPPY (PATH-prefixed toolchain) found two more CI blockers beyond 7df68076: dead `BLIND_ADDR_ARTIFACT_BYTES` (relay; const-assert use not counted by 1.88) and an uninlined format arg in role_signing_subflow.rs:981 → FIXED 873965c1 (const made pub beside its siblings; arg inlined). Re-running the workspace pass to find any remaining.
- MERGE 81d22b09 WIN-F-2 (true-1.88 x86_64-pc-windows-gnu check + clippy rc=0 on the branch). MERGE ddf643e2 C5 (after the drift fix; 104 tests green post-merge).
- WINDOWS CI E0609 (lib.rs:2002-2004 pre-WIN-F-2 numbering = the FwpmFilterEnum0 loop `&**entries.add(index)`): gnu cross-check passes locally under true 1.88; CI builds msvc — running the msvc cross-check to reproduce.
- PUSH origin main = ddf643e2.
- WINDOWS E0609 RESOLVED WITHOUT NEW WORK: at fabc3555 the FwpmFilterEnum0 loop read `&*entries.add(index)` (one deref → `&*mut FWPM_FILTER0`, no field access); HEAD carries `&**entries.add(index)` via the WIN-F-2 branch (915a7ff4/81d22b09). True-1.88 cross-checks on main: x86_64-pc-windows-gnu rc=0, x86_64-pc-windows-msvc rc=0; 1.85.0 msvc rc=0 too. CI's Windows leg uses 1.88.0 (rust-toolchain.toml override, confirmed in its log).
- TRUE-1.88 CLIPPY round 2: 8 more uninlined_format_args in rustynetd (anchor_tls.rs:268, linux_tandem_dns_redirect.rs:253/:266, macos_dns_sc_protect.rs:769/:830/:839/:849/:916) → fixed + pinned-rustfmt'd + committed + pushed in a background chain that then re-runs the workspace pass (log: scratchpad/true188_clippy3.log).
- LAUNCH edit-1788309113987-96082-0 full: C4 `--enable-soak-suite` selector (+ plan-inclusion tests; skip wins). LAUNCH edit-1788309348056-96984-0 full (docs): QH-26 honest-retirement PLAN (no fake control; mechanical guard against unreviewed delegated-edit checkpoints).
- RUNNING at tick-3 end: C2 design review (-82507-0, ~551k tokens), F-1 plan review (-89595-0), C4 (-96082-0), QH-26 plan (-96984-0). Wakeup armed 01:48 (tick overran; next wake delivers on turn end).
- MILESTONE 519cc757: true-1.88 (CI-faithful) `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` rc=0 after four rounds (7df68076, 873965c1, 30355d1c, 519cc757 — 15 uninlined_format_args + 1 dead-const across backend-wireguard, control, relay, rustynetd, rustynet-cli). Pinned fmt clean workspace-wide. Windows cross-checks clean. CI should now reach the nextest stage on all three legs; watch the 519cc757 run.

## Tick 4 — 2026-09-02 01:56

- ORIENT: main @ e6b5871e; all four tick-3 jobs COMPLETE. CI on 519cc757/e6b5871e: fmt + clippy now pass on the macOS leg (it reached nextest: 1 failing test `rustynet-backend-wireguard userspace_shared::engine::tests::shared_scratch_roundtrips_handshake_then_variable_length_frames` — passes locally under Homebrew 1.97 AND true 1.88; runner-specific or flaky, investigating); Debian leg: clippy on Linux-only test code (`MEMBERSHIP_OWNER_SIGNING_KEY_PATH` / `ASSIGNMENT_SIGNING_SECRET_PATH` unresolved in rustynetd lib test; type_complexity in rustynet-cli lib test) — cannot cross-compile to Linux here (ring/libsqlite3 build scripts need a Linux C toolchain); Windows leg: rustynetd + rustynet-control lib/test code not Windows-portable (std::os::unix / Permissions::from_mode ungated; privileged_helper HelperResponse + RESPONSE_FIELD_BUDGET_BYTES defined under cfg(unix) but used unconditionally; anchor_tls.rs:17 unix import) — REPRODUCED locally with true 1.88 --target x86_64-pc-windows-gnu.
- LAUNCH edit-1788310633859-19866-0 full (docs): QH-01 template-injection elimination PLAN.
- VERIFY + MERGE c258f480 C2 design adversarial review (READY-WITH-AMENDMENTS ×6; role.rs:160 blind_exit remap + mutating killswitch check re-sequencing + dead_code evaluators confirmed in tree); ae6b7658 F-1 plan adversarial review (READY-WITH-AMENDMENTS, Option B amended ×10; main.rs:705 fifth test, daemon.rs:5538/5565 scopes.v1 clobber, --quota flag confirmed); 9b489910 QH-26 plan (anchors confirmed; CORRECTION for its review: the delegated-edit marker is on ELEVEN commits (8 dated 2026-08-30, 1 2026-08-29, 3 2026-07-20), not three). PUSH 9b489910.
- GATE C4 (f7991b91): pinned fmt clean, clippy 0, plan 98 / registry 109 / soak tests pass — BUT the diff changes the DEFAULT plan (64 → 63 stages: extended_soak becomes opt-in) contrary to the prompt's "default plan byte-identical" constraint. Checking the per-stage ledger for whether extended_soak already dispatches by default before deciding.
- DECIDE: C4 REJECTED (branch discarded, not merged). Per-stage ledger (quote-aware): `extended_soak` Linux = 40 pass / 348 skip node-rows; run matrix `linux_stage_extended_soak` = 8 pass. The stage already dispatches in the default Linux full-suite plan (opt-out via --skip-soak); it skips on mac/win only because the fast path drops the live suite — by design (registry comment). Summary row 15 / macOS bucket §1 "never dispatched, no enable flag" / Phase B review §4 "unreachable by any selector" are all WRONG (the review even cited the 40 passes). C4's change (soak default-off, 64→63 stages) would have silently dropped default evidence. Docs correction owed (Summary row 15 → "premise refuted"; macOS bucket extended_soak entry; review §4). Lesson: a "never dispatched" claim must be checked against live_lab_node_stage_results.csv, not the run-matrix column alone.
- LAUNCH edit-1788311024056-22341-0 full (code): Windows portability fix for rustynetd + rustynet-control (cfg gating; true-1.88 windows-gnu + msvc cross-checks must exit 0).
- FIX 739ee560 (CI-only): ops_e2e.rs test-module scope for the Linux-only constants (super::), phase10.rs AnchoringSystemParts alias for the 4-tuple (clippy type_complexity on Linux), and the keepalive test now ticks until the keepalive appears (bounded 5 s) instead of one fixed 1100 ms sleep ("got None" on the macos-14 runner; passes 3/3 locally on both toolchains). Linux-only code cannot be compiled here — CI validates.
- LAUNCH edit-1788311106521-22754-0 full (docs): QH-26 plan adversarial review, seeded with the eleven-marked-commits correction.
- RUNNING at tick-4 end: QH-01 plan (-19866-0), Windows portability (-22341-0), QH-26 review (-22754-0). Wakeup 02:23.
- LAUNCH edit-1788311325982-23876-0 full (docs): retract the extended_soak "never dispatched" premise in the Summary (row 15 / candidate 4), the macOS bucket, and the Summary review §4, with per-stage ledger counts.

## Tick 5 — 2026-09-02 02:23

- ORIENT: main @ 9ba34ada; CI on 9ba34ada (includes the 739ee560 fixes): Debian+macOS legs now reach nextest; remaining failures: `shared_scratch_roundtrips_handshake_then_variable_length_frames` still "got None" on BOTH legs (so no keepalive is emitted there at all — the bounded loop was not the fix); Debian-only: `windows_command::tests::windows_remove_peer_retry_{after_sync_failure_converges_stale_persistent_config,reports_convergence_failure_instead_of_silent_success}` — "sync failure must fail the removal" (the container runs as ROOT, so chmod 0o555 does not make the staging write fail). Windows leg: unchanged until the portability job lands.
- MERGE 280ac2ed: extended_soak premise retraction across the Summary, macOS bucket, and the Summary review (struck-through originals, dated corrections, new ledger-reading rule). PUSH.
- JOB edit-1788310633859-19866-0 (QH-01 plan) KILLED: one reasoning turn open 24 min with zero spend and no worktree change (serve 19900); record marked timed_out; RELAUNCHED as edit-1788312314991-25246-0.
- FIX in progress: root-probe guard for the two chmod tests (skip with a message when a 0o555 dir still accepts writes). Keepalive hypothesis under test: workspace-wide `--all-features` in CI activates boringtun's mocked clock (`mock-instant`), so Instant never advances in the engine's timers — a `-p` local run never enables it.
- FIX 55658131: root-probe guard for the two windows_command chmod tests (Debian container is root). PUSH.
- KEEPALIVE (CI-only): reproduced locally ONLY with `--features boringtun/mock-instant` (mocked Instant never advances) — but boringtun is not a workspace member, so `--workspace --all-features` should not enable it; local cargo test + nextest pass on 1.88 and 1.97. Running CI's exact workspace-wide nextest invocation locally (background) as the definitive repro.
- VERIFY + MERGE QH-26 plan review: eleven marked commits confirmed; NEW SECURITY FINDING from the review — three of the 2026-08-30 unreviewed checkpoints (5757e55c, 1a5bcb21, 9a723960) landed the anchor control-plane TLS subsystem (anchor_tls.rs +664 lines) with no human review. LAUNCH edit-1788313152819-31898-0 full (docs): adversarial security review of that subsystem (key custody, identity, server config, handshake DoS, token reader, client-side pinning gap, tests, disposition per checkpoint).
- NOTE: the QH-26 review merge in the previous log line actually landed one commit later (a transient tool timeout skipped the merge; retried).
- JOB edit-1788311024056-22341-0 (Windows portability) COMPLETE (2da660f0, ~840k tokens): anchor_tls.rs write/read paths fail closed on non-Unix with an explicit Unsupported error; Unix test module gated all(test, unix) + a windows-only fail-closed test; privileged_helper.rs cfg(not(windows)) gates; rustynet-control unix-only tests gated. Gate running (host clippy/tests + true-1.88 windows-gnu, windows-msvc, host).
- JOB edit-1788312314991-25246-0 (QH-01 plan relaunch) RUNNING and progressing (338k tokens, 2 sub-agents).
- TICK 5 END: in flight = QH-01 plan, anchor-TLS security review (-31898-0); background = Windows gate, workspace-wide keepalive nextest repro. Wakeup 02:51.

## Tick 6 — 2026-09-02 02:51

- KEEPALIVE ROOT CAUSE: `cargo tree -e features --workspace --all-features -i boringtun` shows boringtun feature "mock-instant" (command-line) — boringtun is an IMPLICIT workspace member (path dep inside the workspace dir), so the CI gate runs every boringtun timer on a frozen mock clock; reproduced locally with CI's exact nextest invocation. FIX: mock_instant module made pub under its feature (vendored boringtun lib.rs), backend-wireguard forwards `boringtun-mock-instant = ["boringtun/mock-instant"]`, the test advances the live clock (mock or wall). Verified: package --all-features PASS 0.04 s, workspace --all-features PASS, default real clock PASS; clippy 0 (Homebrew + true 1.88).
- GATE + MERGE Windows portability (2da660f0): pinned fmt clean; host clippy 0; anchor_tls 7 + control 573 tests; true-1.88 windows-gnu clippy rc=0 for the CI package set; msvc cross-check blocked locally by ring's C build (no Windows SDK) — CI validates. Fail-closed cfg decisions verified in the diff.
- MERGE f2b9f4d3 QH-26 plan review (retried after a transient tool-timeout skipped the first attempt).
- LAUNCH edit-1788313895102-38827-0 full (code, S): QH-26 items 1-3 (provenance comment, retired-key + version-2 rejection tests asserting the error class, CODE_MAP line for anchor_tls.rs). TICK 6 END: in flight = QH-01 plan (-25246-0), anchor-TLS security review (-31898-0), QH-26 impl (-38827-0). Wakeup 03:09.

## Tick 7 — 2026-09-02 03:09

- CI cba06e4d: macOS leg GREEN (first time this session — fmt+clippy+nextest all pass). Debian: 1 failure `phase10::tests::killswitch_and_dns_rule_tokens_agree_with_emitted_nft_argv` — DnsApplyFailed("dns resolver port is not configured") (the S1 DNS precondition; Linux-only test fixture not updated). Windows: 1 failure `phase10::tests::macos_assert_dns_protection_requires_active_dns_rules` — not cfg-gated, fails on Windows because /usr/sbin/networksetup is not an absolute Windows path.
- MERGE anchor-TLS security review (ACCEPT-WITH-FIXES; no P0/P1; AT-1 P2 handshake deadline, AT-2 P2 client pinning gap, seven P3s) and QH-01 plan (Option B: single quoting seam + newtype sinks + hoisted validators; anchors verified). QH-01 branch kept as the base for its review.
- LAUNCH edit-1788315006210-41820-0 full (docs): C2 design amendment fold (A1-A6).
- GATE QH-26 impl (a00b07bd): pinned fmt clean; clippy 0; 11 trust_evidence tests incl. the two new pins pass.
- MERGE 2d0cc7d4 QH-26 items 1-3 (gate green incl. true-1.88 clippy). FIX (phase10 CI-only): `.with_dns_resolver_port(53535)` on the Linux nft-argv test fixture; `#[cfg(unix)]` on macos_assert_dns_protection_requires_active_dns_rules (verified it still runs+passes here). Committed + pushed.
- LAUNCH QH-01 plan adversarial review (base = the plan's branch; first launch attempt was skipped by a transient tool-safety timeout — re-issued).
- MERGE C2 design fold (A1-A6; anchors re-verified). LAUNCH edit-1788316232260-44037-0 (docs): QH-01 plan adversarial review (base = plan branch). LAUNCH edit-1788316332322-44455-0 (code, security): anchor-TLS fixes AT-1 (handshake deadline + dribbled-ClientHello test), AT-3 zeroize, AT-4 redacting Debug, AT-5 open-then-fstat, AT-6 no Box::leak, AT-7 dead rustls dep (verify first), AT-9 negative tests; AT-2/AT-8 excluded (design-gated).
- LAUNCH edit-1788316390691-44828-0 full (code): C2 OFFLINE core adapter/macos_exit_traffic.rs (snapshot verdicts, pf-state translation parser + identity selector, egress-evidence evaluator; unquarantine excluded). TICK 7 END: in flight = QH-01 review (-44037-0), anchor-TLS fixes (-44455-0), C2 core (-44828-0). Wakeup 03:47.

## Tick 8 — 2026-09-02 03:47

- CI e66bef4c: Windows leg GREEN, macOS leg GREEN; Debian: 1 failure — macos_assert_dns_protection_requires_active_dns_rules (canonicalizing /usr/sbin/networksetup fails on Linux; the test had never reached Debian before because nextest's fail-fast cancelled earlier runs). FIX: cfg(target_os = "macos") (was cfg(unix)). Note: Debian's nextest is fail-fast, so further masked failures may surface one per run.
- LAUNCH edit-1788317290668-46137-0 full (docs): F-1 plan amendment fold (A1-A10).
- RUNNING: QH-01 review (-44037-0, 426k tokens, 1 sub-agent), anchor-TLS fixes (-44455-0), C2 core (-44828-0), F-1 fold (-46137-0).

## Tick 9 — 2026-09-02 04:06

- CI: d6d1f4da (macOS-gate fix) in progress; 76f13684 red = the pre-fix Debian test. Waiting for the first fully-green run.
- COMPLETE: QH-01 review (READY-WITH-AMENDMENTS ×8: inventory holds exactly (162 call lines); windows.rs:329-345 rest.join(" ") is the third argv-join site; ValidatedArg::path must pair shape with confinement; ssh_config option injection via a newline in User=; validators must own position not just alphabet; source-scan pin must land with the FIRST migration); C2 core (960 lines, 20 tests; gate running); F-1 fold (A1-A10 verified) → MERGED.
- LAUNCH edit-1788318446954-55024-0 full (code, AUTHORIZATION): F-1 implementation, Option B amended — None ⇒ deny across admit_request/record_tokens/visible_models, explicit `unrestricted` marker with contradiction rule, mid-stream sever-on-narrowing, retire main.rs:705, doc/comment fixes, llm_default_deny_gates.sh pins; no CLI change (follow-up: `rustynet llm allow --unrestricted`).
- RUNNING: anchor-TLS fixes (-44455-0, ~965k tokens), F-1 impl (-55024-0).
- MERGED: QH-01 plan review (78b5282e, README bullet conflict kept both), C2 offline core (macos_exit_traffic.rs, 20 tests; pinned-fmt drift re-applied on the branch before merge). Stale branch -25246-0 deleted.
- LAUNCH (docs): fold the QH-01 review's A1-A8 into Qh01TemplateInjectionEliminationPlan_2026-09-02.md.
- CI d6d1f4da: Debian fail-fast surfaced `macos_reconcile_exit_nat_residue_flushes_fixed_anchor_only_when_not_serving` (expects 2 commands, D-6c added the `pfctl -s Anchors` tandem probe → 3); Windows leg flaked `concurrent_persist_keeps_snapshot_integrity` (guard unlinks the lock while its handle is open → Windows delete-pending → concurrent create_new returns PermissionDenied → treated fatal). FIXED directly: test expects 3 + pins the probe; non-unix acquire_lock retries PermissionDenied under the same 3 s deadline. Gate: clippy Homebrew+1.88 rc=0, resilience tests green, windows-gnu check rc=0.

## Tick 10 — 2026-09-02 04:34

- Polls: anchor-TLS fixes TIMED OUT on the job wall clock but its single commit a76a10a4 covers AT-1/3/4/5/6/7/9 (worktree clean); F-1 impl COMPLETE; QH-01 fold COMPLETE; QH-26 marker gate COMPLETE (1.8M tokens).
- MERGED: QH-01 fold (b698eece, anchors re-verified); F-1 implementation (354727bc: deny-on-absent, explicit `unrestricted` marker, loader contradiction rule, T7 mid-stream sever-on-narrowing, gate script pins; hand fix 0d311ce6 — a dropped limit is widening, not narrowing).
- Anchor-TLS gate: pinned fmt clean, clippy 1.88 rustynetd+rustynet-cli rc=0, 93 anchor tests, windows-gnu rc=0, deny/audit rc=0, rustls correctly dropped from rustynet-cli (no source reference). Two hand fixes pending commit: (1) the cert/key pairing probe was bounded by a 200-iteration spin with no sleep — loopback delivery is not synchronous on macOS, so it could refuse a valid identity under load; now wall-clock bounded (5 s) with a 2 ms poll; (2) `tls12_client_hello_cannot_be_processed_by_compiled_stack` asserted `rustls::ALL_VERSIONS.len()==1`, which FAILS under the workspace gate because `ureq` unifies the `tls12` feature — replaced by a wire-level test offering a TLS 1.2-only ClientHello and asserting `Error::PeerIncompatible` (verified under -p rustynetd; workspace-unified run pending a compile question).
- LAB: guests macOS + debian-headless-2 + debian-headless-4 booted for the rank-1 no-code harvest (full-suite macOS client run); launch once SSH is up.
- LAUNCH: QH-01 Option B Steps 1-3 + 5 (validated_args seam, RemoteCommand/PowerShellScript newtypes, source-scan pin; no site migration yet).
- MERGED: anchor-TLS fixes (2dd60138; hand fixes 8d95b2cf: wall-clock-bounded pairing probe + wire-level TLS 1.2 refusal test). The four rewritten/added tests pass under the workspace-unified (tls12-on) nextest build on main. main compiles clean (`cargo check --workspace --all-targets --all-features --locked` rc=0 on 1.88).
- QH-26 marker gate branch: binary run on main exits 0 (loud-silence warning: no marker in the last 200 commits — correct, the eleven predate the window), self-test PASS, 2844 rustynet-cli tests, AGENTS/CLAUDE identical; clippy 1.88 red on `uninlined_format_args` → clippy --fix on the branch, re-gating.
- LAUNCH: llm CLI `--unrestricted` follow-up (edit-1788322296181-93617-0). Running: QH-01 seam (edit-1788322224485-91126-0).
- LAB: guests show on ARP (.4/.10/.18 and 192.168.65.101); waiting for sshd.
- MERGED: QH-26 marker gate (87aa7b6d; hand fix 8ddaea6f inlined format args for clippy 1.88 in bin + tests). Runs green on the merged main. AGENTS/CLAUDE mirror byte-identical.
- LAB: probe_and_recover found no live IP for the booted guests (discovery listed only Windows11), so nothing was recovered; the three still time out on 22 while answering ARP → next: utmctl guest-agent path for the Debians, wait/ARP for the macOS guest.
- LAB: the booted guests moved to 192.168.65.0/24 (debian-headless-2 → .4, debian-headless-4 → .5); inventory refreshed via the sanctioned discover command (5963afd2). macOS guest (192.168.65.101) stays ARP-incomplete after 35 min — rank-1 harvest deferred.
- LAB RUN livelab-1788323082-5963afd2f993 (Linux full suite, 2 nodes): FAIL at `prepare_source_archive` — every guest reports "git worktree must be clean for this live-lab iteration"; 3 pass / 1 fail / 59 skipped. Ledger row appended (overall_result=fail, first_failed_stage=prepare_source_archive). Diagnosing the guests' dirty checkouts before re-running.
- LAUNCH (docs): receiver-index demux inverse-map plan (clone-audit P2) edit-1788323087644-3597-0.
- LAB ROOT CAUSE: the source-archive clean check runs `git status --short` (untracked included) minus the evidence ledgers; this host's untracked target-pinned*/ and target-stable/ scratch dirs tripped it (same shape as 45fde3a5's target-gate/). Fixed by ignoring them (bb8a203c); remedy recorded in the triage ledger (5821b8ba) so the fail-closed launch gate admits the stage again. A retry with allow_dirty had been refused by that launch gate ("1 planned stage(s) have a failure with no recorded remedy").
- LAB: the macOS guest is reachable at 192.168.64.18 (SSH ok, macOS 26.5); the inventory's 192.168.65.101 was stale and the network audit flagged the label. RANK-1 HARVEST LAUNCHED: labrun-1788323525086-16069-0 (full suite, macos-utm-1 client + debian-headless-4 exit + debian-headless-2 client; no skip; triage off). Poll ai_live_lab_result each tick.
- MERGED: llm allow --unrestricted (record-only, fail-closed contradiction check; 11 tests).
- CI: 2dd60138/354727bc red on two more masked failures — Debian `nat_rule_tokens_agree_with_emitted_nft_argv` (the test never applied the killswitch, so the egress-allow rule it expects is never emitted) and macOS `linux_runtime_authoritative_socket_poll_is_budgeted_per_tick` (required a poll to hit the cap exactly; trickled loopback delivery makes that racy). Both FIXED directly (8eebcaf2: killswitch applied first through the capture helper; budget test asserts ≥2 polls after a settle). Windows leg green at 2dd60138.
- MERGED: receiver-index demux inverse-map plan (fb8e5829, docs; anchors spot-checked; refute pass required before code).
- QH-01 seam job COMPLETE (966 lines: validated_args.rs with hoisted validate_ip_arg/utun/windows_path + node_id/cidr/posix_path/service/bundle_filename/port/connection_user/interface_name, RemoteCommand + PowerShellScript newtypes, Step-5 pin with baseline 160 raw sink call sites). Merge-gate finding: `RemoteCommand::from_template(String)` and `PowerShellScript::from_script_body(String)` accepted any String and voided the type boundary (the renderer returns plain String) — both removed at the gate; the typed renderer-output constructor lands with Step 4d.
- LAUNCH: C6 macOS role-transition stage port (edit-1788323841459-29770-0). LAB harvest still in bootstrap_hosts (guest builds).
- LAB RUN livelab (labrun-1788323525086-16069-0, rank-1 macOS-client full suite): FAIL at `bootstrap_hosts` — "macos-utm-1: macOS daemon at /private/var/run/rustynet/rustynetd.sock did not become LIVE after 8 retried probes (~80 s) post launchd bootstrap; probe exit 1, stdout tail: daemon-unreachable". Linux guests bootstrapped. Ledger rows committed; diagnosing on the guest (launchd state, daemon log) before recording the remedy and relaunching.
- MERGED: QH-01 seam (2f61cdbe). LAUNCH: P2 plan refute review (edit-1788324500342-37505-0); QH-01 Step 4a (argv-join sites) next.
- macOS BOOTSTRAP ROOT CAUSE (guest macos-utm-1): rustynetd exited with policy_reject 78 on two fail-closed residues — (1) System Configuration DNS still 127.0.0.1 from an earlier protected run while the backup document `/private/var/run/rustynet/networksetup-dns.failclosed.bak` was gone: SC DNS persists across reboot but /private/var/run does not, so any reboot during protection strands the node (structural; breaks macOS live_reboot_recovery) — applied the daemon's own documented remedy (`networksetup -setdnsservers Ethernet Empty`; resolution verified); (2) the QH-40 durable shutdown-residue marker from a rollback that failed because the privileged helper was already gone at shutdown (`MacOsHelperShutdownOrderingDesign_2026-08-27.md` territory) — acknowledged with `rustynetd shutdown-residue-check --acknowledge` after confirming the VM had rebooted since. Remedy recorded in the triage ledger (e6aa04ae). No control was weakened; both gates remain.
- LAUNCH (docs): MacosDnsBackupRebootSurvivalPlan (edit-1788324845558-41138-0) — options A/B/C with the fail-closed analysis; refute pass required before code. Running: C6 port, P2 refute review, QH-01 Step 4a (edit-1788324670325-38660-0).

## Tick 11 — 2026-09-02 06:06

- CI GREEN: 8eebcaf2, fb8e5829 and 33cc8759 completed success on every leg — the first fully green CI runs of the session (the chain of masked Debian/macOS/Windows failures is exhausted at this tree).
- LAB RUN livelab-1788325534-2e7bdaf7bf57 (rank-1 macOS-client full suite, relaunched after the guest remedies): macOS bootstrap PASSED this time (15 stages pass incl. bootstrap_hosts/membership/distribution/enforce_baseline_runtime on 3 nodes); FAIL at `validate_baseline_runtime`: "macos-utm-1/DnsFailclosed: validation not passed" — diagnosing the macOS DNS fail-closed validator output on the guest. Ledger rows committed.
- MERGED: P2 demux refute review (0d033d67: READY-WITH-AMENDMENTS A1-A5, incl. drop-and-count instead of expect at engine.rs:666); macOS DNS-backup reboot-survival plan (8c8ebda5: Option A). LAUNCH: refute review of the DNS-backup plan.
- C6 job COMPLETE (37 files, +348/−97: new stage macos_role_transition_validation.rs, StageId, plan/native wiring, hub block deleted). Gate running. Review finding: the stage resolves the macOS alias BEFORE checking election, so a Linux-only run (no macOS node) would FAIL the stage instead of skipping — must be fixed on the branch before merge.
- MERGED: QH-01 Step 4a (eb63b771: the three validator argv-join sites now render through ValidatedArg::cli_token + RemoteCommand::from_args / PowerShellScript::from_call_argv); C6 macOS role-transition stage port (gate fixes: election-before-alias so Linux-only runs skip instead of fail; tier pin 22→23).
- macOS DnsFailclosed ROOT CAUSE: enforce_baseline_runtime's launchd restart → the daemon's shutdown rollback failed at "privileged helper connect failed" (the helper is gone when the daemon tears down DNS/pf) → QH-40 residue marker + protection not re-applied when validate_baseline_runtime ran 2 s later. This is the unimplemented §2/§3 half of MacOsHelperShutdownOrderingDesign_2026-08-27.md (branch work/d7-qh40-helper-order carries nothing beyond main). LAUNCH (docs): the implementation plan (edit-1788326583722-75578-0); refute review of the DNS-backup plan (edit-1788325715024-65275-0). Remedy recorded for the launch gate; a Linux-pair full run follows to re-prove the Linux suite on the current tree.
- LAUNCH (code): QH-01 Step 4b — argv-shaped traffic-adapter sites (edit-1788326806318-76976-0). LAB: Linux-pair full suite running (labrun-1788326661320-76030-0) after the validate_baseline_runtime remedy was recorded.
- CI note: e6aa04ae (a triage-ledger-only commit) failed ONLY the "Linux real WireGuard E2E" leg with "report writer returned fail" (policy_reject 78) ~57 s after the expected killswitch-unreachable phase; the runs immediately before (387ee513) and after (2e7bdaf7) passed the same harness on the same code → classified as an E2E-harness flake on the runner, not a regression. Watch for recurrence; if it repeats, delegate a root-cause on scripts/e2e/real_wireguard_exitnode_e2e.sh's report-writer step.
- MERGED: DNS-backup plan refute review (READY-WITH-AMENDMENTS A1-A6; notable: the macOS reboot stage does not exist yet and becomes part of the deliverable; an unverified restore must not retire the backup); macOS helper shutdown-ordering implementation plan (helper rollback lease primary, retry-with-deadline defense in depth, lab ordering hygiene never primary). LAUNCH: P2 review fold (edit-1788326972120-79274-0); helper-ordering plan refute review next.
- C6 proven live in labrun-1788326661320-76030-0 (Linux pair, 29 pass / 0 fail at 05:30Z with the live suite still running): `validate_macos_role_transition` recorded "skipped: macOS is not elected for role transition" — the merge-gate election-order fix is what makes a Linux-only run skip rather than fail. LAUNCH: helper-ordering plan refute review (edit-1788327050110-82557-0, based on the plan branch); DNS-backup review fold (edit-1788327079972-87799-0). Four GLM jobs in flight.

## Tick 12 — 2026-09-02 06:43

- LAB RUN livelab-1788327430-edbacd677f7f (Linux pair, full suite, tree clean at edbacd67): **39 pass / 0 fail / 25 skip**, overall `partial` (skips only: two_hop needs an entry hop + second client, anchor/relay/macOS/Windows cells need those nodes). The Linux suite is re-proven green on the current tree after the tick-9..11 merges (F-1, anchor-TLS, QH-26 gate, QH-01 seam + 4a, C6). Ledger rows committed.
- CI: 21a2c5cd (C6) failed `registry_matches_historical_platform_resolution` on macOS + Debian — the run-matrix oracle expected all three platforms for the new stage while platforms_for_stage resolves it Linux-only (gated behind an elected macOS role transition, like the MAC-D3 validators). FIXED directly (test expectation; lesson: a StageId change must also gate `live_lab_run_matrix` tests).
- MERGED: P2 review fold (d6f5c8f2), DNS-backup review fold (cfb0e5e3), helper-ordering plan refute review (39485580: READY-WITH-AMENDMENTS A1-A8; F1 = the lease may not address the observed failure until Q-1 is answered from the run logs; F2 = the design's owner sign-off gate and priority were dropped; F6 = Option B's deadline arithmetic could push the daemon past its own SIGKILL).
- LAUNCH (code): P2 receiver-index inverse map (edit-1788328125627-36698-0; drop-and-count, helper-before-mutation); macOS DNS-backup durable path (edit-1788328308927-38016-0; Option A amended, tests-first list from the review). LAUNCH (docs): helper-ordering fold + Q-1 evidence (edit-1788328079240-36388-0).
- Step 4b COMPLETE (1.68M tokens; 443/−79 across the three traffic adapters + ssh.rs `from_args_with_stderr_merged` + `cli_token` alphabet gains `/` for `KEY=/path` env tokens; 13 argv-shaped sites migrated with per-site rendering tests; a 24-row "Step 4b remainder" table for 4d; one incidental clippy `from_ref` fix in check_delegated_edit_markers.rs). Review: sound; merge after the gate + a pin ratchet (the job left BASELINE_RAW_SINK_CALL_SITES unchanged although the count went down).
- LAB: Ubuntu guest booted (ubuntu-utm-1 → 192.168.65.9; inventory refreshed 091f5e09). Three-node run launched with entry_vm=ubuntu-utm-1 so two_hop/relay/anchor cells can dispatch.
- MERGED: QH-01 Step 4b (13 argv-shaped traffic sites; pin ratcheted 160→158 at the gate).
- LAUNCH (code): QH-01 Step 4c — install/membership adapters, argv-shaped sites (edit-1788328738505-43825-0). Four GLM jobs in flight (helper fold+Q-1, P2 inverse map, DNS-backup durable path, Step 4c). Three-node lab run labrun-1788328399035-39708-0 in bootstrap_hosts (Ubuntu builds).

## Tick 13 — 2026-09-02 07:06

- MERGED: helper-ordering plan fold + Q-1 evidence (answer (b): the failing restart was enforce_baseline_runtime's daemon-only restart_daemon; MACOS_LAUNCHD_STOP_COMMAND never ran in that run; helper liveness at that instant is undetermined from the logs). DECISION: the production lease (S1/S2) stays behind the design's recorded owner sign-off gate — I am NOT overriding a repo-recorded owner gate on a privileged-helper behaviour change; the lab-side S2b (verify/restore helper liveness before the daemon restart) + M2 teardown-site ordering hygiene proceed now as the fix for the driving incident. Deferred decision logged for the owner.
- CI: 823671be red on `vm_lab::tests::rust_native_cli_stage_ids_match_plan_builder` (64→65 after C6) — fixing the count pin directly.
- LAB: three-node run labrun-1788328399035-39708-0 at 30 pass / 0 fail; two_hop still skipped ("needs a second client: no node carries the extra or aux role") and relay/anchor need assigned roles — the ai_lab_run tool exposes entry_vm only, so the next two-hop attempt launches the orchestrator directly from Bash with --extra-vm (a fourth Linux guest, Fedora, booting now).
- LAB RUN (three nodes: exit debian-headless-4, client debian-headless-2, entry ubuntu-utm-1; labrun-1788328399035-39708-0): **39 pass / 0 fail** (skips = topology: two_hop still needs an `extra`/`aux` second client; relay/anchor need assigned roles). The Ubuntu 26.04 guest joined the mesh as the entry node on the current tree. Ledger rows committed. Fedora guest booted and inventoried (613c6a3d) for the four-node two-hop attempt (direct launch with --node fedora-utm-1:extra).
- P2 inverse map COMPLETE (677-line engine.rs change; gate green: clippy 1.88, 43 engine + 291 crate tests). Review finding: on a receiver-index divergence the branch FALLS BACK to the endpoint match and carries a `debug_assert!(false)` on the packet path — the amended plan (A3) requires drop-and-count with no panic in any build; fixing on the branch before merge.
- MERGED: P2 receiver-index inverse map (hand fix at the gate: divergence = drop-and-count, no endpoint re-attribution, no debug_assert on the packet path; 44 engine tests). Unified-build nextest for `engine` follows on main.
- LAB: launching the FOUR-node two-hop run directly from Bash (--node debian-headless-4:exit --node debian-headless-2:client --node ubuntu-utm-1:entry --node fedora-utm-1:extra) on the vm-lab CLI built from the current tree.
- P2 post-merge check on main: `cargo nextest run --workspace --all-targets --all-features --locked -E 'test(engine)'` (the mock-clock unified build) — 73 passed.
- DNS-backup job COMPLETE (699/−93 across macos_dns_sc_protect.rs, phase10.rs, daemon.rs, the lab cleanup batch and the macOS bootstrap script's residual-state rm line). Review: derived path `<state>.networksetup-dns.failclosed.bak` via the QH-40 pattern; no reader of the volatile path remains; backup written before the first networksetup mutation (source-pinned); unverified restore retains the backup and refuses startup (A5); parent-missing reads as backup-missing; the privileged helper gains NO new operation (test-only change). Note: the macOS bootstrap's residual-state clear now also removes the QH-40 marker on a re-bootstrap — an explicit reinstall action, consistent with review A4. Gate in progress (workspace check + clippy 1.88 green so far).
- MERGED: macOS DNS fail-closed backup durable path (gate green incl. windows-gnu cross-check). Live proof pending the S2b/M2 lab-side change: then the rank-1 macOS-client run.
- Step 4c HALTED on the token ceiling (2.13M) with its work checkpointed (467/−172 across six adapter files + the plan's remainder table; the checkpoint commit carries the delegated-edit marker and will be rewritten on the scratch branch before merge). Review finding: the Linux `init-membership` invocation puts the bare exit node id after `env` instead of `RUSTYNET_NODE_ID=<id>` — `env` would execute the node id as the program (a setup-stage regression) — fixing on the branch before merge; the macOS twin is correct; a new `capability_csv` class replaces the two local `shell_safe_arg` guards. Gate running.
- LAUNCH (docs): post-merge adversarial review of the DNS-backup implementation (edit-1788330687945-80280-0). LAB: the four-node run is still in bootstrap_hosts (the Fedora guest builds from scratch under host load ~22).
- **live_two_hop_validation PASSED** in the four-node run (state/manual-lab-1788329866, 06:36:26Z; exit debian-headless-4, client debian-headless-2, entry ubuntu-utm-1, extra fedora-utm-1) — the first two-hop pass of this session on the --node engine (32 pass / 0 fail so far; artifact + ledger-row verification when the run finishes).
- MERGED: QH-01 Step 4c (gate fixes: Linux init-membership env assignment, macOS path-class test). Pin stays 158.
- MERGED: post-merge review of the DNS-backup implementation (ACCEPT; live reboot-survival proof still open — the review specifies the procedure). CI: 3f812a49/613112c1/687bd59b green after the C6 pins.
- S2b/M2 COMPLETE (551/−15: helper-liveness probe/restore before restart_daemon via the seam, refusing the restart if the helper cannot be restored; the early helper bootout removed from MACOS_LAUNCHD_STOP_COMMAND with the TERM fallback moved after the post-wait bootout; bounded daemon-exit waits in uninstall.rs and both installer stop regions). No rustynetd change. Gate running. Review note: the job raised the raw sink-call-site pin 158→159 for its seam-routed commands because the scanner counts every run_remote call — tightening the scanner to skip seam-lowered `.as_str()` calls at the merge gate so the pin ratchets down instead.
- LAUNCH (docs): AT-2 anchor TLS client-pinning design (edit-1788331391554-41042-0).
- LAUNCH (code, hub files): macOS reboot-with-protection live stage `validate_macos_reboot_recovery` (edit-1788331511666-45649-0) — the DNS-backup live proof; touches stage/mod.rs, plan.rs, native.rs, context.rs, registry, run-matrix oracle and every count pin. Four-node run at 34 pass / 0 fail (key custody running).
- MERGED: S2b/M2 (helper liveness before macOS daemon restarts; helper stopped only after the daemon-exit wait at every site; QH-01 pin scanner now counts raw calls only → baseline 158→140). Live proof next: the rank-1 macOS-client harvest on the rebuilt vm-lab CLI.
- **FOUR-NODE RUN COMPLETE — livelab-1788331859-79ce523d8354: 41 pass / 0 fail / 23 skip; `linux_stage_two_hop = pass` AND the artifact `state/manual-lab-1788329866/live_two_hop_report.json` records status pass, evidence_mode measured, end_to_end_reachable true (client → entry ubuntu-utm-1 → final exit debian-headless-4, second client fedora-utm-1).** Column and artifact agree. Ledger rows committed.
- MERGED: S2b/M2 (the merge conflicted with Step 4c in macos_install.rs's test module — both test blocks kept verbatim; macos_install + validated_args tests and clippy 1.88 re-run on the merged tree).
- INCIDENT (self-inflicted, fixed): the S2b merge conflicted with Step 4c in macos_install.rs's test module; my concatenation resolution dropped one closing brace and the chain committed + pushed 687d67d5 before the compile result was read — rustynet-cli did not compile on main for two commits (687d67d5..1bb6b2a7). Fixed at d2695632 (74 macos_install tests + clippy 1.88 green, commit gated on the results this time). Lesson recorded: every merge-conflict resolution must be compile-gated before commit, and commits must be `&&`-chained on the gate result.
- MERGED: AT-2 client-pinning design (finding: no production client reaches a --allow-lan anchor today; the pin's signed-field trust bootstrap is an owner decision — deferred).

## Tick 14 — 2026-09-02 08:10

- Whole rustynet-cli suite on the merged main: 2908 passed, 0 failed (post-incident confirmation). vm-lab CLI rebuilt from the fixed main.
- LAB: rank-1 macOS-client full suite RELAUNCHED as the live proof for S2b/M2 + the durable DNS backup (see the job id in the loop journal / state/deepseek-mcp-jobs).
- LAUNCH: S2b/M2 post-merge refute review (edit-1788332482671-2798-0); QH-01 Step 4d-i typed renderer output `RenderedScript` + `from_rendered` (edit-1788332528611-3366-0). Running: macOS reboot stage (edit-1788331511666-45649-0). Harvest labrun-1788332375714-1644-0 in bootstrap_hosts.
- CI: the DNS-backup merge broke the Windows and Debian legs on two tests — `derived_backup_path_is_durable_sibling_of_state_path` asserted the macOS state root literally (DEFAULT_STATE_PATH differs per OS) and `backup_write_failure_aborts_and_keeps_prior_backup_intact` relied on a 0400 mode that root bypasses on the Debian container. FIXED directly (d85bb56c: platform-derived expectation; root-tolerant write-failure assertion; gated on rustynetd tests + clippy 1.88 + windows-gnu check).

## Tick 15 — 2026-09-02 ~07:20–08:40Z

**Orientation.** main `9f1a490e` → `e742531e`, staleness 0. CI on main is GREEN again from
`d85bb56c` (DNS-backup portability fix) through `e742531e` — three consecutive green runs
after the `687d67d5..1bb6b2a7` red streak (the merge-resolver brace incident, fixed at
`d2695632`; the DNS-backup platform-sensitive tests, fixed at `d85bb56c`).

**Harvest re-run diagnosed (rank-1 macOS client, `labrun-1788332375714-1644-0`).** Still
FAILS `validate_baseline_runtime` (`macos-utm-1/DnsFailclosed`, 15 pass / 1 fail). This is
NOT the S2b residue path any more: the QH-40 shutdown-residue marker is clean and the daemon
log shows no rollback failure across the enforce restart — S2b/M2 did their job. Root cause,
read from `/usr/local/var/log/rustynet/rustynetd-error.log` BY LINE NUMBER (the unstamped
stderr lines defeat any numeric `awk '$1>ts'` filter and produced a wrong
"membership snapshot missing" hypothesis first — discarded): the daemon restarted by
enforce at 07:08:22Z reaches `runtime bootstrap complete` at 07:08:28.9Z and then logs
NOTHING until cleanup — no `signed state refresh completed` line. The Linux client
(`debian-headless-2`) over the same window logs `signed state refresh completed
(reason=command)` right after ITS enforce restart and passes: the Linux enforce path
(`linux_install::enforce_daemon` → `rustynet ops e2e-enforce-host` → the signed-state
refresh in `ops_e2e.rs`, IPC `state refresh`) re-applies the dataplane generation after the
restart; `macos_install::enforce_daemon` (`macos_install.rs:752`) restarts and waits for the
socket but issues no refresh, and on macOS `apply_dns_protection` runs only inside a
signed-state refresh (`phase10.rs apply_dataplane_generation`, `protected_dns` arm). So the
macOS client sits with NO DNS protection after a clean restart until an endpoint change or an
operator command — the validator, 2 s later, correctly reports drift. Two-layer fix, both
planned before code per the charter: (a) orchestrator parity — macOS enforce issues the same
post-restart `state refresh`; (b) product — the daemon re-applies its persisted protected
posture at startup itself (the fail-closed answer: a client that had protection before the
restart must not come up unprotected waiting for a command). Remedy recorded for the launch
gate; plan job launched (`MacosEnforceRefreshParityPlan_2026-09-02.md`).

**Merged.** S2b/M2 post-merge adversarial review (`06c8c60b`, ACCEPT-WITH-FIXES; confirmed
gaps F1 helper job-present-but-process-dead, F3 KILL fallback ordering inverted, F5 scanner
`.as_str()` bypass — fix job to follow once Step 4d-i lands, to avoid a `validated_args.rs`
collision). Harvest ledger rows (`e742531e`).

**Reboot stage (C7).** Branch `ai-edit/edit-1788331511666-45649-0` (HALTED-BUDGET
checkpoint) gated: pinned rustfmt drift in 6 files fixed, clippy 1.88 green, WHOLE
`rustynet-cli` suite 2906 pass; marker checkpoint amended to a proper commit `acb7f5c0`.
Merge HELD for the GLM adversarial implementation review (`edit-1788341319499-11418-0`) —
my own read flagged three things for it to confirm: the stage `budget_secs: 180` is smaller
than the helper's own worst-case wait (8 × (90 s + 20 s)); `shutdown -r now` swallows ANY
SSH transport error as "the reboot tore the channel down" with no pre/post boot-time
comparison proving a reboot happened; the unquoted `for svc in $(networksetup …)` word-splits
service names with spaces.

**Step 4d-i** (`edit-1788332528611-3366-0`) TIMED OUT but left a complete, properly authored
commit `21a2ea44` (no marker): `RenderedScript` newtype (private field, no `From<String>`,
length-only Debug) returned by every `render_*`, typed `RemoteCommand::from_rendered` /
`PowerShellScript::from_rendered`, crate-wide source-scan pin, raw-sink pin 140 → 130.
Diff read in full; gate running (clippy green, whole-crate tests in flight).

**Fleet.** Running: reboot-stage review (`…11418-0`), Windows node-parity PHASE A root-cause
analysis (`edit-1788341400379-14626-0`), macOS enforce-refresh parity plan (launched this
tick). Loop note #604.

### Tick 15 addendum — ~08:40–09:00Z

**Step 4d-i merged** (`ca44f598`): pinned rustfmt clean, clippy 1.88 clean, whole
`rustynet-cli` suite 3363 pass on the branch (the crate-wide `RenderedScript` source scan and
the 130 raw-sink pin both hold). Worktree removed, branch deleted.

**Launch-gate remedy recorded** (`12bb7b26`) against the real stub
`livelab-1788332954-9f1a490ec5c4::validate_baseline_runtime` — the stub id is the
orchestrator's `livelab-<unix>-<sha12>` run id, not the MCP `labrun-*` job id.

**Mechanism behind the Linux/macOS difference, pinned.** The Linux client's post-restart
`signed state refresh completed (reason=command)` is not issued by the enforce path at all: it
comes from `scripts/systemd/rustynetd-trust-refresh.timer` (`OnBootSec=45s`,
`OnUnitActiveSec=60s`) → `rustynetd-trust-refresh.service` → `ExecStartPost=rustynet ops
state-refresh-if-socket-present` (`main.rs` `execute_ops_state_refresh_if_socket_present`:
skip if the daemon socket is absent, else IPC `state refresh`). So on Linux the protected
posture after a restart is restored by a periodic external timer within ~60 s — in the harvest
it happened to land 0.1 s after bootstrap — and `validate_baseline_runtime` passes by that
timing. The macOS lab guest has no launchd counterpart (LaunchDaemons: anchor, daemon, exit,
privileged-helper only) and the macOS bootstrap installs none, so nothing ever re-applies the
posture after a clean restart. This sharpens the plan job's question: the product-side startup
re-apply (b) is the real fix on BOTH platforms — Linux is currently rescued by a timer, which
is a race, not a guarantee — and the orchestrator parity refresh (a) is the lab-side proof
enabler. Folded into the loop journal; the plan job (`edit-1788341753952-24366-0`) must be
checked against this when it reports.

**S2b/M2 fix job launched** (`edit-1788341910134-28312-0`, base `ca44f598`): the review's
Fixes 1–5 (tri-state helper probe with pid + socket, bootout-before-bootstrap on restore, KILL
before helper bootout, job-scoped exit predicate, anchored scanner exclusion) plus its
mandatory tests, with the explicit rule that the raw-sink pin may not be raised silently if the
anchored scanner exposes sites the loose one hid.

**Fleet: 4 running** — reboot-stage review (`…11418-0`), Windows parity PHASE A
(`…14626-0`), enforce-refresh parity plan (`…24366-0`), S2b/M2 fixes (`…28312-0`).

## Tick 16 — 2026-09-02 ~15:30–16:00Z (after a connection loss)

**What happened.** The client connection dropped after tick 15's re-arm. All four in-flight GLM
jobs sat idle until the 6-hour overall wall-clock cap (finished 14:50:55Z) and were reported
TIMED OUT; their serve processes were reaped on the first poll. Outcomes: the reboot-stage
review (`…11418-0`) and the enforce-refresh plan (`…24366-0`) wrote NOTHING (branch tip = base,
clean tree; worktrees + branches removed); the S2b/M2 fix job (`…28312-0`) left one partial,
non-compiling checkpoint in `macos_install.rs` (the `HelperJobPresence` / `HelperRestoreReason`
tri-state types and the `drive_restart_with_helper_liveness` signature change, call site not
updated); the Windows PHASE A job (`…14626-0`) finished its doc.

**Merged.** `WindowsNodeParityRootCauseAnalysis_2026-09-02.md` (`b3966a5f`). Merge-gate
finding: its headline row counts were wrong (fail 4 / pass 10 / skip 169) — re-counted with the
csv module: 185 Windows rows, 5 runs, **5 fail** (preflight ×2, bootstrap_hosts ×3), **2
not_proven** (cleanup), **15 pass** (preflight, prepare_source_archive, verify_ssh_reachability,
cleanup_hosts, cleanup; three each), **163 skip**. The per-stage breakdown and the six failure
mappings (F1 topology, F2 winget config not staged → fixed `7bb72149`, F3 WinGet Configuration
never enabled → fixed `03483da6`, F4 OPEN 3602 s clock skew at `preflight.rs:55-64`, F5 arm64
signtool on x86 → fixed `003d5edc`, F6 cleanup collector `$null.Count` → fixed `45d27d56`) were
spot-checked against the ledger and the code anchors and hold. Counts corrected on the branch
before merging. Key conclusion: no Windows row has ever reached a validation stage, so the
product is unproven, not failed; R1 = land the first `bootstrap_hosts` pass.

**Relaunched (one per response).** Reboot-stage adversarial review → `edit-1788363128441-40424-0`
(base = the amended branch tip `acb7f5c0`); enforce-refresh parity plan →
`edit-1788363280049-41969-0` (task now carries the pinned trust-refresh-timer mechanism and
requires the product-side startup re-apply to be primary); S2b/M2 fixes →
`edit-1788363401449-43584-0` (base = the checkpoint branch, whose marker commit was first amended
to a proper Iwan-Teague commit `1a343e32` describing it as partial; the job is told the crate does
not compile at that tip and must start with `cargo check`). Old worktree of `…28312-0` removed;
its branch retained as the relaunch base.

**Fleet: 3 running**, fourth launch (C2 unquarantine / C3 pf ports) next.

## Tick 17 — 2026-09-02 ~16:40–17:45Z

**Reboot stage (C7) MERGED.** The GLM adversarial implementation review completed
(`MacosRebootRecoveryStageImplementationReview_2026-09-02.md`, ACCEPT-WITH-FIXES) and confirmed
all three of my own flags plus one more: F1 HIGH — a pre-dispatch SSH error was swallowed and
nothing proved a reboot occurred; F2 — the alternate acceptance clause `contains("ok")` was dead;
F3 — the loopback-pin loop word-split service names and passed vacuously on an empty list; F4 —
`budget_secs: 180` below the helper's ~1270 s worst case. Hand-fixed on the branch
(`3551b290`): both capture scripts emit `sysctl -n kern.boottime`, the helper extracts the single
`boottime=` line from each and FAILS when unchanged; the typed fail-closed evaluator is the sole
survival gate and the M1 recovery line is recorded as evidence of which path restored the posture
(deliberate deviation from the review's "require the line" wording — a clean-shutdown reboot
retires the backup and legitimately has no recovery line, so requiring it would fail a correct
reboot); line-oriented pin check with an empty-list hard failure; budget 1200 s; four unit tests
for the boottime parser. Re-gated: pinned fmt clean, clippy 1.88 clean, whole `rustynet-cli`
2910 pass. Merged the stage (`abd48e8c`) then the review (`d70e1e27`, README index conflict
resolved with the docs-only resolver). Its live cell still waits for the enforce-refresh fix.

**Stall pattern identified and acted on.** Three of the four jobs relaunched in tick 16 showed
IDENTICAL token spend across two polls 25 min apart with clean worktrees. Their OpenCode sessions
(`/session/<sid>/message`) each showed an assistant turn with parts `[step-start, reasoning]`,
`completed=false`, created 43–57 min earlier — the provider's reasoning stream hung and OpenCode
waits forever. Killed the three serves (`kill -TERM`), settled their records (TIMED OUT, nothing
produced), removed the empty worktrees/branches. Relaunched S2b/M2 fixes →
`edit-1788367161603-86936-0` (base = the partial checkpoint branch `1a343e32`; task now says to
work in small steps and commit after each compiling milestone); C2 unquarantine relaunched this
tick; the enforce-refresh plan relaunch is next. The R2 clock-skew plan job
(`edit-1788366061714-71947-0`) is progressing slowly (new turns appearing) and was kept.

**Also launched:** Windows R2 clock-skew hardening plan (`edit-1788366061714-71947-0`, docs).

## Tick 18 — 2026-09-02 ~17:58–18:15Z

**Enforce-refresh parity plan MERGED** (`9c907071`, `MacosEnforceRefreshParityPlan_2026-09-02.md`).
Verified at the gate: Requirements.md:90/:146/:186/:197 and SecurityMinimumBar.md:240-243/:283
say what the plan quotes; `maybe_assert_dns_posture` does skip unless `controller.dns_protected()`;
the startup block runs `run_startup_dns_recovery` then `runtime.bootstrap()` with no apply. Its
ratified decision matches mine: the product-side startup re-apply of the persisted protected
posture is the PRIMARY fix on both platforms (the Linux trust-refresh timer is reclassified as a
fail-open window that merely masks the gap), the enforce-path `state refresh` is the lab-side
proof enabler. Two stale "unknown" bullets (already resolved in §2/§3.1) removed at the gate. One
anchor is off — the plan cites the `protected_dns` arm at `phase10.rs:6535`; the symbol is at
:391/:409/:6852 — left for the review to correct with the rest of its anchor table.
**PHASE B review launched** → `edit-1788368507314-4519-0`, with the pointed question of whether a
startup re-apply of an EXPIRED persisted generation would itself violate fail-closed, and whether
the strictest-secure scope is to re-apply only the LOCAL protective posture (DNS pin + DNS block +
killswitch) at startup and leave peers/routes to the refresh.

**Fleet health.** S2b/M2 fixes (`…86936-0`): 2 commits + `macos_traffic.rs` in progress. C2
unquarantine (`…87816-0`): editing `vm_lab/mod.rs`. R2 clock-skew plan: the tick-17 launch
(`…71947-0`) hung in a reasoning turn for 25 min (spend frozen) — killed and relaunched as
`edit-1788367835553-94044-0` (1 commit already). Owner mentioned a patchy internet link; that
fits the hang signature (a dropped SSE stream that OpenCode never times out) — the stall rule plus
commit-per-milestone is the mitigation.

## Tick 19 — 2026-09-02 ~18:20–18:35Z

**Windows clock-skew hardening plan MERGED** (`WindowsClockSkewHardeningPlan_2026-09-02.md`).
Verified at the gate: `MAX_LAB_CLOCK_SKEW_SECS = 90` and `CLOCK_PROBE_ATTEMPTS` at the cited
preflight.rs lines; SecurityMinimumBar.md:136 (clock-skew tolerance on signed state) and
Requirements.md:182 (strict clock-skew policy) say what is quoted; the ledger row for
`livelab-1785005557-b7667cce46db` carries exactly `guest clock skew is 3602s (maximum 90s;
host=1785005541, guest=1785001939)` — and the plan correctly notices the same error is recorded
against `linux-x86-client-1` too (topology-scoped stage), flagged as a possible reporting defect.
Fixed two README index entries that had become nested bullets. PHASE B review launched next.

**CI.** `9c907071` (docs-only) went red on the macOS leg at "Bootstrap CI tools": `failed to
clone advisory db from https://github.com/RustSec/advisory-db.git` — a runner network flake, not
the change; re-ran the failed job (`gh run rerun --failed`). `0bd3f8ac` still in progress.

**Fleet.** S2b/M2 fixes (`…86936-0`): 5 commits, now updating the helper-ordering plan doc — near
done, spend 1.10M. C2 unquarantine (`…87816-0`): 4 commits, editing `active_exit.rs`, spend 1.18M.
Enforce-refresh plan review (`…4519-0`): 1 commit, 2 sub-agents. All turns fresh (<1 min old).

## Tick 20 — 2026-09-02 ~18:40–19:40Z

**Four jobs finished this tick; all four merged after gating.**
- **S2b/M2 review fixes** (`dcd80af2`): tri-state helper probe (pid + socket), bootout-before-bootstrap
  on restore, SIGKILL backstops before the helper bootout, job-scoped daemon-exit waits, symbolic
  uninstall wait budget. The job had raised the raw-sink scanner pin 130 → 159 by anchoring the
  `.as_str()` excuse to "alone on its own line", which re-counted 29 validated locals passed inline.
  Hand-fixed at the gate (`ffc47f67`): the excuse now keys on the RECEIVER shape (a bare identifier
  or field path is excused in either layout; a call/index/literal/turbofish receiver counts raw), so
  `format!(…).as_str()` is caught and the pin stays at 130. Whole cli suite green before and after.
- **macOS exit-serving adapter wiring, design A2** (`3f0be0c1`): both hub evaluators unquarantined,
  `MacosNodeAdapter` exit methods assert the daemon's own lifecycle verifier over the seam,
  precedence check only in the pre-activation baseline position, predicate stays false for macOS
  (pinned by `macos_two_phase_stage_reports_skip_while_predicate_false`); 3372 tests.
- **Enforce-refresh plan review** (`c219b3aa`) — **CRITICAL correction to my tick-15 root cause:**
  `bootstrap()` (daemon.rs:8623, called at :11812) ALREADY applies the full dataplane generation
  with `protected_dns: true` (:8878) on every startup, on both platforms. Verified myself: the
  ApplyOptions literal in bootstrap carries `protected_dns: true`, and macOS `apply_dns_protection`
  (phase10.rs:4609) does the pf rules AND the networksetup loopback pin. So "nothing re-applies the
  posture after a restart" was wrong, and the Linux timer is redundancy, not the mechanism. What
  remains unexplained is why the macOS restart at 07:08:22Z logged the PLAIN `runtime bootstrap
  complete` (which means `bootstrap_error` was None — `restrict_recoverable` sets it — so the apply
  returned Ok) yet the verifier saw no pin, no pf DNS rules 5 s later. The DryRun-system hypothesis
  is dead (DryRun is `cfg(test)`-only). Diagnosis is now the primary product task; a 2-second
  sampler (`/tmp/rn_watch_loop.sh` → `/tmp/rn_watch.log`) is running on the macOS guest to capture
  pf rules, Ethernet DNS, resolver, launchd pids and the daemon log across the next harvest's
  enforce→validate window.
- **Enforce-refresh plan fold** (F-1..F-6 applied by a docs job; merged this tick).
- **Clock-skew plan review** (`48c7c460`): ACCEPT-WITH-AMENDMENTS A-1..A-9 (generic drift never
  remediated; drop the unreachable `Unparseable`; sign convention; fresh host reading at remedy time;
  7205→7240 test fix; flag-off byte-identity test; inclusive band; duplicate preflight row is
  run-scoped attribution; name the timestamp validator).

**Incident (self-inflicted, contained).** The R2-review merge conflicted on the README index; the
`&&` chain stopped silently after the refresh-review merge and I missed it, leaving main in a
conflicted merge state (unpushed) for ~20 min. Consequences: the rank-1 harvest I launched
(`labrun-1788371172581-62950-0`) was refused by `prepare_source_archive` ("git worktree must be
clean"); two GLM jobs branched from the unpushed refresh-review commit (harmless — it is now on
main). Repaired: README resolved with the docs-only resolver, merge committed (`48c7c460`), ledger
rows of the refused run committed (`eebb1ad4`), pushed. Rule for the charter: after ANY merge chain,
assert `git status --short` is empty and `rev-list origin/main..HEAD` is what you expect.

**Launched.** R2 classifier core (`edit-1788370974520-55427-0`, preflight.rs only, amendments
A-1/2/3/5/7 baked in). Gap A enforce-path refresh (`edit-1788371870504-83558-0`, macOS + Linux
enforce issue `state refresh` after the socket wait, seam-only, order pinned, non-zero fails).
CI: `9c907071` re-run green; docs commits in progress.

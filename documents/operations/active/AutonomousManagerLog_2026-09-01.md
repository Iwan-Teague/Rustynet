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

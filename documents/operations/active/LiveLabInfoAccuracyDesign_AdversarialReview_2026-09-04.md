# Adversarial Review — LiveLabInfoAccuracyDesign_2026-09-03 — 2026-09-04

**Status:** UNTRUSTED adversarial review of `LiveLabInfoAccuracyDesign_2026-09-03.md`, written 2026-09-04. Working tree checked at commit `f0709cd` (`0769cd27c0c8ce8cd12f824fe460adcf8b0c68e5`); the design doc states it was grounded at `427f3c85`, which is **128 commits behind** the review commit. Doc-only review: no code was read into or changed by this document; every claim below was verified by reading the working tree.

---

## 0. Dominant finding (read first)

**The design doc proposes, as its top two build picks, work that has already landed in the tree.**

- **Item 2 (structured drift into the stage result) is implemented** in commit `1abc7d68` ("Thread verbatim validator reports into baseline-runtime evidence (design §5.2 Item 2)"):
  - `validator_report_ok` returns `ValidatorVerdict { ok: bool, reports: Vec<serde_json::Value> }` — **not a bool** (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/ssh.rs:879`, fn at `:912`). Its doc comment cites this design's §5.2 by name and states the verdict rules are unchanged.
  - Reports are threaded into validator results (`orchestrator/stage/validate_runtime.rs:203`: `let (passed, summary, report) = match &r { … report_out.reports.last().cloned() … }`) and persisted to `logs/validate_baseline_runtime.validator-evidence.json` (`validate_runtime.rs:255`; schema comment at `:89` cites "design §5.2 Item 2").
  - The failure string now carries the drift reason: `"{alias}/{op:?}: validation not passed — drift: {reason}"` (`validate_runtime.rs:229`). §5.2's "Example impact" is already the shipped behavior.
  - The doc's §4 row "validator_report_ok … returns **bool only** … The evidence-discard point" and §5.2's entire Problem statement are therefore **false at the review commit**. They were accurate at the doc's base `427f3c85` (verified: `git show 427f3c85:…ssh.rs` around `:884` shows the pre-§5.2 fail-closed comment without the verdict struct).
- **Item 4's core defect is fixed** in commit `2c10f9d9` ("Fix macOS DnsFailclosed check: enumerate nested com.apple sub-anchors to find the pf floor"):
  - `merge_rustynet_anchor_names(top_output, nested_output)` exists (`crates/rustynetd/src/macos_dns_failclosed.rs:491`) and `read_pf_dns_block_floor` (`:511`) now issues BOTH `pfctl -s Anchors` AND `pfctl -a com.apple -s Anchors`, unions them, and scans each anchor's rules — with explicit fail-closed commentary ("a failed top-level query still returns `None`… a missing nested query can therefore never make the check PASS"). The §2 claim "the check scans zero rustynet anchors" described the code at `427f3c85` (verified: at that commit `read_pf_dns_block_floor` read only `["-s","Anchors"]`) and **no longer describes the tree**.
  - §5.4's worked example ("after the refactor, `read_pf_dns_block_floor` scans `rustynet_g3` under `com.apple`…") is done, not proposed.
- **Item 9's prune half is partially landed:** `prune_owned_tables` (`crates/rustynetd/src/phase10.rs:4847`) is generation-aware (preserves current + immediately-previous generation, skips blind-exit anchors) and cites `MacosPruneNestedAnchorHygieneReview_2026-09-03`; `list_owned_anchors` (`phase10.rs:4100`) now unions the nested `com.apple` sub-anchor set (comment at `:4112-4126`). The `orphaned_pf_anchors` **drift dimension is not implemented** (zero hits for "orphaned" in `macos_dns_failclosed.rs`), so Item 9 is partially open.

Consequence: §6's ranked build order ("Top two picks: Item 4 and Item 2") is no longer actionable as written. The highest-leverage **remaining** work is Item 1 (evidence bundle), Item 7 (verified still real, F9), Item 9's drift dimension, and Items 3/5/8 (still absent — verified).

---

## 1. Findings

### F1 — HIGH (stale proposal / overclaim). Items 2 and 4 are landed, not proposals
See §0 with commits `1abc7d68` and `2c10f9d9`. The doc's §4 grounding row for `validator_report_ok` ("returns **bool only**") and §2 item 3 ("parsed… and then discarded") contradict `ssh.rs:879-946`. The doc must be re-scoped (mark items DONE with landing commits) before anyone builds from §6.

### F2 — HIGH (would weaken a landed control if followed verbatim). Item 9's prune post-condition is unsafe against the current tree
§5.9.3 proposes: "after flush, the shared enumeration returns zero `com.apple/rustynet_g*` anchors (except the protected blind-exit anchor)". The landed `prune_owned_tables` (`phase10.rs:4847`) deliberately **preserves the current generation** ("flushing it would strand the node in a pin-without-floor half state (A1/A6…)") and the previous generation. Implementing the doc's post-condition as written would flush the live floor-bearing anchor. **Correction required to the doc text:** the post-condition must exclude the current (and previous) generation, matching the landed guard and the test `prune_owned_tables_preserves_active_and_target_generation_tables` (`phase10.rs:14071`).

### F3 — HIGH (gate as spec'd is incompatible with the landed fix). Item 4's divergence-gate tripwire conflicts with the deliberate two-filter design
§5.4.2 proposes a grep tripwire failing on "a second `starts_with(\"com.apple/rustynet_g\")`-style filter outside the shared module". The landed code intentionally has **two** filters: the check uses the broader `parse_pf_anchor_names` filter via `merge_rustynet_anchor_names` (`macos_dns_failclosed.rs:491`), while `phase10.rs:4091-4098` keeps the narrower `owned_anchor_names_from_output` **by design** — its comment (`:4112-4126`) states the narrow filter is kept "NOT the broader DNS-check filter — so the fixed-name `com.rustynet/nat` exit-NAT anchor and `com.rustynet/blind_exit`… are never returned here". The tripwire as written would fail this tree, and "fixing" it by unifying the filters would widen the generation sweep to anchors that must stay out of it. The doc's §5.4 §1 ("All three consumers call it") was **not** how the fix landed, and should not be revived. **Correction:** the gate must encode the two-filter contract (one shared *nested-enumeration merge* per consumer family, distinct prefix policies) rather than a single-filter tripwire.

### F4 — MEDIUM (incorrect statistics). QH-37 numbers are wrong
§5.8 and §8 cite `live_two_hop_validation` "222 skip / 81 fail / 0 pass". The QH ledger's own recount says **"116 fail / 263 skip / 0 pass"** (`QualityHardeningTodo_2026-07-25.md:573`, table at `:612`). The 222/81 figures are the older count that the QH doc's recount superseded. Direction of the claim (0 lifetime passes) is correct; the numbers are stale.

### F5 — MEDIUM (fabricated/typo'd commit id). §8 cites `864918d9`
`git cat-file -t 864918d9` → "Not a valid object name". The real commit is `864919d9` ("Log tick 46: root cause = floor-not-persisted…"). `427f3c85` and `78a8b513` are valid.

### F6 — MEDIUM (wrong line cite, wrong even at the doc's base). §2's `validate_runtime.rs:158`
At `427f3c85`, line 158 of `validate_runtime.rs` is `records.insert(alias, node_records);`, not the failure-string format. At HEAD the string lives at `:229` (with drift reason) and `:231` (bare fallback). The §2 sentence "`validate_runtime.rs:158` formats exactly this string" is unverifiable at any checked commit.

### F7 — LOW (pervasive line drift; cites exact at base). Every `vm_lab/mod.rs`, `phase10.rs`, `macos_dns_failclosed.rs`, `native.rs`, `validate_runtime.rs` line number is stale at HEAD
Representative deltas (base → HEAD): `verify_live_pf_dns_floor` 4770→4800; `read_pf_dns_block_floor` 492→511; `validator_report_ok` 884→912; `DaemonProbeOp` 10139→10182; `DaemonProbe` trait 10173→10216; `LinuxDaemonProbe` 10221→10264; `WindowsDaemonProbe` 10257→10300; `MacosDaemonProbe` 10284→10327; `remote_exec_for` 10115→10158; `daemon_probe_for` 10350→10393; `json_object_candidates` 930→950; `collect_macos_dns_failclosed_snapshot` 540→575; `build_macos_dns_failclosed_report_for_posture` 570→605; `evaluate_macos_dns_failclosed_snapshot_for_posture` 611→646; pre-cleanup hook `native.rs` 791-805→891, `run_with_observer_and_pre_cleanup_hook` 815-818→915, `FinalCleanupStage::new` 846→946; OPS list 93-98→146-153; `ValidatorResult` 139-155→ moved + shape changed (now carries `report`); `validator_results.json` write 163-168→244; `flush_anchor` skip 4115-4126→4145; `prune_owned_tables` 4817→4847; `reconcile_exit_nat_residue` 4845→4891; `list_tandem_owned_anchors` 4881→4472; `TimeoutAwareStageRecorder` 642→636 (opposite direction); `MACOS_SCOPED_RESOLVER_PATH` consumed at 551-552→587/663 (and it lives in `linux_dns_protect`, re-exported). No finding here beyond staleness — but §4 presents these as *current* ("commit `427f3c85`" only appears in the table intro), and any reader at HEAD will fail to find half the symbols at the cited lines. The doc should state per-section that line numbers are base-relative.

### F8 — LOW (path imprecision). §4 cites "`windows_dns_failclosed.rs` (lib.rs :89)"
The file is `crates/rustynetd/src/windows_dns_failclosed.rs` (1797 lines); `:89` is inside `WindowsDnsFailclosedSnapshot` — content matches, "lib.rs" is wrong.

### F9 — NO ISSUE (verified real at HEAD): Item 7's problem stands
`enforce_launch_gate` (`crates/rustynet-cli/src/live_lab_stage_triage.rs:464`) prints the remedy with a **literal** `--stub-id <stub_id>` placeholder (`:495`), while the same message enumerates each blocking record's concrete `stub_id` (`:478-484`). `stub_id` = `format!("{run_id}::{stage}")` (`:113`; doc said `:112`, off by one). `RecordStagePatchConfig` `:143` and `execute_ops_record_stage_patch` `:154` match exactly. This is the doc's most clearly still-actionable small item.

### F10 — NO ISSUE (verified): the three proposed MCP tools do not exist today
`get_stage_result`, `lab_probe_node`, `lab_node_intent`: no registrations in `crates/rustynet-mcp/src/bin/lab_state.rs` (only prose mentions). The seven existing registrations the doc cites are **exact**: `get_vm_diagnostics` :4813, `diagnose_live_lab_failure` :4833, `get_run_result` :4951, `read_report_artifact` :4981, `grep_report` :4993, `get_stage_log` :5006, `stage_triage_history` :5100; dispatch match at `:6053+`. (Handler impls live at different lines — `grep_report` :2529, `get_stage_log` :2599, `stage_triage_history` :3013 — the doc cited registration lines, which is fair.)

### F11 — MEDIUM (residual risk worth stating, not a blocker): Item 6's TTL sweep is launch-dependent
§5.6's TTL fallback runs only "the *next* orchestrate launch (and a new `ops vm-lab-hold-release --all`)". An abandoned lab with no subsequent launch holds pf/DNS mutations indefinitely; the doc's mitigations (default-off, lab-only surface behind `vm-lab` per RNQ-17 — verified as the doc states, `FinalCleanupStage` at `native.rs:946` is inside that surface) bound severity, and the blind-exit rejection correctly mirrors AGENTS.md §10.7 irreversibility. Grounding verified: "always-run cleanup contract" comment `native.rs:174`; pre-cleanup hook ordering `:891`→`:915`; `run_history.rs` exists (`crates/rustynet-cli/src/vm_lab/run_history.rs`). The spec should add: the TTL sweep must also be invocable from a standalone op (it proposes `hold-release`, good — make it mandatory, not parenthetical) and must never be skipped when the held set includes an exit node whose NAT residue reconcile did not complete.

### F12 — LOW (unverified grounding detail, now resolved in the tree): §5.5's `build_bundle_env`
Exists: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/distribute_assignments.rs` (`pub(crate) fn build_bundle_env…`, plus a `…_produces_correct_keys` test). `resolved_plan.rs` and `role_assignment.rs` exist under `orchestrator/`. `macos_dns_posture` (`phase10.rs:801`), its daemon threading (`daemon.rs:8895`, `daemon.rs:10635` — both exact), and its tests (`phase10.rs:816-840` — exact) all verified.

### F13 — NO ISSUE (behavioral claims about pf semantics)
§2 item 5's "on macOS `pfctl -s Anchors` does not list nested anchors" is consistent with pfctl(8) top-level anchor enumeration, with the landed code's own comment (`macos_dns_failclosed.rs:505-516`: "`pfctl -s Anchors` lists only TOP-LEVEL anchor names… so the nested floor anchor is invisible to it"), and with the tick-46 commit record (`427f3c85`). This review did not re-prove it against a live guest; the repo's own landed fix is the evidence.

### F14 — LOW (minor): §4's item-1 grounding understates current coverage
"the baseline-runtime path lacks the equivalent" (exit-node check JSON persistence) — at HEAD the baseline path *does* persist `validator_results.json` (`validate_runtime.rs:244`) **and**, post-`1abc7d68`, `logs/<stage>.validator-evidence.json` (`:255`). Item 1's remaining delta is the *raw observation commands* bundle (pfctl/scutil/networksetup outputs), not check-JSON persistence. Re-scope Item 1 accordingly.

### F15 — NO ISSUE (security posture of the set)
No spec, as corrected above, weakens the `DnsFailclosed` verdict path or any fail-closed control. Item 4's landed direction strictly increases observation coverage while preserving `?`-fail-closed reads (`macos_dns_failclosed.rs:511-549`); Item 2's landed code explicitly keeps the verdict rules "byte-for-byte identical" (`ssh.rs:883-885`); Item 9's landed prune is *more* conservative than the doc's text (see F2). Items 3/8 are read-only additions. Item 5 correctly self-describes as unauthenticated intent reporting. The two doc texts that *would* degrade landed controls if implemented verbatim are F2 and F3 — flagged, not endorsed.

---

## 2. Verified correct (against the working tree)

- Exit-node artifact writers: `write_macos_exit_dns_failclosed_artifacts` `macos_exit_dns_failclosed.rs:104` writing `macos_dns_failclosed_check.json` at `:121-123`; Linux twin `linux_exit_dns_failclosed.rs:112` — **exact**.
- Per-OS siblings: `evaluate_linux_dns_failclosed_snapshot` `linux_dns_failclosed.rs:85`, `build_linux_dns_failclosed_report` `:191`, `collect_linux_dns_failclosed_snapshot` `:245` — **exact**.
- `REVIEWED_PFCTL_PATH` `macos_dns_failclosed.rs:74`, `parse_pf_anchor_names` `:328`, `anchor_rules_contain_both_dns_block_labels` `:347` — **exact**.
- `macos_dns_posture` `phase10.rs:801` + tests `:816-840` + threading `daemon.rs:8895`/`:10635` — **exact**.
- Tautology note ("THREADED by the caller… never inferred… would make the check a tautology") — exact at base `:565-569`, still present at HEAD `:602-605`.
- `collect_failure_diagnostics` `diagnostics.rs:19`, `diagnostics/rust-native-failure/` `:27`, `TimeoutAwareStageRecorder` `:636` — present (± lines).
- `probe_expectations` `validate_runtime.rs:60`; OPS list contents (all six `DaemonProbeOp` values) — verified.
- MCP tool-surface claims (F10) — exact at registration lines.
- `stub_id` format, launch-gate behavior, record enumeration, ledger addressing (F9) — verified.
- QH-07 exists as described (`QualityHardeningTodo_2026-07-25.md:535`, "A ledger column reports `pass` for a stage that has never passed"); quote-aware-parsing context correct.
- `verify_live_pf_dns_floor` body semantics at HEAD `phase10.rs:4800`: in-memory `anchor_name`, `pfctl -a <anchor> -s rules`, `DnsApplyFailed` if udp or tcp/53 block rule missing — matches the doc's description exactly (line stale only). Its "intentionally does not enumerate" claim (§5.4) remains true.
- Motivating-case commits: `427f3c85` and `78a8b513` exist; `427f3c85`'s message matches §8's quote verbatim.
- `run_history.rs`, `resolved_plan.rs`, `role_assignment.rs`, `build_bundle_env` — all exist (F12).

## 3. Considered, no issue

- **Item 3 (`lab_probe_node`) security model** — reusing `build_argv`/`daemon_probe_for` and appending `--no-fail-on-drift` is the correct P2-shaped design; the `--no-fail-on-drift` convention is real (comment at `ssh.rs:895` region; doc cited `:868-875`, stale but the behavior exists). No concern beyond F7 staleness.
- **Item 8's artifact-first composition** — `get_stage_log` really does read `state/stages.tsv` (`lab_state.rs` impl at `:2599`); the `ledger_column` cross-check is additive read-only plumbing. Sound.
- **Item 10 batch** — 10.1 `posture_inputs` is genuinely absent (still actionable); 10.2's recorder exists; 10.3-10.5 are additive observe-only proposals. No issue.
- **P1-P5 principles** — consistent with AGENTS.md §3/§4; no principle conflicts with the codebase as landed (the two-filter reality is a *refinement* of P2 the doc should absorb, F3).
- **"Evidence commands take no extras"** (§5.1) — consistent with the landed `build_argv_with_extra_args` token validation at `mod.rs:10234` (doc `:10191`); no security gap.

## 4. Self-verification

Per the full-mode rule, four of this review's key citations were re-grepped before finishing, all confirmed: `ssh.rs:879` (`pub struct ValidatorVerdict`); `macos_dns_failclosed.rs:491` (`pub fn merge_rustynet_anchor_names`) and `:511` (`pub fn read_pf_dns_block_floor`); `validate_runtime.rs:255` (`validator-evidence.json` write; schema comment at `:89`); `live_lab_stage_triage.rs:495` (literal `--stub-id <stub_id>` in the gate remedy).

## 5. Verdict

Sound design with accurate base-commit grounding, but **stale as a build plan**: its two top-ranked items (5.2, 5.4) and half of 5.9 are already landed (`1abc7d68`, `2c10f9d9`, prune-hygiene), two passages (Item 9's prune post-condition; Item 4's single-filter tripwire) would degrade landed fail-closed behavior if followed verbatim and must be corrected before implementation, and the QH-37 statistics and the `864918d9` commit id are wrong — remaining actionable work is Items 1, 3, 5, 7, 8, 9's drift dimension, and 10.

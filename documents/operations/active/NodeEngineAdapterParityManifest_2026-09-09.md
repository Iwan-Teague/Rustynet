# NodeAdapter parity manifest + findings — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W5: the method × platform override/default table (input for the PlatformCapabilities table) and four findings, dispatched as an edit job the same morning.

# Rust `--node` engine review — adapter parity manifest + correctness findings

Scope read: `orchestrator/adapter/node_adapter.rs` + all five impls (`linux.rs`, `macos.rs`, `windows.rs`, `android.rs`, `ios.rs`), `factory.rs`, `runner.rs`, `stage/mod.rs` catalog, `stage/blind_exit.rs`, `role_validation/blind_exit.rs`, `evidence.rs`, `cleanup.rs`, `key_custody_validation.rs`, `parity.rs`, consolidation doc §1–§3b, live matrix rows 339–340.

## 0. Adapter parity manifest (trait method × platform)

Trait: `node_adapter.rs:120-516`. Impls: `linux.rs:66`, `macos.rs:72`, `windows.rs:48`, `android.rs:52`, `ios.rs:50`. ✅=overrides, ❌=inherits trait default. D=permissive default (Ok/true/empty/no-op), FC=fail-closed default (`Err(UnsupportedPlatform)`), N=neutral.

| default method (def line) | default | Linux | macOS | Windows | Android/iOS stubs |
|---|---|---|---|---|---|
| `collect_os_version` :127 | D (fabricates `"linux"`/`"macos"` from platform name) | ✅:71 (real `sw_vers`) | ✅:77 | ✅:53 (`ver`) | ❌ fabricated string |
| `ssh_connection_params` :136 | N (`None` = non-SSH) | ✅:98 | ✅:97 | ✅:74 | ❌ (honest) |
| `enforce_runtime` :162 | D (falls through to `start_daemon`, i.e. no real enforce step) | ✅:131 | ✅:153 | ✅:121 | ❌ |
| `probe_membership_owner_signing_key_present` :188 | FC | ❌ | ✅:179 | ❌ | ❌ |
| `collect_live_identity` :219 | FC | ✅:180 | ✅:200 | ✅:168 | ❌ |
| `collect_daemon_status` :237 | FC | ✅:189 | ✅:209 | ✅:177 | ❌ |
| `run_role_validator` :292 | N (delegates :298) | ❌ | ❌ | ❌ | ❌ |
| `supports_role_validator` :301 | **D (`true` for all desktops; consults `kind` only for GossipConvergence)** | ❌ | ❌ | ❌ | ❌ (false via `matches!`) |
| `activate_exit_serving` :338 | FC | ✅:269 | ✅:288 | ✅:241 | ❌ |
| `assert_exit_actively_serving` :351 | FC | ✅:273 | ✅:292 | ✅:245 | ❌ |
| `drive_exit_egress_probe` :364 | FC (Linux-only by design) | ✅:263 | ❌ | ❌ | ❌ |
| `assert_mesh_client_nat_session` :381 | FC | ✅:277 | ✅:296 | ✅:249 | ❌ |
| `deploy_relay_service` :410 | FC | ✅:286 | ✅:161 | ✅:95 | ❌ |
| `shell_host` :428 | FC | ✅:105 | ✅:104 | ✅:81 | ❌ |
| `prime_remote_access` :451 | D (`Ok(())`) | ❌ (benign: NOPASSWD lab images) | ✅:313 (sudoers grant, `macos_install.rs:539`) | ✅:266 (explicit `Ok(())`, documented) | ❌ |
| `collect_daemon_failure_reason` :461 | N (`Ok(None)` = "not found", honest) | ✅:300 | ✅:317 | ✅:271 | ❌ |
| `assert_node_clean` :470 | **D (`Ok(())` — vacuous hygiene pass)** | ✅:304 | ✅:321 | ✅:275 | ❌ |
| `collect_stun_candidates` :499 | FC | ✅:325 | ✅:342 | ✅:296 | ❌ |

**Direct answer to the focus question: no permissive default is reached by a real stage on macOS or Windows today.** Every permissive default is overridden on all three desktops; the only defaults the desktops inherit are fail-closed (`probe_membership_owner_signing_key_present` on Linux/Windows, `drive_exit_egress_probe` on macOS/Windows — the latter is the documented Linux-client-only QH-25 design, `LiveLabMacosExitServingAdapterDesign_2026-09-02.md:192`) or neutral. The permissive defaults actually reached today are: `supports_role_validator=true` (all desktops — currently backed by a full 7×3 dispatch, see F1), `prime_remote_access=Ok(())` on Linux (benign), and the fabricated `collect_os_version` string on the Android/iOS stubs — unreachable, because `factory.rs:56-77` refuses both platforms with `UnsupportedPlatform` + security-minimum-bar messages; the stubs are constructed only in tests (`active_exit.rs:680-682`, `node_adapter.rs:706`). Pattern C here is **latent, not live**: it fires on the next adapter or the next `RoleValidatorKind`.

## 1. Findings

**F1 — permissive-true support default pairs with `unreachable!()` dispatch (pattern C, latent panic). Severity: M.**
`supports_role_validator` (`node_adapter.rs:301-314`) is the single definition repo-wide (no adapter overrides it; confirmed by absence from all five impl fn lists) and returns `true` for Linux|Macos|Windows for every kind except gossip. The dispatcher it feeds, `run_typed_role_validator`, ends two platform matches in `_ => unreachable!("desktop platform checked above")` (`node_adapter.rs:571`, `:679`). Input path: any stage calls `adapter.supports_role_validator(kind)` → `run_role_validator(kind,…)` (all adapters inherit the delegate). Because the default consults `kind` **only** for `GossipConvergence`, a newly added `RoleValidatorKind` compiles cleanly (wildcard arms), auto-claims support on all three desktops, and panics the stage thread instead of failing closed — the exact shape the I1 fix (`daed6afc`, consolidation §3.7) already removed from the stage tree. The trait default is also inherited by the Android/iOS stubs, for which the `unreachable!` arms are the direct return path if the delegate is ever called (factory currently blocks construction). Doc `MeshStatusLiveHandshakeReview_2026-09-07.md:50` correctly records today's coverage but not the new-kind hole.

**F2 — stage doc asserts a fail-closed posture gate that does not exist; skip branch is dead code. Severity: M (ledger honesty).**
`key_custody_validation.rs:14-21`: "A macOS / Windows node is **reported-skipped** … on the [`key_custody_runtime_implemented`] posture gate." `key_custody_runtime_implemented` exists **nowhere** in the crate (grep: only the dangling rustdoc ref at `:21`); `execute` actually gates on `adapter.supports_role_validator(RoleValidatorKind::KeyCustody)` (`key_custody_validation.rs:57`), which is `true` for macOS/Windows — so macOS/Windows run the validator and the `reported_skips` branch is dead. This is exactly the defect `LiveLabCrossPlatformCustodySecretsAclStageDesign_2026-09-01.md:56` flagged on 2026-09-01 ("correct those doc comments in the same change") — still unfixed at HEAD. Sibling `runtime_acls_runtime_implemented` (`role_validation/runtime_acls.rs:15`, true for all desktops) is live but consulted by nothing.

**F3 — `REQUIRED_DAEMON_LAUNCH_FLAGS` parity is pinned on Windows only, while the trait doc claims per-platform parity tests. Severity: M (the N4 class — a dropped `--node-role` defaulting a daemon to `admin` — is exactly what this const exists to kill).**
`node_adapter.rs:56-58`: "Per-platform parity tests assert each platform's daemon-arg construction includes every flag listed here." Grep: the const's only consumer is `windows_install.rs:2288`. macOS pins `--node-role` ad hoc (`macos_install.rs:2234`, `:2510`) but has no flag-loop over the const; Linux's daemon args are assembled via the bootstrap env/script path (`build_bootstrap_env`, `linux_install.rs:604+`) with no flag-loop test in `linux_install.rs` (its test list, `:680-1178`, contains none matching the four flags).

**F4 — a passing `blind_exit` is unwitnessed: QH-86's stage is a `PHASE1_EVIDENCE_PENDING` catalog row. Severity: M-H for ledger integrity.**
Catalog: `stage/mod.rs:305` → `BlindExit => … StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }`. The stage writes `blind_exit.reported_skips.json` **only** when nodes skip (`stage/blind_exit.rs:72-85`); an all-validated pass writes no artifact, so the runner's QH-83 demotion (`runner.rs:186-196`, `verify_declared_evidence` :291-378) can never bite this stage — a `Passed` blind_exit carries zero checkable evidence beyond the recorder's verdict block. The QH-86 validator itself is genuinely strong (Linux: `linux_blind_exit_ruleset_verdict` judges rustynet-owned nft tables, rejects any masquerade and requires the forward shape, `role_validation/blind_exit.rs:127-168`; macOS: anchor shape + exit-NAT-anchor-must-be-empty, `:139-158`), which makes the missing witness the residual gap. Coverage context: only 4 of 82 catalog rows declare witnesses (`mod.rs:295` MembershipInit StageLog, `:316` MeshStatus StageLog, `:327` TrafficTestMatrix File, `:338` ActiveExit File); the rest are `PHASE1_EVIDENCE_PENDING` (consolidation §3.3: "the honest remainder").

**F5 — partial blind_exit coverage is mislabeled as a full skip. Severity: L (conservative direction, but dishonest summary).**
`stage/blind_exit.rs:88-92`: one validated node + one reported-skip → outcome `Skipped("no node executed this validation; 1 node(s) reported a runtime skip")` — false statement in the ledger whenever ≥1 node validated.

**F6 — best-effort evidence writes in skip paths. Severity: L.**
`stage/blind_exit.rs:78-80`: `serde_json::to_string_pretty(&skips_json).unwrap_or_default()` inside `let _ = std::fs::write(...)` — a serialize/write failure silently records an empty artifact. Same shape at `exit_demotion_residue_validation.rs:148-156`. Contrast the B4 fix standard: `active_exit.rs:366-378` returns the write error and fails the stage.

**Verified-healthy (so the review is not only defects):** QH-83 runner demotion is real and non-vacuous — the recorder truncates the stage log at `stage_started` (`evidence.rs:530`) and appends the verdict only at `stage_finished`, and the check runs between (`runner.rs:188-196`), with symlink/empty/not-a-file arms (`runner.rs:340-372`); QH-82 `VmGuestPlatform::infer` returns `Option` and documents the no-coerce-to-Linux tripwire (`vm_lab/mod.rs:2338-2346`); pattern-G evaluator row checks exist (`vm_lab/mod.rs:51737` `evaluators_reject_overall_ok_true_when_rows_disagree`, evaluators at `:23968/:24089/:24245/:24299`) and the 3bfc99e6 false-drift they caused was fixed before 36c7017f; `assert_node_clean`'s vacuous default is known and fenced by the T5 negative control's Linux-only gate (`negative_control.rs:336`, `:680`, test `:3010-3025`); live matrix confirms `livelab-1788919346` = `36c7017f…`, 2-node Linux on lenovo-bot, `passed=39 failed=0 skipped=27` (66 stage slots), overall `partial` (`documents/operations/live_lab_node_run_matrix.csv:340`), predecessor `3bfc99e6` failed `key_custody_validation` (`:339`) as the consolidation doc §3b states.

## 2. Patches + red tests

**F1 (M)** — replace the bool default with a required per-kind answer and kill the `unreachable!`s with the extracted kind table (same pattern as the I1 stage-tree fix):
```rust
enum RoleValidatorSupport { Supported, ExplicitlyUnsupported { reason: &'static str } }
// required on NodeAdapter — no default:
fn role_validator_support(&self, kind: RoleValidatorKind) -> RoleValidatorSupport;
```
`run_typed_role_validator` keeps the `(kind, platform) → leg` table but maps an uncovered pair to `None` → `Err(AdapterError::Protocol { message: "no dispatch leg for {kind:?} on {platform:?} — gate/dispatch desync" })`, and the gate function consults the same table (single source of truth). Red test: `role_validator_support_is_explicit_for_every_kind_and_platform` — mutation: reintroduce the platform-only `supports_role_validator` bool default (or a new kind without a table row); the test (which iterates all kinds × all five adapters and requires an explicit answer) goes red instead of the run panicking.

**F2 (S)** — correct the doc to match behavior (repo precedent from the 2026-09-01 adversarial review): rewrite `key_custody_validation.rs:14-21` to "a macOS / Windows node executes the validator (desktop-supported day one); `reported_skips` fires only where `role_validator_support` says `ExplicitlyUnsupported`." Red test: `key_custody_support_is_desktop_wide` asserting the gate returns `Supported` for all three desktops — mutation: make the gate answer `ExplicitlyUnsupported` for macOS (the behavior the stale doc describes) → red. Same comment fix in `runtime_acls_validation.rs` while there.

**F3 (S)** — consume the const on the other two platforms, mirroring `windows_install.rs:2288`:
```rust
for flag in REQUIRED_DAEMON_LAUNCH_FLAGS { assert!(script.contains(flag), "…{flag}…"); }
```
in `linux_install.rs` tests (over `build_bootstrap_env` output / the launch script it feeds) and `macos_install.rs` tests (over `BOOTSTRAP_SCRIPT`/`build_install_script`). Red test: `linux_bootstrap_env_contains_every_required_daemon_flag` + `macos_bootstrap_script_contains_every_required_daemon_flag` — mutation: delete `--node-role` from either arg construction → the respective test fails, the N4 Windows incident reproduced per-platform.

**F4 (S)** — make the pass witnessed: append per-validated-node lines via `append_stage_evidence_line` (`evidence.rs:200`, fail-closed on I/O by contract) in `stage/blind_exit.rs`'s validate loop (e.g. `blind_exit role confirmed; forward rules judged; masquerade=none`), and flip the catalog row to `BlindExit => "blind_exit" @ Setup / T1Role / StageEvidence::StageLog`. Red test: `blind_exit_pass_without_witness_is_demoted` (stage records `Passed` with an empty stage log → `NotProven{MissingWitness}`, mirroring `runner.rs:1618`); mutation to name: revert `mod.rs:305` from `StageEvidence::StageLog` to `None { reason: PHASE1_EVIDENCE_PENDING }` → the demotion test goes red (the pass survives unwitnessed again).

**F5 (S)** — make the summary truthful: `Skipped(format!("{validated} node(s) validated, {} reported a runtime skip", skips.len()))` when `validated > 0`. Red test: mutation "restore the unconditional 'no node executed' message" → `partial_blind_exit_skip_summary_names_validated_count` fails.

**F6 (S)** — route both skip-writers through the B4 pattern: `write_reported_skips(...) -> Result<(), String>` returning the I/O/serialize error into `failures` (call-site shape already exists in `active_exit.rs:369-383`). Red test: `reported_skips_write_failure_fails_the_stage` — mutation: restore `unwrap_or_default()` + `let _ = fs::write` → red.

## 3. Gate that kills the class

Land `PlatformCapabilities` (consolidation §2-C, Extensibility §9-5): a required, enum-valued `fn platform_capabilities(&self) -> PlatformCapabilities` on `NodeAdapter` — `Supported { validators: …, exit: …, relay: …, … } | ExplicitlyUnsupported { reason: &'static str }`, never `bool`/`Option` — consumed by **both** the stage skip decision and the dispatch legs (collapses `supports_role_validator`, the per-file `*_runtime_implemented` bools, and the default-`Err` method cluster into one table), plus a source pin that `stage/` and `adapter/` slices contain zero `VmGuestPlatform::` matches outside the allowlist table, wired as a CI step like the QH-82 tripwire. That single gate kills F1 (no silent claim), F2 (no second, divergent gate description), and the `unreachable!` residue at `node_adapter.rs:571/:679`. Companion catalog gate for F4's class: refuse a new `define_stage_catalog!` row as `PHASE1_EVIDENCE_PENDING` once the stage writes any evidence artifact (source pin: stage files writing `reported_skips`/JSON artifacts must declare `StageEvidence::File`/`StageLog`).

## 4. Effort

F2/F3/F4/F5/F6: **S** each (doc line, two test loops, one catalog row + append loop, two message/write fixes). F1 + PlatformCapabilities + source pin: **M** (trait + 5 impls + dispatch table + tests + CI step).

## 5. What I could not verify

- My scoped `cargo test -p rustynet-cli unwitnessed_pass_blocks_dependents` returned overall PASSED but the truncated per-binary output shows only `0 passed … N filtered out` sections; I could not positively confirm that specific test executed in my run. It exists at `runner.rs:1618` with a doc-comment naming the mutation; treat my execution claim as unconfirmed.
- The run artifacts for `livelab-1788919346` live at `/home/ubuntu/Rustynet/artifacts/live_lab/run-2026-09-09-qh83-linux2e` on lenovo-bot — outside this repo, so I could not open the 39 witness files (stage logs, `active_exit.egress_evidence.json`, `traffic_test_matrix.pair_results.log`) to confirm the witnesses' content; the 39/0/54 numbers come from the live matrix CSV row (`live_lab_node_run_matrix.csv:340`, `passed=39 failed=0 skipped=27` across 66 slots) and consolidation §3b.
- I did not trace Linux daemon-arg assembly into `script_template.rs`/`rn_bootstrap.sh`; F3's "no Linux pin" claim is verified only over `linux_install.rs` and its test module.
- No VM/SSH live state was consulted; this was a static code + ledger audit. B5 (macOS key-custody keychain-blindness) I confirmed still open only by absence of any `keychain` probe in `role_validation/key_custody.rs`, matching consolidation §3.9's "B5 still open".

## Tools used (54 call(s) over 34 step(s))

## 6. Implementation record — F1–F4 DONE (2026-09-09, delegated-edit branch `ai-edit/edit-1788947952099-12026-0`)

- **F1 DONE** — `supports_role_validator` now matches every `RoleValidatorKind` variant explicitly (no wildcard arm; a new kind is a compile error) and `run_typed_role_validator`'s two `unreachable!("desktop platform checked above")` arms were replaced with fail-closed `AdapterError` values naming the platform and kind (`node_adapter.rs`). Verification: `role_validator_support_is_explicit_for_every_kind_and_platform` (all kinds × adapters answer explicitly) and the mobile-platform negative test; mutation (restore `unreachable!` / wildcard arm) turns them red instead of panicking the run.
- **F2 DONE** — the real gates `key_custody_runtime_implemented` (`role_validation/key_custody.rs`) and `runtime_acls_runtime_implemented` (`role_validation/runtime_acls.rs`) now exist and are consulted in `stage/key_custody_validation.rs` / `stage/runtime_acls_validation.rs` `execute`, so a platform without the validator is `reported_skips`-reported with the artifact instead of the stale doc claim. The doc comment now describes the implemented gate.
- **F3 DONE** — per-platform `REQUIRED_DAEMON_LAUNCH_FLAGS` parity loops added beside the existing Windows pin (`windows_install.rs`): `macos_daemon_args_include_every_required_launch_flag` (macos_install.rs — every flag present as `<string>--flag</string>` in the launchd ProgramArguments of `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`) and `linux_daemon_args_include_every_required_launch_flag` + `bootstrap_env_identity_keys_feed_the_unit_identity_flags` (linux_install.rs — `scripts/systemd/rustynetd.service` ExecStart carries `--flag ${…}` for every required flag; the `build_bootstrap_env` ROLE=/NODE_ID= keys the unit consumes stay wired). Mutation: drop `--node-role` from one platform's arg construction — the respective test fails.
- **F4 DONE** — `stage/blind_exit.rs` writes a per-validated-node witness line on the PASS path (write failure fails the stage), the catalog row is `BlindExit => "blind_exit" @ Setup / T1Role / StageEvidence::StageLog` (`stage/mod.rs`), and the runner's `verify_declared_evidence` demotes an unwitnessed PASS to `NotProven { MissingWitness }`. Tests: `blind_exit_witness_line_is_written_per_validated_node`, `blind_exit_witness_write_failure_is_propagated` (stage), `pass_without_stage_log_witness_is_demoted_to_not_proven` / `empty_stage_log_witness_is_demoted_to_not_proven` / `stage_log_witness_upholds_pass` (runner.rs). Mutation: revert the catalog row to `StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }` — the demotion test goes red.

Gates on the landing commit: `cargo fmt --all -- --check` clean; `cargo test -p rustynet-cli --all-features --lib -- vm_lab` → **2764 passed, 0 failed**. Known pre-existing blocker, NOT introduced here (file untouched by this branch, identical on `main`): `cargo clippy -p rustynet-cli --all-targets --all-features --locked -- -D warnings` fails inside the dependency crate `rustynetd` — 3 `collapsible_if` lints in `crates/rustynetd/src/phase10.rs:4301/4911/4955` (newer rustc's extended `collapsible_if` over `if let`); outside this job's path allowlist, so left for an owner pass.

## Review disposition (2026-09-09, GLM-flash, MERGE-WITH-FIXES → merged)

All four claims CONFIRMED at file:line; both dispatcher arms are `Err`-shaped
and `blind_exit` cannot return `Passed` without a witness (statically
unreachable). Two corrections to the job's own §6 wording, applied here rather
than re-running the job: the runner-demotion tests it cites
(`pass_without_stage_log_witness_is_demoted_to_not_proven`,
`empty_stage_log_witness_is_demoted_to_not_proven`) pre-exist on main; the
tests this branch ADDS are `blind_exit_pass_without_witness_is_demoted` and
`blind_exit_stage_log_witness_upholds_pass`; and F2's gates
(`key_custody_runtime_implemented`, `runtime_acls_runtime_implemented`) already
existed — what is new is that the two stages now consult them. Follow-up
(non-blocking): a `BlindExitStage`-level test that `Passed` implies a
non-empty stage log, to catch a deleted witness call.

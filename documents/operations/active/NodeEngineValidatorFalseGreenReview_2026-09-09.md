# `--node` validator false-green hunt — 2026-09-09 (GLM-5.3-flash, grounded, trusted input)

Probe W3 of the correctness pass. Scope honestly partial (the reviewer did not reach all ~45 `evaluate_*_report` bodies). F1/F2/F3/F7 queued as an edit job behind the skip-semantics fixes (same files).

[glm/glm-5.3-flash | AGENT | budget=40 | briefed]

# Rust `--node` live-lab engine — validator false-green hunt

Scope honestly declared up front: I read every `role_validation` wrapper, the QH-83 demotion seam, the key-custody/authenticode/dns producer families in full, and the live-run ledger. I did **not** get through all ~45 `evaluate_*_report` bodies in `vm_lab/mod.rs` nor the large validators (anchor/relay/mesh_status/security_audit/exit-*) — §5 lists exactly what is unverified. Findings below are only what I grounded.

## 1) Findings (LEDGER INTEGRITY severity)

**F1 — MEDIUM: `authenticode_validation` records `pass` on Linux from a producer that reads nothing.**
Producer: `collect_linux_authenticode_report()` in `crates/rustynetd/src/linux_authenticode.rs` is a **constant** — `schema_version:1, overall_ok:true, applicable:false, reason:"Linux does not enforce binary signatures…"`. It performs zero I/O; every Linux host on every run emits the identical bytes (pinned by its own snapshot test `report_pins_canonical_serialized_snapshot_to_detect_silent_shape_drift`). Evaluator `evaluate_linux_authenticode_report` (`vm_lab/mod.rs:24353-24388`) accepts it by design (pass-through test `evaluate_linux_authenticode_report_passes_through_not_applicable_verdict`, `mod.rs:51894`). Stage: `AuthenticodeValidationStage::execute` returns `StageOutcome::Passed` on Linux (fn in `orchestrator/stage/authenticode_validation.rs`). Live consequence: `documents/operations/live_lab_node_stage_results.csv:47725` — `livelab-1788919346…,client,authenticode_validation,node,pass`. A constant producer cannot false-green a *check*, but it green-lights a *ledger row* for a security property (runtime binary attestation) that was never exercised. Same class as B4 (`active_exit` fall-through), which was fixed to `Skipped` with an artifact — this is the remaining instance. Non-Linux nodes are honestly reported-skipped via `authenticode_validation.reported_skips.json`; Linux is the hole.

**F2 — LOW today, latent fail-open: the not-applicable branch of the Linux authenticode evaluator never consults `overall_ok`.**
`vm_lab/mod.rs:24371-24388`: `if report.applicable { if !report.overall_ok { Err } … } else { Ok(…) }`. The `else` returns `Ok` unconditionally. Failing input: `{"schema_version":1,"overall_ok":false,"applicable":false,"reason":"stat failed"}` would pass. **Why none exists today:** the producer is the constant above (`overall_ok` hard-wired `true`), so this shape is currently unproducible — this is a polarity inversion waiting for the first producer change (exactly the "future slice" the code comment anticipates at `mod.rs:24372-24374`).

**F3 — LOW (hardening, no live exploit found): the four `rustynetd *-check` wrappers discard the daemon's exit status.**
`validate_linux_runtime_acls`, `validate_linux_key_custody`, `validate_linux_dns_failclosed`, `validate_linux_service_hardening` (+ macOS/Windows twins) in `role_validation/{runtime_acls,key_custody,dns_failclosed,service_hardening}.rs` all do `run_argv` → `String::from_utf8_lossy(&out.stdout)` → evaluator, never reading `out.is_success()` — in contrast to `validate_blind_exit_runtime`, which checks both exits. Producer (quoted): `run_linux_key_custody_check_command` (`crates/rustynetd/src/main.rs:1592-1607`) defaults `fail_on_drift=true`, prints the report, and on drift returns `Err` → exit 78 **with the drift report on stdout**, so the evaluator still rejects on `overall_ok=false`; an early error yields empty/truncated stdout → parse reject. I could not construct a currently-emittable input where exit≠0 and stdout passes — so no live false green; this is independent evidence (the reviewed exit-code taxonomy, `main.rs:60-91`) being thrown away.

**F4 — INFO (context, not a bug): the QH-83 gate currently witnesses 3 of 81 stages.**
`verify_declared_evidence` is correctly placed **before** `stage_finished` so it cannot read the verdict's own log echo (`runner.rs:186-196`), `StageEvidence::None{..}` rows pass through with a recorded opt-out (`runner.rs:295-305`), and `NotProven` dominates the run to `Failed`, never `Partial` (`parity.rs:106-116, 205-216, test :726-747`). But per the consolidation ledger (§3 item 3: "Only 3 of 81 stages are witnessed at landing"), 36 of the 39 passes in `livelab-1788919346` are `StageEvidence::None` opt-outs: for those rows "pass" means only "the stage fn returned `Passed`".

**F5 — INFO: pattern-G/key-custody family verified clean.**
`evaluate_linux_key_custody_report` (`mod.rs:24245-24297`) and the macOS twin (`:24299-24351`) reject schema≠1, empty entries, `overall_ok=false`, **and** `overall_ok=true` with any non-Ok row or non-empty `drift_reasons` (`:24287-24292`); Windows checks the `drift_reasons` direction at `:20747-20752`. Producer `collect_linux_key_custody_report()` (fn in `crates/rustynetd/src/linux_key_custody.rs`) builds 8 entries from real `symlink_metadata` + owner/mode probes and derives `overall_ok` via the re-deriving `evaluate_linux_key_custody` — it cannot emit clean with a drifted artifact. The `AbsentAsExpected` regression that failed `livelab-1788916793` is fixed with the real shape as fixture (`mod.rs:51699-51703`). Residual (inference, not a live green): the evaluator trusts typed statuses without re-checking `Ok{mode,uid,gid}` values against reviewed constants — a mutated collector could label `0o777` as `ok`; same-binary trust, evaluator-side only.

**F6 — INFO: wrapper-only negative tests use unproducible inputs.**
The four wrapper test modules use `schema_version: 999` as their only report-level negative — the producers cannot emit that. No gap in effect because realistic negatives (drifted row, empty entries, unprobed, drift-reason inconsistency) exist at the evaluator layer in `mod.rs`; flagged per the brief's ask.

**F7 — LOW, fail-closed-direction risk: QH-86 blind_exit verdict has never met its real producer.**
`linux_blind_exit_ruleset_verdict` (fn in `role_validation/blind_exit.rs`) requires, in any `rustynet*` table, tokens `iifname`+`oifname`+`saddr` with `accept` **last**, plus `ct state established,related accept`, and rejects any `masquerade` token. The B3 non-empty-stdout class is closed with real-shaped negative fixtures (empty killswitch table, legacy iptables header, empty string — test `linux_fails_closed_when_no_forwarding_rules`). But (a) the verdict accepts the forward rule anywhere in a rustynet table — no `chain forward`/hook binding; (b) if the daemon's rendered rule carries anything after `accept` under real `nft list ruleset` rendering (e.g. a `comment "…"` statement), the token check false-REDs — safe direction, but the ledger itself says "the blind_exit cell (QH-86) still needs a topology that assigns `blind_exit`", so the validator has never passed or failed against the live producer.

## 2) Patches + red tests

**F1/F2 — `vm_lab/mod.rs` authenticode evaluator:**
```rust
} else {
    if !report.overall_ok {
        return Err(format!(
            "linux-authenticode-check reported overall_ok=false while applicable=false: {}",
            report.reason
        ));
    }
    Ok(format!("Linux authenticode not applicable on {linux_alias} (runtime binary signature …"))
}
```
Red test (mutation: delete the new `overall_ok` guard — test goes red): `evaluate_linux_authenticode_report_rejects_overall_ok_false_when_not_applicable` feeding `{"schema_version":1,"overall_ok":false,"applicable":false,"reason":"stat failed"}` → `expect_err` naming `overall_ok=false`.

**F1 — stage honesty** (`stage/authenticode_validation.rs`): on Linux, write the producer's raw report to `authenticode_validation.report.json` and return `StageOutcome::Skipped("linux authenticode is a non-attesting stub (applicable=false); no runtime signature property verified")` instead of `Passed`. The module doc argues "honest pass-through"; I disagree for the ledger: an owner reading the run matrix cannot distinguish a proved property from a stub, and `Skipped` already softens the run to `Partial` honestly (`parity.rs:212-216`). Red test: Linux-path stage run asserting `matches!(outcome, StageOutcome::Skipped(_))`; mutation (revert to `Passed`) goes red. If the owner prefers keeping `Passed`, the minimal alternative is a `StageEvidence::File("authenticode_validation.report.json")` catalog row so the pass at least requires an auditable artifact — but that still yields a witnessed pass proving nothing, which is why I recommend `Skipped`.

**F3 — all four wrappers**, mirroring `blind_exit.rs`:
```rust
if !out.is_success() {
    return Err(format!(
        "{alias}: `{SUBCOMMAND}` exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    ));
}
```
Red test per wrapper: `MockShellHost` response `code: 1` carrying a fully clean `overall_ok:true` report on stdout must yield `Err` containing "exited non-zero"; mutation (remove the check) goes red. This fixture is deliberately one the producer cannot emit — it pins the wrapper contract, not the producer shape.

**F7 — producer-shape pin:** a test that renders the daemon's actual forward commands (the symbol the validator doc names, `linux_blind_exit::build_linux_blind_exit_forward_commands` — existence unverified, see §5) and feeds the rendered output through the real `nft`-style rendering (including counter statements) into `linux_blind_exit_ruleset_verdict`; plus tighten the verdict to require the rule inside a chain whose header declares `hook forward`. Mutation: change the rendered rule to append a comment after `accept` — the pin fails, naming the drift, instead of a live stage failing.

## 3) Gate that kills the class

Two source pins in the existing `implementation_source_slice` fence style:
1. **Evaluator polarity pin:** every `fn evaluate_*_report` body must obtain `overall_ok` through a shared `require_overall_ok(&report) -> Result<(), String>` helper (field access to `.overall_ok` outside that helper is a pin failure). Every `Ok`-returning path then structurally crosses the check — kills F2 and future overall_ok-only regressions mechanically, and makes the pattern-G parity greppable.
2. **Exit-status pin:** in the `vm_lab` stage/role_validation implementation slices, any `run_argv` result whose stdout is consumed without an

## Tools used (48 call(s); step budget of 40 reached)

## 4) DONE — F1/F2/F3/F7 implemented (2026-09-09, delegated-edit job `edit-1788947977300-12284-0`, branch `ai-edit/edit-1788947977300-12284-0`)

All changes confined to `crates/rustynet-cli/src/vm_lab/**` (+ this doc). Commits: `5bf56679` (F1 not-applicable fail-closed), `6e88c6ac` (F1 Linux stage honesty), `22b47eee` (F3 exit-status gating), `ae67cd14` (F7 hook-forward binding), `4464f3a1` (rustfmt), `c0e9f441` (clippy collapse).

**F1+F2 — authenticode honesty.** `evaluate_linux_authenticode_report` (`vm_lab/mod.rs`) now rejects `overall_ok=false` on the not-applicable branch (fail closed). The Linux stage path writes the producer's raw report to `authenticode_validation.report.json` (write failure → `Failed`) and returns `StageOutcome::Skipped("linux authenticode is a non-attesting stub …")` instead of `Passed`, so the ledger can no longer record a proved property from a constant producer. Tests: `evaluate_linux_authenticode_report_rejects_overall_ok_false_when_not_applicable` (mutation: delete the `overall_ok` guard → red); stage tests asserting `matches!(outcome, StageOutcome::Skipped(_))` (mutation: revert to `Passed` → red).

**F3 — daemon exit status is evidence.** New `require_daemon_success(exit_code, subcommand, alias, stdout, evaluate)` in `role_validation/mod.rs`: exit 0 → evaluate; non-zero + evaluator Err → the drift reasons surface verbatim, wrapped with `(code N; the daemon uses exit 78 to signal drift)`; non-zero + evaluator Ok → `Err("… exited non-zero (code N) while emitting a passing report; failing closed")`. All 12 wrappers (`validate_{linux,macos,windows}_{key_custody,runtime_acls,dns_failclosed,service_hardening}`) now route through it. Tests: `require_daemon_success_rejects_non_zero_exit_with_passing_report`, `require_daemon_success_surfaces_drift_reasons_with_exit_code_note`; per-wrapper `MockShellHost` `code:1`-with-clean-report red tests — `validate_linux_fails_closed_when_daemon_exits_non_zero_with_passing_report` (key_custody), `validate_linux_fails_closed_when_daemon_exits_non_zero_despite_passing_report` (runtime_acls / dns_failclosed / service_hardening) — each comments its mutation (remove the exit-code gate → red).

**F7 — verdict bound to the producer and to the forward hook.** `linux_blind_exit_ruleset_verdict` now tracks chain context: entering a `chain …` header resets it, and only a header declaring `hook forward` re-arms forward/established rule detection (the masquerade scan stays chain-agnostic). Tests: `linux_accepts_ruleset_rendered_from_daemon_producer_commands` (renders `rustynetd::linux_blind_exit::build_linux_blind_exit_forward_commands(&LinuxBlindExitConfig::new("rustynet0","enp0s1","100.64.0.0/10"), "rustynet_g3")` back into `nft list ruleset` shape — quoting `iifname`/`oifname` values — and requires `Ok`; mutation: any producer/validator shape drift → red) and `linux_fails_closed_when_forward_rules_sit_outside_a_forward_chain` (producer-shaped rules parked in the killswitch `hook output` chain must be rejected; mutation: count rules anywhere in a rustynet table → red). All pre-existing blind_exit linux/macos/windows tests stay green.

**Gate evidence.** `CARGO_TARGET_DIR=/Users/iwan/Desktop/Rustynet/target-glm-w3 cargo test -p rustynet-cli --all-features --lib -- vm_lab` → **2766 passed, 0 failed** (was 2764 pre-F7). `cargo fmt --all -- --check` → clean. **Clippy blocker (pre-existing, outside this job's allowlist):** `cargo clippy -p rustynet-cli --all-targets --all-features --locked -- -D warnings` fails with 3 `collapsible_if` errors in `crates/rustynetd/src/phase10.rs:4301,4911,4955` plus the same lint family in already-committed `vm_lab` files this job did not author (`stage/distribute_assignments.rs:330`, `stage/preflight.rs:516,553,648,824`, `stage/validate_runtime.rs:257`) — the toolchain's clippy 1.97 let-chain style postdates the last lint pass on those files; zero commits in this branch touch them (`git log 338b2c45..HEAD -- crates/rustynetd` is empty). Verified with `RUSTFLAGS="--cap-lints=warn"` that this branch introduces **no** new clippy diagnostics: every file this job touched (`role_validation/{blind_exit,key_custody,runtime_acls,dns_failclosed,service_hardening,mod}.rs`, `stage/authenticode_validation.rs`) is clippy-clean. Fixing `phase10.rs` is out of this job's allowlist and is left as an explicit follow-up.

## Review disposition (2026-09-09, GLM-flash, MERGE-WITH-FIXES → merged)

F1/F2/F3/F7 CONFIRMED at file:line; every non-zero daemon exit yields `Err`
(drift reasons surfaced verbatim after the exit-78 note). Blocking fix
applied before merge: the stage-level Linux test
`linux_stub_producer_yields_skipped_with_report_artifact` (deleting the Linux
branch would have fallen through to a vacuous `Passed`). Non-blocking
follow-ups: pin the `comment`-after-`accept` coupling in the F7 forward-rule
check; align authenticode's failing-report message with
`require_daemon_success`'s exit-code prefix.

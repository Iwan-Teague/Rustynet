# `--node` engine audit consolidation — 2026-09-08 (evening)

Owner request: "the --node engine examined thoroughly by GLM flash agents;
see what the learnings are and figure out how we patch the findings."

Five read-only GLM-5.3-flash grounded probes (`ai_agent`, provider `glm`,
40–60 steps each) were run against `main` at `1d455893`–`a5cc3d37`, each
scoped to one systemic pattern from the two 2026-09-08 reports
(`MultiAgentSecurityReview_2026-09-08.md` §3 A–H;
`LiveLabExtensibilityAssessment_2026-09-08.md` §8–§9). Every claim below was
either re-verified by the manager in the tree (marked **verified**) or is
carried as the probe's claim (marked *probe*). Probe output is UNTRUSTED
until verified; nothing here was merged on a probe's word alone.

## 1) What was fixed today because of this pass

| Item | Commit | What |
|---|---|---|
| H2 / QH-84 | `a5cc3d37`, `f699b462` | Windows host runner honours exit status; absence/presence on idempotent netsh/uninstall/add/install proven by a separate successful read. GLM review: MERGE-SAFE. |
| F1/F2 / QH-85 | `c3b127cf` | Lab password removed from argv (`sshpass -e`) and from SOURCE (`echo '<literal>' \| sudo -S` → stdin). **The literal was the live lab password for five guests, public since `6908f20d`. Rotation owed (owner).** |

## 2) Learnings, by probe

### A — gates that pass by construction (pattern B) + self-text pins (pattern A)

**verified on main:** the vacuous-filter class is CLOSED (`run_logged_test`
errors on zero matches, `ops_ci_release_perf.rs:2080-2090`;
`orchestrator_engine_gates.sh:21-26` requires `[1-9][0-9]* passed`), and the
self-pin class is FENCED (`source_pin_self_includes_must_search_the_implementation_slice`,
`vm_lab/mod.rs:38558-38630`; every self-file pin on main is sliced).

*probe, still open:*
- **B1** `traffic_test_matrix` drops its mesh-IP collision guard at the 60 s
  deadline and never refuses self-pings → an evidence-free green row (H4).
  Folded into QH-83 (in flight).
- **B2** vm-lab feature-guard scan is non-recursive with a slack floor
  (`vm_lab/mod.rs:39188`, floor 12 vs 15 measured) — blind, not wrong.
- **B3** `role_validation/blind_exit.rs` NAT probe is a non-empty-stdout check;
  `iptables -t nat -L` / `nft list ruleset` / `pfctl -s nat` always print
  something → a blind_exit that installed NO NAT passes. Fixture
  `stdout: Vec::new()` is unproducible. **HIGH for the ledger.**
- **B4** `active_exit` falls through to `Passed` with no client (no egress
  proof, no artifact).
- **B5** macOS key-custody report is keychain-blind: five file-path entries,
  zero keychain probes, while the module doc claims the Keychain path.

### B — environment preconditions (Extensibility §8-1, §9-6)

**verified:** no lab path mints a `Relay` candidate or distributes relay
session material (`ops_e2e.rs:3773/3792/3946/3953` all `relay_id: None`;
`load_relay_client` returns `Ok(None)` for every lab daemon) — QH-80's root.
`live_two_hop_validation` degrades to `Skipped` on a topology without an
entry/second client (`:30-37`, `:61`); three setup stages hard-require an Exit
without declaring it.

*Design proposed (probe):* a closed `EnvFact` enum + a **required, no-default**
`fn requires(&self) -> &'static [EnvFact]` on `OrchestrationStage` (absence =
compile error; "nothing" must be spelled `NO_ENV_REQUIREMENTS`), a
`provisions()` on producer stages, a **plan-construction gate** (a planned
stage whose facts no planned stage supplies is refused offline — QH-80 would
have died on day one) and a **runner gate** that converts a missing fact into
`NotProven{RequiredCapabilityAbsent}` (blocking, never `Skipped`). Facts are
recorded from bundle CONTENT at the verified production point, never from a
`Passed` outcome. This is the fail-closed form the ParityPlan memory warned
about (a skippable `requires()` is fail-open).

### C — sibling-platform drift / platform scatter (pattern C, Extensibility §8-2)

*probe:* the report's "769 refs" no longer reproduces (~700 incl. tests;
`capability.rs` is new); the canonical hotspots the report named have already
been converted to exhaustive matches. Remaining, all latent or loud today:
- **I1** `exit_nat_lifecycle_validation.rs:75-89` — two `_ => unreachable!()`
  dispatch arms behind a Linux|Macos gate: adding Windows to the gate
  compiles and panics mid-run. Same phantom-pin shape in `anchor.rs:322-324`
  vs `:119-123`/`:365-374`.
- **I2** three divergent SSH-user fallback tables (`stage/mod.rs:19-28`,
  `live_managed_dns_validation.rs:174-181/:264-272`,
  `live_extended_soak_validation.rs:343-351`) — documented as deliberate.
- **I3** `_ => "linux"` evidence labels in three stage files — a new OS would
  be stamped as Linux in the ledger.
- **I4** `role_validation/anchor.rs:511-520` log-redaction validator returns
  `Ok("skipped")` for non-Linux — fail-open polarity, unreachable today.
- **NOT confirmed:** the report's "windows-dns-failclosed-check vs
  windows_install.rs pin mismatch" — the flag exists on both sides on main.

*Gate proposed:* `PlatformCapabilities` on `NodeAdapter` (required method,
enum-valued `Supported{..}|ExplicitlyUnsupported{reason}`, never bool/Option)
+ a source pin that stage/validator implementation slices contain zero
`VmGuestPlatform::` outside an allowlist.

### D — ledger integrity (patterns E, G, H)

**verified on HEAD:** **PF-05 is a ledger tick over shipped code.**
`AdversarialSecurityRemediation_2026-07-29.md:349` marks it DONE at
`8417edf1`, which touched only the two precedence-evaluator modules;
`phase10.rs:5605` (macOS `assert_killswitch`) is STILL
`stdout.contains(MACOS_PF_TERMINAL_BLOCK_RULE)`, and
`evaluate_macos_killswitch_rules` is wired only into the offline report
binary (`main.rs:2656-2665`). A `pass out quick` above the terminator defeats
the killswitch while the assertion credits it. **Product security, macOS. Being
fixed by the manager (owner-implemented class), GLM-reviewed.**

*probe:* four Linux `evaluate_*_report` functions trust `overall_ok` without
the per-row consistency check their five Windows/macOS siblings have
(`vm_lab/mod.rs`, pattern G); `traffic_test_matrix`/`active_exit` write
evidence only on failure (pattern H — QH-83). The RSA ledger sweep found no
OTHER DONE-by-untouched-commit entries among the SHAs it reached (PF-08/09
partially verified; sweep ran out of steps before the tail).

### E — the lab robot's privileged execution (audit §4 item 3)

**verified + fixed:** F1 (`sshpass -p`), F2 (password literal). **Open:** F3 —
`ensure_ssh_target`/`ensure_ssh_user`/`last_known_ip` are denylists
(`vm_lab/mod.rs:32992-33010`, `:32575`): `ssh_target: "-F/tmp/x"` passes the
parser and, before `c3b127cf`, reached `ssh` as an option. The `--` guard is
now in place on the priming path; the sibling hardened paths already had it
(`adapter/ssh.rs:558`). *Verified-clean by the probe:* adapter SSH hardening
(`StrictHostKeyChecking=yes`, `-F /dev/null`, `IdentitiesOnly`, known_hosts
must exist), `launch_live_lab_on_host` arg quoting (QH-01), utmctl
`-EncodedCommand` PowerShell, `lab_state.rs` interface-name allowlist.

## 3) Patch plan (ordered for long-term security)

1. **PF-05 wiring** — `phase10.rs` macOS `assert_killswitch` calls
   `evaluate_macos_killswitch_rules` on the captured anchor rules; negative
   test with a `pass out quick all` above the terminator; ledger row corrected
   (DONE → the real commit). Manager. **DONE `ee3ffdd8` + follow-up**: the
   GLM review of `ee3ffdd8` found that the strict walk rejects the daemon's
   OWN regular render (`pass out quick on <egress> inet all` when
   `allow_egress_interface`, the open PF-01 hole), which would have restricted
   every macOS exit and full-tunnel client. The follow-up mirrors Linux S2:
   the live assertion passes the daemon's egress interface as ACKNOWLEDGED
   only when the daemon set the flag; the offline report stays strict; the
   QH-29 agreement test now pins that the exit posture fails the strict walk
   and passes only acknowledged. The Linux-gated scripted-helper test was
   executed on lenovo-bot (harness is `#[cfg(target_os = "linux")]`).
2. **B3 blind_exit NAT probe** — DONE `07cfb057` (QH-86): judges the
   rustynet nft tables for the blind_exit forward rules and rejects any
   masquerade; macOS reads the blind_exit anchor and requires the exit NAT
   anchor empty; real-shaped negative fixtures. **B2** DONE in the same
   pass: the feature-guard scan walks the stage tree recursively, fails
   closed on an unreadable file, and pins the launcher count exactly (15).
3. **QH-83** (in flight, relaunched `edit-1788908162525-23870-0` on glm-5.3
   after the first attempt stalled 4 h with zero edits) — folds B1, pattern H.
4. **QH-82** (in flight, relaunched `edit-1788908182590-23933-0`).
5. **F3 + gate** — allowlist validators at the inventory parse boundary
   (reuse `validated_args::connection_user`; `last_known_ip` must parse as
   `IpAddr`), sink-side spawn scanner (`ssh`/`scp` carry `--`; `sshpass` never
   `-p`), and `secrets_hygiene_gates` extended to reject `| sudo -S` fed by a
   literal. GLM-flash edit job, vm_lab only.
6. **requires()/provisions()** per probe B — GLM-5.3 design-then-implement,
   depends on QH-83 landing first (same runner seam).
7. **C: I1, I3** small fixes (GLM-flash, after QH-82 lands — same stage
   files), then the `PlatformCapabilities` table (L). **I4 DONE** (this
   commit): the non-Linux arm of `validate_bundle_pull_log_redaction` is now
   `Err`, coverage decisions belong to the caller.
8. **D: pattern G parity** — DONE (this commit): `evaluate_linux_runtime_acls_report`,
   `evaluate_linux_key_custody_report`, `evaluate_macos_key_custody_report`,
   `evaluate_macos_service_hardening_report` now reject `overall_ok=true`
   when a row or `drift_reasons` disagrees, as the Windows siblings do;
   one test per evaluator (`evaluators_reject_overall_ok_true_when_rows_disagree`).
9. **B4, B5** (S/M). B2 done (see item 2).

## 4) Method notes

- Probe runs: two of five came back EMPTY on the first launch (0 bytes, no
  stderr) and succeeded on relaunch with `max_steps` 40 — treat an empty
  `ai_agent` result as a transport failure, not a "no findings" answer.
- The two in-flight OpenCode edit jobs sat `busy` for ~4 h on a single
  reasoning turn with zero tool calls; the ~75-min job cap only fires when
  `ai_edit_result` is POLLED. The watchdog now also flags a busy serve whose
  newest session timestamp has not moved for 20 min.

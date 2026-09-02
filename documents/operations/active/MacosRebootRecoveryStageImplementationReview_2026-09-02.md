# macOS Reboot-Recovery Stage Implementation Review — 2026-09-02

**Type:** docs-only Phase-B adversarial implementation review. No code changed, no lab run, no pass claimed.
**Subject:** the C7 stage `validate_macos_reboot_recovery` (`StageId::MacosRebootRecoveryValidation`, elected by `--reboot-platform macos`) as implemented on this branch (HEAD `acb7f5c0`, "Add the macOS live reboot-recovery validator as a first-class --node stage (C7)", diff vs `main` = 44 files, +675/−24), reviewed against `MacosDnsBackupRebootSurvivalPlan_2026-09-02.md` (Option A, live-proof mandate from its adversarial review A3).
**Verdict: ACCEPT-WITH-FIXES** — one high-severity finding (the stage can pass without a reboot having occurred), two medium, one low/medium. The wiring, fail-closed election, string contracts, evidence hygiene, and pin consistency all survive attack.

All anchors cite this worktree at `acb7f5c0` unless noted.

## 1. Scope reviewed

- Stage: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/macos_reboot_recovery_validation.rs` (184 lines: skip when not elected, fail-closed when elected with zero or ≥2 macOS nodes, dependency on `ValidateBaselineRuntime`, `StageFanout::Once`, 3 unit tests).
- Helper: `exercise_macos_reboot_recovery_live` at `crates/rustynet-cli/src/vm_lab/mod.rs:14896-15092`; evidence writer `write_macos_reboot_recovery_evidence` at `:15099-15136` (writes `<report_dir>/logs/validate_macos_reboot_recovery.{log,json}`, fail-loud on write error).
- Wiring: `native.rs` (election `reboot_platform_macos_elected` ~`:1102-1108`; elected∧plan-contains tightening ~`:441-448`, mirroring C6), `plan.rs` (selector, fast-path retain exception, stage box, count pins), `context.rs` (flag default false, reset false on resume), `live_lab_stage_registry.rs` (`EnableRule::RebootPlatform`, `TargetSelectors.reboot_platform`, spec at `:1247-1253`), `main.rs` (`--reboot-platform` parser), `evidence.rs` (manifest selectors), `live_lab_stage_manifest.rs` / `live_lab_run_matrix.rs` / `topology.rs` / `run_exclusion.rs` (fixtures + threading).

## 2. Findings

### F1 — HIGH: reboot occurrence is never proven; a pre-dispatch SSH error is swallowed and the stage passes on an unrebooted guest

**Evidence:** `mod.rs:14970` — the dispatch arm is `Err(_) => {}`: *any* SSH transport error around `shutdown -r now` is treated as the expected teardown. The pre-reboot capture a few seconds earlier proves SSH worked then; it does not prove the shutdown command dispatched. If the connection fails *before* dispatch (network blip, transient sshd reset), the stage proceeds to probe a guest that never rebooted: the daemon is still live (daemon-live check passes), and the recovery log line it greps for is the one the daemon logged at its **original** start — `run_startup_dns_recovery` logs the identical line at every start that finds a backup (`rustynetd/src/macos_dns_sc_protect.rs:833/868/981`), and the backup has existed since apply — so the `grep -hF` at `mod.rs:14903` finds it. **The stage passes without any reboot.** No `kern.boottime` / uptime / boot-id comparison exists anywhere in the helper.

**Minimal fix:** capture `sysctl -n kern.boottime` in the pre-reboot script output and again post-reboot; fail unless the value changed. Concretely, append `echo "boottime=$(sysctl -n kern.boottime)"` to both capture scripts, parse both values in the helper, and gate the success path on `pre != post` before the daemon-live checks. Secondary hardening: narrow the `Err(_)` arm to connection-closed/reset error kinds only, so a non-teardown transport failure fails the stage instead of being mistaken for it.

### F2 — MEDIUM: the fail-closed gate's alternate acceptance path is dead code (`contains("ok")` can never be true)

**Evidence:** `mod.rs:15066` — `if !startup_recovery_line_present && !failclosed_summary.contains("ok")`. The only `Ok` value `evaluate_macos_dns_failclosed_report` can return is `"macOS DNS fail-closed verified on {macos_alias}"` (`mod.rs:21543`); every drift or `overall_ok = false` is an `Err` (`mod.rs:21503-21544`). The summary therefore **never** contains `"ok"` at the gate, and the gate reduces to `!startup_recovery_line_present ⇒ fail`. The declared alternate acceptance path — a clean typed re-apply when the log line is absent (rotated/truncated log), worded in the summary at `mod.rs:15078` — is unreachable. Direction is fail-closed (a false *failure*, never a false green: `"not ok"` cannot appear because the evaluator errors first).

**Minimal fix:** since reaching the gate already proves the typed check is clean (the evaluator fails the stage on drift), drop the vacuous clause: `if !startup_recovery_line_present { return Err("...recovery log line absent...") }`, with the message adjusted to name the absent line rather than implying the check failed — or make `evaluate_…` return `(summary, overall_ok)` and test the bool so both paths are live.

### F3 — MEDIUM: `LOOPBACK_PIN_CHECK` word-splits service names, diverging from the daemon's parser (false failure on multi-word services) and passing vacuously on an empty list

**Evidence:** `mod.rs:14905-14912` — `for svc in $(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*')` applies IFS word-splitting: a multi-word enabled service (`Thunderbolt Bridge`) is visited as two bogus fragments; each fragment's `networksetup -getdnsservers <fragment>` fails with stderr suppressed, the `case` never matches `*127.0.0.1*`, and the capture script exits 1. The daemon itself parses the list **line-by-line and allows spaces** (`parse_networksetup_service_list`, `macos_dns_sc_protect.rs:256-294`; `is_valid_networksetup_service_name` `:98-108` rejects only control characters), so M1 pins `Thunderbolt Bridge` as one service — the stage would false-fail on any guest with such a service enabled (both pre- and post-reboot captures). Second defect: if the service list is empty/unparseable the loop body never runs and the check passes vacuously (backstopped only because the daemon's own fail-closed enumeration would then error into the evaluator).

**Minimal fix:** replace the for-glob with a line-oriented read and a non-empty guard:

```sh
networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' |
  while IFS= read -r svc; do
    [ -n "$svc" ] || exit 1
    case "$(networksetup -getdnsservers "$svc" 2>/dev/null)" in
      *127.0.0.1*) ;;
      *) exit 1 ;;
    esac
  done
```

(and count the services once before the loop so an empty list is a hard failure, matching the daemon's enumeration behaviour).

### F4 — LOW/MEDIUM: `budget_secs: 180` under-declares the stage's own worst case (~1270 s)

**Evidence:** registry spec `live_lab_stage_registry.rs:1251` sets `budget_secs: 180`, while the helper's own arithmetic is ≈ 120 s pre-capture + 30 s shutdown dispatch + up to 880 s return-probe loop (8 × (90 s capture timeout + 20 s sleep), `mod.rs:14988-15007`) + 120 s post-capture + 120 s fail-closed check ≈ **1270 s**. Not a hard kill today — the `--node` engine enforces `config.stage_timeout_secs` (default 0 = off, `native.rs:392-408`); `budget_secs` feeds only the manifest (`live_lab_stage_manifest.rs:226`) and evidence-verifier fixtures — so the live stage is not truncated, but the manifest misreports the budget and any future consumer treating `budget_secs` as a deadline kills the stage mid-proof. (C6 carries the same 180 but its helper is cheaper.)

**Minimal fix:** raise `budget_secs` to ≥ 1200 for this spec.

## 3. Considered, no defect

- **String contract set (exact):** `RECOVERY_LOG_LINE` (`mod.rs:14903`) byte-equals the daemon's `log::info!` at `rustynetd/src/macos_dns_sc_protect.rs:981`, and the log crate reaches disk (env_logger + `TeeLogWriter`, `rustynetd/src/main.rs:528`) with launchd `StandardErrorPath` `/usr/local/var/log/rustynet/rustynetd-error.log` (`scripts/launchd/com.rustynet.daemon.plist:70`) — the `*.log` glob matches. Backup path `$ST.networksetup-dns.failclosed.bak` == `NETWORKSETUP_DNS_BACKUP_SUFFIX` (`macos_dns_sc_protect.rs:310`, derivation `:324-331`, state sibling). Residue marker `$ST.shutdown-residue.json` == `SHUTDOWN_RESIDUE_MARKER_SUFFIX` (`shutdown_residue.rs:59`, `:182-189`). Daemon-live marker + node-id contract == `DAEMON_LIVE_MARKER` (`macos_install.rs:360`) with `parse_status_node_id` (`ssh.rs:856`). The `rustynetd macos-dns-failclosed-check --no-fail-on-drift` subcommand exists (`rustynetd/src/main.rs:445`).
- **Elected-tightening:** mirrors C6 exactly (election ∧ plan-contains at `native.rs:441-448`; flag reset false on resume in `context.rs`). Elected ⇒ dispatched; the Skipped arm is only reachable when not elected.
- **Dependency cannot silently skip:** `ValidateBaselineRuntime` sits at Setup / T0Core (`stage/mod.rs:197`) and the Setup suite is retained even under the fast-path filter, so an elected fast-path run always executes its dependency (and a baseline failure fails the run anyway).
- **Matrix/pin consistency:** plan count pins all updated and correct (66/75/70/79/67/76); `t2_resilience` 13→14 (`registry:3160-3168`); oracle arms `run_matrix:4791` and `:5220`; manifest fixture `reboot_platform` (`live_lab_stage_manifest.rs:349`); topology/run-exclusion fixtures; the `macos_stage_reboot_recovery` column pre-existed (`run_matrix:124`) and the roll-up fallback `stage.contains("reboot")` catches the new name.
- **Secrets hygiene:** every evidence capture (pre/post script stdout, `rustynet status` stdout, fail-closed JSON) holds public identity and DNS/service state only — no key material, nothing Debug-printed.
- **Fail-loud evidence writing:** `write_macos_reboot_recovery_evidence` errors on write failure rather than degrading.

## 4. Disposition

ACCEPT-WITH-FIXES: land F1 (required — it is the difference between proving the plan's live acceptance and proving nothing) before the first real evidence run; F2–F4 in the same or an immediately following change. The stage otherwise faithfully implements the plan's live acceptance procedure (apply → durable backup → reboot → auto-restore through `survivors.is_empty()` → backup retired) and the run-matrix/artifact contract stated in `MacosDnsBackupImplementationReview_2026-09-02.md`.

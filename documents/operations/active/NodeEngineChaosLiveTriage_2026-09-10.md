# --node Chaos + Negative-Control Live Triage (2026-09-10)

**Run:** lenovo-bot, 2-node Linux (`lenovo-client-1:client`, `lenovo-exit-1:exit`), main `f6d926c0` (code-identical to `41c5cf1d`; the later commits were docs-only), flags `--enable-chaos-suite --enable-negative-control`, report `artifacts/live_lab/chaos-negctl-41c5cf1d` on the host, ledger row `livelab-1789047225-f6d926c02b2a` (fetched into both ledgers). **48 pass / 3 fail / 28 skipped.** First-ever `--node` run of these two plans.

**What passed live, with QH-83 witnesses:** all four negative controls (`signed_bundle_rejection`, `planted_residue`, `wrong_node_substitution`, `daemon_kill_mid_stage` — each wrote its inversion transcript) and six of nine chaos stages (`daemon_fault`, `daemon_sigstop_sigcont`, `membership_adversarial`, `privileged_boundary`, `resource_exhaustion`, `signed_state_adversarial`). Note the plan gating: chaos stages declare `LiveMixedTopologyValidation` as a dependency, but that stage's Linux-only *skip* does not cascade (only a non-pass verdict does), so the chaos plan does run on a single-platform lab.

## The three failures — none is a product defect

| Stage | Symptom | Root cause (verified on `lenovo-exit-1`) | Class |
|---|---|---|---|
| `chaos_clock_attack` | `ssh command failed against debian@192.168.0.31:22 with status 1` four seconds in, right after "injecting stage JumpForward via libfaketime drop-in" | **libfaketime is not installed on the guest** (`/usr/lib/x86_64-linux-gnu/faketime/` absent; the bin's `DEFAULT_FAKETIME_LIB` points there). The bin has no precheck, so the failure is opaque. | environment precondition (the `requires()` class, `StageEnvironmentPreconditionsDesign_2026-09-09.md`) + lab-bin diagnosability |
| `chaos_network_impairment` | same opaque `status 1`, after "client exit-path traffic started" | Remote stderr is swallowed by the bins' ssh helper, so the failing command is not named. Guest facts: `tc` exists at `/usr/sbin/tc` and `sch_netem` loads (`modprobe -n` clean), but the guest's non-login `PATH` is `/usr/local/bin:/usr/bin:/bin:/usr/games` (no sbin — the RSA-0080/sbin-PATH class); the script's `command -v tc` preflight is the prime suspect. Unproven until stderr is captured. | lab-bin diagnosability (stderr) + probable sbin PATH |
| `chaos_crash_recovery` | `recovered=false`, `measured_recovery_secs=91`, state intact (`bundle_after=present`, `bundle_parse_after=true`, watermark unchanged, no empty keystore files) | The bin fires **12 `kill -9`s in ~90 s** against a unit with `StartLimitBurst=5` / `StartLimitIntervalSec=60` (`scripts/systemd/rustynetd.service`); systemd stops restarting the daemon after the fifth kill ("Failed with result 'signal'") and the bin never `reset-failed`s, so the daemon cannot come back inside the deadline. **The product did what its hardening says**: atomic old-or-new state, no watermark downgrade, no plaintext leak, and a deliberate restart rate limit. | test design |

## Fixes (lab bins only; no product change)

1. **Surface remote stderr** in the chaos bins' "ssh command failed" error (shared helper under `crates/rustynet-cli/src/bin/`), so the next failure names the command.
2. **`chaos_clock_attack`: precheck the faketime library** on the target (`test -f <lib>`) and fail with `missing_faketime_lib=<path>` naming the package (`libfaketime`) — a reported precondition, not an opaque status 1. Until `requires()` lands, the lab-host onboarding runbook gains `libfaketime` as a guest package.
3. **`chaos_crash_recovery`: `systemctl reset-failed <service>` before each restart wait** in the kill loop (the test measures the daemon's own recovery, not systemd's rate limiter, which is separately pinned by `service_hardening_validation`), and record `start_limit_resets=N` in the report so the reviewer sees how often the limiter would have engaged.
4. **`chaos_network_impairment`: run the remote script with an explicit sbin-bearing `PATH`** (the RSA-0080 pattern) — to be confirmed by fix 1's stderr on the next run.

Re-run the two plans on lenovo-bot after the bin fixes land; the three rows then either pass or fail with a named cause.

## Fixes landed (2026-09-10)

- **Remote stderr/stdout surfaced** on every failed remote command in the lab bins (`live_lab_bin_support::failed_remote_command_error`, bounded to the last 20 lines / 2 KiB per stream, UTF-8-safe; GLM flash job `edit-1789049328878-79086-0` merged `0bd2f77b`, boundary and single-long-line defects fixed by the manager with tests). The clock bin already printed `faketime_lib_present=false` on stdout — it was the swallowed stdout that made it opaque — so fix 2 is discharged by this.
- **Crash-recovery loop clears the start limit** (`systemctl reset-failed` before each per-iteration start and the final restart) and reports `start_limit_resets=N` in its key=value output and JSON report (required field; test `remote_script_resets_start_limit_per_kill_and_reports_the_count`).
- **sbin-bearing PATH pinned** at the top of the clock and network-impairment remote scripts (tests `remote_script_pins_an_sbin_bearing_path_before_any_lookup`).
- Still owed before the rerun: `libfaketime` on the lenovo guests (owner-free: `sudo apt-get install -y libfaketime` on debian@192.168.0.30/.31, or add it to the guest provisioner package list), then re-run the two plans.

## Role cells on the 2-node Linux lab (2026-09-10, lenovo-bot, main `41c5cf1d`)

Owner: "get as many live labs done as we can". With two guests a role cell is `exit + <role>` (preflight requires exactly one Exit; the cell has no client, so client-dependent stages report-skip).

| Cell | Run | Result | Role stages |
|---|---|---|---|
| exit + **blind_exit** | `livelab-1789057224` | 32 / 1 / 33 | `blind_exit` pass, `blind_exit_dataplane_validation` pass — **first live proof of blind_exit on the `--node` engine** (QH-86 validator exercised: forward rules judged, no masquerade) |
| exit + **relay** | `livelab-1789060725` | 34 / 1 / 31 | `deploy_relay_service` pass, `relay_validation` pass |
| exit + **anchor** | `livelab-1789062468` | 32 / 1 / 33 | `anchor_validation` pass; `live_anchor` skipped by dependency (see below) |
| exit + **admin** | `livelab-1789064178-41c5cf1d6d21` | 32 / 1 / 33 | `admin_issue` pass |

A first blind_exit launch as `client + blind_exit` failed preflight ("lab requires exactly 1 Exit node, found 0"): blind_exit is its own role, it does not stand in for Exit. Remedy recorded.

The single failure in each cell is the same lab-engine gap: `live_managed_dns_validation` failed with "no node with role label 'client'" instead of report-skipping like its siblings — fixed `18768ac6` + `825a63fb` (the topology skip is decided from assignments before any adapter resolves). Remedies recorded against all three stubs. Second gap: `live_anchor` declared `LiveMixedTopologyValidation` (the three-platform stage) as its dependency, so the skip cascade made it unreachable on every single-platform lab — fixed `449d91e1` (depends on `anchor_validation`; topology completeness stays the stage's own reported skip). Both fixes are on main behind the B5 push.

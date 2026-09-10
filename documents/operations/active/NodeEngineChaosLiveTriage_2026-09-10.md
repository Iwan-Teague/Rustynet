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

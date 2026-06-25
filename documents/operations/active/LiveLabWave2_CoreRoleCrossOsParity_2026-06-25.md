# Live-Lab Wave 2 — Core-Role macOS/Windows Parity (code) — Plan + Spec — 2026-06-25

Parent: `LiveLabCoverageAndHonestyAudit_2026-06-25.md` (§6 Wave 2; §5.6 strategy).
Author: Iwan-Teague. **Code-only.** Deliverable = the cross-OS TEST code
(assertion logic + per-OS command/path branches + unit-tested pure parsers).
**Status produced = "code-complete + unit-tested, LIVE-RUN-PENDING"** — the same
honest posture the relay/mixed-topology cells already hold. Running each ported
test against a real mac/win guest is the deferred human step.

## 0. The strategy (why this is tractable here)
The standalone `live_*` test binaries run ON the orchestrator (Linux) and SSH to
the guest via the cross-OS `RemoteShellHost` seam (argv-only, base64-framed). The
per-OS differences are **runtime `match platform` branches**, NOT `cfg` — so the
whole binary compiles + unit-tests on this Linux host. Today these binaries
fail-closed for non-Linux via `enforce_linux_only_until_validator_lands`
(`live_lab_support/mod.rs:63`, `live_lab_bin_support/mod.rs:103`). Porting = remove
that gate for the binary and add real macOS + Windows command/path branches.

**Proven in-repo templates (study these first):**
- `crates/rustynet-cli/src/bin/live_linux_relay_test.rs` — genuine 7/7 cross-OS
  parity via `RemoteShellHost` (launchctl/lsof on macOS, Get-Service/Get-NetUDPEndpoint
  on Windows, systemctl/ss on Linux), same assertion body.
- `crates/rustynet-cli/src/bin/live_mixed_topology_test.rs` — 5/5 cross-OS.

## 1. Non-negotiable honesty rules (carry from Wave 0/1)
- **No fake-pass on mac/win.** Port the REAL assertion; fail-closed `probe_attempted`
  discipline (a never-run probe = FAIL, never a silent pass).
- **If an operation has no macOS/Windows daemon equivalent**, the ported test must
  fail-closed with a SPECIFIC reason (not a blanket "not enabled"), AND the agent
  must FLAG that cell in its report as "test ported; daemon-side support
  unconfirmed/absent on <OS>" so we know the live run will expose a real gap, not a
  test bug. Do NOT invent a command that merely "passes".
- **Per-OS command correctness is inference** (can't run here): derive macOS/Windows
  commands from the relay-test template + the daemon's actual CLI surface (read
  `rustynetd`/`rustynet` subcommands), and unit-test every pure parser with realistic
  per-OS output samples. Mark any command you're unsure of with a `// REVIEW:`
  comment naming the uncertainty.

## 2. Cells (effort + cfg-exposure)
All are orchestrator-side (Linux-compilable). "Daemon-side risk" = whether the
mac/win *daemon* may lack the operation (a live-run gap, not a compile blocker).

| Cell | File | Effort | Daemon-side risk (live) |
|---|---|---|---|
| **exit-handoff real failover** | `live_linux_exit_handoff_test.rs` | HIGH | mac/win currently run a *narrower* NAT-lifecycle check (deceptive green) — replace with the real 6-check failover. Windows-as-exit is unsupported (`role.rs:65`), so the Windows path likely fail-closes live — flag it. |
| **two-hop** | `live_linux_two_hop_test.rs` | MED | W0-C already built the data-plane + TTL−2 proof; make it `--platform`-aware. macOS-as-intermediate-hop support unconfirmed — flag. |
| **lan-toggle / blind_exit** | `live_linux_lan_toggle_test.rs` | MED | W0-D added enforced-denial; port the killswitch/route/blind_exit assertions per-OS (pf/nft/WFP). blind_exit is unproven on mac/win. |
| **managed-DNS** | `live_linux_managed_dns_test.rs` | MED | 14 checks (split-DNS, alias, fail-closed bundle-tamper) — mostly resolver queries, portable. |
| **role-switch matrix** | `live_linux_role_switch_matrix_test.rs` | MED | macOS host-branch exists; **Windows has none** — add it. |
| **network-flap** | `live_linux_network_flap_test.rs` | MED | daemon roaming/re-handshake on mac/win unconfirmed. |
| **reboot-recovery** | `live_linux_reboot_recovery_test.rs` | MED | service auto-start (launchd/SCM) recovery. |
| **enrollment-restart** | `live_linux_enrollment_restart_test.rs` | MED | enrollment-token consume + restart-safety per-OS. |

## 3. Batching (parallel agents, disjoint files)
Each binary = one agent in an isolated worktree. They do NOT edit the shared
`live_lab_support` / `live_lab_bin_support` modules (the gate fn stays for
not-yet-ported binaries; ported binaries simply stop CALLING it). If an agent
believes it needs a shared helper, it adds it to its own binary or FLAGS it for the
reviewer — never edits the shared module (would collide).

- **Batch A (dispatch now, 4 parallel):** exit-handoff, two-hop, lan-toggle/blind_exit,
  managed-DNS. (Highest value: exit-handoff kills the deceptive false-parity; the
  other three build on Wave-0 groundwork or are self-contained.)
- **Batch B (after A reviewed):** role-switch matrix, network-flap, reboot-recovery,
  enrollment-restart, + wire the dead macOS producers (`macos_runtime_acls`,
  `macos_key_custody`, `MacosDaemonProbe`) into a macOS validate stage.

## 4. Per-agent contract
- Remove `enforce_linux_only_until_validator_lands` from your binary's `run()`.
- Thread `config.platform` through every Linux-specific command/path: add `match
  platform { Linux => …, MacOs => …, Windows => … }` branches, modeled on
  `live_linux_relay_test.rs`. Keep the Linux behaviour byte-identical.
- Keep + extend the fail-closed discipline (probe_attempted; a never-run/unparsed
  probe = FAIL).
- Unit-test every pure parser you add/branch with realistic per-OS output samples
  (the live commands aren't runnable here; the parsers are what's verifiable).
- Do NOT fake-pass; if an op has no mac/win daemon path, fail-closed with a specific
  reason + flag it.
- GATES: `cargo fmt --all`; `cargo check -p rustynet-cli --bin <your_bin>`;
  `cargo clippy -p rustynet-cli --bin <your_bin> --all-features -- -D warnings`;
  `cargo test -p rustynet-cli --bin <your_bin>`.
- Commit in your worktree (no Co-Authored-By trailer; `-c commit.gpgsign=false`).
  Report: branch, SHA, `git show --stat HEAD`, per-OS command choices + WHY, the
  pure parsers + their tests, every `// REVIEW:`/flagged uncertainty, and any
  daemon-side gap you expect the live run to expose. Do NOT push; do NOT edit files
  outside your owned binary.

## 5. Reviewer (me) responsibilities
Merge the disjoint diffs, run the full workspace gate, scrutinise the inferred
mac/win command branches (the highest-risk part — verify against the daemon CLI and
the relay-test template), confirm no fake-pass crept in, confirm Linux behaviour is
unchanged, then commit (Iwan-Teague) + push. Record the live-run-pending status +
every flagged daemon-side gap in this doc's outcome section and the ParityPlan §3
matrix.

## 6. Definition of done (Wave 2, code)
- Each ported binary compiles, its pure parsers are unit-tested, and `--platform
  {macos,windows}` no longer hard-fails at the gate — it runs the real per-OS
  assertion logic (which will pass or fail-closed honestly on a live guest).
- Linux behaviour is byte-identical to before.
- Every cell whose mac/win daemon support is unconfirmed is explicitly flagged
  (so the live run is interpreted correctly).
- All gates green (excluding documented env-blocked tests). Committed as
  Iwan-Teague, pushed. **Live runs against mac/win guests remain the human step.**

## 7. Honest scope note
Porting a test ≠ the role works on that OS. Where the mac/win daemon lacks an
operation, Wave 2 converts a blanket "not enabled" into a *specific, honest*
fail-closed test that the live run will light up red — surfacing the real
daemon-side gap (which may itself be `cfg(macos)`/`cfg(windows)` work needing a
builder, tracked separately). That is the intended, honest outcome.

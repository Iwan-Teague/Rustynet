# Live lab night run, Rust `--node` engine — 2026-09-26/27

Owner direction (2026-09-26, late evening): "keep running live labs all night, lets get as much done and proven with the node engine as possible", Linux and macOS focus, on the machines the lab lists as usable. This is the durable record of that night: where runs ran, what they proved, what they found, and what is still open.

**Evidence.** Every run appended a row to `documents/operations/live_lab_node_run_matrix.csv`, per-stage rows to `live_lab_node_stage_results.csv`, and triage records to `live_lab_stage_triage.jsonl`. The runs executed in lab worktrees of this repo and on the lenovo-bot host. Their rows were merged into this tree with a multiset-diff port against the unchanged base ledgers. The run ids below are the join key.

The 13 Mac-launched runs are in the ledger now. The five runs launched on lenovo-bot (box-l2 … box-l5) are summarized below from their live logs. Their rows are still on that host, which stopped answering at about 05:00Z (see Findings); they get ported once it is back.

## Where runs ran, and why

| stream | orchestrator host | guests | why |
|---|---|---|---|
| lenovo, Mac-launched | the Mac | lenovo-client-1, lenovo-exit-1 (libvirt, bridged LAN) | first attempts; management SSH crosses a WAN link |
| lenovo, on-host | lenovo-bot | same | Mac→guest SSH goes over a Tailscale subnet route with 442 ms RTT, 6–10 s per ssh exec. Two runs failed on "Connection timed out during banner exchange". On-host ssh takes 0.3–0.6 s, as in the 2026-09-11 green runs. |
| UTM | the Mac | debian-headless-2, debian-headless-4, ubuntu-utm-1, fedora-utm-1 (QEMU, one vmnet bridge) | local network, and 3- and 4-node topologies the two lenovo guests cannot form |
| macOS | — | macos-utm-1 (Apple Virtualization, the other vmnet bridge) | **blocked.** The engine's cross-bridge preflight correctly refuses a macOS+Linux topology until the owner loads the CP-1 pf override (sudo). |

On-host lenovo runs used `~/lab/rn-onbox`, a standalone snapshot repo whose tree hash equals suite `a3dfb390a:projects/rustynet` (tree `6792471d4a4de27951de62b865421e336f7f0507`). Its commit `128a43b` is what those rows record.

Runs marked "+fix" ran with a reviewed-or-under-review harness or product fix applied uncommitted. They used `--allow-dirty`, which the ledger records, and `--source-mode working-tree` wherever the guests needed the patched product code.

## Runs

| run | where | nodes (roles) | code | result |
|---|---|---|---|---|
| linux-c243b63f5-r2 | Mac → lenovo | client, exit | c243b63f5 | 31 pass, 1 fail (WAN ssh banner timeout) |
| linux-c243b63f5-r4 | Mac → lenovo | client, exit | c243b63f5 | 32 pass, 1 fail (WAN ssh banner timeout) |
| macos-m1-a3dfb390a | Mac → UTM | 2 Linux + macOS | a3dfb390a | refused at preflight (CP-1 split) |
| linux-u1-admin | Mac → UTM | client, exit, admin | a3dfb390a | 35 pass, 1 fail (AQ-68 harness drift) |
| linux-u2-relay | Mac → UTM | client, exit, relay | a3dfb390a | 37 pass, 1 fail (AQ-68) — relay + hello-limiter flood pass |
| linux-u4 / u4b | Mac → UTM | 4-node two-hop | a3dfb390a | bootstrap: EL libfaketime (Rocky), Fedora `tc` |
| linux-u4c-twohop | Mac → UTM | client, exit, entry, aux | a3dfb390a | 35 pass, 1 fail (AQ-68) — **two-hop passes** |
| linux-u3-blindexit | Mac → UTM | client, exit, blind_exit | a3dfb390a | 21 pass, 3 fail — **found the blind_exit regression** |
| linux-u5-chaos +fix | Mac → UTM | client, exit, admin | a3dfb390a +AQ-68 lab fix | 40 pass, 2 fail (chaos tcpdump tally, harness) — the live chain unblocked |
| linux-u6-blindexit-fix +fix | Mac → UTM | client, exit, blind_exit, aux | 24a184704 +blind_exit fix | 38 pass, 1 fail (enrollment restart, AQ-68 daemon side) — **fix verified live** |
| linux-u7-blindexit-chaos +fix | Mac → UTM | client, exit, blind_exit | 24a184704 +fixes | **45 pass, 0 fail** |
| linux-u8-extra-lantoggle +fix | Mac → UTM | client, exit, extra | 24a184704 +fixes | **39 pass, 0 fail** — LAN toggle passes |
| box-l2-chaos | lenovo-bot | client, exit | 128a43b (=a3dfb390a) | 38 pass, 1 fail (AQ-68) |
| box-l3b-negctl | lenovo-bot | client, exit | 128a43b | 38 pass, 1 fail (AQ-68) |
| box-l4-chaos +fix | lenovo-bot | client, exit | 128a43b +AQ-68 lab fix | **49 pass**, 2 fail (chaos tcpdump tally) — 7 of 9 chaos stages pass |
| box-l5-chaosfix | lenovo-bot | client, exit | 128a43b +fixes | bootstrap timeout: the box was overloaded by a landing leg run beside it |

## Proven live (Linux)

These 51 stages passed at least once in the ported Mac-launched runs:

- **Setup and control plane:** preflight, source archive, SSH reachability, host cleanup, bootstrap, membership, assignment, traversal and DNS-zone distribution, admin issuance.
- **Baseline runtime and posture:** enforce and validate baseline runtime, security audit, DNS fail-closed, runtime ACLs, service hardening, key custody, mesh status, gossip convergence, IPv6 leak.
- **Data path:** traffic matrix, role-switch matrix, exit handoff, active exit, exit DNS fail-closed, exit NAT lifecycle, exit demotion residue.
- **Relay:** deploy relay service, relay validation, relay hello-limiter flood.
- **Blind exit** (after the fix): blind_exit and blind_exit dataplane.
- **Two-hop.**
- **Live chain:** managed DNS, network flap, reboot recovery, secrets-not-in-logs, live key custody, LAN toggle.
- **Cross-network:** preflight and NAT classification.
- **Chaos:** crash recovery, daemon fault, daemon SIGSTOP/SIGCONT, membership adversarial, network impairment.

The on-host lenovo runs add, from their live logs:
- chaos: privileged boundary, resource exhaustion, signed-state adversarial and clock attack (clock attack failed twice on 2026-09-11);
- four negative controls: signed-bundle rejection, planted residue, wrong-node substitution, daemon kill mid-stage.

Only one stage never passed: `live_enrollment_restart_validation`, blocked by Finding 3.

Not reachable tonight:
- **macOS**, because of CP-1.
- **mixed topology**, which needs every platform.
- **extended soak**, which needs exit + client + entry + aux, and aux is blocked by Finding 3.
- **the rest of the cross-network suite**, which a vxlan-substrate run (linux-u9) was exercising at the time of writing.

## Findings

1. **Linux blind_exit regression (product). Fixed, reviewed and landed as 2e142db00.**
   - Symptom: every Linux blind_exit node failed closed and restricted itself permanently, because the privileged helper refused `add rule inet rustynet_g1 forward ct state established,related accept`.
   - Cause: AQ-70/F2 (2ceb1ac6e, 2026-09-21, its message mislabeled as an action-queue record) replaced the helper's unqualified established/related arms with three IPv4-scoped arms and updated phase10, but `linux_blind_exit.rs` kept emitting the old rule.
   - Fix: emit the shared scoped rules. A drift witness runs every emitted argv through the helper's own validator and fails on the old code with the live error.
   - Live: verified in linux-u6 and linux-u7.
   - Follow-ups: AQ-253.
2. **AQ-68 lab-harness drift, CLI side. Fix reviewed SOUND; landing held on the box (batch 3).** Since AQ-68 the CLI refuses a plaintext enrollment secret unless it is migrated into the OS keystore or explicitly opted in.
   - Headless Linux guests have no keystore; Secret Service needs a desktop session. So the secrets-not-in-logs mint failed in every run, and about 25 dependent stages were skipped.
   - The lab mint now opts in with `env RUSTYNET_ALLOW_PLAINTEXT_ENROLLMENT_SECRET=1` on that one command.
   - This is also live evidence for AQ-86/OI-14: headless Linux cannot mint enrollment tokens under the current posture without the lab override.
3. **AQ-68, daemon side.**
   - The enrollment-restart test's aux enrollment goes through the admin daemon's enrollment IPC, which refuses the plaintext secret too.
   - The lab e2e bootstrap also seeds the secret on every node, where production seeds admin nodes only.
   - Lane b29r2 wrote the lab-only fix; its independent review (a54) is pending.
4. **Chaos leak tally rejects tcpdump 4.99's standard notice (harness).** tcpdump 4.99 always writes `tcpdump: verbose output suppressed, …` to stderr, and the tally counted it as an error.
   - `chaos_daemon_fault` and `chaos_daemon_sigstop_sigcont` failed on every node with zero plaintext captured.
   - Fix: whitelist the exact line; a behavioural test covers it. Reviewed SOUND WITH CORRECTIONS, corrections applied.
   - Live: verified in linux-u7, where both stages passed.
5. **EL guests cannot bootstrap (harness).** `libfaketime` is only in EPEL on Rocky/Alma, and `tc` needs `iproute-tc` on Fedora/EL.
   - Fix: optional-on-EL with a loud WARN, add `iproute-tc`, and the clock-attack stage SKIPs rather than passes without libfaketime. Reviewed SOUND.
   - No repository was added (ADR-027).
6. **The killswitch-bypass negative control never adjudicated (harness).** It ran one second after the daemon-kill control, mid-restart, and its table selector also matched `rustynet_g1_dns`. Fix reviewed SOUND.
   - A 5-second nft sampler showed the boot-layer `rustynet_boot` killswitch chain present throughout, so fail-closed held.
7. **Libvirt readiness probe timeout (harness).** Remote `virsh` over ssh takes 3–11 s against a 5 s probe, so healthy remote guests were marked unready and rebooted. Reviewed SOUND WITH CORRECTIONS; corrected patch in batch 3.
8. **Operational.**
   - Mac-launched lenovo runs are unreliable (WAN); launch on the host.
   - Do not run a landing Linux leg on lenovo-bot during a lab bootstrap: L5 timed out at 900 s.
   - **lenovo-bot stopped answering at about 05:00Z.** Tailscale shows tx but no rx, even over the DERP relay, and its guests are unreachable. It needs a physical check.
   - A fleet lane's `pkill -f secrets_hygiene_gates` killed a landing gate; pattern kills are now banned in the lane rules.
   - The lane supervisor now salvages the worktree diff of a lane that ends without a report, and no longer stalls every lane when the box is unreachable.
   - The LAN-toggle stage's "no blind_exit node" skip means "no aux, extra or entry node to promote". The message is misleading, but the behaviour is by design.

## Landed tonight

| commit | what |
|---|---|
| a143fbf62, a3dfb390a | relay `--no-relay-accept-v1` actually refuses v1 hellos; stderr inventory pin re-stamp |
| c1219b620 | security ledger RSA-0001..0089 reconciled with the code (OI-53 for new wording) |
| 6f6132560 | nested self-ops exec a pinned copy of the binary (Linux "(deleted)" ENOENT fix) |
| 24a184704 | AQ-07: ten security gate scripts wired into the macOS and Debian CI legs (OI-54) |
| 2e142db00 | Linux blind_exit scoped established/related rules (Finding 1) |

**Held, all reviewed:**
- AQ-08 step 7 (rustynet-sysinfo lint lockdown);
- the libvirt probe timeout;
- the AQ-68 lab mint opt-in;
- the chaos tally fix;
- the killswitch-control race fix;
- the EL bootstrap fix.

Their macOS gates were running at the time of writing. The landing rule requires the Linux leg, which waits for lenovo-bot.

## Owner actions

- **Unblock every macOS run (CP-1).** Load the override: `sudo pfctl -a com.apple/100.rustynet-lab -f /Users/iwan/Desktop/rustysuite/projects/rustynet/scripts/vm_lab/cross_vmnet_pf_override.pf`. It is runtime-only; undo it with `sudo pfctl -a com.apple/100.rustynet-lab -F all`.
- **Check lenovo-bot.** It has been unreachable since about 05:00Z.
- **OI-53:** ledger wording. **OI-54:** CI-time ripgrep installs.
- **Optional, to speed up local landings:** macOS Gatekeeper scans every freshly built test binary on first run, so the secrets gate crawls for hours. Adding the terminal app under System Settings → Privacy & Security → Developer Tools exempts the binaries it launches. This is a security setting and the owner's call; tonight the gate ran on the Linux box instead.

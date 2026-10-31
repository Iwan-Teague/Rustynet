# Live lab runs, Rust `--node` engine — 2026-09-27/28

This record continues [LiveLabNodeEngineNightRun_2026-09-27.md](./LiveLabNodeEngineNightRun_2026-09-27.md). It covers the runs after that record was written: the 5-node UTM runs on 2026-09-27 (linux-u10 to linux-u12b) and the 2026-09-28 runs on the two Linux lab hosts, katana and lenovo-bot. For each run it gives where it ran and why, what it proved, what it found and what is still open. Owner direction is unchanged: prove as much as possible with the node engine, Linux and macOS first.

**Evidence.**
- Every run appended a row to `documents/operations/live_lab_node_run_matrix.csv`, per-stage rows to `live_lab_node_stage_results.csv`, and triage records to `live_lab_stage_triage.jsonl`. The run ids below are the join key.
- Stage verdicts here come from the per-stage ledger and, where a pass needed checking, from the stage's own report in the run's report directory (CLAUDE.md §12.3).
- The katana and lenovo runs executed on those hosts from snapshot repos, and their rows were ported into this tree with the same multiset-diff port as the night runs.

## Where runs ran, and why

| stream | orchestrator host | guests | why |
|---|---|---|---|
| UTM, Mac-launched (2026-09-27) | the Mac | debian-headless-2, debian-headless-4, ubuntu-utm-1, fedora-utm-1, rocky-utm-1 | 4- and 5-node topologies: entry, aux, relay and anchor roles |
| katana, on-host (2026-09-28) | katana, an x86_64 KVM host reached over Tailscale | katana-client-1 and katana-exit-1; from katana-u15 on, also katana-entry-1 and katana-aux-1 | The Mac was on battery, so builds and VMs moved to the lab hosts. The guests sit on katana's libvirt NAT network (192.168.122.0/24) and are reachable only from katana, so runs launch there. |
| lenovo, on-host (2026-09-28) | lenovo-bot | lenovo-client-1, lenovo-exit-1 (libvirt, bridged onto the home LAN) | a second Linux host whose guests share a real LAN with other devices |
| macOS | — | — | still blocked by CP-1 (see the night record's owner actions) |

Each katana and lenovo run used a standalone snapshot repo on its host. The snapshot was built from the lab worktree: suite `20774f851` plus the lab patch stack under review. The commit each row records (for example `f25be8512` for katana-u16) is that snapshot's commit. The rows are marked clean because the snapshot is committed. The lab patch stack is what makes them "+fix" runs in the night record's sense.

katana-entry-1 and katana-aux-1 were provisioned on 2026-09-28 with `ops vm-lab-provision-guest` and `vm-lab-provision-toolchain` (2.5 GB each), so katana could host 4-node topologies.

## Runs

| run | where | nodes (roles) | code | result |
|---|---|---|---|---|
| linux-u10-aux-enroll-soak-xnet | Mac → UTM | client, exit, entry, aux | 24a184704 +fixes | 41 pass, 0 fail. Its enrollment-restart pass was vacuous (Finding 7). |
| linux-u11b-5node-negctl-relayfwd | Mac → UTM | client, exit, entry, relay, aux | 87f689b52 +fixes | 45 pass, 3 fail: relay-forward proof HP-3 (Finding 6), plus its cascade |
| linux-u12-5node-chaos-negctl-anchor | Mac → UTM | client, exit, entry, anchor, aux | 0965c53ad +fixes | bootstrap failed: untracked files missing from the source archive (Finding 12) |
| linux-u12b-5node-chaos-negctl-anchor | Mac → UTM | same | 0965c53ad +fixes | 53 pass, 5 fail (Findings 2, 8, 9, 10, 11) |
| katana-u13-chaos-negctl | katana | client, exit | aa6979200 | 51 pass, 2 fail: crash-recovery window (Finding 5), tcpdump notice (Finding 2) |
| katana-u14-chaos-negctl | katana | client, exit | 2ded2dec6 | 39 pass, 1 fail: reboot recovery (Finding 3). **The AQ-46 exit egress witness passes for the first time.** |
| katana-u15-4node-chaos-negctl | katana | client, exit, entry, aux | 95f688828 | 38 pass, 1 fail: two-hop preflight (Finding 4). **All six negative controls pass, including enrollment-token replay for the first time.** |
| katana-u16-4node-chaos-negctl | katana | client, exit, entry, aux | f25be8512 | 45 pass, 1 fail: LAN toggle, a product bug (Finding 1). It took out mixed topology, soak, cross-network and all nine chaos stages. |
| lenovo-u16l-chaos-negctl | lenovo-bot | client, exit | a4b486f35 | 52 pass, 1 fail: AQ-46 witness on the bridged LAN (Finding 2). **All nine chaos stages pass.** |
| katana-u17-4node-chaos-negctl | katana | client, exit, entry, aux | 27c686bf2 | 56 pass, 2 fail: soak exit-handoff preflight (Finding 4), replay-control ledger count (Finding 13). **LAN toggle passes (Finding 1); all nine chaos stages pass on katana.** |
| lenovo-u17l-chaos-negctl | lenovo-bot | client, exit | da37caa9c | **53 pass, 0 fail.** The AQ-46 witness passes on the bridged LAN (Finding 2). The run-matrix row reads `partial` because of 22 platform-inapplicable skips. |
| katana-u18-4node-relayfwd-chaos-negctl | katana | client, exit, relay, aux | 76c1d194f | 47 pass, 2 fail: HP-3 relay path never formed (Finding 6), enrollment restart on a demoted exit (Finding 14). The rest of the live suite, chaos and soak were skipped behind the enrollment-restart failure. **The HP-3 cascade is gone: both HP-3 peers stayed healthy through the refresh, and every negative control after HP-3 passed.** |

## Proven live (Linux)

New since the night record:
- **AQ-46 exit egress witness:**
  - first pass in katana-u14;
  - passes on lenovo-bot's bridged LAN since lenovo-u17l.
- **Enrollment-token replay negative control:** first pass in katana-u15. All six negative controls now pass in one run (katana-u15, katana-u16).
- **Enrollment restart:** first genuine pass in katana-u16. The report shows the admin daemon accepted the consume before the kill ("enrollment accepted", `enrollment_outcome=consumed`), and the ledger refused the token after the restart (`already_consumed=true`). The earlier ledger passes were vacuous (Finding 7).
- **Reboot recovery with a real reboot:** the stage now waits for a new boot id (katana-u16, lenovo-u16l).
- **Two-hop on x86_64 guests:** katana-u16.
- **All nine chaos stages:** on lenovo-bot's guests (lenovo-u16l, lenovo-u17l) and on katana (katana-u17, crash recovery included with the widened window).
- **LAN toggle on x86_64 guests:** katana-u17.
- **Cross-network preflight and NAT classification:** on both hosts.

Not reachable yet:
- **macOS**, because of CP-1.
- **Cross-network scenarios**, which need two guest subnets. Each lab host has one.
- **Mixed topology**, which needs every platform.

## Findings

1. **ops install-systemd took a stale socket file as readiness (product).**
   - Symptom: katana-u16's LAN toggle failed with `rustynet state refresh: connect /run/rustynet/rustynetd.sock failed: Connection refused`.
   - Cause:
     - `rustynetd.service` is `Type=simple`.
     - The daemon runs its runtime bootstrap before it removes and rebinds its control socket, and nothing unlinks the socket on stop.
     - So right after `systemctl restart`, the socket path still names the previous daemon's dead socket, and `wait_for_unix_socket` (`crates/rustynet-cli/src/ops_install_systemd.rs`) accepted it.
     - The guest journal on katana-client-1: the unit started at 13:32:34.157, install-systemd failed 17 ms later, and bootstrap completed at 13:32:35.899.
   - Fix: the wait requires a successful `connect` (same 40 x 250 ms budget; symlinks and non-sockets are still refused). Three tests: a stale socket file, a live listener, and a stale file that is later rebound. Both stale-file tests fail against the old code.
   - Review: a65 SOUND WITH CORRECTIONS. The one correction (test socket paths under a long TMPDIR on macOS) is done and confirmed by a67.
   - Live: katana-u17 passes the LAN toggle, the stage that failed in katana-u16.
   - Same flaw in `ops_e2e.rs` `wait_for_daemon_socket_locally`: a65 confirmed it, and the fix is lane b40. `main.rs` `wait_for_socket_path` is safe, because a retried status check follows it.
2. **AQ-46 exit egress witness, three harness corrections.**
   - It read the WireGuard port from `wg show`, which prints nothing for the Rustynet data plane (linux-u12b). It now reads the port from the killswitch's single accept pair on the egress interface.
   - It rejected tcpdump 4.99's standard "verbose output suppressed" notice (katana-u13). That exact line is now benign, as in the chaos tally.
   - On a bridged LAN, promiscuous tcpdump counted another device's IPv6 neighbour solicitations as egress from the exit (lenovo-u16l). The IPv6 clause now counts only frames the exit's own NIC sends (its MAC from `ip -brief link`, fail closed), and the DNS, DoT, ICMP and WireGuard port clauses sit in one IPv4-only group.
   - Reviews: a61, a62, a64 (SOUND WITH CORRECTIONS; the correction was the IPv4 group) and a65 (SOUND).
   - Live: lenovo-u17l passes on the same bridged LAN.
3. **Reboot recovery answered on the old boot (harness).**
   - `systemctl reboot` returns before the guest goes down, so the exit answered SSH on its old boot and the boot-id check correctly failed (katana-u14).
   - Fix: the stage waits, within the same bound, for a boot id other than the pre-reboot one.
   - Review: a63 SOUND. Live: katana-u16, lenovo-u16l.
   - Any other stage that reboots a guest and polls SSH should get the same wait.
4. **Two-hop required a command it never runs (harness).**
   - `live_linux_two_hop_test` refused to start on katana, which has no `xxd`, and it never invokes `xxd`. The requirement was dropped.
   - Review: a64 SOUND. Live: katana-u16.
   - The same stale entry in `live_linux_exit_handoff_test` failed katana-u17's soak; it is dropped there and in `live_linux_role_switch_matrix_test` (review a71 SOUND). a64 also found other unused entries in the two-hop list: follow-up.
5. **Crash recovery converges slowly on katana (harness tuning; the root cause is open).**
   - The state checks passed, but the mesh re-proved a handshake about 214 s after recovery, past the 180 s window.
   - The window is now three recovery deadlines (270 s). Review: a62 SOUND.
   - Live: katana-u17 passes crash recovery. The slow re-handshake itself is still open.
6. **HP-3 relay-forward proof: the harness broke the mesh it was testing (harness).**
   - `live_two_hop_validation` narrows each node's signed assignment to a chain and never restores it. `refresh_signed_bundles` then re-minted only a full-mesh traversal bundle.
   - The daemons correctly refused a traversal snapshot naming peers their assignment does not manage, and escalated to Permanent FailClosed (linux-u11b).
   - The daemon's refusal is correct and stays.
   - Fix (lane b36): mint assignment and traversal from one snapshot and install them as a pair behind a quiesce fence with a bounded health poll. Also added: a health pre-flight, and a cleanup that reports failures.
   - Review: a66 SOUND WITH CORRECTIONS. Corrections done: the fence markers are conditional on `systemctl` success, with behavioural tests; every peer's cleanup health is checked at least once. Confirmation: a68 CORRECTIONS DONE.
   - linux-u11b's `extended_soak` failure was an issuance-side key-custody error, not demonstrably this cascade (a66 F2).
   - Live (katana-u18): the cascade is fixed. The stage got past its health pre-flight to the relay wait, both HP-3 peers stayed ExitActive with no reconcile failures, and every negative control after HP-3 passed.
   - But the relay path still never formed ("timed out after 90s waiting for both peers to report a relay-routed session"). Both peers report `relay_session_configured=false`, `relay_session_state=disabled` and `transport_socket_identity_state=blocked_backend_opaque_socket`.
   - Cause (harness provisioning gap, not a daemon regression): the daemon builds a relay client only when a relay session token source (a preissued token spool or a local issuer) is configured, and nothing in the harness configures one on the peers; `relay_session_configured=false` alone rules the session out. Independently, relay session setup needs the backend's authoritative transport, which the kernel `linux-wireguard` backend does not expose, and the run used the kernel backend.
   - HP-3 has never passed on any host. A design for peer relay-client provisioning (token source and custody, backend requirement, relay candidates in the traversal bundle, the 90 s window) is lane b42.
7. **Enrollment-restart passes were vacuous (harness).**
   - In linux-u10 to linux-u12b the stage passed without the consume ever reaching the admin daemon.
   - The stage now waits for the daemon's IPC readiness and requires the daemon's acceptance (a58). katana-u16 is the first genuine pass.
8. **Enrollment-replay control needed a ledger file that did not exist yet (harness).**
   - The daemon creates the consumed-token ledger on its first accepted consume, so an admin that never enrolled anyone has none (linux-u12b).
   - An absent ledger is now a zero-row baseline. Review: a61 SOUND.
9. **Anchor log-redaction check expected a line AQ-44 removed (harness).**
   - The substage demanded a `token_thumbprint=` journal line, but the anchor keeps no per-flow logs since AQ-44 (linux-u12b).
   - It now asserts that no raw token appears, and that an invalid-token probe is rejected. Review: a61 SOUND.
10. **Resource-exhaustion chaos on UTM guests (environment).**
    - The IPC status probes fell back to `nc -U`, which keeps the connection open after stdin EOF, and timed out (linux-u12b).
    - The daemon itself held. The UTM guests lack `socat`; the stage passes on katana (katana-u13) and lenovo-bot.
11. **Soak two-hop reachability with a Rocky client (open).**
    - linux-u12b's soak failed only its end-to-end reachability check with rocky-utm-1 (EL, firewalld) as the second client.
    - The same run passed `live_two_hop_validation`. Queued for triage.
12. **Operational.**
    - A `--source-mode working-tree` archive is a `git stash create` snapshot, so untracked files are not shipped. `git add` new files in the lab worktree before launching (linux-u12).
    - katana's default umask of 002 made about 56 permission-checking unit tests fail there. The prep script now forces 022.
    - Two Linux-only test races (a shared temp dir and an ETXTBSY exec) were fixed. Review: a62 SOUND.
    - Bootstrap takes about 25 minutes for four katana guests, inside the 40-minute stage timeout.
13. **Enrollment-replay control: a row-count rule broke under legitimate purging (harness).**
    - katana-u17: the genuine consume was accepted, all three replays were refused, verify said already_consumed=true, and the token was recorded once. But the ledger went 1 -> 1, because the daemon purges consumed entries whose expiry has passed (`purge_expired_against`) when it records a new one, and the one prior row (the enrollment-restart token) had expired 14 minutes earlier.
    - Fix: a ledger diff replaces the "+1 rows" rule. The attack token must be absent before and present once after, with no other rows added and no still-live row removed, and the counts must reconcile. Both mutations (the old rule; no live-removal check) are caught by tests.
    - Review: a70 SOUND (minor test notes N1/N2; the seconds-wide early-purge window is an accepted residual).
    - Live: katana-u18 passes the replay control.
14. **Exit-demotion residue check left the exit demoted (harness).**
    - `exit_demotion_residue_validation` demotes the assigned exit (`role set admin`, then `role set client`) to prove the NAT table and forwarding are gone, and never restores it.
    - In the client/exit/entry/aux layout this was masked: `live_two_hop_validation` runs later and re-enforces the exit as admin. In katana-u18's relay layout two-hop is skipped (no entry role). `role set` only persists the role for the next daemon restart, so the client role took effect at the next restart and held: network flap saw the exit as `node_role=client state=DataplaneApplied exit_node=none` (katana-u17: `admin`, `ExitActive`). The exit had also stopped serving.
    - `live_enrollment_restart_validation` elects the Exit as the enrolling admin, and a client daemon refuses the consume: "command denied: current node role does not permit this operation". The daemon held: it recovered after the kill, the ledger stayed valid and unconsumed, and membership integrity passed.
    - The later enrollment-token replay control on the same node still passed. It goes through the anchor enrollment listener, which is gated by membership capability, not by the IPC role check, so it does not contradict this.
    - Fix (lane b41): restore both the admin role and exit serving after the residue proof, and verify them from the node's own status; a failed restore fails the stage.
    - Review of both katana-u18 dispositions: an independent Claude reviewer found Finding 14 SOUND WITH CORRECTIONS (the restart mechanism, and the exit stopped serving) and the HP-3 cause SOUND (minor: only the two HP-3 peers, not the whole mesh, stayed ExitActive). The corrections are in this record. The ledger stubs keep their first wording because the triage tool refuses to overwrite a recorded disposition.

## Landed

| commit | what |
|---|---|
| 3ba81e45d, 0d3f25a17, 242057257, b73c39aa9, 740d03d27, 0965c53ad | the night record's six held changes (2026-09-27) |
| 50177fdaf, 96a84c642, 0426cc1e1 | evidence for linux-u10, linux-u11b and the lenovo-bot night runs, linux-u12/u12b |
| 0c1c126b3, 20774f851, d2ddee2f0, 97ea6a3c8 | evidence for katana-u13 to katana-u16 and lenovo-u16l |
| defd9e7c8 | evidence for katana-u17 and lenovo-u17l |
| 972c60af8 | evidence for katana-u18 |
| 3441d219d | live-lab coverage gap audit for Linux and macOS (draft for owner decision) |
| 951f1213a | AQ-36 re-dated: BLOCKED on OI-27 and two owner decisions |

**Held, reviewed, waiting for their landing gates (macOS leg and Linux leg):**
- the install-systemd socket wait (Finding 1);
- the AQ-46 witness corrections (Finding 2);
- the reboot new-boot wait (Finding 3);
- the two-hop `xxd` drop (Finding 4);
- the crash-recovery window (Finding 5);
- the enrollment-restart readiness and acceptance changes (Finding 7);
- the replay-ledger baseline (Finding 8);
- the anchor redaction check (Finding 9);
- the Linux test races (Finding 12);
- the katana-entry-1 and katana-aux-1 inventory entries (a63; `katana-aux-1` uses `lab_role` `linux_aux`, so it does not collide with rocky-utm-1's `aux`).

- the HP-3 bundle-pair refresh (Finding 6; reviewed a66 and a68, live in katana-u18);
- the ops_e2e socket wait (Finding 1 sibling, a71) and the replay-control ledger diff (Finding 13, a70).

Open: the HP-3 peer relay-client provisioning (Finding 6, lane b42) and the exit-demotion restore (Finding 14, lane b41).

## Owner actions

- **Unblock macOS (CP-1).** Unchanged from the night record.
- **katana's host record.** The suite inventory still gives katana's libvirt URI at its old LAN address (`qemu+ssh://debian@192.168.18.44/system`). On-host runs rewrite it to `qemu:///system` in their snapshot, and Mac-side provisioning needed the Tailscale address. Decide which address the tracked inventory should carry.

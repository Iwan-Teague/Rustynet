# Live-Lab Stage Status — 2026-08-14

**Read this before claiming any stage works.** It states, per OS, what is proven, what is failing,
and what has never been exercised. Every figure comes from a stage's own report artifact, never from
a ledger column (§12.3 explains why the columns lie in both directions).

Latest run: `qh61-sudopath-20260816b` → `livelab-1787913512-a5e93c8dd781` (2026-08-28; Runs 45–48
below). The Linux topology is 5 nodes; macOS was elected into two focused cells on 2026-08-28;
Windows has never been elected.

---

## The one-line answer

**Linux: 44 of 44 runnable stages pass — zero-failure end to end (first on 2026-08-16, re-proven
2026-08-28, Run 45). macOS: elected for the first time on 2026-08-28 — anchor and exit cells both
🔴 blocked with located blockers (Runs 47/48). Windows: never elected; bootstrap root-caused,
fixes landed, guest currently unreachable.**

The Linux figure is a **Linux-only** result. It says nothing about cross-platform parity, which
remains the larger release blocker per
`CrossPlatformRoleParityPlan_2026-06-21.md` — but parity now has its first `--node`-engine data
points, and neither mac cell is green.

---

## Per-OS status

| OS | Nodes in topology | Stages run | Status |
| --- | --- | --- | --- |
| **Linux** | 5 (Debian 13 ×2, Fedora 44, Rocky 10.2, Ubuntu 26.04) | 44 runnable / 17 honest skips | **44 pass / 0 fail** (Run 45, 2026-08-28) |
| **macOS** | 1 (elected 2026-08-28, focused cells) | 2 cells ran; 0 macOS role stages green | **🔴 BLOCKED** — anchor: posture gate circular (`role.rs:68-70`) + needs `--anchor-platform macos`; exit: membership owner-key path defect (`macos_membership.rs:29-34`). Runs 47/48. |
| **Windows** | **0** | **0** | **NOT ELECTED** — `windows_stage_bootstrap` gates all; root-caused 2026-08-28 (winget Configuration, code primary); W-FIX-1/2/3 landed; guest currently has no remote management path. See the Windows section. |

*(Corrected 2026-08-28. The 2026-08-14 original read: Linux 35/36 reachable, 35 pass / 1 fail;
macOS and Windows "UNPROVEN — not in topology, stages never appear".)*

The macOS and Windows stages are still **not among the Linux runs' skips** — without a platform node
elected they are not planned at all, so do not read the 17 skipped as covering them. macOS's first
appearances came from its own focused elections (Runs 47/48); Windows stages remain absent entirely.

### The 23 Linux skips

| Cause | Count | Meaning |
| --- | --- | --- |
| Cascade from the single failure | ~19 | Never ran. Blocked downstream of `live_network_flap_validation`; `live_mixed_topology_validation` alone gates 13 (all `cross_network_*` + `live_anchor`). |
| Role not elected | 4 | `blind_exit` (×2), `anchor`, `admin` — no node in this topology holds them. Not defects; needs a topology that elects them. |

Fixing the one failure should unblock ~19 stages, taking Linux to roughly 54/59.

*(Resolution 2026-08-16/28: it did. Run 44 reached 44 pass / 0 fail with every skip
topology-conditional, and Run 45 re-proved it at 44/0/17 on the larger 61-stage plan. This section
describes the 2026-08-14 cascade and is retained for the record.)*

---

## WORKING — fixed and verified this session

All seven are mutation-proven (the test was shown to fail when the fix is reverted).

| ID | Defect | Proof |
| --- | --- | --- |
| **QH-46** | firewalld's forward chain (priority `filter+10`) runs AFTER Rustynet's (priority 0) and rejects the hairpin; the runtime-created tunnel is in no zone. Any RHEL-family host could not forward as relay/exit. | **LIVE-PROVEN.** `live_two_hop_validation` passes for the FIRST time in the `--node` engine's history: `two_hop_reply_ttl=63` (one hop) on a Fedora entry — the same value Debian entries produced in June. Stable across 5 runs. |
| **QH-49** | LAN-toggle stage hardcoded SSH username `debian`, so any non-Debian guest in exit/client/blind_exit was dialled as `debian@<their-ip>`. | 3 unit tests + mutation |
| **QH-50** | blind-exit NAT scan read `ct status dnat` (a conntrack MATCH) as NAT — impossible to satisfy on any firewalld host — AND missed a leading-token `dnat to`. Wrong in both directions. | 8 tests + 3 mutations |
| **QH-51a** | `persistent_keepalive_secs` never populated in production (only `Some(..)` in the repo was a helper unit test). | Behavioural test on a peer loaded from a real signed bundle |
| **QH-51b** | Flap stage's metric conflated "unreadable" with "very old" (`u64::MAX` for three distinct states), so its disruption check passed on missing data. | Check flipped pass→fail on identical behaviour — the repair's own proof |
| **QH-51c** | `configure_peer` rebuilt the crypto session on every reconcile of an UNCHANGED peer, wiping handshake telemetry each cycle. | Mutation also broke an existing endpoint-relink test, confirming correct composition |
| **QH-51d** | Endpoint-only change rebuilt the tunnel instead of roaming in place; and the userspace engine passed a hardcoded `None` for boringtun's keepalive argument, discarding the configured value. | 255 crate tests + roaming test |

---

## NOT WORKING — open

### `live_network_flap_validation` (Linux) — the only failing stage

> **RESOLVED — superseded 2026-08-15 and 2026-08-27; everything below is retained for the record and
> nothing in it is open.** The stage PASSED for the first time in `--node` history on Run 41, and has
> passed every run since (including Run 45). QH-51 was resolved by measurement, not another patch: a
> packet-level capture on live guests (`NetworkFlapHandshakeCapture_2026-08-27.md`, main `4b0d18aa`)
> shows 4/4 flap cycles recovering in 8s — the peer keeps sending WG handshake initiations through
> the whole blackout and the first one after the block lifts is answered within milliseconds, data
> crossing seconds later. The historical `recovery_arrived=false` signature is explained by the
> since-fixed instruments (hypothesis 8's stamp-based recovery oracle, plus a broken ENTRY
> underneath the probe: QH-46's firewalld reject, then the QH-53 restart race) and the QH-04
> reconcile rework. No assertion was widened; the data-crossing recovery check is stricter than the
> stamp it replaced.

3 of its 4 checks pass. `recovery_arrived=false`: after the block lifts, the handshake metric never
refreshes inside the 180s poll, while `tunnel_active=true` and `membership_intact=true`.

**Six hypotheses tested and ELIMINATED** — do not re-run these:

1. Roaming churn destroying the record — refuted live (fix landed anyway, correct on its own merits)
2. Keepalive not reaching the tunnel — refuted live (fix landed anyway, same)
3. Probe suppression by the flap breaker — eliminated by reading: `traversal_probe_due` has no
   breaker consult; the breaker gates only the quality re-race (`daemon.rs:6885`)
4. boringtun timers not pumped — eliminated: `engine.rs:452` calls `Tunn::update_timers`
5. Keepalive missing from the client's peer — eliminated: `daemon.rs:13438` is the ONLY production
   `PeerConfig` site in the daemon and it sets `Some(25)`
6. Handshake record being deleted — eliminated: it now survives both an unchanged reconcile and a roam

**HYPOTHESIS 8 (current, fits every observation): a 35s block does not invalidate the session, so
there is no second handshake to record.**

The capture on `qh51-capture2-20260814k` settled that the metric is NOT merely paced — the probe path
runs each reconcile (`next_reprobe_unix` advances 30s per sample, and only the probe-ran path re-arms
it at `daemon.rs:6838`; the not-due branch at `:6631` retains the old value). It writes
`latest_handshake_unix` from the backend every pass, and the backend reports `none` throughout.

The timer plumbing is complete and correct: `poll_peer_timers` ticks every 1s (`runtime.rs:827`,
called at `:1164`), `update_peer_timers` sends what boringtun emits via `drive_outbound_result`, and
every observed handshake IS recorded (`:850-854`). So nothing is dropping handshakes.

Which leaves: **no handshake occurs at all.** WireGuard rekeys at ~120s; a 35-second block does not
expire the session. When the block lifts, traffic resumes on the SAME session, `update_timers` emits
keepalives rather than a handshake, `drive_outbound_result` observes nothing to record, and the
record — cleared during the disruption — is never repopulated.

If that is right, the stage's premise is wrong rather than the daemon: it induces a 35s outage and
then demands a NEW handshake as proof of recovery, when correct WireGuard behaviour is to resume
without one. The honest fix is then to prove recovery by DATA flowing (which is what "recovered"
actually means), not by a handshake timestamp — and that is a stricter, more meaningful assertion,
not a weaker one. VERIFY FIRST: confirm what cleared the record during the block (nothing in
`configure_peer` should now, so look at `remove_peer`), and confirm no handshake occurs post-unblock
before changing the stage.

**Superseded hypothesis (REFUTED by the capture): the metric is PACED, not dead.** `traversal_probe_due`
backs off for a handshake that was already stale at the previous evaluation — exactly the state a 35s
block produces — and the field the stage reads only refreshes when a probe runs. If the back-off
exceeds the 180s poll, the tunnel can genuinely recover while the metric never refreshes inside the
window. Consistent with `tunnel_active=true` on every failing run.

**Settle it with a capture, not another fix:** sample `traversal_probe_attempts` and
`traversal_probe_next_reprobe_unix` on the client across the recovery poll. Static attempts with a
reprobe time beyond the window proves pacing; rising attempts with a stale timestamp proves the
daemon records nothing.

**Do NOT widen the recovery assertion.** It is the only check proving the tunnel comes back.

**The capture was ATTEMPTED on run `qh51-capture-20260814j` and FAILED — do not repeat these two
mistakes.** It produced a single empty sample and exited:

1. `2>/dev/null` on the ssh invocation swallowed the error, so an empty line was indistinguishable
   from a failed command. This is the THIRD time suppressed stderr has cost a reading in this
   investigation. Capture stderr (`2>&1`) and print it.
2. The loop's exit condition matched `recovery_arrived=` in the orchestrator log, which was already
   present from an earlier line, so the poll ended after one iteration. Gate the exit on a
   NEW occurrence (record the line count first, or match the stage's own log file rather than the
   orchestrator's).

Also note the daemon is UNREACHABLE after the run (`/run/rustynet/rustynetd.sock` is gone —
`final_cleanup` is `always_run`), so this cannot be sampled retroactively. It must run mid-stage or
not at all.

### Cross-platform — the larger blocker

`CrossPlatformRoleParityPlan_2026-06-21.md` requires every role live-proven on **macOS AND Windows**,
not just Linux. **Updated 2026-08-28: the frontier moved.** macOS anchor and exit were elected for
the first time (Runs 47/48 — both 🔴 blocked with located blockers), and the Windows bootstrap
failure was root-caused with its first three fixes landed (see the Windows section below). Still open:

* **Windows stages have never run** — no node elected; the cell is gated at bootstrap and the guest
  currently has no remote management path at all.
* **macOS anchor is not green**: the posture gate is circular as written (`role.rs:68-70`), and the
  macOS-specific anchor validator set needs the `--anchor-platform macos` selector plus a full-suite
  run; the exit/blind_exit cells additionally need the membership adapter's owner-key path fixed.
* **`userspace_shared_macos` may need the QH-51c/d fixes mirrored.** The session-rebuild and roaming
  fixes landed in `userspace_shared`; macOS has its own variant. NOT checked — do this before
  assuming macOS benefits from the QH-51 work. (Still unexamined as of 2026-08-28.)
* **QH-46's Windows analogue is unexamined.** firewalld is RHEL-specific, but the defect CLASS —
  a foreign filter at the same hook silently discarding traffic we authorised — has an obvious
  Windows counterpart in WFP filter weights. Nobody has looked. (The CP-4 triage did not examine
  it either.)

### Also open (filed, not fixed)

* **QH-47** — nothing flushes conntrack when NAT rules change; affects any node gaining an exit/relay
  role while traffic flows. *(Updated 2026-08-28: FIXED on Linux — a `linux-conntrack-flush` helper
  builtin, unit- and mutation-tested; LIVE PROOF OUTSTANDING.)*
* **QH-48** — the live suite is a strictly linear dependency chain, so one failure blocks ~19 stages
  and a 17-minute run surfaces at most one defect.

## Run 39 (`qh51-peerprobe-20260814p`) — KILLED EXTERNALLY, answered nothing

The peer-probe discriminating experiment (commit `9ac63abd`) NEVER RAN. The run was externally
SIGTERMed at 11:07:44Z, ~296s into `live_managed_dns_validation`: the orchestrator's own stdout
records `rust orchestrator: received SIGTERM/SIGINT — 25 stage(s) skipped`, and the in-flight
stage's `cargo run` child died with `exit signal: 15 (SIGTERM)`. Everything downstream — including
`live_network_flap_validation` — was cascade-skipped. 33 stages passed before the kill, among them
`live_two_hop_validation` (second consecutive pass; the QH-46 firewalld fix keeps holding).

Do NOT read the `live_managed_dns_validation` fail row as a stage or product defect:

* No RNQ-07 deadline was armed (the direct CLI defaults `--stage-timeout-secs` to 0, and a deadline
  kill would have recorded `timed_out`, not `fail`).
* The stage was mid-normal bundle propagation (4th of 4 peers) when killed; the same stage passed
  all 11 prior runs on 2026-08-14 in 245–281s.
* The kill correlates with the handover session's teardown: the run was `nohup`ed from that
  session's shell, and `nohup` does NOT give the child its own process group, so reaping the
  session's background task TERMed the whole tree. The orchestrator survived long enough to run
  `always_run` cleanup because it handles SIGTERM; the cargo child did not.

**Launch-path lesson (recorded so it is not re-learned):** the "reload-proof, own process group"
protection described in CLAUDE.md §12.5 belongs to the MCP launch path only. A direct-CLI run
launched from an agent session's shell dies with that session unless the orchestrator is wrapped in
its own session/process group (e.g. a `python3 os.setsid()` exec wrapper). Run 40 uses exactly that.

Triage: recorded against stub `livelab-1786705680-c7eb8a1f00e5::live_managed_dns_validation`
(no code change; environmental kill; relaunch).

## Run 40 (`qh51-peerprobe2-20260814q`) — probe target fixed, and a NEW defect found underneath

35 pass / 1 fail (`live_network_flap_validation` only) / 23 skipped. `live_two_hop_validation`
passed again (third consecutive). Launched setsid-isolated after run 39's kill; no external
interference this time.

The peer-probe retarget (`9ac63abd`) did its job: the probe host resolved to the ENTRY
(`fedora@192.168.64.103`). But the probe printed `<unresolved>` again — and this time the discovery
command is NOT at fault. Verified directly on the guest: `ip` resolves fine on Fedora
(`/usr/bin/ip`, PATH fine, command exits cleanly). The interface it was asked about did not exist.

**The entry was tunnel-less for the whole flap window.** From fedora's journal (UTC):

* 11:36:00 — `managed_dns` bundle propagation restarts fedora's daemon (2s stop→start gap).
* 11:36:02 — the restarted daemon logs
  `restrict_recoverable: dataplane bootstrap apply failed: system error: i/o failed: interface
  "rustynet0" not present in sysfs: No such file or directory` — the error text of
  `require_virtual_network_device` (privileged_helper.rs:1264), i.e. the QH-46 firewalld-bind
  builtin refusing to bind an interface that does not exist yet.
* 11:36–11:41 — the daemon reports `runtime bootstrap complete` and then sits with NO tunnel
  interface until cleanup stops it. `restrict_recoverable` never actually recovers the dataplane;
  nothing retries the apply.

So `recovery_arrived=false` in run 40 says nothing about client session recovery — the client's
peer had no tunnel. Hypothesis 8 remains OPEN, still neither established nor refuted.

**The defect class (new, introduced with the QH-46 fix on `dda439a2`):** the firewalld zone bind
runs at the tail of `apply_firewall_killswitch` (phase10.rs:2351), which by design runs BEFORE
tunnel interface creation. When the bind runs on a firewalld host and the interface does not exist
yet, the helper's virtual-device guard fails the whole apply, and the daemon parks in
`restrict_recoverable` with no retry. Debian nodes escape because `presence=Absent` short-circuits
before the device check (privileged_helper.rs:1103). The same fedora daemon restarted cleanly at
11:32:04 (21s gap) and fatally at 11:36:02 (2s gap) with identical role state — a race, likely
against interface teardown/creation timing, not a deterministic ordering bug. NOT yet planned or
fixed; needs the PLAN → ADVERSARIAL REVIEW cycle. Also note the separate observations from the
same window: traversal `bundle replay detected` / `signature verification failed`
restrict_recoverable events at 11:33–11:35, and a pre-existing `force_fail_closed failed ...
truncated frame header` spam loop on fedora at 10:31Z.

Triage: recorded against stub `livelab-1786707675-c7eb8a1f00e5::live_network_flap_validation`.

## Run 41 (`qh53-liveproof-20260815a`) — QH-53 LIVE-PROVEN, flap PASSES, QH-51 RESOLVED

39 pass / 1 fail / 19 skipped — the deepest the `--node` cascade has ever reached. Launched on
main at `f2cd7d09` (the QH-53 fix landed and gated).

**`live_network_flap_validation` PASSED for the first time in `--node` history.** From the
stage's own artifact: the peer probe resolved the entry's mesh IP (`100.123.159.114` — the entry
SURVIVED the managed_dns restart, which is the QH-53 fix doing its job live), and
`recovery proven by data crossing the tunnel`, `recovery_arrived=true recovery_time_s=6`.

**QH-51 is thereby resolved, and the answer is the one nobody could see:** the client's session
recovery was NEVER broken — data crosses within 6 seconds of the block lifting once the client's
peer is actually alive. Every historical `recovery_arrived=false` was a broken ENTRY underneath
the probe: first the firewalld FORWARD reject (QH-46), then the restart race that left the entry
tunnel-less (QH-53). Hypothesis 8 (the stage's premise is wrong) is closed alongside hypotheses
1-7: the premise was fine; the instrument was measuring a dead peer.

**The cascade's next defect, exactly as QH-48 predicts:** `live_enrollment_restart_validation`,
reached for the first time, failed with `Permission denied` dialing `debian@192.168.64.105` —
that address is rocky-utm-1 (user `rocky`). The stage's `alias_matching_label` hardcodes
`"debian"` for every non-Windows guest (live_enrollment_restart_validation.rs:135). This is
QH-49's defect class: that fix repaired only the LAN-toggle stage and left `resolve_ssh_user`
private to it. Five stages still hardcode the username (chaos.rs:235, cross_network.rs:1036,
live_enrollment_restart_validation.rs:135, live_anchor.rs:193, live_mixed_topology_validation.rs:158)
— filed as QH-56; fix is the mechanical port of the QH-49 pattern to a shared helper.

## Run 42 (`qh56-enrollment-20260815b`) — QH-56 live-proven; the toggle stage cuts its own branch

39 pass / 2 fail / 18 skipped on main at `2607d294`. **`live_enrollment_restart_validation`
PASSED on its first post-fix run** — the QH-56 wiring is live-proven (the stage dialled
rocky-utm-1 with the inventory username).

The cascade then reached `live_lan_toggle_validation`, which failed and took `cleanup` down with
it. Mechanism, proven live on the wedged client (debian-headless-4):

* The stage issues signed LAN-toggle assignments that move the client's management CIDR to the
  simulated second LAN, `192.168.18.0/24`. The full-tunnel bypass follows the management CIDR:
  policy table 51820 ended up as `default dev rustynet0` + bypass routes for `192.168.18.0/24`
  and the exit peer only. `ip route get 192.168.64.1` → `dev rustynet0 table 51820`: every
  host↔guest packet dove into the tunnel. Guest↔guest kept working (peer-endpoint bypass + mesh),
  which is what made this look like a host-side vmnet wedge at first.
* The stage's own SSH session rides the LAN it toggles away — it died mid-stage
  (`Connection reset by peer`), the toggle-back never ran, and the wrong CIDR PERSISTED in signed
  state across daemon restarts AND a full VM power cycle (generations g3→g7 all re-derived the
  18.x bypass). `cleanup` then timed out against the unreachable client.
* Recovery: `systemctl stop rustynetd` + drop `ip rule` pref 10000 via `utmctl exec` (SSH cannot
  reach a wedged client, by construction). The killswitch nft rules were NOT the blocker —
  `oifname enp0s1 accept` admits replies; the routing bypass was.

Filed as QH-57. The stage needs a design pass (plan + adversarial review): a LAN-toggle that
moves the management CIDR must either keep BOTH LANs in the management set for the transition,
drive the toggle from a path that survives it (utmctl exec, or a peer), or bound the assignment
with an auto-revert the daemon applies when the new LAN never materialises. Do not paper over it
by exempting SSH from the tunnel — that would be a fail-open hole in the exact control the stage
exists to prove.

## Run 44 (`qh61-sudopath-20260816b`) — ZERO FAILURES: 44 pass / 0 fail / 15 skipped

The first zero-failure run in the `--node` engine's recorded history, on main at `5510b726`.

* **`live_lan_toggle_validation` PASSED** — first pass in its 488-row lifetime, live-proving both
  QH-57 (the stage now threads the run's real management CIDRs; the client survived role
  enforcement with SSH intact) and QH-61 (absolute `REMOTE_RUSTYNET_BIN` invocations survive
  Rocky's `/usr/local/bin`-less sudo secure_path).
* **`extended_soak` PASSED on its first-ever execution** — previously unreachable behind the
  lan-toggle cascade.
* Every one of the 15 skips is topology-conditional: mac/win stages need those platforms elected
  into the topology (`--macos-vm` / `--windows-vm` / role-platform selectors), the cross-network
  family needs `live_mixed_topology_validation`, and the anchor/admin/blind_exit cells need those
  roles assigned. Nothing is failure-cascaded.

The Linux live suite on this five-guest topology is, for the first time, fully green end to end.
The remaining frontier is exactly the parity mandate: elect macOS and Windows nodes and drive the
same suite through the mixed and cross-network stages.

## Run 45 (`livelab-1787906534-877a0226693c`) — 2026-08-28: zero failures re-proven; six historical offenders green together

44 pass / 0 fail / 17 skipped on main at `877a0226693c` (branch `work/live-validate2`, clean; ledger
row 186; window 08:21:01Z→08:42:14Z). Topology: ubuntu-utm-1:client, rocky-utm-1:admin,
debian-headless-4:exit, fedora-utm-1:relay, debian-headless-2:anchor; profile `mgmt_shared_smoke_v1`.
This ties the all-time high set by Run 44 — on a larger plan: 61 planned stages (17 skips, up from
15 — the two new `cross_network_substrate_setup`/`teardown` scaffolding stages, both pass). Zero
per-stage flips against the night's baseline `livelab-1787825655-3afd39b18164`; the result is purely
additive. (It was the night's fourth attempt: attempt 1 was refused by the fail-closed stage-triage
gate on an undispositioned stub; attempt 2 `livelab-1787903378-068b29ebc54b` ran but failed at
`bootstrap_hosts` on debian-headless-2 — the one guest its remedy never touched, via a stale
`/etc/default/rustynetd` pinning `RUSTYNET_EGRESS_INTERFACE=rustynet-vx0`; attempt 3 failed
preflight.)

The run's real news (`LiveValidation_2026-08-28.md` §11.3): **six stages that historically failed
are green together for the first time**, each against its recorded remedy — `traffic_test_matrix`
(six null-patch stubs in late July), `live_managed_dns_validation` (four stubs),
`live_network_flap_validation` (six stubs — QH-51's whole subject), `gossip_convergence_validation`
(`gossip_accepted_total=0` on four nodes, run `livelab-1787843764`),
`exit_dns_failclosed_validation` (missing `dig` on lenovo, run `livelab-1787885499`), and
`bootstrap_hosts` (four failures from the stale egress pin, runs `livelab-1787849060` through
`livelab-1787903378`). No new triage stub was opened: nothing failed.

The 17 skips are all declared topology conditionals: blind_exit absent (×3), no second
client/entry/aux (×4), not-every-platform (`live_mixed_topology_validation`), the vxlan-substrate
block (×9), and chaos (opt-in `not_run`). Judged on what this topology can run, the suite is
44 for 44. **The "35 of 36 reachable" headline that opened this document is thereby superseded: the
Linux suite is zero-failure end to end.**

## Run 46 (`livelab-1787908428-6d9224cfd954`) — 2026-08-28: CN-PROOF vxlan — the cross-network scenarios cannot dispatch on this fleet

43 pass / 1 fail / 17 skipped on main at `6d9224cfd954` (branch `work/cn-proof`, clean; ledger row
187; window 08:54:37Z→09:13:47Z). Identical topology to Run 45; the delta is exactly one flag,
`--cross-network-substrate vxlan`. **All 8 CN-3 scenario stages skipped**, every one with the same
verbatim reason: `cross-network topology requires a role that no node in this topology is assigned`
— the relay/probe participants resolve from `entry`+`aux` (cross_network.rs:929-932), and this fleet
has neither. Three structural gates were verified live: the vxlan `plan_overlay` returns `Ok(None)`
on a single-LAN fleet (<2 /24 groups; substrate.rs:754-756, 1529-1532), `entry`/`aux` are absent
from the topology, and `distinct_underlay_prefixes` reads the management SSH /24s
(cross_network.rs:514-520, 944-949) — every guest sits on 192.168.64.0/24, so the scenarios would
skip even with the roles elected.

The one failure is the gate's own defect, CN-PROOF-D1: `cross_network_nat_matrix` failed the run on
matrix evidence the skipped suites never wrote — `run_nat_matrix` lacked the topology guards its
eight siblings share (the validator was right to fail closed; the gating one level up was wrong).
**FIXED on `work/cnproof-d1-gate`**: the guards are now one shared `resolve_dispatchable_topology`
function, so the gate and the suites it grades cannot answer differently about the same topology;
past the guard it still fails closed on genuinely missing evidence. Also recorded: CN-PROOF-D2 —
on this fleet the vxlan flag is a strictly losing trade, since it removes
`cross_network_nat_classification` (netns-only) and adds nothing.

Two standing conclusions (`LiveValidation_2026-08-28.md` §12, and the owner decision now recorded
in `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.6):

* **A skip is not a pass: CN-3 (8 ported validators) and CN-4 remain unproven — 0 of 8 dispatched;
  not one line of the ported validator code has executed on hardware.** CN-2's netns NAT gates ARE
  live-proven for 3 of 5 profiles — by Run 45's `cross_network_nat_classification`, not by this run.
* **Owner decision (spec §0.6): Tier B now REQUIRES a physically 2-LAN fleet as an input rather
  than producing one.** No qualifying topology exists in the current fleet (probed 2026-08-28), so
  every re-run of this topology reproduces this exact result until a fleet or design change lands.

## Run 47 (`livelab-1787911937-77ff1933885f`) — 2026-08-28: macOS anchor elected for the FIRST time — 🔴 blocked, blocker located

19 stages: 15 pass / 1 fail / 3 skipped on main at `77ff1933885f` (clean). Topology:
macos-utm-1:anchor + lenovo-exit-1:exit + lenovo-client-1:client. **First macOS role election in
`--node` history** — the per-OS table's original "macOS: UNPROVEN, stages never appear" row is
thereby superseded — and the cell earned no green:

* The one failure is `validate_baseline_runtime`'s macOS DnsFailclosed check, and it is an HONEST
  red (QH-39): `/etc/resolv.conf` claims loopback while `scutil --dns` reports 1.1.1.1/8.8.8.8 — a
  real macOS DNS fail-closed ENFORCEMENT gap, correctly exposed by the validator.
* `anchor_validation` skipped honestly: the macOS capability advertisement PASSED (the cross-OS
  shell seam works), but the bundle-pull runtime substages (`bundle_pull_loopback`, `invalid_token`,
  `log_redaction`) are gated off by the posture gate at role.rs:68-70 (`Anchor|Admin|Relay` ⇒ Linux
  only) — a gate that is CIRCULAR as written: it lifts only on a green run that the stage it
  controls cannot produce. The promotion route is the macOS-specific anchor validator set
  (`deploy_macos_anchor_profile`, `validate_macos_anchor_bundle_pull`,
  `validate_macos_anchor_port_mapping_authority`; live_lab_stage_registry.rs:1151/1158/1168), which
  requires the `--anchor-platform macos` selector — independent of role election — plus a
  full-suite run (`--skip-linux-live-suite` drops `live_anchor` and all three exit validations).
* QH-40's shutdown-residue marker FIRED CORRECTLY on macOS for the first time — and the check that
  reads it was then found fail-open on macOS (its default state path was the Linux `/var/lib` path).
  **Fixed the same day**: `DEFAULT_STATE_PATH` gained a macOS arm plus a shared
  `daemon::default_state_path()` used by both writer and checker (disposition in
  `QualityHardeningTodo_2026-07-25.md`, QH-40 entry, 2026-08-28).

## Run 48 (`livelab-1787913512-a5e93c8dd781`) — 2026-08-28: macOS exit elected for the FIRST time — 🔴 blocked at membership_init

19 stages: 9 pass / 1 fail / 9 skipped; **the run is recorded dirty, so it is diagnostic only and
cannot count toward any stability claim.** Topology: macos-utm-1:exit + lenovo entry/client via
`--macos-promote-exit`. The election itself worked — preflight passed with exactly one exit, and
bootstrap deployed to all three nodes — then the cell died at `membership_init`:
`membership owner public key not found on remote`. The macOS membership adapter reads the wrong
path (`MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` →
`/usr/local/var/rustynet/membership/membership.owner.key.pub`, macos_install.rs:27-28) AND cats it
without sudo (macos_membership.rs:29-34); the key actually lives at
`/etc/rustynet/membership.owner.key.pub` (present since Jul 9, proving a wrong-path read rather
than a fresh-install seeding gap). **This blocks macOS holding ANY membership-owner role** — the
exit cell fully, blind_exit by the same shape — and no exit-stage evidence exists from any OS-mac
path yet.

Standing constraints for both mac cells (`MacCellsHarvest_2026-08-28.md`): the posture-gate
circularity (Run 47), `--skip-linux-live-suite` dropping four of the five harvest stages, and the
QH-41 vmnet bridge split (macOS sits alone on 192.168.65.0/24; lenovo guests stand in as peers, and
the lenovo→mac direction is 100% loss).

## Windows — 2026-08-28: bootstrap root-caused; fixes landed; no guest reachable (no run executed)

No Windows node has ever been elected, and no run was launched — deliberately. `windows-utm-1`
boots and answers ICMP/SMB, but OpenSSH never listens and RDP/WinRM/QEMU-guest-agent are all
closed, so there is **no remote management path at all**; a run would only fail upstream at SSH
reachability and (pre-W-FIX-3) poison the `windows_stage_bootstrap` column with another spurious
fail. The CP-4 triage verdict (`WindowsNodeBootstrapTriageVerdict_2026-08-28.md`): the `--node`
bootstrap failure is **BOTH code and guest, code primary** — `Bootstrap-RustyNetWindows.ps1:1130`
hard-depends on WinGet **Configuration**, an opt-in per-machine feature that nothing in the
repository ever enabled or precondition-checked, so every fresh guest reproduces the failure. The
headline "5 fails" was in fact 3 bootstrap failures plus 2 upstream preflight skips, across four
distinct causes. Landed 2026-08-28: **W-FIX-1** (the bootstrap now enables the feature itself and
fails closed with a named, actionable error), **W-FIX-2** (the SSH adapter's error seam decodes the
CLIXML that buried the real cause in the ledger for five weeks), **W-FIX-3** (run-scoped `preflight`
failures no longer poison the per-OS `*_stage_bootstrap` columns — forward-only; historical rows
stand as written). Still outstanding: **W-FIX-4** (guest remediation from the UTM console, then the
minimal exit+client topology to produce the first `windows_stage_bootstrap=pass` in `--node`
history) and **W-FIX-5** (restore `ubuntu-kvm-1` — unreachable, and the only home of failure #5 and
the `windows-x86-1` guest). Until W-FIX-4 lands, Windows remains gated at bootstrap and every
Windows cell below it is unreachable.

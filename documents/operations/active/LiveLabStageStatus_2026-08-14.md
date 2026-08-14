# Live-Lab Stage Status — 2026-08-14

**Read this before claiming any stage works.** It states, per OS, what is proven, what is failing,
and what has never been exercised. Every figure comes from a stage's own report artifact, never from
a ledger column (§12.3 explains why the columns lie in both directions).

Latest run: `qh46-firewalld-20260814c` → `qh51-keepalive-applied-20260814i`
(`artifacts/live_lab/`). Topology: 5 nodes, **all Linux**.

---

## The one-line answer

**Linux: 35 of 36 reachable stages pass. macOS and Windows: NOT EXERCISED AT ALL.**

The headline number (35/59) is a **Linux-only** result. It says nothing about cross-platform parity,
which remains the larger release blocker per
`CrossPlatformRoleParityPlan_2026-06-21.md`.

---

## Per-OS status

| OS | Nodes in topology | Stages run | Status |
| --- | --- | --- | --- |
| **Linux** | 5 (Debian 13 ×2, Fedora 44, Rocky 10.2, Ubuntu 26.04) | 36 reachable | **35 pass / 1 fail** |
| **macOS** | **0** | **0** | **UNPROVEN — not in topology, stages never appear** |
| **Windows** | **0** | **0** | **UNPROVEN — not in topology, stages never appear** |

The macOS and Windows stages are **not among the 23 skips**. They are absent entirely, because no
node of that platform was elected. Do not read "23 skipped" as covering them.

### The 23 Linux skips

| Cause | Count | Meaning |
| --- | --- | --- |
| Cascade from the single failure | ~19 | Never ran. Blocked downstream of `live_network_flap_validation`; `live_mixed_topology_validation` alone gates 13 (all `cross_network_*` + `live_anchor`). |
| Role not elected | 4 | `blind_exit` (×2), `anchor`, `admin` — no node in this topology holds them. Not defects; needs a topology that elects them. |

Fixing the one failure should unblock ~19 stages, taking Linux to roughly 54/59.

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

### Cross-platform — the larger blocker, untouched

`CrossPlatformRoleParityPlan_2026-06-21.md` requires every role live-proven on **macOS AND Windows**,
not just Linux. Nothing in this session addressed that. Specifically open:

* **macOS/Windows stages have never run in this topology** — elect nodes of those platforms to find
  out where they stand.
* **`userspace_shared_macos` may need the QH-51c/d fixes mirrored.** The session-rebuild and roaming
  fixes landed in `userspace_shared`; macOS has its own variant. NOT checked — do this before
  assuming macOS benefits from tonight's work.
* **QH-46's Windows analogue is unexamined.** firewalld is RHEL-specific, but the defect CLASS —
  a foreign filter at the same hook silently discarding traffic we authorised — has an obvious
  Windows counterpart in WFP filter weights. Nobody has looked.

### Also open (filed, not fixed)

* **QH-47** — nothing flushes conntrack when NAT rules change; affects any node gaining an exit/relay
  role while traffic flows.
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

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

**Leading remaining hypothesis (UNVERIFIED): the metric is PACED, not dead.** `traversal_probe_due`
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

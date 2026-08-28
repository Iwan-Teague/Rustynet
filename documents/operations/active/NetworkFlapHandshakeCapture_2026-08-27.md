# QH-51 Network-Flap Handshake Capture — 2026-08-27/28

**Task:** QH-51-CAPTURE. The ledger (`QualityHardeningTodo_2026-07-25.md`, QH-51) ordered a
measurement, not another fix: after a 35s WireGuard-UDP egress block is lifted on the client,
recovery was never observed within the stage's poll window across the 2026-08-14 run series, and
two predicted-fix hypotheses were falsified on live runs. This document records the capture
design (written before measurement), the evidence taken on live lab guests, and the verdict.

**VERDICT: NON-REPRODUCTION on current main (`4b0d18aa`) — the tunnel recovers in 8 seconds,
every time, on BOTH Linux backends, and the packet captures show exactly how.** 4/4 flap cycles
passed the fixed harness with `recovery_time_s=8`: three on `linux-wireguard` (kernel), one on
`linux-wireguard-userspace-shared`. Details and the recovery mechanism in §5.

## 1. Ledger claims re-verified against current code (pre-capture)

The ledger's QH-51 entry was written against the pre-QH-04 daemon and is stale in three
load-bearing places. Verified against worktree `work/qh51-flap-capture` (base `4b0d18aa`,
current main):

1. **"The flap breaker gates only the quality re-race at daemon.rs:6885" — NO LONGER TRUE.**
   In `sync_traversal_runtime_state_detailed` (daemon.rs:6884-6901) the FIS-0010 breaker consult
   now ANDs against the WHOLE `traversal_probe_due` result: while a peer's breaker is open the
   direct re-race is withheld entirely (relay retained), unless `force_reprobe` or a pending
   quality reprobe bypasses it. Note `traversal_flap_breaker` defaults to `false`
   (daemon.rs:1958) and no breaker transition was logged on any capture run.
2. **"The metric only refreshes when a probe actually runs" — NO LONGER TRUE.**
   Every sync pass reads `controller.managed_peer_latest_handshake_unix(&peer)` directly from
   the backend (daemon.rs:6857, 6945) and folds it into the retained status even when
   `probe_due` is false (daemon.rs:6990). The captures confirm it live: the client's
   `traversal_probe_latest_handshake_unix` advanced within one 5s sample of the on-wire
   handshake in every repetition (§5).
3. **The harness oracle changed (commits e64a5747, 2df86b99, 9a816ed0).**
   `live_linux_network_flap_test.rs` now proves disruption AND recovery by DATA CROSSING (ping
   of the client's own peer's mesh address), because a 35s block is shorter than WireGuard's
   ~120s rekey — a correct recovery may legitimately produce no new handshake. The phantom
   `ops verify-membership` verb is fixed (HARNESS-VERBS), so `membership_intact` is now a real
   check and it passed on every run.

## 2. Capture design (written before measurement)

**Reproduction:** the fixed harness `live_linux_network_flap_test` (built from current main in
this worktree), driven from the controller Mac against a two-node lab: `lenovo-client-1`
(client, 192.168.0.30) and `lenovo-exit-1` (exit = the client's direct WG peer, 192.168.0.31),
mesh brought up by the Rust `--node` orchestrator (`--setup-only`). The harness blocks client
egress `udp dport 51820` via nft for 35s, removes the rule, then polls up to 180s for recovery.

**Recorded on each side for the whole run (baseline → block → unblock → poll end):**

- `tcpdump -U -i eth0 -w <pcap> "udp port 51820 or udp port 51821"` on BOTH guests (`-U` after
  rep 1-2 lost their tails to write buffering).
- A 5s state sampler on BOTH guests: unix ts + `rustynet netcheck` fields
  `traversal_probe_result/reason/attempts/endpoint/latest_handshake_unix/next_reprobe_unix`,
  `path_mode`, `path_live_proven`, `path_latest_live_handshake_unix`,
  `transport_socket_identity_state` — the exact tuple the ledger's "capture that settles it"
  section demanded.
- `journalctl -u rustynetd -f -o short-unix` on both guests (breaker transitions print with
  intensity at daemon.rs:7086; none occurred).
- Clocks: guests are on the same LAN/NTP; every sampler line carries the guest's own epoch
  seconds; pcap timestamps are kernel timestamps on the same hosts.

**Discriminators** (what each outcome would have meant):

| Observation after unblock | Verdict |
| --- | --- |
| Client emits no WG datagrams at all | Daemon never re-initiates (breaker/timer defect) |
| Client sends, exit never receives | Block residue / route defect |
| Exit receives, never answers | Peer-side session/daemon defect |
| Exit answers a stale endpoint | Endpoint-churn class |
| WG flows but ping fails | Inner routing/allowed-ips defect |
| WG flows and ping succeeds | Non-reproduction — record precisely |

The last row is what every repetition produced.

## 3. Environment and runs

- Controller: macOS host, worktree `work/qh51-flap-capture` at `4b0d18aa` (current main,
  includes QH-04 reconcile fix and the HARNESS-VERBS harness fix).
- Guests: `lenovo-client-1` (debian@192.168.0.30), `lenovo-exit-1` (debian@192.168.0.31),
  bridged LAN guests on libvirt host `lenovo-bot`; daemons built from the same commit ON the
  guests by the orchestrator's bootstrap.
- Mesh bring-up: `ops vm-lab-orchestrate-live-lab --node lenovo-client-1:client --node
  lenovo-exit-1:exit --setup-only --skip-gates`, report dir
  `artifacts/live_lab/qh51-capture-20260828e/` (all 15 setup stages pass).
- Flap cycles (all artifacts under `artifacts/live_lab/qh51-capture-20260828e/`, raw captures
  under `captures/`):

| rep | backend | baseline_age_s | disruption | recovery | recovery_time_s | harness |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | linux-wireguard | 102 | confirmed | **yes** | **8** | PASS (`flap_rep1_report.json`) |
| 2 | linux-wireguard | 55 | confirmed | **yes** | **8** | PASS (`flap_rep2_report.json`) |
| 3 | linux-wireguard | 98 | confirmed | **yes** | **8** | PASS (`flap_rep3_report.json`) |
| 4 | linux-wireguard-userspace-shared | 0 | confirmed | **yes** | **8** | PASS (`flap_rep4_userspace_report.json`) |

Rep 4 exists because the 2026-08-14 failing series ran on the userspace backend (the ledger's
telemetry chain was isolated to `userspace_shared`); the non-reproduction holds there too.
Reps 1-2 pcaps lost their post-block tails to tcpdump write buffering (kept for the pre-block
baseline); reps 3-4 used `-U` and captured the full window.

## 4. Packet evidence (rep 3, kernel backend — rep 4 shows the same shape)

Client-side pcap `captures/qh51_rep3_lenovo-client-1.pcap`, times UTC+1, block up ≈07:13:57Z,
lifted ≈07:14:32Z (35s), all packets 192.168.0.30:51820 ↔ 192.168.0.31:51820:

```
(pre-block)   240B probe/gossip both ways every ~30s; 32B WG keepalives from client
07:14:00.796  exit → client  148B   WG handshake INITIATION  ─┐ exit re-initiates ~every 5.4s
07:14:05.983  exit → client  148B                             │ for the whole blackout; the
07:14:11.359  exit → client  148B                             │ client's replies are dropped
   ...        (6 more initiations)                            ┘ by its own egress rule
07:14:32.607  exit → client  148B   initiation (first after unblock)
07:14:32.608  client → exit   92B   handshake RESPONSE — egress now open, 1.4ms later
07:14:32.610  exit → client   32B   keepalive: session live
07:14:39-40   128B data both ways   = the harness's recovery ping crossing the tunnel
```

State sampler on the client across the same window (`captures/qh51_rep3_state_client.log`):
`traversal_probe_latest_handshake_unix` froze at `1787901120` during the block, then flipped to
`1787901272` — the epoch second of the on-wire handshake response — within one 5s sample, with
`path_live_proven=true` on the same line. Journals on both guests over the window contain only
routine gossip mint/accept and signed-state refresh lines: **no flap-breaker transition, no
restrict, no reconcile failure**.

Rep 4 (userspace) is the same story with more aggressive re-initiation (exit sends paired 148B
initiations ~every 5.4s), first post-unblock initiation answered in 6ms, recovery ping at +7s.
The userspace daemon's handshake stamp also refreshed continuously (sampler shows the stamp
advancing every few seconds even mid-block, because the exit→client half of handshakes still
completes — only client egress was blocked).

## 5. Verdict

**The handshake DOES return on current main; the QH-51 failure signature no longer exists.**
Where the 2026-08-14 series saw `recovery_arrived=false` for 180s, current code recovers in 8s,
4/4 repetitions, both backends. Mechanism, packet-proven: WireGuard's peer-side retransmission
keeps sending handshake initiations right through the blackout; the moment the client's egress
opens, the next initiation completes (ms), and data crosses seconds later. The daemon needs to
do nothing special — and its telemetry now reflects reality because the QH-04-era reconcile
reads the backend handshake stamp every pass instead of only on probe runs.

What changed since the failing series (any or all are sufficient to explain it):
1. the recovery ORACLE was wrong and was fixed — a 35s block needs no new handshake, so the old
   stamp-based assertion could not see a correct recovery (hypothesis 8 in the harness header);
2. the QH-04 reconcile rework — handshake evidence is read from the backend every sync pass, so
   the stamp the stage samples can no longer stay frozen while the tunnel is healthy;
3. the HARNESS-VERBS fix — `membership_intact` previously always read `fail` on runs whose
   other checks passed, poisoning `overall_status`.

**Concrete next step for QH-51: close it.** The remaining work is bookkeeping, not engineering:
the ledger entry should record this capture as the closing evidence. If a regression guard is
wanted, the flap stage is already in the T2 resilience tier and now passes; no assertion was
widened (the recovery check is stricter than before — data must cross).

### Operational findings made in passing (lab, not QH-51)

- **Stale `/etc/default/rustynetd` bricks re-bootstrap** (root-caused live): a prior
  cross-network run bakes `RUSTYNET_EGRESS_INTERFACE=rustynet-vx0`; `cleanup_hosts` never
  removes the file; `resolve_egress_interface` (ops_install_systemd.rs) prefers `existing_env`
  over live detection; every later same-network bootstrap fails with "egress interface does not
  exist: rustynet-vx0". Two runs failed on this before the file was removed by hand
  (triage stubs `livelab-1787870225-…` and `livelab-1787884299-…::bootstrap_hosts`, both
  dispositioned in `live_lab_stage_triage.jsonl`). Follow-up task spawned.
- **`--stop-after-ready` is a dead flag in the Rust `--node` engine**: parsed
  (main.rs:4454) and validated (vm_lab/mod.rs:1309) but consumed nowhere — a "ready" run
  proceeds through the full validation suite and final cleanup tears the mesh down.
  `--setup-only` is the verb that actually leaves a live mesh.
- `exit_dns_failclosed_validation` requires `dig` on the guest; the lenovo guests lacked
  `dnsutils` (installed now; stub `livelab-1787885499-…` dispositioned).
- Guests restored to `RUSTYNET_BACKEND=linux-wireguard` and capture temp files removed.

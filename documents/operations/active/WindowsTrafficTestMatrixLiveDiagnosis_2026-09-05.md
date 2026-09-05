# Windows `traffic_test_matrix` — live diagnosis of the WireGuard handshake failure

- Status: **ACTIVE investigation, root cause NOT yet confirmed.** This is live-lab
  evidence gathered by direct guest inspection during `run-2026-09-05-windows-16-setuponly`
  (commit `89596acd78a6d74d290e34d4496c80961292c770`), not a static code trace. No code
  was changed. Several plausible causes have been ruled out with hard evidence; the
  actual mechanism is still open.
- Date: 2026-09-05
- Topology: `linux-x86-client-1` (client), `linux-x86-exit-1` (exit),
  `windows-x86-1` (client) — all on one libvirt LAN, `192.168.121.0/24`, on
  `ubuntu-kvm-1`.

## 1) The symptom

After `70e16a63` (collect_pubkeys fix) and `3f7fc8d3` (enforce_baseline_runtime /
tunnel-interface-admit ordering fix) landed, `bootstrap_hosts` through
`validate_baseline_runtime` all pass cleanly on `windows-x86-1` for the first time
(run `run-2026-09-05-windows-11`, 46/0/0). The very next stage, `traffic_test_matrix`,
fails with **100% bidirectional packet loss** between `windows-x86-1` and both Linux
nodes — reproduced identically across three separate runs
(`run-2026-09-05-windows-12-full`, `-14-artifacts`, and confirmed again live in this
investigation). `default-deny` checks come back `INCONCLUSIVE` because no mesh peer
was reachable at all, so the negative control can't be attributed to policy.

## 2) Daemon-level evidence: the handshake never completes

Queried `rustynet status` on both ends while the mesh from a **passing**
`--setup-only` run (`run-2026-09-05-windows-16-setuponly`) was still live (no
`--stop-after-ready` — that flag was tried first and found NOT to leave the guest
state up: `--setup-only` on a **passing** run does, per
`orchestrator/native.rs:934-940`'s comment: "setup-only success intentionally
leaves the mesh up for a later run-only pass"):

- **`linux-x86-client-1`**: `path_programmed_peer_count=2 path_live_peer_count=1
  path_live_direct_peers=1 path_latest_live_handshake_unix=1788580038`. One of its
  two configured peers (the other Linux node, `linux-x86-exit-1`) is live; the
  Windows peer is not.
- **`windows-x86-1`**: `path_programmed_peer_count=2 path_live_peer_count=0
  path_live_direct_peers=0 path_latest_live_handshake_unix=none
  path_reason=direct_handshake_unproven traversal_probe_attempts=0
  transport_socket_identity_state=blocked_backend_opaque_socket`. **Zero** live
  peers — neither the Linux client nor the Linux exit node. The
  `transport_socket_identity_state` field documents *why* Windows cannot run its own
  STUN/traversal probing (WireGuard-NT is a command-only adapter with no
  packet-I/O handle the daemon can use as an authoritative transport — by design, not
  a bug), but this instrumentation gap is orthogonal to the actual protocol
  handshake, which is owned entirely by the WireGuard-NT driver once peer config is
  pushed.

## 3) Driver-level evidence: `wg.exe show` (WireGuard-NT, unlike Linux's in-process
   boringtun, DOES expose the real driver state)

```
rustynet0  <local-pub>  <local-priv>  51820  off
rustynet0  8iYQ...=(linux-client pub)  (none)  192.168.121.137:51820  100.104.224.119/32  0  0  4144  25
rustynet0  Wb9I...=(linux-exit pub)    (none)  192.168.121.26:51820   0.0.0.0/0,100.75.31.80/32  0  0  4588  25
```

Format is `iface peer psk endpoint allowed-ips latest-handshake rx tx keepalive`.
**Both peers: latest-handshake=0 (never), rx=0, tx>0 (4144/4588 bytes, growing over
time as retries continue).** Windows is sending handshake-initiation retries to both
peers and receiving nothing back from either, symmetrically. This — not a
Windows-vs-a-specific-peer asymmetry — rules out a peer-specific config error (wrong
pubkey/endpoint for one side); both peer configs are correct (endpoint, pubkey,
allowed-ips all match the signed assignment bundle, cross-checked against
`linux-x86-client-1`'s own `rustynetd.assignment` file).

## 4) Firewall-level evidence: WFP is NOT the blocker

- `windows_firewall_allow_wg_handshake_args` (`phase10.rs:9177`) only creates an
  **outbound** allow rule for UDP 51820 (`RustyNetKS-AllowEgress`, `dir=out`). No
  explicit **inbound** allow rule for UDP 51820 exists anywhere in the ~750 firewall
  rules dumped from the live guest (`netsh advfirewall firewall show rule name=all`).
  However, the global profile policy set by `windows_firewall_block_outbound_policy_args`
  (`phase10.rs:9109`) is `allowinbound,blockoutbound` — inbound is allowed by
  default policy, and no rule blocks UDP 51820 inbound specifically, so an explicit
  inbound rule should not, in theory, be required.
- The native WFP tunnel-permit filter added by `apply_tunnel_interface_admit`
  (today's fix, `3f7fc8d3`) is scoped to the `rustynet0` interface's LUID
  (`apply_wfp_tunnel_permit`, `rustynet-windows-native/src/lib.rs`). The actual
  WireGuard UDP handshake traffic travels over the **physical** `Ethernet` adapter
  (WireGuard-NT's transport socket binds the underlay, not the tunnel interface
  itself), so this filter is **structurally unrelated** to the symptom — it cannot be
  the cause, confirmed by re-reading exactly what interface it scopes to.
- **Enabled WFP audit** (`auditpol /set /subcategory:"Filtering Platform Packet Drop"
  /success:enable /failure:enable`, plus `"Filtering Platform Connection"`) live on
  the guest and waited through multiple WireGuard retry/keepalive cycles (keepalive
  interval is 25s per the `wg show` dump). **Zero** 5152/5157/5150/5151 events were
  logged referencing port 51820, or at all. If WFP were dropping these packets, this
  audit configuration would have caught it. This is fairly strong evidence WFP is not
  the layer discarding the traffic.

## 5) Wire-level evidence: the packets ARE arriving, bidirectionally

Used `pktmon` (Windows' built-in ETW-based packet monitor, operates below the
firewall at the NDIS layer) filtered to port 51820, running through several retry
cycles:

```
[Rx] 192.168.121.137.51820 > 192.168.121.108.51820: UDP, length 148   (repeated, both peers)
[Rx] 192.168.121.26.51820  > 192.168.121.108.51820: UDP, length 148
[Tx] 192.168.121.108.51820 > 192.168.121.137.51820: UDP, length 148
[Tx] 192.168.121.108.51820 > 192.168.121.26.51820:  UDP, length 148
```

Both **Rx** (packets arriving from both Linux peers) and **Tx** (Windows replying)
are clearly present at the physical-adapter/NDIS level, on a roughly 2-5 second cycle
— i.e. this is **not** a case of packets never leaving the wire or never arriving at
Windows' NIC. The mismatch is stark: raw Ethernet/UDP capture shows healthy
bidirectional traffic, while WireGuard-NT's own driver state (`wg show`, §3) shows
zero bytes ever received. **Something between the physical NIC and the WireGuard-NT
driver's own packet processing is where the traffic is being lost — not the
firewall, and not the wire.**

Note: 148 bytes matches the WireGuard `handshake_initiation` message size exactly
(the fixed-size message type). Both directions showing the same 148-byte length is
circumstantial evidence that BOTH ends may be perpetually sending fresh
**initiations** rather than the smaller (92-byte) **response** message — i.e. this
may not just be "packets lost after arrival" but possibly a protocol-level
never-completes-a-round-trip symmetry, though this was not confirmed by decrypting
or fully parsing the captured payloads (out of scope for a live-guest, non-destructive
investigation).

## 6) Ruled out: simple NDIS/HNS binding conflict

This guest has Hyper-V + nested virtualization enabled deliberately, for the
`windows-x86-1` WinNAT/exit-role testing track (per the inventory notes: "nested virt
(Hyper-V) works so WinNAT/exit-role is capable"). `Get-NetAdapterBinding -Name
Ethernet` shows two active NDIS filter drivers bound to the physical adapter that are
part of Windows' container/HNS networking stack: `ms_l1vhlwf` (Nested Network
Virtualization) and `ms_l2bridge` (Bridge Driver) — both `Enabled: True`. (The
`Hyper-V Extensible Virtual Switch`, `vms_pp`, is present but `Enabled: False` on
this adapter — not the culprit by itself.) The earlier firewall-rule dump also shows
"HNS Container Networking" rules, confirming HNS is active on this guest.

This looked like an extremely plausible mechanism (an L2 bridge driver on the
physical NIC diverting inbound traffic before it reaches the IP stack), so it was
tested directly: `Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_l2bridge`,
waited through a retry cycle, re-checked `wg show`. **Result: no change** — tx grew
(more retries happened) but rx stayed 0 and `Test-Connection` to the Linux client
still failed. The binding was re-enabled afterward to restore the guest to its
original state. **This specific mechanism is ruled out** as the (sole) cause,
though HNS/nested-virt remains circumstantially suspicious as *a* contributing
factor in this specific guest's networking stack, given no other Windows guest has
ever reached this test before today.

## 7) What is NOT yet known

- Whether a non-Hyper-V-enabled Windows guest (no nested virtualization, no HNS)
  would reproduce the same symptom — this would be the single most decisive next
  experiment, since it would confirm or fully rule out "nested-virt/HNS guest
  environment" as the root cause versus a genuine WireGuard-NT/rustynet defect that
  would reproduce anywhere.
- Whether the packets pktmon captured as "arriving" are byte-for-byte identical to
  what Linux sent (not confirmed — only the UDP 5-tuple and length were inspected,
  not decrypted/parsed payload content).
- Whether WireGuard-NT's own internal driver-level logging (accessible via
  `Get-WinEvent` against the `WireGuard` ETW provider, or the `wireguard.exe /log`
  facility from the official WireGuard for Windows client, if installed) would show
  a specific rejection reason (bad MAC, cookie-reply-only due to rate limiting,
  timestamp/replay rejection, wrong interface index, etc.) — not yet queried.
- Whether the problem is symmetric (does `linux-x86-client-1` also show tx>0/rx=0
  specifically for its Windows peer, matching Windows' zero-live-peer report) — not
  directly measurable from Linux, since its userspace-shared boringtun backend has
  no UAPI control socket for `wg show` to query (`wg show all dump` exits 0 with
  no output on that backend). Would need the daemon's own per-peer status detail
  (not currently exposed by the `Status` IPC beyond the aggregate `path_live_*`
  counters) or a `tcpdump`/packet capture on the Linux side for the same 5-tuple.

## 8) Ranked hypotheses for the next investigation session

Checked first and ruled out while writing this document: `wg show <iface> dump`'s
interface line format is `<iface> <private-key> <public-key> <listen-port> <fwmark>`
(per `wg(8)`) — so of the two 44-char base64 values on that line in §3
(`GLO5r6ukZq/...` then `TamZKyk5/...`), the **second** is the public key. It matches
`rustynet status`'s `local_wg_public_key=TamZKyk5/RkKERQ3ipZXJ/fnjQC3yjCKXa+paclhUxk=`
exactly. **No local-key mismatch** — that lead is closed, not open.

1. **Guest-specific nested-virtualization/HNS networking-stack interaction**
   (highest remaining suspicion, though the specific `ms_l2bridge` mechanism is now
   ruled out per §6). Test: reproduce on a Windows guest with Hyper-V/Containers
   features NOT installed, or temporarily disable Hyper-V entirely
   (`Disable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All`,
   `-Containers`, requires reboot) on a scratch copy of this guest and re-run
   `traffic_test_matrix`. This remains the single highest-leverage experiment: it
   would either confirm environment-specific and redirect the WinNAT/exit-role
   testing to accept the Hyper-V dependency as mutually exclusive with the
   client-role mesh test on the same guest, or fully clear nested-virt as a factor.
2. **WireGuard-NT driver-level rejection** (cookie/MAC/replay/rate-limit) that
   silently discards otherwise-valid-looking packets without incrementing rx —
   query the driver's own diagnostic surface if one exists (WireGuard-NT ships an
   ETW provider; `Get-WinEvent -ListProvider "*WireGuard*"` was not yet tried); compare
   packet payload bytes between what Linux sent and what pktmon captured arriving at
   Windows (are they byte-identical, or corrupted/truncated somewhere in the
   nested-virt NIC emulation path? pktmon's `-p` filter only matched on port; a
   payload-level `format` diff was not performed).
3. **A genuine rustynet peer-config defect specific to the Windows WireGuard-NT
   config-push path** that WireGuard-NT accepts syntactically (shows up correctly in
   `wg show`: endpoint/pubkey/allowed-ips all correct) but that is cryptographically
   wrong in a way `wg show` can't surface — e.g. the PEER's public key as configured
   on Windows doesn't match what that peer's actual private key would produce (a
   stale/rotated key never re-pushed). Check by comparing the peer pubkeys
   `wg.exe show` lists on Windows against each Linux node's own
   `local_wg_public_key` from ITS `rustynet status` — not yet cross-checked in this
   document.
4. Symmetry check from the Linux side: does `linux-x86-client-1` (or
   `linux-x86-exit-1`) show tx>0/rx=0 specifically for ITS Windows peer (matching
   Windows' zero-live-peer report), via a `tcpdump` capture on Linux for the same
   5-tuple — not yet performed (§7 also flags this as unmeasured).

## 9) Non-destructive, reversible actions taken during this investigation

All reverted before concluding: enabled then disabled WFP audit policy
(`Filtering Platform Packet Drop`, `Filtering Platform Connection`); disabled then
re-enabled the `ms_l2bridge` NIC binding; ran and cleaned up a `pktmon` capture
(filter removed, temp `.etl`/`.txt` files deleted). No orchestrator-tracked state was
touched; this was pure guest-side read/diagnostic work between two orchestrator runs.

## 10) Evidence index

- Fixed ordering bug (today, prerequisite for reaching this stage at all):
  `phase10.rs:611-629` (trait), `:6268-6341` (Windows apply split), `:7278-7304`
  (call site in `apply_dataplane_generation`).
- Transport-socket-identity Windows gap (pre-existing, orthogonal to this symptom):
  `daemon.rs:7045-7047` (`blocked_backend_opaque_socket`), IPC status format
  `daemon.rs:9259` (`transport_socket_identity_state` field).
- Windows firewall rule builders: `phase10.rs:9109` (block-outbound policy),
  `:9140-9171` (SSH reply/out — the `dir=out`-for-inbound-initiated-flow pattern),
  `:9177-9189` (WG handshake outbound-only allow), `:5658-5690`
  (`apply_windows_scoped_egress_allows`, the caller).
- `--setup-only` leaves a passing mesh up: `orchestrator/native.rs:934-940`.
- `--stop-after-ready` does NOT preserve guest state on failure or (as tested) in
  general for this purpose — superseded by `--setup-only` for live-inspection intent.
- Companion docs: `WindowsCollectPubkeysEmptyReadAnalysis_2026-09-04.md`,
  `WindowsMembershipInitPostPubkeysAnalysis_2026-09-05.md`,
  `WindowsPostEnforceRuntimeLiveStagesAnalysis_2026-09-05.md`.

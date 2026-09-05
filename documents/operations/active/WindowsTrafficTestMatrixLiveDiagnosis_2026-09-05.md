# Windows `traffic_test_matrix` — live diagnosis of the WireGuard handshake failure

- Status: **ROOT CAUSE CLASS CONFIRMED (exact mechanism not yet pinned).** This is
  live-lab evidence gathered by direct guest inspection during
  `run-2026-09-05-windows-16-setuponly` (commit `89596acd78a6d74d290e34d4496c80961292c770`),
  not a static code trace. No code was changed. §11 (added after §1-10 below were
  first written) confirms the failure is a **stale WireGuard public key** distributed
  to peers: WireGuard-NT's own diagnostic log shows "Invalid MAC of handshake" — a
  cryptographic MAC1 rejection that occurs exactly when the sender computed the
  handshake MAC against a public key that does not match the responder's actual
  current key — and direct comparison confirms Windows' real running public key does
  NOT match what Linux's signed assignment bundle has on file for it. What is not yet
  pinned down is the *exact* code path that lets a stale key reach the bundle; §11
  lays out the strongest hypothesis and the concrete next check.
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

## 7) What is NOT yet known (superseded — see §11 for the confirmed mechanism class)

**§11 (added after this section was written) confirms the root cause class**: a
stale public key reached the distributed assignment bundle. The items below were the
open questions *before* that check; kept for the investigation record, but do not
start from here — start from §11.3's "concrete next check."

- ~~Whether a non-Hyper-V-enabled Windows guest ... would reproduce the same
  symptom~~ — likely moot: §11 gives a mechanism (stale key distribution) that has
  nothing to do with Hyper-V/HNS. Not worth spending the reboot-and-rebuild cost on
  this experiment until §11.3's check rules the stale-key mechanism back out.
- ~~Whether the packets pktmon captured are byte-for-byte identical to what Linux
  sent~~ — moot: §11.1 explains the 148-byte-both-directions observation without
  needing payload comparison (every packet is a fresh Initiation because no MAC ever
  validates).
- ~~Whether WireGuard-NT's own internal driver-level logging ... would show a
  specific rejection reason~~ — **answered in §11.1**: "Invalid MAC of handshake."
- Whether the problem is symmetric (does `linux-x86-client-1` also show tx>0/rx=0
  specifically for its Windows peer) — **still open**, and less important now that
  §11.2 found the mismatch directly (comparing the bundle's recorded key against
  Windows' actual key, rather than needing Linux's own tx/rx counters).

## 8) Ranked hypotheses (historical — see §11.3 for the current best-supported hypotheses)

This section predates §11's discovery of the actual "Invalid MAC" log line and the
confirmed key mismatch; kept for the investigation record. **Use §11.3's two
candidates instead of the list below when picking up this investigation.**

Checked first and ruled out while writing this document (still valid — this is a
narrower, different check than §11.2's cross-artifact comparison): `wg show <iface>
dump`'s interface line format is `<iface> <private-key> <public-key> <listen-port>
<fwmark>` (per `wg(8)`) — so of the two 44-char base64 values on that line in §3
(`GLO5r6ukZq/...` then `TamZKyk5/...`), the **second** is the public key. It matches
`rustynet status`'s `local_wg_public_key=TamZKyk5/RkKERQ3ipZXJ/fnjQC3yjCKXa+paclhUxk=`
exactly — i.e. `wg show`'s own two fields are internally consistent with each other
and with the daemon's self-report. **The mismatch §11.2 later found is a different
comparison**: that self-consistent key against what Linux's *bundle* has on file,
which is a genuinely different (older) value.

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

## 11) BREAKTHROUGH — the actual WireGuard-NT driver log confirms a stale distributed public key

Everything in §1-10 above was written believing the mechanism was still open. Two
further live-guest checks (both non-destructive, read-only) resolved it almost
completely.

### 11.1 `wireguard.exe /dumplog` — the official WireGuard client binary's own ring-buffer log

Windows' WireGuard-NT tunnel is actually run as a **separate Windows service**
(confirmed via `Get-WinEvent` System log, event ID 7045: "Service Name: WireGuard
Tunnel: rustynet0", "Service File Name: \"C:\Program Files\WireGuard\wireguard.exe\"
/tunnelservice C:\ProgramData\RustyNet\config\rustynet0.conf.dpapi"). The same
`wireguard.exe` binary supports `/dumplog`, which dumps its internal diagnostic ring
buffer — not exposed anywhere in `rustynetd`'s own logs or IPC status, and not tried
until this check:

```
2026-09-05 04:23:26.170384: [TUN] [rustynet0] Invalid MAC of handshake, dropping packet from 192.168.121.137:51820
2026-09-05 04:23:26.893294: [TUN] [rustynet0] Invalid MAC of handshake, dropping packet from 192.168.121.137:51820
2026-09-05 04:23:27.534264: [TUN] [rustynet0] Handshake for peer 1 (192.168.121.137:51820) did not complete after 5 seconds, retrying (try 5)
2026-09-05 04:23:27.534264: [TUN] [rustynet0] Sending handshake initiation to peer 1 (192.168.121.137:51820)
... (repeats for peer 2, 192.168.121.26:51820, identically)
```

**"Invalid MAC of handshake" is a cryptographic verdict, not a networking one.**
WireGuard's `mac1` field on every handshake message is computed by the *sender* as
`MAC(HASH(LABEL_MAC1 || responder's-static-public-key), message)`. The responder
recomputes the same MAC using *its own* static public key and rejects the packet if
they disagree. **This specific rejection reason only occurs when the sender's copy
of the responder's public key does not match the responder's actual key** — every
other failure mode (firewall drop, NAT, wrong endpoint, network partition) would
produce a *different* observable (no packet at all, a different rejection, or no log
line whatsoever), not this one. This also fully explains §5's observation that every
captured packet was 148 bytes (an Initiation): since Windows never validates any
incoming packet as a legitimate Response, it can never advance past retransmitting
its own Initiations — there is no protocol-level round-trip ambiguity left to
consider.

### 11.2 Direct key comparison — confirmed mismatch, both peers, not a display artifact

Compared byte-for-byte (via a Python one-liner, not eyeballing base64):

- Windows' **actual, currently-loaded** public key, from `wg.exe show all dump`'s
  interface line (`<iface> <private-key> <public-key> <port> <fwmark>` per `wg(8)` —
  the **third** field, verified against `rustynet status`'s `local_wg_public_key`,
  which agrees exactly): base64 `TamZKyk5/RkKERQ3ipZXJ/fnjQC3yjCKXa+paclhUxk=` = hex
  `4da9992b2939fd190a1114378a965727f7e78d00b7ca308a5dafa969c9615319`... — 32 bytes,
  64 hex chars, confirmed via `len()`.
- **What `linux-x86-client-1`'s own signed assignment bundle has on file** for
  `windows-x86-1-bootstrap` (`sudo cat /var/lib/rustynet/rustynetd.assignment` on the
  live guest, same run): `peer.1.public_key_hex=`
  `70ccfa5870a9b4ed95f071515ec7e4184e6dc39a9921460f9ac1f19504b99961`.
- **These do not match.** Confirmed programmatically (`==` on the two hex strings),
  not a copy/paste or field-order error.
- Ruled out as a trivial swap: `70ccfa58...` does not match `linux-x86-client-1`'s own
  key (`8iYQMU7bXMQ9cDOEJ+5LtJ5//km0atZdn26IPlKeQyk=`) or `linux-x86-exit-1`'s own key
  (`Wb9I+uSl0czaZVQwGDhxhwk7xBM7bXB6oZ4j14LLTkI=`) either — it is not a simple
  cross-node index mixup within the same bundle.

### 11.3 The timing anomaly that points at the mechanism

`/var/lib/rustynet/rustynetd.assignment` on `linux-x86-client-1` has mtime
`1788579921` (2026-09-05 03:45:21 UTC). `windows-x86-1`'s `rustynetd.log` contains
exactly **one** `"rustynetd startup: run_daemon entered"` line, at `1788579952375`ms
(03:45:52.375 UTC) — **31 seconds AFTER** the assignment bundle was already written
to disk on Linux. The bundle that names Windows' peer key was finalized *before* the
(only observed) daemon session whose key it is supposed to describe had even started.

This is inconsistent with a simple "collect-then-distribute, once, in order" model —
`CollectPubkeysStage::execute` (`collect_pubkeys.rs:47-92`) was read in full and is
**provably sequential with no concurrency** (`aliases.iter().map(...).collect()`,
then a second synchronous loop that inserts each node's own collected value under its
own `d.alias` — no closure-capture or interleaving is possible here), so a race
*inside* that one stage invocation is ruled out.

The consistent explanation across all directly-observed evidence: **this run
distributed the Windows public key from an earlier point in the pipeline than the
one whose daemon is now actually running the tunnel** — i.e. something between
`collect_pubkeys`/`distribute_assignments` and the currently-live daemon instance let
the key regenerate (or let a second daemon session start with different key material)
*without* the already-issued bundle being refreshed. Two concrete candidates, neither
yet confirmed:

1. **A repeat/stability mechanism re-runs bootstrap** (the run-matrix for this run
   lists `preflight` → `cleanup` three times; whether that is three per-node fanout
   sequences or three full-topology repeats was not settled in this investigation)
   and Windows' `rustynetd key init --force` (unconditional regeneration,
   `windows_install.rs:1063` per the companion membership-init doc) runs again on a
   later repeat, while the earlier repeat's already-distributed bundle on Linux is
   never refreshed — e.g. because the Linux-side bundle **install** step is
   idempotent-skip (mirroring the exact pattern the membership-init doc already found
   for the Windows log-header case, `distribute_membership.rs` §4: "initializes the
   log header `version=1` **if the log is missing or zero-length**" — the same
   "only if not already present" shape, applied to the wrong artifact, would exactly
   produce this symptom).
2. Something re-runs `key init` (or an equivalent regeneration) specifically around
   the `enforce_baseline_runtime` daemon-(re)start step, after `collect_pubkeys` /
   `distribute_assignments` already ran and captured the pre-restart key.

**The concrete next check** (not yet performed): re-run with per-stage wall-clock
logging of exactly when `collect_pubkeys` captured windows-x86-1's key (a specific
timestamp + hex value written to the stage log — the log format seen in this
investigation was pass/fail only, no captured value) versus exactly when
`rustynetd key init --force` last ran on the Windows guest (the daemon's own log or
the bootstrap script's own transcript should carry this) versus when
`distribute_assignments` actually wrote the bundle to Linux. Whichever of the two
candidates above is confirmed, the fix is the same shape either way: **the pipeline
must guarantee the bundled public key always matches the key the *currently running*
daemon instance will use**, either by moving key generation strictly before the one
collection point that feeds distribution, or by re-collecting and re-distributing
whenever the key can change afterward — not by chasing this specific repeat/restart
interaction as a one-off.

## 12) §11.3's two candidate mechanisms both ruled out; the real one narrowed further via targeted instrumentation

Three follow-up live-lab runs (`run-2026-09-05-windows-17-diag2` through `-20-diag5`)
added targeted logging and reproduced the mismatch two more times (5 total data
points across this investigation, all showing the same shape). No code fix landed
yet — this section records what the instrumentation ruled out and narrowed.

### 12.1 §11.3 candidate 1 (repeat/stability mechanism) — RULED OUT

`BootstrapHostsStage::fanout()` (`orchestrator/stage/install.rs:59-61`) is
`StageFanout::PerNode`, confirmed by direct read. The "3 repeated `preflight` →
`cleanup` blocks" in the run-matrix are the 3 nodes' own per-node sequences, not a
stability/soak repeat of the whole topology. `key init --force` therefore runs
exactly once per node per run — there is no repeat mechanism regenerating it.

### 12.2 The `collect_pubkeys` ↔ `distribute_assignments` hand-off — confirmed clean

New logging in both stages (`collect_pubkeys.rs`, `distribute_assignments.rs`,
commit `f6fdf3a0`) shows, across two further runs, that `distribute_assignments`
always reads back **exactly** the value `collect_pubkeys` inserted into
`ctx.collected_pubkeys` — for all three bundle kinds (Assignment/Traversal/DnsZone),
every time. The corruption is not in this hand-off, and not a decoder bug (the
hand-rolled `base64_decode_simple` was independently verified byte-for-byte against
Python's stdlib on a real captured value in §8 and reproduced correct here too).

### 12.3 Clock skew between the orchestrator host and the Windows guest — checked, negligible

Measured directly (`date +%s` on `ubuntu-kvm-1` vs `[DateTimeOffset]::UtcNow` on
`windows-x86-1`): 2 seconds apart. Not an explanation for the ~31-41 second gaps
observed between `collect_pubkeys`' captured timestamp and the only
`"run_daemon entered"` line visible in `rustynetd.log` afterward.

### 12.4 The real mechanism: `rustynetd.log` is truncated on every daemon restart, and even the SURVIVING session's own logged key doesn't match what `collect_pubkeys` captured

Two decisive checks, in order:

1. **`init_daemon_logging` (`main.rs:500-533`) opens the log file with
   `.truncate(true)` (`:523-527`) on every call** — i.e. every time the Windows
   service (re)starts. This structurally confirms that if the daemon restarts even
   once during a run, an earlier session's log entries are gone by the time a
   post-run inspection happens. This resolves the apparent paradox of
   `collect_pubkeys` succeeding (which requires a live, pipe-listening daemon)
   *before* the only "run_daemon entered" line visible afterward: there was an
   earlier session, and its logs were overwritten.
2. **New daemon-side logging** (`daemon.rs`, commit `7402c894`: logs the derived
   public key — never the private key — immediately after every
   `DaemonRuntime::new()`) shows something sharper than "there were two sessions":
   in `run-2026-09-05-windows-19-diag4`, there is (as always) exactly **one**
   `"run_daemon entered"` / `"local wireguard public key"` pair, and **that
   session's own logged key does not match what `collect_pubkeys` captured via
   `rustynet status` in the same run** (`04298782...` logged by the daemon vs
   `2c659cf6...` captured by `collect_pubkeys` — compared programmatically, not by
   eye). Combined with (1), the only consistent picture is: **an earlier daemon
   session (never directly observed — its logs are gone) is what `collect_pubkeys`
   talked to, and it held a different key than the session that survives to the end
   of the run** (almost certainly the one `enforce_baseline_runtime`'s documented
   `stop_daemon`-then-`start_daemon` cycle, `windows_install.rs:521-560`, produces).

This reopens a question this investigation had provisionally treated as settled:
§9's confirmed reading of `windows_install.rs:994-999` says "the service is NOT
started" during bootstrap — but `collect_pubkeys` requires a live, IPC-reachable
daemon to succeed, and it does succeed, before the one daemon start whose logs
survive. Either that comment/reading no longer describes an accurate sequence (a
service start exists somewhere in the bootstrap/install path that was not found),
or `collect_pubkeys`'s successful query is being served by something other than a
literal `run_daemon()` instance. This was NOT resolved this session.

### 12.5 Newest instrumentation, not yet observed: `write_public_key` call logging

Commit `7f084cea` adds `eprintln!` logging (chosen over `log::`, since some
callers — e.g. the one-shot `rustynetd key init` CLI invocation — may run before
any logger is initialized) to `write_public_key` in `key_material.rs:1011`, the
single chokepoint every writer of the on-disk public-key file funnels through
(`key init`, rotation prepare-swap, `restore_key_backups` — rotation itself stays
hard-guarded off Windows, per the original `collect_pubkeys` analysis). This will
show directly whether the on-disk key file is written more than once in a single
run. `run-2026-09-05-windows-20-diag5` is the first run carrying this
instrumentation; its result was not yet read when this section was written.

### 12.6 Updated next steps

1. **Read `run-2026-09-05-windows-20-diag5`'s guest-side output for
   `write_public_key` lines** (the launch log on `ubuntu-kvm-1`, and/or
   `C:\ProgramData\RustyNet\logs\rustynetd.log` / the bootstrap script's own
   captured PowerShell output, since a `key init` one-shot invocation's stdout may
   not land in `rustynetd.log` at all). If it fires more than once, that pins the
   mechanism (something re-runs key generation) and the fix is to make that
   re-run also re-collect/re-distribute, or to prevent it. If it fires exactly
   once, the mystery deepens further and points at either (a) a genuinely earlier,
   undiscovered service-start path in the bootstrap/install script, or (b) a
   `rustynet.exe status` response being served from something other than the
   `run_daemon()` instance's live in-memory state (the existing "no fallback to
   the config env-file" doc comment on `query_live_identity` covers the
   live-identity challenge path specifically — worth checking whether an
   analogous fallback exists for the plain `status` verb `collect_pubkeys` uses).
2. Once the mechanism is confirmed: the fix must guarantee the bundled public key
   always matches whichever daemon session is running when peers actually try to
   handshake — not necessarily "collect earlier," possibly "collect later, after
   whatever produces the final session."
3. All instrumentation added this pass (`collect_pubkeys.rs`, `distribute_assignments.rs`,
   `daemon.rs`, `key_material.rs`) is explicitly marked TEMPORARY in its own code
   comments and should be removed once the mechanism is confirmed and a real fix
   lands.

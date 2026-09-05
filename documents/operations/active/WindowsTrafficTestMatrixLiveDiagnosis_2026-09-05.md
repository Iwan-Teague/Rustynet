# Windows `traffic_test_matrix` — live diagnosis of the WireGuard handshake failure

- Status: **ROOT CAUSE CLASS CONFIRMED; a specific, well-supported mechanism
  identified in §13 (not yet fixed).** This is live-lab evidence gathered by direct
  guest inspection across 7 runs (`run-2026-09-05-windows-16-setuponly` through
  `-21-diag6`), not a static code trace. No production behavior was changed — only
  temporary diagnostic logging (§11.3, §12.5, §13.1), all clearly marked for
  removal once a real fix lands. The failure is a **stale WireGuard public key**
  distributed to peers: WireGuard-NT's own diagnostic log shows "Invalid MAC of
  handshake" — a cryptographic MAC1 rejection that occurs exactly when the sender
  computed the handshake MAC against a public key that does not match the
  responder's actual current key. §13 traces this to a **known-weak verification
  point**: the cleanup stage that runs before every fresh bootstrap only confirms
  the Windows service *registration* reports `Stopped`, never that the underlying
  daemon *process* has actually exited — and this project's own prior live-lab
  evidence already shows the daemon's shutdown path can do slow, failing rollback
  work after reporting itself stopped. This is assessed as the most likely
  mechanism, not yet independently reproduced by directly observing the
  hypothesized orphaned process (see §13.4 for the exact verification a future
  session should run first, before implementing a fix).
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

## 13) The decisive run: `write_public_key` fires exactly once, and everything except `collect_pubkeys` agrees

`run-2026-09-05-windows-20-diag5` (commit `24d65839`) added one more diagnostic
(`f9395dac`: the bootstrap script now unconditionally appends `key init`'s captured
stdout/stderr to `C:\ProgramData\RustyNet\logs\bootstrap-native-output.log`, since
`Invoke-RustyNetBootstrapNative`'s captured `$keyInit.Output` was silently discarded
on success — the reason the `write_public_key` logging added in `7f084cea` never
appeared anywhere: that log line runs inside the one-shot `rustynetd key init`
process, which never opens `rustynetd.log` at all — only the persistent service
process does, via `init_daemon_logging`). `run-2026-09-05-windows-21-diag6`
(commit `24d65839` also, no further code changes needed) is the run this section is
built from.

### 13.1 Four independent sources, one run, compared directly

| Source | Value (base64) |
| --- | --- |
| `write_public_key` (the ONE call this entire run, from `key init`) | `2aBaTNcnAs3/iEBjaOslb9iyN4iTvPRAmvhHHBIhPXQ=` |
| Daemon's own logged key at `DaemonRuntime::new()` (`daemon.rs`, `7402c894`) | `2aBaTNcnAs3/iEBjaOslb9iyN4iTvPRAmvhHHBIhPXQ=` |
| `wg.exe show all dump`, live guest, third field of the interface line | `2aBaTNcnAs3/iEBjaOslb9iyN4iTvPRAmvhHHBIhPXQ=` |
| `collect_pubkeys` (via `rustynet status`, `2b3422d3`-era fix) | *different value* |

**The first three agree exactly** (verified programmatically, not by eye). Only
`collect_pubkeys`' value differs. This is the single clean result across the whole
investigation and it overturns the working theory from §12.4: it is **not** that
two daemon sessions each derive a different key from the same file — the on-disk
key file is written exactly once, and every consumer of it (the daemon's own
in-memory cache, and the actual running WireGuard-NT driver) agrees. The
divergence is entirely on `collect_pubkeys`' side of the query.

### 13.2 `collect_pubkeys`' timestamp is ~40s before the only daemon start, again — and the trust CLI has no fallback path

Re-confirmed the pattern from §12.4 in this run too: `collect_pubkeys` captured its
(wrong) value at `unix=1788590920`; the only `"run_daemon entered"` line is at
`1788590960.719` — ~40 seconds later. Read `rustynet-windows-trust-cli.rs`
directly (not trusting the earlier GLM trace's characterization a second time):
`execute_status()` (`:480-486`) calls `send_command(IpcCommand::Status)` and
returns `Err` on any non-`ok` response; `send_command` (`:443-453`) does a real
named-pipe RPC via `call_windows_daemon_control_raw` with **no fallback path at
all** — if the pipe is unreachable, this must fail closed with a connection error,
not return a plausible key. Yet `collect_pubkeys` reported success with a
well-formed, 32-byte key. **Something must be answering that pipe 40 seconds before
the daemon service this run's `key init` and `enforce_baseline_runtime` produced
ever started** — and it cannot be reading stale data from a file (the file was
written exactly once, by this run's `key init`, and its value matches the *later*
sessions, not `collect_pubkeys`' value).

### 13.3 Most likely mechanism: an orphaned daemon process from the *previous* run, still bound to the same named pipe

The cleanup stage that runs before every fresh bootstrap (`cleanup_hosts`, deps
`[VerifySshReachability]`, before `bootstrap_hosts`) calls
`windows_traffic::cleanup_runtime_state` →
`windows_stop_and_wait_services_script()` (`windows_traffic.rs:638-652`):

```
& sc.exe stop 'RustyNet' 2>&1 | Out-Null;
& sc.exe stop 'RustyNetRelay' 2>&1 | Out-Null;
for ($i = 0; $i -lt 20; $i++) {
    $svc = Get-Service -Name 'RustyNet' -ErrorAction SilentlyContinue;
    ...
    $svcDown = ($null -eq $svc) -or ($svc.Status -eq 'Stopped');
    ...
    if ($svcDown -and $relayDown) { break };
    Start-Sleep -Seconds 1
}
```

**This polls only the Service Control Manager's registered status for the service
name — never whether the underlying `rustynetd.exe` process has actually exited.**
`assert_node_clean` (`:955-958`, probe at `:827-849`) has the same blind spot: its
`service=<running|stopped|absent>` token also comes from `Get-Service`, not
`Get-Process`. Both pass as long as SCM reports "Stopped", which for a service that
calls `SetServiceStatus(SERVICE_STOPPED)` before its own process has finished
tearing down (rather than strictly after) can happen while the process is still
alive for some further interval.

This project's own prior live-lab evidence already shows the daemon's shutdown path
does exactly this kind of slow, sometimes-failing post-stop work: the
`shutdown_rollback_residue_detected` / `shutdown rollback failed` log lines
observed repeatedly this session (e.g. §2 of this document, and independently in
`run-2026-09-04-windows-8`'s captured `rustynetd.log`) are the daemon reporting a
failure from *inside* its own shutdown handling, after the stop was triggered.

Every observation is consistent with: **a daemon process from the previous run's
bootstrap, left running past `cleanup_hosts`' SCM-status-only check because its own
shutdown rollback is slow/erroring, still holds `\\.\pipe\RustyNet\rustynetd` open
with its (old, different) key when `collect_pubkeys` queries status early in the
*next* run — 40 seconds before that next run's own `key init` → service (re)install
→ `enforce_baseline_runtime` start sequence produces the real, correct daemon that
every other observation in §13.1 agrees on.** The fresh `sc.exe create` on every run
(§1's five 7045 "service was installed" events, one per run, confirmed in the
System event log) would leave such an orphan with no SCM registration at all once
the old registration is replaced — invisible to `Get-Service`, `assert_node_clean`,
and `windows_node_clean_assert_script` alike, all of which query by service name,
never by process.

### 13.4 The verification this hypothesis still needs (not yet done — requires a live run, deliberately not run this session per the wrap-up commitment above)

Immediately after a `cleanup_hosts` pass and before the next `bootstrap_hosts`
begins, check for a `rustynetd.exe` process on the guest that is **not** associated
with the current `RustyNet` service registration:

```powershell
Get-Process -Name rustynetd -ErrorAction SilentlyContinue | Select-Object Id, StartTime
Get-CimInstance Win32_Service -Filter "Name='RustyNet'" | Select-Object ProcessId, State
```

If a `rustynetd.exe` PID exists that does **not** match the current service's
`ProcessId` (or exists while the service `State` is not yet `Running`), that
confirms the orphan directly. The fix, once confirmed, is straightforward: make
`windows_stop_and_wait_services_script`/`assert_node_clean` also verify at the
**process** level (e.g. resolve the service's `ProcessId` before stopping it, then
poll `Get-Process -Id <pid>` for absence, not just `Get-Service ... Status`), so a
slow/failing shutdown rollback cannot leave a process alive past what cleanup
believes is a clean state.

### 13.5 Updated evidence index

- Trust CLI status path (no fallback, confirmed clean): `rustynet-windows-trust-cli.rs:443-453, 480-486`.
- Cleanup's SCM-only verification: `windows_traffic.rs:638-652` (`windows_stop_and_wait_services_script`),
  `:827-849` (`windows_node_clean_assert_script`), `:862+` (`parse_windows_node_clean_probe`),
  `stage/cleanup.rs:39-86` (`CleanupHostsStage::execute`, `cleanup_runtime_state` +
  `assert_node_clean` call sites).
- Fresh service (re)install every run: System event log, 7045 events, one per run
  (§ live-guest inspection, this session).
- Shutdown rollback failures as prior evidence of slow/erroring shutdown: daemon
  log lines captured earlier this session (§2; `run-2026-09-04-windows-8`).

## 14. ROOT CAUSE CONFIRMED AND FIXED (2026-09-05) — supersedes §13's orphan-process hypothesis

§13's orphan-from-the-previous-run hypothesis was never confirmed, and the
process-level check named in §13.4 turned out to disprove it rather than confirm
it: a decisive live re-run (`run-2026-09-05-windows-22-orphancheck`, then
`run-23-orphancheck`) with continuous `Get-Process -Name rustynetd` /
`Get-CimInstance Win32_Service -Filter "Name='RustyNet'"` polling (3s interval,
spanning the whole `bootstrap_hosts` → `validate_baseline_runtime` window) found
**no `rustynetd.exe` process of any kind on `windows-x86-1` for the first ~13
minutes of `bootstrap_hosts`** — i.e. nothing survived from before this run, ruling
out an orphan from a *previous* run's cleanup as the mechanism. The real
mechanism is a **within-this-run double key-init**, entirely independent of
cleanup:

1. `install_daemon` (`windows_install.rs`) runs `Install-RustyNetWindowsService.ps1`
   (`install_script`, called before `run_windows_e2e_bootstrap`). That script:
   - runs its own `rustynetd key init --force` under the service's runtime
     identity (`Install-RustyNetWindowsService.ps1:1293-1318`, step
     `rekey-wireguard-under-runtime-identity` — writes keypair **A** to disk),
   - then (`:1534-1550`, step `start-runtime-service`) **starts the RustyNet
     service itself**, non-enforcing mode. This process derives and caches
     keypair A. This is the process later runs saw as `rustynetd.exe` pid 4984
     (run-23) / pid 5984 (run-22) — a **fresh daemon this run created for
     itself**, not a survivor of anything.
2. `install_daemon` then calls `run_windows_e2e_bootstrap`
   (`windows_install.rs:1033-1097`), which runs a **second, independently
   security-hardened** `rustynetd key init --force` (the "Phase 27 reviewer
   fold-in": statistically independent WG/signing passphrases, atomic
   DPAPI-protected write — added later than the `.ps1`'s own rekey step, for
   good reasons unrelated to this bug: BLOCKER 1/HIGH 1 in the code comments).
   This **overwrites the on-disk key with keypair B** — but the daemon started
   in step 1 is still running and never reloads; it keeps keypair A cached in
   memory.
3. `collect_pubkeys` queries that already-running daemon's status over its
   named pipe (not the key file) and captures **keypair A** — stale from the
   moment key-init #2 ran.
4. `enforce_baseline_runtime` later calls `enforce_daemon`, which
   stop/starts the daemon for the `auto_tunnel_enforce` flip. This fresh start
   reads the **current** on-disk key — keypair B — which is what `wg.exe show`
   and the daemon's own startup log report from then on.

Peers hold keypair A (via the bundle `distribute_assignments` built from
`collect_pubkeys`'s value); the guest's WireGuard-NT tunnel runs keypair B.
Every incoming handshake initiation computed against keypair A fails MAC
validation against the real running key B — exactly the "Invalid MAC of
handshake, dropping packet" from §11.

**Decisive live confirmation (`run-23-orphancheck`, `--setup-only`, mesh left up
since `validate_baseline_runtime` passed and cleanup is skipped on a passing
`--setup-only` run):**

| Source | Value (base64) |
| --- | --- |
| `collect_pubkeys` capture (→ `distribute_assignments`, all 3 bundle kinds) | `PTEkYqSTEkcId8M9LZrIhCUcEG4EMsG5hbF40BFH61w=` (hex `3d312462a49312470877c33d2d9ac884251c106e0432c1b985b178d01147eb5c`) |
| Guest's own `bootstrap-native-output.log`, run-23's key-init (unix 1788593495, ~18s before `collect_pubkeys` finished) | `yo8GmFTCuI7MZMsxlGM1MgX5RyuYEFhNXuGkFc/fiWc=` |
| Live `wg.exe show all dump` on the guest (mesh still up) | `yo8GmFTCuI7MZMsxlGM1MgX5RyuYEFhNXuGkFc/fiWc=` |
| Daemon's own startup log (`rustynetd startup: local wireguard public key = ...`) | `yo8GmFTCuI7MZMsxlGM1MgX5RyuYEFhNXuGkFc/fiWc=` |

`collect_pubkeys`'s value matches **none** of the three key-init entries logged
for this guest across the last two runs — it is genuinely a different-generation
daemon's cached value, not a decode or file-timing artifact (both already ruled
out in §12).

**Fix landed:** `5c74a65c` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs`).
After `run_windows_e2e_bootstrap` completes, `install_daemon` now checks whether
the `RustyNet` service is running (`windows_daemon_is_running`, new) and — if so —
restarts it with the same `stop_daemon`/`start_daemon` pair `enforce_daemon`
already uses for its own later restart. This makes whichever key-init ran last
authoritative for every reader downstream, `collect_pubkeys` included. A gated
(`-NoDaemonStart`) install never starts the daemon in step 1, so the check is a
no-op there. Unit-tested (`windows_daemon_status_query_reports_absent_and_running_distinctly`,
`windows_daemon_status_running_parse_is_exact_match`); `cargo fmt --check`,
`cargo clippy -p rustynet-cli --features vm-lab --all-targets -- -D warnings`,
and the crate's test suite all verified clean before landing. **Not yet
re-proven live end-to-end through `traffic_test_matrix`** — the two runs that
produced the decisive evidence above both used `--setup-only` (by design, to
allow live guest inspection) and never reached that stage; the next live-lab run
against this commit should drop `--setup-only` and confirm `traffic_test_matrix`
passes for `windows-x86-1`.

All temporary diagnostic instrumentation added this session (`collect_pubkeys.rs`,
`distribute_assignments.rs`, `daemon.rs`, `key_material.rs`, and the
`windows_install.rs` `bootstrap-native-output.log` addition) remains in place —
it is exactly what produced the confirmation table above and should stay until
the fix is live-proven, then be removed as its own comments say.

### 14.1 Cross-platform check: macOS/Linux do not share this bug class

Checked directly (file:line) rather than assumed, since this defect class
(a redundant rekey after a daemon has already started) is exactly the kind of
thing that could recur on another platform's install path:

- **Linux** (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs`):
  no `key init` (or any rekey/regenerate-keypair) call anywhere in the
  orchestrator's install path at all — grepped for `key`/`rekey`/`genkey` across
  the whole file, the only hits are the (public) assignment-authority
  *verifier* key handling for the relay unit, unrelated to WireGuard identity
  keys. Whatever produces the Linux node's WireGuard keypair happens entirely
  inside the daemon's own first-start self-init, a single code path with no
  orchestrator-driven second call to overwrite it.
- **macOS** (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`
  plus its two embedded scripts, `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`
  and `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`): `key init` is
  called exactly **once**, at `Bootstrap-RustyNetMacos.sh:1107`, and that same
  script's own final step is what loads the launchd plist (starts the daemon;
  `macos_install.rs:404` comment). `Install-RustyNetMacosService.sh` never calls
  `key init` (confirmed by grep — it only does `launchctl bootstrap`/keychain
  work), and there is no separate e2e-bootstrap script with its own rekey
  (`scripts/e2e/rn_bootstrap_macos.sh` has zero `key init` hits). So the one
  rekey always precedes the one daemon start, in the same script execution —
  structurally incapable of leaving a stale-keyed daemon running the way
  Windows' two-separate-scripts arrangement did.

Windows is architecturally the odd one out here: it is the only platform whose
orchestrator-driven install path runs `key init` from **two different, separately
maintained scripts** (`Install-RustyNetWindowsService.ps1`'s own rekey step, added
for DPAPI-runtime-identity alignment, and `run_windows_e2e_bootstrap`'s later,
independently-hardened rekey, added for the Phase 27 passphrase-separation fix) —
neither script's author had full visibility into the other having already started
a daemon. No further cross-platform action needed; this is closed.

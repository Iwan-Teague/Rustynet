# Cross-Network NAT Traversal — First Live Evidence (2026-07-29)

**Status:** Active evidence record. First time rustynet's own NAT traversal has been
exercised against two genuinely separate physical networks. **Seven defects found and
fixed**; direct hole-punched connectivity achieved, **bulk data transfers byte-exact
over it at 13.69 Mbit/s with 0% loss**. Remaining open: reflexive endpoints are never
published into the signed bundle (§4.4) and the same-site NAT hairpin that follows from it
(§4.4b), plus kernel-WireGuard's inability to run STUN (§4.5).

**Why this could not be done before:** every prior cross-network claim was blocked on
"the owner does not have a second network right now"
(`CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.2 point 4, §5 Phase X2). That
constraint is now gone.

---

## 1. Lab topology

Two hosts on **different physical LANs**, no direct route between them:

| Site | Host | Host LAN | Public IP | Guests | Guest subnet |
| --- | --- | --- | --- | --- | --- |
| Mac | iwan's MacBook Pro | 192.168.15.218 | 80.169.236.70 | UTM | 192.168.64.0/24 |
| Ubuntu | ubuntu-kvm-1 | 192.168.8.152 | 213.233.155.131 | libvirt/KVM | 192.168.121.0/24 |

Four rustynet nodes, two per site, one flat mesh (`network_id=xnet-lab`, membership
epoch 4):

| node | site | underlay | mesh IP |
| --- | --- | --- | --- |
| `xnet-mac-1` | Mac | 192.168.64.4 | 100.91.223.78 |
| `xnet-mac-2` | Mac | 192.168.64.10 | 100.90.68.89 |
| `xnet-ubu-1` | Ubuntu | 192.168.121.26 | 100.122.218.46 |
| `xnet-ubu-2` | Ubuntu | 192.168.121.137 | 100.119.203.92 |

### 1.1 Measured NAT behaviour (D14.c field data)

RFC-5780-style mapping classification, one socket against three STUN servers:

| Site | Mapping | Evidence |
| --- | --- | --- |
| Ubuntu | **endpoint-independent (cone)** | same mapped port `14478` to all three servers |
| Mac (host, direct) | **symmetric** | `MappingVariesByDestIP: true` |
| Mac (as guests egress) | **cone** | via the tailscale exit node — see §5 caveat |

`PortMapping:` is empty on both routers (no uPnP/NAT-PMP/PCP), and neither site has
IPv6. **D14.a and D14.b cannot help this pair** — do not spend effort there for this
lab.

---

## 2. Defects found and fixed

All seven were measured, not inferred, and each is fixed on `main`. §2.1–§2.3 unblocked
the handshake; §4.1 covers the two MTU faults that unblocked bulk data; §4.2 the
handshake-collision storm behind the packet loss; §4.2b the frozen boringtun clock that
was the root cause beneath both the loss and the empty liveness counters.

### 2.1 Boot killswitch never received the STUN allow-list — `fe634559`

`traversal_bootstrap_allow_endpoints` was emitted only into the daemon's
generation-rotated table (`rustynet_g<N>`), never into `rustynet_boot`. Both install a
base chain on `output` at priority 0, and in nftables an `accept` in one base chain does
not terminate traversal of the others — a `policy drop` in any of them still drops the
packet. The boot chain therefore vetoed every STUN datagram the daemon's own table
explicitly accepted.

*Effect:* total. `srflx` gathering could never leave the host, so NAT traversal was
impossible on any node with the boot table resident.

*Proof:* STUN probe returned `EPERM`; inserting the equivalent allows into
`rustynet_boot` by hand made the same probe return a 32-byte reply and the daemon
immediately began discovering candidates.

Note the identical failure mode had already been fixed for the WireGuard listen port,
and is documented in `install_linux_boot_killswitch`'s own doc comment — the traversal
endpoints simply never received the same treatment.

### 2.2 Outbound WireGuard allowed only by destination port — `c5018acb`

Both killswitch tables permitted outbound WireGuard by **destination** port matching the
local listen port. That silently assumes every peer listens on the same port we do —
true on a LAN, and exactly what NAT traversal breaks, since a peer reached at its
server-reflexive candidate sits on an arbitrary NAT-mapped port.

*Proof:*

```
UDP socket send_to failed for 51.186.254.100:44883: Operation not permitted (os error 1)
```

Every node sat in `FailClosed` with `path_programmed_peer_count=0` because the traversal
probe could never emit its first packet.

*Fix:* also match on **source** port. Every datagram the daemon emits leaves its bound
WireGuard socket with the listen port as source, whatever the destination — as narrow as
the dport form, but covering any peer endpoint a NAT hands us. Applied to both chains,
plus a matching drift assertion in the generation table's verifier.

### 2.3 Privileged boundary rejected the new rule shape — `5bbf2062`

The privileged helper validates every nft argv against an explicit schema allow-list and
refused the source-port rule:

```
wireguard source port 51820 allow rule failed: unsupported nft add rule argument schema
```

That is the boundary behaving **correctly** — it refuses argv shapes it has not been
taught. The new arm is bounded identically to the dport arm it mirrors (owned
fail-closed table token, validated interface name, u16 port): one extra argv shape, no
new destination reach.

*Operational note:* the privileged helper is a **separate systemd service**. Restarting
`rustynetd` alone leaves the old schema live; `rustynetd-privileged-helper` must be
restarted too.

---

## 3. Result — direct hole-punched connectivity, live

With all three fixes deployed and peers carrying their discovered reflexive endpoints,
WireGuard handshakes traverse both NATs over the open internet. Packet capture on both
sides simultaneously:

```
ubu-2:  51.186.254.100.48189  > 192.168.121.137.51820: UDP, length 148   (WG handshake init, inbound)
        192.168.121.137.51820 > 51.186.254.100.48189:  UDP, length 92    (WG handshake response, outbound)
mac-2:  213.233.155.131.15782 > 192.168.64.10.51820:   UDP, length 92
```

Mesh reachability over that path:

- `xnet-ubu-1 → xnet-mac-2` (100.90.68.89): **4/4 replies, 0% loss, 84 ms**
- `xnet-mac-1 → xnet-ubu-2`: 1/4 replies, 82 ms
- All four nodes: `state=DataplaneApplied`, `path_mode=direct_programmed`,
  `path_programmed_peer_count=3`, `traversal_probe_result=direct`

**No VXLAN and no tailscale carries this dataplane** (see §5 for the exit-node caveat).

---

## 4. Open gaps (not yet fixed)

### 4.1 ~~MTU not adapted to the discovered path~~ — **FIXED** (`e3741da2`, `4c4d6c5f`)
Two distinct faults, both now closed:

1. **The userspace-shared TUN lifecycles never set an MTU at all** (`e3741da2`). The
   kernel, macOS and Windows backends all pin `SAFE_BRINGUP_TUNNEL_MTU` before link-up —
   the Linux kernel path even comments that it is "closing the never-set-MTU gap" — but
   both userspace-shared lifecycles were missed, leaving the platform default of **1500**.
   1500 plus WireGuard overhead does not fit even a clean 1500-byte Ethernet underlay.
2. **Even the 1420 default is too large for a NAT-traversed path** (`4c4d6c5f`). The
   outer hop here is 1280 bytes, leaving 1220 for the inner packet.
   `RUSTYNET_WG_TUNNEL_MTU` now overrides the bring-up value, bounded to
   `MIN_BRINGUP_TUNNEL_MTU..=SAFE_BRINGUP_TUNNEL_MTU`, falling back to the default on
   anything absent/unparseable/out-of-range. The **ceiling is the audited default**, so an
   override can only ever make a tunnel more conservative. The privileged helper's
   allowlist entry moved from an exact literal to that same bounded range — which its own
   comment had asked for once the value became dynamic.

Measured progression on the same path:

| interface MTU | ICMP 1000B | ICMP 1192B | ICMP 1200B | 4 MB TCP |
| --- | --- | --- | --- | --- |
| 1500 (before) | OK | — | FAIL | stalled |
| 1420 (parity fix) | OK | — | FAIL | **stalled after 0.03 MB** |
| **1220 (override)** | OK | **OK** | n/a | **4194304 bytes, sha256 `b14138a3ca83b79c` both ends** |

**Still interim.** A static value — default or override — cannot track a path MTU that
varies per peer and over time. The real answer is per-path measurement via the DPLPMTUD
state machine that already exists in `rustynetd::path_mtu`, fully unit-tested, **with no
consumer** (FIS-0027 Phase 3).

### 4.2 ~~Punched path is lossy~~ — **FIXED** (`7a3af8fe`)
The loss was **not** the network. The underlay is clean: 50/50 ICMP, **0% loss**, to the
exact public address the punched path uses, from both the host and the guest.

It was a **handshake-collision storm inside rustynet**. Wire capture on one peer pair
during a 40-ping burst:

| length | count | meaning |
| --- | --- | --- |
| 116 | 40 | data packets (the pings) |
| 148 | **105** | WireGuard handshake **initiations** |
| 92 | **105** | handshake responses |

~6 handshakes/second against 40 data packets. Both peers were initiating, so handshakes
collided continuously and whatever the superseded session had in flight was discarded.

**Cause:** the Direct arm of the re-probe predicate had no rate limit. While a handshake
was not fresh it returned true on *every* reconcile tick (1/s), and each re-race calls
`initiate_peer_handshake`. The Relay arm has always been paced by `next_reprobe_unix`;
Direct was the asymmetry, and that field was only ever armed for Relay decisions.

**Fix:** arm the floor for every decision, and split staleness by cause — if the
handshake was fresh at the last evaluation the path has *just* died, so re-race
immediately (this preserves prompt direct→relay failover, which a blunt timer would have
delayed by 30 s and which an existing test correctly caught); if it was already stale,
the re-race did not help, so pace the repeat. A no-longer-offered endpoint still bypasses
the floor, and an explicit force still wins.

**Measured effect**, identical 40-ping burst:

| | before | after |
| --- | --- | --- |
| handshake initiations | 105 | **5** |
| packet loss (ubu→mac) | 17.5% | **0%** (100/100) |
| packet loss (mac→ubu) | 7.5% | **1%** (99/100) |
| 4 MB TCP throughput | 0.37 Mbit/s | **6.94 Mbit/s** (sha256 matched) |

### 4.2b ~~Liveness never registers~~ — **FIXED** (`3e44e627`)
**Nothing in the workspace ever called `Tunn::update_timers`.** That is boringtun's clock
driver: it advances the internal `TimeCurrent`, and every other timer is stored relative
to it. With it frozen,

```
time_since_last_handshake = time_since_tun_start - TimeSessionEstablished
```

grew without bound, because the second term stayed at its initial value. A peer that had
just handshaked reported an ancient one and never satisfied the freshness window — which
is why `path_live_*` read empty on a path demonstrably carrying 4 MB byte-exact.

It is also **why the §4.2 re-race loop engaged at all**: the Direct arm re-probes while a
handshake is not fresh, and the handshake could never *become* fresh. `7a3af8fe` paced
that loop; this removes the reason it engaged.

Two further consequences of the frozen clock, both also fixed: persistent keepalives were
never emitted (NAT bindings left to expire on their own) and the periodic rekey was never
driven.

Both userspace-shared backends share one engine, so the tick is implemented once and each
runtime drives it once per second. The tests pin that each runtime **drives** the tick,
not merely defines it — defining without calling would reproduce the defect exactly.

**Measured effect**, all four nodes:

| | before | after |
| --- | --- | --- |
| `path_live_peer_count` | 0 | **2** (of 3; the third is the §4.4b hairpin peer) |
| `path_live_direct_peers` | 0 | **2** |
| `path_latest_live_handshake_unix` | none | **real timestamp** |
| `path_mode` | direct_programmed | **mixed_active** |
| loss (60 pings) | 0-1% | **0%** (60/60) |
| 4 MB TCP | 6.94 Mbit/s | **13.69 Mbit/s** |

Throughput across the whole session: **0.37 → 6.94 → 13.69 Mbit/s** (37x).

### 4.4b Same-site peers cannot connect — NAT hairpin, OPEN
Two nodes behind the *same* NAT hold only each other's server-reflexive endpoint
(e.g. `xnet-ubu-2/213.233.155.131:14558` as seen from `xnet-ubu-1`, its own site's public
address). Reaching that requires NAT hairpinning, which many NATs do not support, so the
pair never connects — 100% loss, and it is the reason `path_live_peer_count` is 2 of 3
rather than 3 of 3.

The bundle format already supports a candidate *list* per peer
(`TraversalCandidateType::{Host,ServerReflexive,Relay}`), which is exactly what ICE needs
to prefer a host candidate for a same-site peer and srflx only for remote ones. Nothing
populates more than one candidate today, so this is the same root as §4.4: candidates are
never published, they are hand-minted one-per-peer.

### 4.3 `path_live_peer_count` stays 0 while traffic flows — reporting discrepancy
Real bidirectional traffic is captured on the wire and mesh pings succeed, yet the
daemon reports `path_live_peer_count=0`, `path_live_proven=false`,
`path_latest_live_handshake_unix=none` — while `traversal_probe_result=direct` and
`traversal_probe_latest_handshake_unix=multiple`. The liveness accounting disagrees with
observable reality; treat `path_live_*` as unreliable evidence until reconciled.

### 4.4 Reflexive endpoints are never published — the structural gap
`srflx_candidates` counts candidates **inside the signed traversal bundle**
(`daemon.rs:5906-5918`), not locally-gathered STUN results. Nothing feeds a node's
discovered reflexive address back into the bundle its peers receive, so the endpoints had
to be collected and re-minted **by hand** for this run, and they go stale on every daemon
restart. This is the piece D14.d (gossip-coordinated punch) needs to automate before
traversal is self-sustaining.

### 4.5 Kernel-WireGuard backend cannot do STUN — by design, needs a product decision
On `--backend linux-wireguard` the daemon reports
`transport_socket_identity_state=blocked_backend_opaque_socket` and refuses STUN: the
kernel backend is a command-only adapter with no authoritative packet-I/O handle, so STUN
would run on a different socket and yield a mapping for the wrong port. Correct
fail-closed reasoning, but it means **NAT traversal is only possible on a userspace
backend**. Both Ubuntu nodes had to be switched to
`linux-wireguard-userspace-shared` for this run.

---

## 5. Caveats on this evidence

- **The Mac routes its default through a tailscale exit node** (`server`,
  100.123.146.3 / 51.186.254.100). Mac-side egress therefore presents the exit node's
  NAT (cone), not the Mac's own (symmetric). The traversal mechanism is proven; the
  Mac's *true* NAT is not yet exercised. Turning the exit node off changes the operator's
  machine-wide internet routing, so it was left in place.
- Guests are **double-NAT'd** (vmnet / virbr0 on top of the home routers).
- The lab's SSH control plane still uses the tailnet; only the *dataplane* claim is
  tailscale-free.
- The two site repos are on **divergent lineages** — guest binaries were built from
  `8a2d6136`-era source plus the three fixes above. See the operator note on
  `RUSTYNET_SOURCE_COMMIT` before treating cross-fleet results as commit-attributable.

---

## 6. Reproduction notes

- STUN servers must be **numeric `ip:port`** (`--traversal-stun-servers` uses
  `parse_optional_socket_addr_csv_arg`), e.g.
  `74.125.250.129:19302,162.159.207.0:3478`.
- Set them in **`/etc/default/rustynetd`**, not a systemd drop-in: the unit loads
  `EnvironmentFile=` and a drop-in is **silently overridden** — `systemctl show` reports
  the drop-in value while `/proc/<pid>/cmdline` shows an empty argv element.
- `TRAVERSAL_TTL_SECS` defaults to **120 s**; hand-minted bundles go stale in two minutes
  and fail-close every node. Pass `86400` for manual runs.
- The membership owner approver id is `<node_id>-owner`, not `<node_id>`.
- `e2e-bootstrap-host --skip-apt` also skips the `cargo build`, which matters on the
  1 GB-RAM UTM guests.

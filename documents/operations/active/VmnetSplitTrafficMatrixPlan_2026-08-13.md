# `traffic_test_matrix` fails on a vmnet L2 split — diagnosis and plan — 2026-08-13

**Status: PLAN, unreviewed.** Diagnosis is measured, not inferred; every number below came from
a live probe on 2026-08-13 or a quote-aware read of the 110-row `--node` ledger.

## 0. The failure

`traffic_test_matrix` is the sole failing stage in three consecutive runs
(`rebaseline-20260813c/e/f`, each 21 pass / 1 fail / 36 skip). It fails identically each time:
100% packet loss **in both directions** between `macos-utm-1` and both Debian nodes, while the
two Debian nodes reach each other. `default-deny` is reported INCONCLUSIVE — correctly, since a
node that reached no peer cannot attribute a blocked egress to policy.

## 1. Diagnosis — measured

**This is not a Rustynet defect.** There is no IP path between the two guests, so WireGuard has
nothing to handshake over.

| probe | result |
| --- | --- |
| `macos-utm-1` interfaces | one: `en0` = 192.168.65.101, gateway 192.168.65.1 |
| macOS → 192.168.64.4 / .10 | unreachable |
| debian → 192.168.65.101 | unreachable |
| debian → **192.168.65.1** (the host's *own* address on the other bridge) | **unreachable** |
| `traceroute` debian → 192.168.65.101 | dies at hop 1, no reply |
| host `net.inet.ip.forwarding` | already `1` |
| host bridges | `bridge100` = 192.168.64.1 (7 QEMU members), `bridge101` = 192.168.65.1 (1 member, flags include `PRIVATE`) |

Debian cannot reach the host's own address on the other bridge, so this is host-level isolation
between two vmnet networks, not a routing gap. The backend split is the cause and is permanent:
`vm-lab-network-audit` reports `macos-utm-1 backend=apple` and every other guest `backend=qemu`.
A macOS guest cannot run under QEMU on Apple Silicon, so it cannot join the QEMU vmnet.

This also **settles an open question** carried on this stage from an earlier run, which proposed
two hypotheses — split-default routes capturing the handshake, or the tunnel never handshaking.
It is the second, and for a reason neither hypothesis named: the endpoints are mutually
unreachable, so no handshake is ever attempted.

**What the macOS node does have** (same runs, all passing): `mesh_status_validation`,
`runtime_acls_validation`, `key_custody_validation`, `service_hardening_validation`,
`dns_failclosed_validation`. The control plane is healthy; only the dataplane has no underlay.

### 1.1 The escape hatch, also measured

Both planes reach the physical LAN and the internet through their respective vmnet NATs:

| from | 192.168.8.1:80 (LAN router) | 192.168.8.147:22 (host) | 1.1.1.1 |
| --- | --- | --- | --- |
| `macos-utm-1` | **TCP OPEN** | **TCP OPEN** | reachable |
| `debian-headless-2` | **TCP OPEN** | **TCP OPEN** | reachable |

So a **common rendezvous exists that both sides can dial *out* to**, even though neither can be
dialled *in* to from the other. That is precisely the shape this project's zero-ingress relay
role is designed for.

## 2. Options

| # | Option | Verdict |
| --- | --- | --- |
| A | Host `pf` change to permit inter-bridge forwarding | **Rejected.** Needs the operator's password (host `sudo` is not passwordless), it is a host security-settings change, and vmnet re-applies its own rules on VM restart — a fix that can silently revert is worse than none, because the next green run would be unexplained. |
| B | Re-home the fleet to Bridged on one L2 | **Rejected for now.** Largest blast radius (every guest's NIC), and it reverses a deliberate Bridged→Shared migration whose rationale must be recovered before reversing it. Keep as fallback. |
| C | **Route mac↔Linux through a relay reachable from both planes** | **Proposed.** No host security change; uses the product's own zero-ingress design; both planes provably reach a common rendezvous. |
| D | Scope macOS out of the same-LAN matrix | **Rejected.** Defers a release-blocking parity mandate and makes the matrix assert less than it appears to. |

## 3. The risk that must not be buried

**Option C rests on a mechanism this project has never demonstrated.** Quote-aware read of all
110 `--node` ledger rows:

| column | lifetime |
| --- | --- |
| `linux_relay_forwards_frame` | **`not_run` × 110 — never once executed** |
| `macos_relay` | `not_run` × 110 |
| `windows_relay` | `not_run` × 110 |
| `macos_relay_alias` / `_node_id` / `_target` | empty × 110 |
| `linux_relay` | 14 pass / 5 skip / 91 not_run |
| `cross_os_relay_path` | 3 pass / 13 skip / 94 not_run |

Relay *service lifecycle* has passed (the process starts and binds). Relay **frame forwarding**
has never run on any OS. So C is not "use the existing relay path" — it is "prove the relay path
for the first time, and then use it". The plan must be honest that this is two pieces of work,
and that the first may itself fail.

## 4. Proposed change

**C1 — prove relay frame forwarding on Linux first.** Elect a Linux relay in a normal same-LAN
topology, where all nodes can already reach each other, and make `linux_relay_forwards_frame`
execute and pass. This isolates "does relaying work at all" from "does relaying bridge the
vmnet split". If C1 fails, C is dead and B becomes the plan.

**C2 — place a relay where both planes can reach it.** No current VM qualifies: every QEMU
guest is on 192.168.64.0/24 (invisible to macOS) and the macOS guest is on 192.168.65.0/24
(invisible to the rest). Options, to be settled by review:
  - give one Linux guest a second, Bridged NIC on 192.168.8.0/24;
  - run the relay on the host at 192.168.8.147 (proven reachable from both, but puts a lab
    service on the operator's machine);
  - a dedicated LAN-attached VM.
Note both guests reach the LAN through **NAT**, so the relay must accept inbound on the LAN side
while both nodes dial out to it. That matches the zero-ingress design, but must be verified
rather than assumed.

**C3 — make the topology legible.** Already landed on 2026-08-13: the `network_group` labels now
say which L2 each node is on, and `--require-same-network` correctly rejects a mac+Linux pair.
No further work; recorded here because C2 depends on it.

## 5. Open questions for review

1. **Does `traffic_test_matrix` accept a relayed path, or does it assert directness?** If the
   stage requires a direct peer path, C makes the mesh work and the stage still red, and the
   plan is wrong. This is the single question that decides whether C is a fix at all — settle it
   from the stage implementation, not from the stage name.
2. Is C1 achievable at all, given `linux_relay_forwards_frame` has never run? Is it unimplemented,
   unreachable in the current stage graph, or merely never elected?
3. For C2, which relay placement — and does putting a lab service on the operator host violate
   the orchestrator/product separation rule?
4. Should B's Bridged→Shared migration rationale be recovered before B is ruled out? If the
   original reason no longer applies, B may be simpler and more honest than C.
5. Does the killswitch prevent a relay guest from forwarding, the way it blocks a rustynetd host
   from acting as a router? If so, C2 needs a relay that is not also a mesh node.

## 6. Definition of done

`traffic_test_matrix` passes with `macos-utm-1` in the topology, by a mechanism that is
*explained* rather than incidental; `linux_relay_forwards_frame` has executed and passed at least
once; the run-matrix row is verified against the stage's own report artifact rather than the
column; and no host firewall state was changed to achieve it.

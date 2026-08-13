# `traffic_test_matrix` fails on a vmnet L2 split — diagnosis and plan — 2026-08-13

> **REVISION 2 — adversarially reviewed. The proposed remedy was WRONG and is withdrawn.**
> The diagnosis survived; option C did not. Corrections, each verified against the tree:
>
> 1. **Option C is dead in this lab.** A relay candidate on an RFC1918 address is rejected at
>    traversal-bundle *parse* time (`rustynetd/daemon.rs:14699-14705`), and the check is called
>    with `?` inside the per-candidate decode loop (`:14402`), so it aborts the **entire bundle** —
>    not just that candidate. Every address available here is private (192.168.8/64/65/121.x).
>    Minting such a candidate would be *worse* than doing nothing: it would invalidate the
>    traversal bundle and break the Debian↔Debian paths that currently work.
> 2. **The lab cannot even express a relay candidate.** `RELAY_SPEC` has zero hits repo-wide; the
>    only issuer the lab uses emits one `Host` and an optional `ServerReflexive`, both with
>    `relay_id: None` (`ops_e2e.rs:3728`). A test at `ops_e2e.rs:7694` pins the absence.
> 3. **`traffic_test_matrix` asserts reachability only** — the §5 Q1 question, answered
>    favourably. It pings `ctx.mesh_ips` and accepts only `TrafficTestResult::Reachable`
>    (`traffic_test_matrix.rs:136`, `:148`); nothing reads a path mode, endpoint or Direct/Relay
>    decision. So a relayed mesh *would* have satisfied it — C fails on feasibility, not on
>    semantics.
> 4. **"Not a Rustynet defect" was half wrong**, and the wrong half is load-bearing. See §1.2.
> 5. **"The control plane is healthy" was overstated.** See §1.3.

**Status: PLAN (REVISION 2), reviewed. Proposed remedy is now the one-guest bridge experiment (§4).**

## 0. The failure

Sole failing stage in four consecutive runs (`rebaseline-20260813c/e/f`, `relay-coverage-20260813h`):
100% loss **both directions** between `macos-utm-1` and both Debian nodes, while the Debians reach
each other. `default-deny` reports INCONCLUSIVE — correctly, since a node that reached no peer
cannot attribute a blocked egress to policy.

## 1. Diagnosis — measured

| probe | result |
| --- | --- |
| `macos-utm-1` | one interface `en0` = 192.168.65.101, gw 192.168.65.1, UTM `backend=apple`, host `bridge101` |
| Linux guests | 192.168.64.0/24, `backend=qemu`, host `bridge100` |
| debian → 192.168.65.101 | unreachable |
| debian → **192.168.65.1** (host's own address on the other bridge) | **unreachable** |
| `traceroute` debian → macOS | dies at hop 1, no reply |
| host `net.inet.ip.forwarding` | already `1` |

Host-level isolation between two vmnet networks, not a routing gap. Permanent: a macOS guest
cannot run under QEMU on Apple Silicon, so it cannot join the QEMU vmnet.

Settles an open question this stage carried: it is **not** split-default routes capturing the
handshake — the endpoints are mutually unreachable, so no handshake is attempted.

### 1.1 The escape hatch, measured

Both planes reach the physical LAN and internet through their vmnet NATs — TCP OPEN from *each*
of `macos-utm-1` and `debian-headless-2` to `192.168.8.1:80` and `192.168.8.147:22`. So a common
dial-**out** rendezvous exists, though neither can be dialled **into** from the other.

Caveat the review added and the plan must carry: only **TCP** was measured. The relay control
port is **UDP** 4500 plus an allocated UDP range (`rustynet-relay/src/main.rs:167`, `:429`), so
UDP traversal of both vmnet NATs is **assumed, not measured**.

### 1.2 "Not a Rustynet defect" — corrected

The *immediate* failure is environmental. But three real product/tooling defects were surfaced
and must not be absolved by that sentence:

- the traversal issuer cannot express a relay candidate at all (§ Rev-2 item 2);
- the daemon's relay-session config is unreachable in every deployment — `load_relay_client`
  returns `Ok(None)` (`daemon.rs:3993`) unless env/CLI knobs that **nothing** in the repo sets;
- `linux_relay_forwards_frame` is unreachable under the default `--node` engine while its ledger
  column silently reads `not_run` — now **111 of 111 rows**.

### 1.3 "The control plane is healthy" — corrected

Four of the five macOS validations are genuine but purely **local posture** (`runtime_acls`,
`service_hardening`, `key_custody`, `dns_failclosed`); none touches peer reachability. The fifth,
`mesh_status_validation`, is **vacuous as invoked**: the orchestrator dispatches
`argv = [daemon_path, "macos-mesh-status-check"]` with no arguments
(`role_validation/mesh_status.rs:45-47`), so there is no `--expected-peer-id` and no
`--max-age-seconds`, and it passes whenever the state file exists, parses and passes integrity.
This is the "MeshStatus false-green without expected-peer-id" hazard the repo already knows.

Honest wording: *four local-posture checks pass; the fifth proves only that the state file loads.*

## 2. Options

| # | Option | Verdict |
| --- | --- | --- |
| A | Host `pf` change | **Rejected** — needs the operator's password, and is a host security-settings change. (Rev 1 also claimed vmnet re-applies rules on restart; that was **unmeasured** and is withdrawn as a reason.) |
| B | Re-home to Bridged | **PROPOSED, scoped to one guest** — see §4. |
| C | Relay between the planes | **Rejected** — `daemon.rs:14699-14705`. Not merely unhelpful: minting a private relay candidate invalidates the whole bundle. |
| D | Scope macOS out | **Rejected** — defers a release-blocking mandate. |

## 3. What the relay run did establish

`relay-coverage-20260813h` (row 111) elected `fedora-utm-1:relay` and raised coverage 21 → **24
passes**: `deploy_relay_service` pass, `relay_validation` pass, `cross_os_relay_path` pass,
`macos_stage_relay_service_lifecycle` pass. Relay **lifecycle** works.

`linux_relay_forwards_frame` remained `not_run` — confirming empirically that it is unreachable
from the `--node` engine, not merely unelected.

## 4. Proposed change — bridge ONE guest

Put **`macos-utm-1` only** on a Bridged NIC at 192.168.8.x. Not the fleet.

Rationale: the Debians already dial *out* to 192.168.8.x successfully (measured). macOS→192.168.64.4
would still fail, but WireGuard needs only **one** side to initiate — the daemon models endpoint
roaming explicitly (`traversal.rs:925 on_endpoint_roamed`, pinned by
`direct_session_survives_endpoint_roam` at `:2215`) — so a Debian-initiated handshake should
establish the session and macOS replies to the observed source.

- **Blast radius:** one guest, versus every NIC for full B. Recovery is documented
  (`scripts/vm_lab/probe_and_recover_local_utm.sh`).
- **Cost:** one NIC change + `--update-inventory-live-ips` + one ~13 min run.
- **Residual risk, stated:** `reconfigure_managed_peer` (`phase10.rs:6246-6268`) may re-program
  the configured endpoint over the roamed one. This experiment is precisely what answers that.
- **Prerequisite:** recover the Bridged→Shared migration rationale first (§5) — it is the one
  input that could invalidate both this and full B.

## 5. Prior art to reconcile

- `VmLabNetworkStandard.md:26` documents this split and asserts "the macOS guest joins over the
  host route" — **refuted** by measurement (debian cannot reach 192.168.65.1). Its stable-address
  table is also stale in four rows (macos `.2` vs `.101`; fedora `.20` vs `.103`; rocky `.22` vs
  `.105`; windows `.14` vs `.25`). Correct in the same change.
- `QH41CrossBackendL2SplitPlan_2026-08-11.md` — the predecessor; reconcile rather than duplicate.
- QH-42 — the audit's modal-plane heuristic.

## 6. Definition of done

`traffic_test_matrix` passes with `macos-utm-1` in the topology; the mechanism is confirmed by a
**separate path-evidence read** (handshake endpoint / `path_programmed_mode`), because this stage
reads no path field and a green cannot distinguish mechanisms on its own; no host firewall state
was changed. Note the stage writes **no report artifact** — its evidence is the recorder's
`stages.tsv` row plus `logs/traffic_test_matrix.log`.

## 7. Separate defects to file (out of scope here)

1. `mesh_status_validation` dispatches with no expected-peer/max-age → vacuous pass on every OS.
2. `linux_relay_forwards_frame` unreachable under `--node` while its column reads `not_run`.
3. `select_relay_forward_test_topology` ignores `include_in_all` and permits a relay whose
   `network_group` differs from both peers'; it should fail loud at selection.

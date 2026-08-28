# Windows WFP Coexistence Audit — the QH-46 defect class on Windows

**Date:** 2026-08-28
**Status: EXAMINED — audit only.** This document maps how Rustynet's Windows dataplane installs
WFP filters, enumerates the coexistence hazards against foreign WFP providers (Defender Firewall,
third-party AV), states a verdict per hazard with file:line evidence, and states the exact fix
shape for the real-and-undetected one. **It implements nothing** — no production code change, no
enforcement point, no test. It is the Windows counterpart examination that
`LiveLabStageStatus_2026-08-14.md:176-179` flagged as unexamined; it closes that flag by
**confirming a real gap** (verdict 1 below), not by clearing the Windows arm.

## Method

All evidence below was gathered by direct reads of the working tree (HEAD `6d8997f8`): a full
grep across `crates/` for the WFP surface, then line-by-line reads of every hit plus its
consumers. No external model was used (DeepSeek was out of credit, Kimi rate-limited at audit
time), so every file:line is first-hand. Every claim of the form "X does not exist" was verified
by grep (negative evidence named inline where load-bearing).

## 1. What the Windows dataplane actually installs

The entire WFP surface lives in `crates/rustynet-windows-native/src/lib.rs` (2457 lines), with
consumers in `crates/rustynetd/src/phase10.rs` and a smoke harness in
`crates/rustynetd/src/windows_killswitch_smoke.rs`. Nothing else in `crates/` touches WFP.

**Sublayer + filters** (`lib.rs:1544-1558` design comment, `lib.rs:1572-1576` stable GUIDs):

- One dedicated **persistent RustyNet sublayer** at **max weight `u16::MAX`** (`FWPM_SUBLAYER_FLAG_PERSISTENT` + `weight = 0xFFFF`, `lib.rs:1633-1634`), deliberately out-weighing the `netsh advfirewall set allprofiles firewallpolicy … blockoutbound` default-block so our permit arbitrates over Defender Firewall. Stable GUID `5b8f2a31-9c4d-4e7a-b1f0-3d6e8a2c9f44`.
- Two **hard-permit filters** (`FWP_ACTION_PERMIT` + `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) at **ALE_AUTH_CONNECT_V4** and **ALE_AUTH_CONNECT_V6** (GUIDs `…a32…` / `…a33…`), each with a **single condition**: `FWPM_CONDITION_IP_LOCAL_INTERFACE == <tunnel interface LUID>` (`lib.rs:1656-1659`, `:1661-1670`).
- The filters carry **`FWP_EMPTY` (auto) weight** — no explicit 64-bit weight (`lib.rs:1667`). Key arbitration fact: WFP ranks explicit `FWP_UINT64` filter weights **above** the u16 sublayer-weight range, so a foreign filter with an explicit high weight can outrank our permit even inside our max-weight sublayer's arbitration neighborhood.
- `PERSISTENT` on both sublayer and filters is deliberate (`lib.rs:1555-1557`): the persistent killswitch block must not outlive its persistent permit into a daemon crash, or the box is locked out.

**Apply/remove/verify:**

- `apply_wfp_tunnel_permit` (`lib.rs:1682-1719`): resolve LUID → open engine → transaction (delete-by-key both filters + sublayer, re-add all three, commit); abort + close on any error. Delete order is **filters before sublayer** (`wfp_delete_objects`, `lib.rs:1614-1626`) — reverse order fails with `FWP_E_IN_USE`. Idempotent by delete-first.
- `remove_wfp_tunnel_permit` (`lib.rs:1721-1740`): transactional delete-all.
- `wfp_tunnel_permit_present(tunnel_alias, forbidden_aliases)` (`lib.rs:1865-1899`): read-back via `FwpmFilterGetByKey0` (the ONLY enumeration-ish call used — `FwpmFilterEnum`/`FwpmSubLayerEnum`/`FwpmProvider*` appear nowhere in the tree, verified by grep) plus structural shape validation against a portable `wfp_filter_shape` module (`lib.rs:1923-2110`, compiles off-Windows; const drift pins at `lib.rs:1761-1767`). Rejects: not-PERMIT, zero conditions (a permit-all bypass), wrong field key/encoding, LUID mismatch, LUID resolving to an underlay NIC. Missing filter → `Ok(false)` → callers fail closed. This is the WIN-03 hardening (rationale comments `lib.rs:1844-1864`, `:1902-1922`).

**Dataplane integration** (`crates/rustynetd/src/phase10.rs`, Windows `DataplaneSystem`):

- `apply_firewall_killswitch` (`phase10.rs:4984-5027`): netsh default-policy `allowinbound,blockoutbound` (inbound deliberately stays allowed for management/SSH, `:4993-4999`) → loopback allow rule → `apply_wfp_tunnel_permit(interface_name)` (`:5013`; wintun adapters are not netsh-scopable, hence WFP) → scoped egress allows (RN-06: mgmt SSH CIDRs, WireGuard UDP from listen port, traversal bootstrap, `:5018-5024`). **Order: block policy lands BEFORE the permit** — the interleave window is a block, i.e. fails closed.
- `rollback_firewall` (`:5029-5060`), `apply_dns_protection` (`:5110-5170`, netsh 53-blocks on non-tunnel interfaces + NRPT), `assert_dns_protection` (`:5172-5194`, OS re-query), `hard_disable_ipv6_egress` (`:5230-5258`).
- `assert_killswitch` (`:5278-5337`): re-queries the OS for the netsh policy + rules (catches an external `netsh advfirewall reset`, `:5287-5311`), then `wfp_tunnel_permit_present(interface_name, [egress_interface])` (`:5323-5335`; missing → `KillSwitchAssertionFailed`). **It verifies only OUR objects' existence and shape — it never proves passability and never sees foreign filters.**
- `block_all_egress` (`:5374-5398`): killswitch re-apply, then explicitly `remove_wfp_tunnel_permit` + delete TUNNEL/EGRESS rules so only loopback survives — the comment at `:5377-5381` notes skipping the WFP removal would make block-all **fail open**. Ordering is correct.
- `assert_exit_serving` (`:5343-5372`): nat_applied gate + assert_killswitch + NetNat + forwarding verification.

**The hole this audit is about** — Windows `admit_host_firewall_forwarding` (`phase10.rs:4870-4876`), verbatim:

> "firewalld is Linux-only. The Windows analogue of this defect class (a foreign WFP filter at a
> competing weight discarding authorised forwarded traffic) is tracked in the parity plan; when it
> gains an enforcement point, it belongs here."

…returns `Ok(())`. `withdraw_host_firewall_forwarding` (`:4878-4882`) is the paired no-op. The
QH-54 periodic posture loop (`daemon.rs:497` `HOST_FIREWALL_ADMISSION_ASSERT_INTERVAL_SECS = 30`;
`daemon.rs:10366-10418` `maybe_reassert_host_firewall_admission`; `phase10.rs:6416-6439`
`reassert_host_firewall_admission` → on Err: fail-closed rollback) therefore runs **vacuously on
Windows**: a no-op `Ok(())` can never trigger the fail-closed arm, so nothing periodic detects any
Windows-side discard. Linux's real implementation (firewalld zone verify+re-assert,
`phase10.rs:1145-1177`, fail-closed on reject) has **no Windows counterpart**.

## 2. Verdicts

| # | Hazard | Verdict |
|---|--------|---------|
| 1 | Foreign WFP provider (3rd-party AV / higher-weight filter) silently discards **forwarded exit traffic** while the daemon reports exit-serving | **REAL AND UNDETECTED** |
| 2 | Foreign higher-weight block defeats the client **tunnel-permit** at ALE_AUTH_CONNECT_V4/V6 | **REAL, undetected at run time; bounded by fail-closed direction** |
| 3 | Our own WFP permit removed mid-run (`netsh wfp reset`, engine flush) | Detected (fail-safe) — **only at next transition/assert, not periodically** |
| 4 | Our netsh killswitch rules/policy wiped mid-run (`netsh advfirewall reset`) | Detected at next assert (OS re-query); exposure window until then |
| 5 | Foreign inbound block discards WireGuard handshakes | Marginal — indistinguishable from peer-down, fails closed |
| 6 | Apply/rollback ordering hazards | Not applicable — ordering verified correct, fail-closed throughout |
| 7 | Missing Windows rule-text precedence analyzer | Not applicable by design — WFP arbitrates by weight, not rule text |

### Verdict 1 — forwarded exit traffic discarded by a foreign filter: REAL AND UNDETECTED

This is the exact QH-46 class. On Windows, exit-serving forwards through NetNat
(`apply_nat_forwarding`, `phase10.rs:5062-5075`) which installs **no forwarded-layer WFP
filters of its own** — it relies on the absence of a foreign block, never asserting one way or
the other. The detection half of the Linux QH-46 fix (verify the firewall posture, re-assert,
fail closed on rejection) is wired to `admit_host_firewall_forwarding` through the QH-54 loop,
and on Windows that hook is a self-documented no-op (`phase10.rs:4870-4876`). The periodic loop
therefore cannot fire on Windows regardless of what a foreign provider does. Nothing anywhere in
the tree enumerates foreign WFP state (no `FwpmFilterEnum` — verified by grep). A third-party WFP
provider that REJECTs forwarded traffic would leave every Rustynet assertion green while exit
traffic dies — the exact silent-discard signature QH-46 produced on Linux for months.

The code itself concedes the gap: the comment at `phase10.rs:4870-4876` says the enforcement
point "belongs here" and defers it. Nobody has come back for it.

### Verdict 2 — foreign higher-weight block vs the client tunnel-permit: REAL, undetected at run time

Our sublayer sits at max u16 weight (`lib.rs:1634`), which out-weighs Defender Firewall's
outbound default-block (the common case, deliberately handled per `lib.rs:1551-1553`). But WFP
arbitration ranks **explicit 64-bit filter weights above the u16 sublayer range**, and our own
filters use `FWP_EMPTY` auto-weight (`lib.rs:1667`) — so a third-party AV provider that pins an
explicit high weight on an outbound block at ALE_AUTH_CONNECT can outrank our permit. `assert_killswitch`
runs only at apply/transition call sites (`phase10.rs:655,658,928,3193,3213,4243,5340,5350` +
dispatch `:5631-5634`), **not periodically** — the periodic tick touches only the (vacuous on
Windows) firewall-admission assert and heartbeats (`daemon.rs:10366-10371`). Between transitions,
such a block is undetected.

Bounded: the ambient posture is default-block-outbound, so foreign interference here tends to
fail **closed** — traffic is discarded (availability loss), not leaked. Residual risk is
therefore an availability defect, not a confidentiality one, and it is strictly smaller than
verdict 1 (which is also a correctness lie: the node reports exit-serving while discarding).

### Verdict 3 — our own permit removed mid-run: detected, but only lazily

`wfp_tunnel_permit_present` returns `Ok(false)` on a missing filter (`lib.rs:1865-1899`) and
`assert_killswitch` converts that to `KillSwitchAssertionFailed` (`phase10.rs:5331-5335`) — the
node then fails closed. But the assert runs only at transitions; `netsh wfp reset` between
transitions is invisible until the next one. Persistent flags keep the crash case safe by design
(`lib.rs:1555-1557`). Availability-only loss.

### Verdict 4 — netsh policy/rules wiped mid-run: detected at next assert

`assert_killswitch`'s PowerShell re-query (`phase10.rs:5287-5311`) and `assert_dns_protection`
(`:5179-5183`) both re-read live OS state and catch an external `netsh advfirewall reset`. Same
cadence caveat as verdict 3, plus the window between reset and next assert has the killswitch
gone (outbound open). That is the classic loss-of-killswitch window shared by every OS; the
QH-46 class itself is verdicts 1-2.

### Verdict 5 — foreign inbound block vs handshakes: marginal

We set `allowinbound` (`phase10.rs:4993-4996`); a third-party higher-weight inbound block would
discard handshakes but is indistinguishable from a down peer and fails closed. Same class as
verdict 2, lesser. No detection either — noted for completeness.

### Verdict 6 — ordering hazards: not applicable (verified correct)

- Block-before-permit apply window fails **closed** (`phase10.rs:4984-5027`).
- `block_all_egress` explicitly removes the WFP permit, avoiding the fail-open the code itself
  warns about (`phase10.rs:5374-5398`, comment `:5377-5381`).
- Persistent sublayer + filters prevent a crash leaving block-without-permit lockout
  (`lib.rs:1555-1557`).
- `wfp_delete_objects` orders filters before sublayer (`lib.rs:1614-1626`); reverse fails
  `FWP_E_IN_USE`.

### Verdict 7 — no Windows rule-text precedence analyzer: not applicable by design

`killswitch_precedence.rs` (`crates/rustynetd/src/killswitch_precedence.rs`) is an nft
**text** evaluation-order analyzer (Linux-only by construction: `:168`, `:205`, `:442`). WFP has
no readable rule file — arbitration is engine-side weight comparison — so the correct Windows
analogue is **foreign-filter enumeration/arbitration analysis**, which does not exist anywhere in
the tree (no `FwpmFilterEnum` — verified by grep). That absence is exactly verdict 1's detection
gap.

## 3. Exact fix shape (NOT implemented)

For verdict 1 — the load-bearing one — mirror the Linux QH-46 posture at the reserved spot
`phase10.rs:4870`:

1. Give the Windows arm of `admit_host_firewall_forwarding` a real enforcement point: enumerate
   foreign filters at the layers exit traffic traverses (NetNat forward path; the ALE layers) —
   `FwpmFilterEnum` scoped to sublayers of interest — or, cheaper and closer to the Linux
   verify+re-assert posture, detect a foreign block at or above our arbitration weight and
   **treat it as the Linux firewalld-reject case**: return Err.
2. No new plumbing needed beyond that: `reassert_host_firewall_admission`
   (`phase10.rs:6416-6439`) already dispatches per-platform and already fail-closes on Err
   (rollback + `force_fail_closed("host_firewall_admit_failed")`), and the QH-54 loop
   (`daemon.rs:10366-10418`) already drives it every 30 s on an exit-serving node. The no-op
   returning `Ok(())` is the only thing keeping that machinery inert on Windows.
3. The firewalld fix's discipline carries over: argv-only privileged helpers, no shell
   construction, fail closed when WFP state is unreadable (mirror `FirewalldPosture`'s
   unknown-presence-is-treated-present rule, `phase10.rs:6399-6415`), and a verification test per
   the security-control rule.

For verdict 2, the narrower shape: extend the periodic posture tick (or the transition asserts)
to additionally read back arbitration-relevant foreign state at the tunnel-permit layers, or
pin explicit high `FWP_UINT64` weights on our own filters so they cannot be outranked inside
their own weight class — a one-line change at `lib.rs:1667` plus shape-validation updates in
`wfp_filter_shape`.

## 4. Provenance

- Audit scope: working tree at `6d8997f8`, branch `ai-edit/edit-1787933835041-56044-15`.
- All file:line references first-hand reads; negative claims ("no `FwpmFilterEnum` anywhere")
  verified by grep at audit time.
- Companion records: QH-46 ledger entry (`QualityHardeningTodo_2026-07-25.md`, 2026-08-14 fix),
  `LiveLabStageStatus_2026-08-14.md:176-179` (the flag this document closes),
  `phase10.rs:4870-4876` (the self-documented gap).

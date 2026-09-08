# MeshStatus Peer Expectation Design — Adversarial Review — 2026-09-08

Status: UNTRUSTED adversarial review (docs-only; no code changed). Reviews `MeshStatusPeerExpectationDesign_2026-09-08.md` (QH-81 daemon-side fix). Every claim below was re-verified against the current tree by reading the cited code.

## Verdict: BUILD-WITH-CHANGES

The defect statement is **true** (verified line-by-line below) and the design's core moves — honest field names, a real peer-id source, no dual-read window, an execute-level vacuous-pass guard — are correct and directly answer the `d944c700` lesson. But the design misses an **already-shipped, already-proven mechanism that solves QH-81 on the orchestrator's terms** (the macOS `expected_node_ids` signed-membership check, `macos_mesh_status.rs:162-208` + `role_validation/mesh_status.rs` `--expected-node-id` dispatch), its premise that "a snapshot key is the only honest path" is **factually wrong** (§2 bullet 3), and its OD1 consequence ("one-time restore failure") **materially understates the blast radius** — I verified the restore-failure posture is `restrict_permanent` + fail-closed (`daemon.rs:8683-8688`), which on the persistent lab guests is exactly the "fails a stage on every multi-node run" shape that killed `d944c700`.

Blocking changes: **B1** (weigh/adopt the membership-port alternative), **B2** (OD1 posture + lab state-file lifecycle), **B3** (schema_version bump + `rebuild_nodes` mixed-build handling). Nice-to-have: **N1–N4**.

## A. Is the problem statement true? — YES, verified

Every citation checked against the tree:

- `daemon.rs:10302-10317` — `persist_state` builds `SessionStateSnapshot { peer_ids: self.advertised_routes.iter().cloned().collect() }`. **Confirmed**: the field holds route CIDRs.
- `resilience.rs` — struct at `:33-38` (`pub peer_ids: Vec<String>`), serialized as `peer_ids=` (`:105-107`), parsed at `:163-177`, missing key → `InvalidFormat` (`:213`, the `ok_or` chain). **Confirmed**; the parser rejects unknown lines (`:635-648` load test) and is digest-protected (plain SHA-256 of the body — unkeyed, i.e. integrity-not-authenticity, consistent with "local privileged state" threat model).
- All three collectors copy `snap.peer_ids` verbatim: `linux_mesh_status.rs:59`, `macos_mesh_status.rs:145`, `windows_mesh_status.rs:110`. **Confirmed.**
- The expectation mechanic is correct-but-starved: `windows_mesh_status.rs:179-185` (`for expected in expected_peer_ids { if !peer_ids.iter().any(|p| p == expected) … }`); same call on Linux (`:76-80`) and macOS (`:209-213`). **Confirmed** (design said `:179-182`; actual `:179-185` — immaterial).
- `validate_runtime.rs:54-76` — `probe_expectations(MeshStatus)` emits only `--max-age-seconds 180`. **Confirmed.** The stage doc comment (`:54-64`) itself documents the defect and defers to QH-81.
- `main.rs` already parses `--expected-peer-id` on all three subcommands (`:1001/:1017/:1047`, `:1625/:1641/:1669`, `:1839/:1857/:1899`) and `--expected-node-id` on the macOS one (`:1841-1901`). **Confirmed** — orchestrator-side emission has zero CLI-plumbing cost, as claimed.
- `phase10.rs:8794` — `pub fn managed_peer_ids(&self) -> Vec<NodeId>` over `managed_peers: BTreeMap<NodeId, ManagedPeer>` (`:7363`). **Confirmed.**

The characterization of the reverted `d944c700` attempt matches `MeshStatusEvidenceReview_2026-09-08.md` (commits `e5a8f71b`/`d944c700`/`dee283aa`). No misread found. The numbers in the design are accurate — unlike several recent docs flagged for confident miscounts.

## B. Does the chosen option beat the rejected alternatives? — INCOMPLETE: the strongest alternative is never weighed

The design rejects keep-name/change-content (correct — `restore_state` (`daemon.rs:10399-10415`) reads `peer_ids` back into `advertised_routes`; changing content under the name would corrupt restore) and add-only (correct — perpetuates the lie). But §2 bullet 3 asserts: *"the collectors are probe-mode binaries that read the persisted snapshot file … they have no other channel to daemon state. A snapshot key is the only honest path. (Other IPC channels: UNVERIFIED — none observed in the three collectors)."*

**This is false.** The macOS collector reads a *second*, independent channel today: the **signed-membership snapshot** (`macos_mesh_status.rs:162-208`, `load_membership_snapshot` from `rustynet-control::membership` — platform-neutral, `daemon.rs:140-145`), verifies node ids against the verified ACTIVE roster, and **fails closed** when membership is unreadable (`macos_mesh_status.rs:189-207`). And the dedicated `mesh_status_validation` stage **already emits the orchestrator-side expectation**: `role_validation/mesh_status.rs` dispatches `--expected-node-id node-9` when the orchestrator knows the slot's id, and fails closed on an unverified roster (its own tests: `macos_dispatch_carries_expected_node_id_when_known`, `macos_dispatch_fails_closed_when_membership_unavailable`). The membership snapshot path exists for all platforms (`daemon.rs:223/226/228`: macOS `/usr/local/var/rustynet/membership/membership.snapshot`, Linux `/var/lib/rustynet/membership.snapshot`, Windows equivalent).

So the capability QH-81 asks for — "the orchestrator can express a peer expectation that the daemon can honestly satisfy" — **already exists end-to-end on macOS**. The linux/windows gap is a *port* of `macos_mesh_status.rs:162-208` plus extending the `mesh_status_validation` dispatch pattern to `validate_runtime.rs`. That option:

- touches **no** session-snapshot format → **no OD1 at all** (no restore-failure cliff, no lab state wipe, no `d944c700`-shaped risk);
- reuses a mechanism already live-proven on macOS with fail-closed semantics and existing tests;
- asserts presence against **signed, replay-protected** state (watermark checks are in the same import set) rather than the unkeyed-SHA-256 key/value snapshot — strictly stronger provenance for "these are the peers this node should see".

The design's counter-argument would be that OD2's phase10 peer table is preferable because it matches what the live-handshake poll reads. That is a real semantic difference — verified-roster-presence vs programmed-WG-peer-presence — but the design never states it, because it never noticed the membership channel exists. **B1 (blocking): rewrite §2 bullet 3 and §8 OD2 to weigh the membership-port option. My recommendation: make the membership port THE QH-81 fix (it closes the orchestrator-expectation gap on all three platforms with the smallest risk surface), and demote the `managed_peer_ids` snapshot/report change to a separately-gated follow-up that adds the WG-peer-table assertion for the platforms that want it.** If the owner prefers the design's option, the membership alternative must be rejected with a stated reason, not by omission.

## C. Fail-closed — mostly sound, one consequence understated

- Absent old file / new daemon → `InvalidFormat` (`resilience.rs:213` pattern). **Confirmed fail-closed.**
- Tolerated-unknown-lines means an old daemon reading a new file fails too (requires `peer_ids=`). **Confirmed.**
- Empty `advertised_route_cidrs` legitimate; empty `managed_peer_ids` drift-caught on multi-node. Reasonable.
- **OD1 is worse than the design says.** §3/§8 call the rename consequence "one-time restore failure per node after upgrade" and leave the posture UNVERIFIED. I verified it: `daemon.rs:8683-8688` — `restore_state` Err → `restrict_permanent("state restore failed integrity checks")` + `force_fail_closed_or_restrict("state_restore_integrity_failed")`. That is not a soft one-time cost: the node comes up permanently restricted and every baseline validator (MeshStatus *and* the freshness bound, which deliberately reads a stopped heartbeat) goes red. Lab guests persist state files across runs (`/var/lib/rustynet/rustynetd.state` et al.), so the **first post-change run fails every pre-existing guest** until each state file is removed. **B2 (blocking): if the snapshot change proceeds, the design must specify the lab migration — state-file deletion at deploy (orchestrator prepare/bootstrap step) or an explicit documented one-run wipe — and state the verified posture (`restrict_permanent`, `daemon.rs:8683`) in OD1(a).** This is precisely the mechanism by which `d944c700` failed Setup/T0Core on every multi-node run; the design's own test 6 would catch it at execute level, but only after burning the run.
- "Set by someone who should not": correct — expectations are orchestrator argv derived from orchestrator-held state; the report is read-only evidence.
- The vacuous-pass trap (§4 last bullet): a report lacking `managed_peer_ids` on multi-node must fail the stage. **Correct and the single most valuable item in the design** — it is the guard whose absence made `d944c700` invisible. But see B3: key it on schema_version, not on field-absence sniffing.

## D. Is it implementable as written? — yes, with three unstated blockers

1. **`probe_expectations` signature.** It is `fn(op: DaemonProbeOp) -> Vec<String>` (`validate_runtime.rs:65`) and is invoked without context (`:178`) and in tests (`:337`). Emitting per-non-self ids requires `(op, ctx, alias)` plumbing through `dispatch_argv` and both test helpers. Trivial, but the design never says it — state it.
2. **Identity string space.** `ctx.node_ids` values are daemon-reported node ids (`collect_pubkeys.rs:128`, from the daemon's own `node_id` answer — a good property: both ends speak the daemon's identity vocabulary). `managed_peer_ids()` returns `NodeId` keys of the WG peer table (`phase10.rs:7363`, backend-API type, `:161`). The design's OD2 flags the *access path* as UNVERIFIED but not the *string space*: if `NodeId`'s display form differs from what the daemon reports as its node id, every expectation misses and the change IS `d944c700` again. **B3a (blocking, part of B3): add an explicit verification step — one execute-level test or the gating live-lab run must prove emitted ids match `managed_peer_ids` strings on a healthy 2-node mesh — before the rename lands.**
3. **Version skew is real, not "one commit boundary".** §3 dismisses versioning because report and consumer update together. True for a full run — false for the repo's own fast-verify loop: `rebuild_nodes` redeploys *some* nodes and deliberately leaves others on the old build, so one run can carry old daemons producing old reports (`peer_ids`, no `managed_peer_ids`, `schema_version: 1`). The absence-guard then reds healthy nodes with a misleading "lacks managed_peer_ids" message. The reports carry `schema_version` for exactly this, pinned by tests (`linux_mesh_status.rs:485-498`; the linux validator already rejects "unsupported schema_version"). **B3b (blocking): bump report `schema_version` to 2 on all three reports and make the orchestrator's guard test the version — a v1 report on a multi-node context fails with an explicit stale-daemon-build message.** This also answers the mixed-version question directly: an old daemon cannot produce an empty new field that reads as a pass, because the version gate fires first.

Not blocking: the mesh-status report is generated and consumed within one run's binary set, so there is no cross-run wire-compat problem beyond the above; `--no-fail-on-drift` interplay is unchanged; shell-safety of ids in argv is already enforced (`dispatch_argv_rejects_a_non_shell_safe_extra_argument`).

## E. What did it miss?

- **The macOS membership channel** (B1 above) — the biggest miss; it changes the recommended shape of the fix.
- **Restore-failure posture** (B2) — flagged UNVERIFIED, now verified worse than assumed.
- **`rebuild_nodes` mixed builds** (B3b) — the design's versioning dismissal ignores the efficiency plan's primary loop.
- **Overlap on macOS after the fix**: macOS would carry *both* `expected_peer_ids`-vs-`managed_peer_ids` *and* `expected_node_ids`-vs-membership — two overlapping presence assertions with two different state sources. Fine, but the design should say the macOS check surfaces stay and which one `validate_runtime.rs` emits (it cannot emit both flags from one `probe_expectations` without deciding).
- **OD3 scoping is right**: `evaluate_linux_mesh_status_report` (`vm_lab/mod.rs:23631-23656`) reads `overall_ok`/`expected_peer_ids` by field name; the design's rename keeps `expected_peer_ids` as the echo field, so the legacy evaluator keeps compiling and its pinned tests hold — deferring it as a QH-81 follow-up is coherent, and the field rename does not silently break it.
- **Single-node vacuous pass** is honestly documented (no peer to expect). Agreed — not permissive.

## F. Effort and counts — believable, conditionally

3–4 days for the design's option is plausible-to-slightly-optimistic: the three collectors carry ~400 lines of tests that pin `peer_ids` shapes (Linux alone has ~30 tests constructing `WindowsMeshSnapshotLoad::Ok { peer_ids: … }`), plus `resilience.rs`/`daemon.rs` persist+restore tests, plus the orchestrator guard and emission tests. The grep-sweep line item is necessary — `windows_mesh_status::WindowsMeshSnapshotLoad`'s `peer_ids` variant field is consumed by every Linux test. Under the B1 membership-port option the estimate likely *shrinks* (no format change, no OD1, no collector shape churn — macOS code is the template), which is itself evidence for B1.

## Required-changes summary

Blocking:
1. **B1** — Weigh the existing macOS signed-membership expectation mechanism (`macos_mesh_status.rs:162-208` + `--expected-node-id` dispatch in `role_validation/mesh_status.rs`) as the QH-81 fix; recommend adopting the linux/windows port of it as the primary fix and demoting the snapshot `managed_peer_ids` change to a separate follow-up. If rejected, reject it with a stated semantic reason (roster-presence vs programmed-peer-presence), not omission.
2. **B2** — If the snapshot change proceeds: record the verified restore-failure posture (`restrict_permanent` + fail-closed, `daemon.rs:8683-8688`) and specify the lab state-file migration/wipe; otherwise the first post-change run fails every persistent guest — the `d944c700` shape the design is sworn not to repeat.
3. **B3** — Bump report `schema_version` to 2 and gate the orchestrator's vacuous-pass guard on it (explicit stale-build failure); add the identity-string-space proof (emitted ids match `managed_peer_ids` on a healthy 2-node mesh) as a landing requirement.

Nice-to-have:
4. **N1** — State the `probe_expectations` signature change (`op` → `op, ctx, alias`).
5. **N2** — Say explicitly which expectation flag macOS dispatches post-fix (avoid two overlapping assertions with no owner).
6. **N3** — Note the snapshot digest is unkeyed SHA-256 (integrity-not-authenticity) where the membership snapshot is signed — relevant to OD2's provenance argument.
7. **N4** — Correct §2 bullet 3's "no other channel" wording regardless of the chosen option; correct `windows_mesh_status.rs:179-182` → `:179-185`.

The design is worth building — its fail-closed instincts and the execute-level vacuous-pass guard are exactly right. Land it after B1–B3, and prefer the membership port unless the owner specifically needs the WG-peer-table assertion.

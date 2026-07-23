# Cross-Platform Role Parity — `--node`-Native Refresh — 2026-07-23

**Status:** DRAFT (grounded 2026-07-23; adversarial review pending). This refresh
re-scopes the release-blocking parity mandate to the **engine of record** — the
Rust `--node` orchestrator, which the `NodeEngineAcceptanceSpec_2026-07-23.md`
**G2 (parity attainment → release)** gate reads. It supersedes the *status* half of
`CrossPlatformRoleParityPlan_2026-06-21.md` §3 and `CrossPlatformRoleParityRoadmap_
2026-06-22.md` for the G2 era; those two docs remain the historical **bash** record
and the per-cell design detail.

Mandate unchanged: every role + capability (client, admin, anchor, exit,
blind_exit, relay, + nas/llm) must be LIVE-LAB-PROVEN on macOS **and** Windows, not
just Linux. What changed is *what counts as proven*.

---

## 0. The reframe — bash-proven ≠ G2-proven

The existing ParityPlan §3 matrix shows most macOS/Windows cells ✅. **Every one of
those ✅s cites a run in the frozen bash archive (`live_lab_run_matrix.csv`); none
is in the `--node` ledger (`live_lab_node_run_matrix.csv`).** Since G2 reads the
`--node` ledger and bash is being deleted (Track D / W5.7), the bash proofs **do
not count toward release.** On the engine of record:

- `--node` ledger: **88 rows, zero overall `pass`** (81 fail / 7 partial).
- **Cross-OS is 0-proven:** `live_mixed_topology_validation` (the `--node` cross-OS
  carrier per AcceptanceSpec §3-T3) has **never gone green** (0/88).
- **Windows is 0-proven and cannot even bootstrap on `--node`** (every
  `windows_stage_bootstrap` row = fail).
- **macOS is partially stage-green** (admin, relay-lifecycle, core, security stages
  pass in isolation) but **no macOS run passes overall** — `two_hop` fails every
  time, and exit/blind_exit/anchor were never elected onto a macOS `--node`.

Both old docs also record their Definition-of-Done evidence against the **bash
archive** (ParityPlan §5/§8; Roadmap §10) — a stale pointer for G2.

**Net:** the honest G2 status is *far* less green than the ParityPlan implies. This
refresh states the `--node` reality and sequences the work to close it.

## 1. `--node`-native status matrix (the G2 picture, 2026-07-23)

Legend: 🟢 stage-green on `--node` (isolated) · 🔴 fails on `--node` · ⬛ never
elected/run on `--node` · 🔒 blocked (hardware/env) · 🚫 out-of-scope by design.
Linux = the reference: 24/25 green on `--node`, sole fail `network_flap` (§3).
Every cell here is "as proven on `--node`," independent of the bash archive.

| Role | macOS (`--node`) | Windows (`--node`) |
|---|---|---|
| **client** | 🔴 `two_hop` fails → `macos_client=fail` | ⬛ bootstrap never green |
| **admin** | 🟢 `macos_admin=pass` (`livelab-1784501586`, commit `537e1901`, clean) — run overall failed on `two_hop` | ⬛ bootstrap blocker |
| **relay** (lifecycle) | 🟢 `macos_stage_relay_service_lifecycle=pass` (`livelab-1784497253`, `11620a6`, clean) | ⬛ / 🟠 SCM contract only |
| **relay** (frame-forwarding) | 🔒 HP-3 (unproven on ALL OS) | 🔒 HP-3 |
| **anchor** | ⬛ never elected on `--node` | ⬛ never exercised |
| **exit** | ⬛ never elected on `--node` | 🔒 WinNAT hardware (§4) |
| **blind_exit** | ⬛ never elected on `--node` | 🚫 out-of-scope by design |
| **role-transition** | ⬛ never run on `--node` | ⬛ never run on `--node` |

**Crucial nuance: the stages EXIST.** The `--node` registry already carries
`validate_macos_admin_issue`, `validate_macos_relay_service_lifecycle`,
`validate_macos_exit_nat_lifecycle`, the `validate_windows_*` trio, and
`live_mixed_topology_validation` (`live_lab_stage_registry.rs:~1031-1369,1906`). The
gap is **running them green**, not missing stages — which is why the critical path
(§2) is about clearing blockers and *electing* roles, not authoring validators.

## 2. Critical path — three blockers gate everything

Nothing macOS/Windows can be G2-proven until these clear. Two are code, one is
hardware; a fourth (Windows bootstrap) must be triaged.

- **CP-1 (code) — `two_hop` / client↔client on `--node`.** `two_hop` fails on macOS
  **and** Linux → `traffic_test_matrix=fail`, so no macOS run passes overall and the
  macOS `client` cell is red. Diagnosed (see the client↔client memory) as a
  **userspace shared-socket WireGuard transport-handshake** bug
  (`path_live_peer_count=0`), NOT an ACL/policy problem. **Highest-value code
  blocker for the whole macOS column** — it cascades into every macOS run's overall
  verdict. Owning fix is core-dataplane (`rustynet-backend-userspace` shared socket
  / daemon `initiate_peer_handshake`), §13.2 security-sensitive.
- **CP-2 (code) — `network_flap` / traversal self-sustenance.** The sole Linux
  `--node` fail and a real production gap (mesh fail-closes ~120 s after the last
  distribution). Approved design + in-flight implementation in
  `TraversalSelfSustenancePlan_2026-07-23.md` (I1/I2 merged; I3-I6 remain). Per
  AcceptanceSpec §6/B6 it must be RED-for-the-right-reason for **G1** (already true)
  and GREEN for **G2**. Gates the resilience tier on every OS.
- **CP-3 (hardware) — Windows exit WinNAT.** `promote_windows_exit_active` is
  code-complete but needs `MSFT_NetNat`/HNS, which **cannot run in UTM on Apple
  Silicon** — requires a physical Windows-11-Pro/Ent-on-ARM device (CompletionBrief
  §8.1). External blocker; owner task. Blocks only the Windows *exit* cell.
- **CP-4 (triage) — Windows `--node` bootstrap fails.** Every `windows_stage_
  bootstrap` row (2026-07-19) failed, which blocks **all** Windows `--node` cells
  (not just exit). Root cause **unverified** — code vs guest health. Must be
  triaged first; it is the single gate in front of the entire Windows column.

## 3. Ordered program (dependency-sequenced)

1. **Clear CP-1 (`two_hop` client↔client handshake).** Unblocks the macOS column's
   overall verdict and the Linux client-mesh. Core-dataplane, security-sensitive —
   the single biggest lever for macOS parity.
2. **Land CP-2 (`network_flap`/traversal).** Finish `TraversalSelfSustenancePlan`
   I3-I6, live-verify green. Unblocks the resilience tier on all OSes.
3. **Triage + fix CP-4 (Windows `--node` bootstrap).** Determine code vs guest;
   until this is green, the Windows column cannot be exercised at all.
4. **Elect + prove the macOS roles on `--node`.** Stages exist; admin/relay already
   stage-green. Add election + green runs for macOS `exit`, `blind_exit`, `anchor`,
   and `role-transition` (drive them onto a macOS `--node` via the role-platform
   selectors / `--macos-promote-exit`). Two-consecutive-valid-green per
   AcceptanceSpec §5.4.
5. **Prove cross-OS on `--node`.** Get `live_mixed_topology_validation` green
   (Linux + macOS + Windows all present) — currently 0/88; the whole cross-OS bar
   rides on it.
6. **Prove the Windows roles on `--node`** (once CP-4 clears): admin, anchor,
   relay-lifecycle, role-transition. Windows `exit` waits on CP-3 (hardware).
7. **Parked, tracked as deferred-with-reason** (AcceptanceSpec §6.1): relay
   frame-forwarding (HP-3, all OS), Windows `blind_exit` (design-excluded), nas/llm
   (D13 program).

## 4. Blockers — environmental vs code

| Blocker | Kind | Owner | Notes |
|---|---|---|---|
| CP-1 `two_hop` client↔client handshake | **code** | dataplane | userspace shared-socket WG transport; §13.2 |
| CP-2 `network_flap` traversal self-sustenance | **code** | traversal track | I3-I6 of the traversal plan |
| CP-4 Windows `--node` bootstrap | **triage** | TBD | code-vs-guest unverified; gates all Windows |
| CP-3 Windows exit WinNAT | **hardware** | operator | physical Win-on-ARM device; not fixable in UTM/ASi |
| Fedora passwordless-sudo + host-route sudo | environmental | operator | CompletionBrief §8.3-8.4 |
| Healthy macOS/Windows guests | environmental | operator | CompletionBrief §8.2 (repair, not rebuild) |

## 5. §5.2 platform-adapter gaps — current status

- **mac/win role evaluators:** macOS `admin` + `relay` evaluators pass on `--node`;
  `exit`/`blind_exit`/`anchor` macOS evaluators exist but were never elected.
  Windows evaluators all blocked behind CP-4.
- **anchor gossip_seed:** the gossip **substrate now exists in the production
  daemon** (commits `001cc97`→`e804723`, post-roadmap — construct/attach gossip
  runtime, register peers from membership, epoch-bind bundles). No live anchor-gossip
  proof yet, so the *cell* stays unproven, but the roadmap's "unbuilt" framing is
  outdated.
- **anchor enrollment_endpoint:** ParityPlan §10 says "zero runtime enforcement";
  **unverified** whether the gossip-runtime work touched it — triage before scoping.
- **Windows authoritative port mapping:** still open (no `windows_membership_
  capabilities` equivalent).

## 6. Intended OS divergence — NOT parity holes (drift-direction rule)

These are legitimate per-OS differences; do not force uniformity or treat as gaps
(AcceptanceSpec §8 — bash is never the oracle, and neither is Linux):

- **Windows `blind_exit`** — hard-excluded by design (`main.rs` hard-error). 🚫.
- **macOS exit ≡ blind_exit dataplane** — macOS Exit maps to enforce-time `pf` NAT
  (anchor hard-locked), so the activate→assert→NAT-session shape doesn't apply;
  macOS keeps a fail-closed default for the client-egress NAT-session assertion
  (ParityPlan §11). Lifecycle proven; per-session translation is a scoped
  macOS-model follow-up, not a bash-parity failure.
- **Custody / dataplane / service-manager**: DPAPI vs Keychain vs encrypted-file;
  WFP + WinNAT vs `pf` vs nft; SCM vs launchd vs systemd. All intended.
- **Windows admin custody verbs** — `trust keygen`/`trust issue` (DPAPI) vs unix
  `assignment init-signing-secret`/`issue`; the unix verbs don't exist on Windows.
- **`cross_os_*` CSV columns** — bash-dialect aggregates, not `--node` StageIds;
  cross-OS on `--node` = `live_mixed_topology_validation` (A1 drift-correction).

## 7. Stale-doc corrections to apply (to the old plan + roadmap)

- **ParityPlan §3 matrix** — every ✅ is bash-proven; re-scope to two columns
  (bash-proven vs `--node`/G2-proven) or annotate each cell with its engine.
- **DoD evidence pointers** (ParityPlan §5/§8; Roadmap §10) — change from
  `live_lab_run_matrix.csv` (frozen bash archive) to
  `live_lab_node_run_matrix.csv` (the G2 ledger).
- **Roadmap operating model (§6/§8/§9)** — written around the bash orchestrator
  (`--legacy-bash-orchestrator`, `--macos-vm`, chaos3); re-express in `--node` terms
  (CompletionBrief §5 + AcceptanceSpec).
- **"macOS admin/relay need a live stage"** (Roadmap §6 Cells 1/5) — stale in the
  *other* direction: these now exist and pass stage-level on `--node` (`537e190`,
  `bbcb1f9`/`b519220`). The blocker is CP-1 (`two_hop`), not the stage.
- **`anchor_validation` reds** in older ledger rows — a resolved `nc`-absence
  transient (`a8c5ed7`/`ae678de`/`dff628d`, 2026-07-22), not a standing regression.
- **`main.rs` blind_exit line cite** — drifted (Roadmap `11768` vs ParityPlan
  `11833`); re-cite when touched.

## 8. Mapping to the acceptance spec

- This refresh **is** the G2 (parity attainment) work; G2 gates **release**, not the
  lab default flip (that's G1, the flip track).
- Each cell's "proven" means green under a **valid `--node` run** (AcceptanceSpec §4
  evidence properties, recomputed by the independent verifier / §4.8) with the
  **two-consecutive-valid-green** stability rule (§5.4).
- `network_flap` (CP-2) is the one cell explicitly allowed RED for G1 and required
  GREEN for G2 (§6/B6).
- Parked cells (§3 step 7) use the fenced disposition process (AcceptanceSpec §6.1):
  named ledger, per-item owner sign-off, expiry.

## 9. References

- Historical bash record + per-cell design: `CrossPlatformRoleParityPlan_2026-06-21.md`,
  `CrossPlatformRoleParityRoadmap_2026-06-22.md`.
- The G2 bar: `NodeEngineAcceptanceSpec_2026-07-23.md`.
- CP-2 design: `TraversalSelfSustenancePlan_2026-07-23.md`.
- Adapter gaps + lab prereqs: `RustNodeOrchestratorCompletionBrief_2026-07-12.md`
  (§5.2, §8).
- Evidence ledger (G2): `documents/operations/live_lab_node_run_matrix.csv`
  (88 rows; 0 overall pass; macOS admin pass @ `livelab-1784501586`; relay-lifecycle
  pass @ `livelab-1784497253`; Windows bootstrap fail rows @ 2026-07-19).
- Stage vocabulary present on `--node`: `crates/rustynet-cli/src/live_lab_stage_registry.rs`.

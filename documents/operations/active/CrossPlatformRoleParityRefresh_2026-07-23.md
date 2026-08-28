# Cross-Platform Role Parity — `--node`-Native Refresh — 2026-07-23

**Status:** DRAFT (grounded + **adversarially reviewed** 2026-07-23; verdict
"sound-with-fixes," all folded in). The reframe (bash-proven ≢ G2-proven; mac/win
~0% on `--node`) was verified clean against both ledgers. Fixes folded: B1 (CP-1
restated macOS-scoped — Linux `two_hop` is 35-pass, not a blocker — and its cause
flagged UNVERIFIED, first action = triage not fix), B2 (stability = §5.4
flake-sized N-of-N at a single clean commit, not the replaced "two consecutive"),
B3 (program restructured into 3 parallel tracks joining at cross-OS, not a false
serial), S1 (cross-OS is 0/88 — 0/178 as re-counted 2026-08-28 — because never
*attempted*; first step is run+triage),
S2 (macOS exit `pf` divergence does NOT waive the end-to-end egress proof), S3
(`SignedMembership` transitions restored to scope), S4 (`network_flap` G1 =
"correctly adjudicated," not "must be RED"). This refresh
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
  *Re-counted 2026-08-28 at `34a9e6f8`: **178 rows**, still zero overall `pass`
  (141 fail / 37 partial). The ledger is append-only — re-derive, do not cite.*
- **Cross-OS is 0-proven:** `live_mixed_topology_validation` (the `--node` cross-OS
  carrier per AcceptanceSpec §3-T3) has **never gone green** (0/88; **0-for-178**
  as re-counted 2026-08-28 — 632 per-stage rows, every one `skip`).
- **Windows is 0-proven and has not bootstrapped on `--node`** (every
  `windows_stage_bootstrap` row *where it ran* failed — n=3, all 2026-07-19; the
  other 85 rows are `not_run`, so this is a thin single-day signal, see CP-4).
  *Re-counted 2026-08-28: **n=5 fail** across two days (three 2026-07-19 @
  `db3ff1aaafe6`, two 2026-07-25 @ `b7667cce46db`), 173 `not_run`, still zero
  `pass`. The claim holds; it is no longer single-day.*
  **CORRECTED 2026-08-28 by [WindowsNodeBootstrapTriageVerdict_2026-08-28.md](./WindowsNodeBootstrapTriageVerdict_2026-08-28.md)
  §0-§1: only THREE of those five are bootstrap failures.** The `n=5` is read
  from the run-matrix roll-up column; joined against the per-stage ledger,
  `bootstrap_hosts` ran and failed 3 times and was `skip` twice (both runs died
  upstream at `preflight` — one on lab topology, one on a 3602 s guest clock
  skew). The roll-up records `fail` for a `skip`ped stage on **every** OS column
  at once, so the Linux and macOS bootstrap fail counts are inflated the same
  way. Still zero `pass`; the "Windows has never bootstrapped on `--node`"
  conclusion is unchanged, but the magnitude was overstated.
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
| **anchor** | 🔴 **elected 2026-08-28** (`livelab-1787911937-77ff1933885f`, `77ff1933`, clean) — capability advertisement **passed** live; bundle-pull runtime reported-skipped on the `is_supported_for_platform` posture gate, so `anchor_validation=skip`. `live_anchor` not dispatched (dropped with `--skip-linux-live-suite`). See MacCellsHarvest §2 | ⬛ never exercised |
| **exit** | 🔴 **elected 2026-08-28** (`livelab-1787913512-a5e93c8dd781`, **dirty** — diagnostic only, cannot count toward §5.4) — fails at `membership_init`: the macOS owner-key path constant points at a file that does not exist. No exit stage has ever dispatched. See MacCellsHarvest §4 | 🔒 WinNAT hardware (§4) |
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

- **CP-1 (code) — macOS `two_hop` (client↔client).** On macOS `--node`, `two_hop`
  fails **8/8 where it ran** → `traffic_test_matrix=fail`, so no macOS run passes
  overall and the macOS `client` cell is red. **On Linux this is NOT a blocker** —
  `linux_stage_two_hop` is 35 pass including all four most recent runs; the sole
  Linux `--node` fail is `network_flap` (CP-2). **Diagnosis is UNVERIFIED on current
  code (review B1):** the "userspace shared-socket WG transport-handshake" hypothesis
  is imported from a 2026-07-15 memory about the `traffic_test_matrix` client↔client
  cell — a *different* stage — and no shared-socket/handshake fix appears in the
  `rustynet-backend-userspace`/`rustynetd` commits since 2026-07-14, so it may never
  have explained macOS `two_hop` or has stopped applying. **First action is a fresh
  triage of a current macOS `two_hop` report**, not a fix on the stale hypothesis. It
  is *probably* the highest-value macOS-column lever (it caps every macOS run's
  overall verdict), but that ranking is provisional pending triage. Owning area is
  core-dataplane, §13.2 security-sensitive.
- **CP-2 (code) — `network_flap` / traversal self-sustenance.** The sole Linux
  `--node` fail and a real production gap (mesh fail-closes ~120 s after the last
  distribution). Approved design + in-flight implementation in
  `TraversalSelfSustenancePlan_2026-07-23.md` (I1/I2 merged; I3-I6 remain). Per
  AcceptanceSpec §6/B6 it must be **correctly adjudicated** for **G1** — RED-for-the-
  right-reason today, *or* genuinely GREEN once the fix lands (both satisfy G1) —
  and GREEN for **G2**. Gates the resilience tier on every OS.
- **CP-3 (hardware) — Windows exit WinNAT.** `promote_windows_exit_active` is
  code-complete but needs `MSFT_NetNat`/HNS, which **cannot run in UTM on Apple
  Silicon** — requires a physical Windows-11-Pro/Ent-on-ARM device (CompletionBrief
  §8.1). External blocker; owner task. Blocks only the Windows *exit* cell.
- **CP-4 (triage) — Windows `--node` bootstrap fails. TRIAGED 2026-08-28 →
  [WindowsNodeBootstrapTriageVerdict_2026-08-28.md](./WindowsNodeBootstrapTriageVerdict_2026-08-28.md).
  Verdict: BOTH, code primary.** Still zero `pass`, so CP-4 still gates **all**
  Windows `--node` cells, but the root cause is no longer unverified.

  **Named failing step:** `Ensure-WingetConfigurationDependencies` →
  `& winget configure --file RustyNetBootstrap.winget.yml …` at
  `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1130`, throwing at
  `:1132`. The guest's own stdout states it verbatim: *"Configuration is not
  enabled. Run `winget configure --enable` to enable it."*

  **Code half (primary, reproduces on every fresh guest):** the bootstrap hard-
  depends on WinGet **Configuration**, an opt-in per-machine feature, and never
  enables or precondition-checks it. `Require-Winget` (`:548-571`) gates only on
  `winget.exe` presence; `Get-WindowsBootstrapToolingState` (`:456-…`) collects
  ten-plus WinGet facts but not the Configuration feature's state; and nothing in
  the repository ever runs `winget configure --enable`. The step is not optional —
  it is what installs Git, PowerShell 7, rustup and **WireGuard**.

  **Guest half:** the 2026-07-19 `windows-utm-1` had the feature disabled. Also,
  as of 2026-08-28 that guest has **no remote management path at all** — it boots
  and answers ICMP with RPC/NetBIOS/SMB listening, but TCP/22, 3389 and 5985 are
  all closed and the QEMU guest agent is absent, so remediation needs the UTM
  console. No fresh run was launched for that reason (see the verdict doc §6).

  **Not one cause:** the five ledger rows are four distinct causes across two
  guests and two commits, and only two of them share a root cause. One 2026-07-25
  failure on `windows-x86-1` remains **unresolved** — its report lives on the
  currently-unreachable `ubuntu-kvm-1` host.

  **First Windows fix task:** W-FIX-1 — make the WinGet Configuration precondition
  explicit and self-healing in `Bootstrap-RustyNetWindows.ps1` (verdict doc §7.2).
  Do the code fix before the guest fix; the guest fix is only a testing
  prerequisite and resolves nothing durable.

## 3. Program — three PARALLEL tracks joining at cross-OS (revised per review B3)

The blockers share no cross-dependencies, so this is **not** a serial 1→7 list —
that falsely serialized independent work (CP-4 marked "triage first" yet placed
third behind two unrelated code fixes with different owners). Three tracks run in
parallel and converge only at the cross-OS join. **Stability throughout:** a cell is
"proven" only under the AcceptanceSpec **§5.4 flake-sized N-of-N-at-a-single-clean-
commit** rule (default 3-of-3, 5-of-5 for a flake-recorded stage) — *not* "two
consecutive" (which §5.4 explicitly replaced as arithmetically too weak).

- **Track M — macOS.** Two sub-streams that DON'T block each other: (a) **triage
  then fix CP-1** (macOS `two_hop`) — needed for the macOS `client` cell and any
  *overall*-green macOS run; (b) **elect + prove the other macOS roles** (`exit`,
  `blind_exit`, `anchor`, `role-transition`) via the role-platform selectors /
  `--macos-promote-exit`. Sub-stream (b) does **not** wait on CP-1: the ledger shows
  per-CELL stage-greens accrue even in overall-*failed* runs (that is exactly how
  `macos_admin`/`macos_relay` earned their green cells while `two_hop` failed). So
  role-cell greens can be harvested in parallel; only the `client` cell + a fully-
  green macOS run gate on CP-1.
- **Track L — Linux / traversal.** Land **CP-2** (`network_flap`) —
  `TraversalSelfSustenancePlan` I3-I6, live-verify green. Independent of Tracks
  M/W; unblocks the resilience tier everywhere.
- **Track W — Windows.** **CP-4 triage is DONE (2026-08-28)** — verdict BOTH,
  code primary, failing step named at
  `Bootstrap-RustyNetWindows.ps1:1130` (see §2 and the
  [verdict doc](./WindowsNodeBootstrapTriageVerdict_2026-08-28.md)). The track now
  leads with **W-FIX-1** (make the WinGet Configuration precondition explicit and
  self-healing), then W-FIX-4 (restore `windows-utm-1`'s SSH + WinGet Configuration
  from the UTM console and re-run the minimal `debian-headless-2:exit` +
  `windows-utm-1:client` topology to land the first `windows_stage_bootstrap=pass`).
  It still gates the entire Windows column, and still runs in
  parallel with M and L. Then prove Windows `admin`, `anchor`, `relay`-lifecycle,
  `role-transition`. Windows `exit` waits on **CP-3** (WinNAT hardware); Windows
  `blind_exit` is design-excluded (§6).
- **JOIN — cross-OS.** `live_mixed_topology_validation` needs Linux + macOS +
  Windows all present and healthy, so it depends on Tracks M and W (and L for a
  clean mesh). **First sub-step is "run it once and triage," not "make it green"
  (review S1):** it is **0-for-88 because it has NEVER been attempted** — every row
  is `skip`/`not_run`, zero `fail`, zero `pass` *(unchanged at **0-for-178**,
  re-counted 2026-08-28)* — so there is no triage signal yet;
  the first execution is an unknown-unknown and deserves its own diagnosis step.
- **Parked, deferred-with-reason** (AcceptanceSpec §6.1 fenced disposition): relay
  frame-forwarding (HP-3, all OS), Windows `blind_exit` (design-excluded), nas/llm
  (D13 program).

## 4. Blockers — environmental vs code

| Blocker | Kind | Owner | Notes |
|---|---|---|---|
| CP-1 `two_hop` client↔client handshake | **code** | dataplane | userspace shared-socket WG transport; §13.2 |
| CP-2 `network_flap` traversal self-sustenance | **code** | traversal track | I3-I6 of the traversal plan |
| CP-4 Windows `--node` bootstrap | **triaged 2026-08-28** | **BOTH — code primary** | Failing step `Bootstrap-RustyNetWindows.ps1:1130` (`winget configure`, Configuration feature never enabled or checked); guest `windows-utm-1` also has no remote management path. Still gates all Windows. Next: W-FIX-1 |
| CP-3 Windows exit WinNAT | **hardware** | operator | physical Win-on-ARM device; not fixable in UTM/ASi |
| Fedora passwordless-sudo + host-route sudo | environmental | operator | CompletionBrief §8.3-8.4 |
| Healthy macOS/Windows guests | environmental | operator | CompletionBrief §8.2 (repair, not rebuild) |

## 5. §5.2 platform-adapter gaps — current status

- **mac/win role evaluators:** macOS `admin` + `relay` evaluators pass on `--node`;
  `blind_exit` macOS evaluator exists but was never elected. **`anchor` and `exit`
  were elected 2026-08-28** (§1) and both produced real signal — neither is
  "never elected" any more, and neither is green. Windows evaluators all blocked
  behind CP-4. Two blockers were located in the process
  (`MacCellsHarvest_2026-08-28.md`):
  **(a)** the `Anchor`/`Admin`/`Relay` posture gate at
  `vm_lab/orchestrator/role.rs:68-70` is Linux-only while its own comment
  promises promotion "once a green run is archived" — but
  `anchor_validation.rs:181` gates the runtime substages on that same predicate
  and `outcome_for` (`:236-247`) grades any reported skip as `Skipped`, so the
  green run required to lift the gate cannot be produced by the stage the gate
  controls. The promotion route has to come from the `--anchor-platform macos`
  stage set instead (`live_lab_stage_registry.rs:1151,1158,1168`), which the
  role election alone does not enable.
  **(b)** macOS cannot hold a membership-owner role: `membership_init` is
  role-gated to `exit`, and the macOS adapter reads the owner pubkey from
  `/usr/local/var/rustynet/membership/membership.owner.key.pub`
  (`adapter/macos_install.rs:27-28`) with a bare `cat`
  (`adapter/macos_membership.rs:29-34`), where the Linux twin reads
  `/etc/rustynet/membership.owner.key.pub` with `sudo -n`
  (`adapter/linux_membership.rs:25-31`). On the guest the key exists only at the
  latter path, and the former directory is `0700 rustynetd` so the bare `cat`
  cannot read it either.
- **Harvest-form caveat (`--skip-linux-live-suite`).** The fast-path flag every
  mac/win target key sets (`ai_agent.rs:1864-1892`) drops the whole post-baseline
  suite — `plan.rs:545-549`, 61 → 19 stages. That excludes `live_anchor` and all
  three `exit_*_validation` stages, which are `state_machine_only` and so have no
  bash-archive substitute. **Role-cell greens for those stages cannot be
  harvested on the fast path**; they require paying for the full Linux live suite.
- **anchor gossip_seed:** the gossip **substrate now exists in the production
  daemon** (commits `001cc97`→`e804723`, post-roadmap — construct/attach gossip
  runtime, register peers from membership, epoch-bind bundles). No live anchor-gossip
  proof yet, so the *cell* stays unproven, but the roadmap's "unbuilt" framing is
  outdated.
- **anchor enrollment_endpoint:** ParityPlan §10 says "zero runtime enforcement";
  **unverified** whether the gossip-runtime work touched it — triage before scoping.
- **Windows authoritative port mapping:** still open (no `windows_membership_
  capabilities` equivalent).
- **`SignedMembership`-kind role transitions (both OS) — dropped scope, restored
  (review S3).** ParityPlan §3 tracked capability-*changing* transitions as an
  explicit follow-up to the LocalOnly-flip proofs (the §1 matrix's role-transition
  row covers only the LocalOnly flips). They are unproven on `--node` on either OS —
  either add them to Track M / Track W as role-transition sub-cells, or park them
  via §6.1 (owner sign-off + expiry). Do not silently omit them.

## 6. Intended OS divergence — NOT parity holes (drift-direction rule)

These are legitimate per-OS differences; do not force uniformity or treat as gaps
(AcceptanceSpec §8 — bash is never the oracle, and neither is Linux):

- **Windows `blind_exit`** — hard-excluded by design (`main.rs` hard-error). 🚫.
- **macOS exit — `pf` NAT *mechanism* divergence, but the egress PROOF is NOT waived
  (review S2).** macOS Exit maps to enforce-time `pf` NAT (anchor hard-locked), so
  the Linux activate→assert→NAT-*session* shape doesn't apply (ParityPlan §11). That
  is a legitimate *mechanism* difference — but NOT a licence to skip proof. A macOS
  exit cell must **not** reach G2-green without an **equivalent-strength end-to-end
  egress assertion** — a client's packets provably egress through the macOS exit to
  an external target — just expressed via the `pf` model rather than the nft
  NAT-session assertion. Lifecycle-proven ≠ egress-proven; waiving the egress
  assertion would be exactly the "excuse a real gap as intended divergence" error
  the drift rule warns against (§8).
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
  evidence properties, recomputed by the independent verifier / §4.8) under the
  **§5.4 flake-sized N-of-N-at-a-single-clean-commit** stability rule (default
  3-of-3, 5-of-5 for a flake-recorded stage) — the rule that *replaced* the
  arithmetically-refuted "two consecutive."
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
  (88 rows — **178** as re-counted 2026-08-28; 0 overall pass; macOS admin pass @ `livelab-1784501586`; relay-lifecycle
  pass @ `livelab-1784497253`; Windows bootstrap fail rows @ 2026-07-19).
- Stage vocabulary present on `--node`: `crates/rustynet-cli/src/live_lab_stage_registry.rs`.

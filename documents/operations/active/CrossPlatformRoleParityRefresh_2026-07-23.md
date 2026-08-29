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
"correctly adjudicated," not "must be RED"). **Matrix updated 2026-08-28:** the
macOS Track M cells now reflect the first `--node` elections of `anchor`/`exit`
(runs 47/48) and the MAC-D1/MAC-D2 fixes (`fix-landed-rerun-pending`), plus the
owner-gated macOS DNS fail-closed enforcement gap and the landed path-constant
hardening. This refresh
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
  time, and `blind_exit` has never been elected onto a macOS `--node`. *Update
  2026-08-28: `anchor` and `exit` were elected for the FIRST time on `--node`
  (runs 47/48) — both blocked with the blocker located, then both blockers fixed
  in code (MAC-D1 `8ec851a9`, MAC-D2 `03619d0f`); re-runs pending.*

Both old docs also record their Definition-of-Done evidence against the **bash
archive** (ParityPlan §5/§8; Roadmap §10) — a stale pointer for G2.

**Net:** the honest G2 status is *far* less green than the ParityPlan implies. This
refresh states the `--node` reality and sequences the work to close it.

## 1. `--node`-native status matrix (the G2 picture, 2026-07-23; macOS cells updated 2026-08-28)

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
| **anchor** | 🔴 **elected-blocked → fix-landed-rerun-pending.** Elected 2026-08-28 (`livelab-1787911937-77ff1933885f`, `77ff1933`, clean) — capability advertisement **passed** live; bundle-pull runtime reported-skipped on the `is_supported_for_platform` posture gate, so `anchor_validation=skip` (blocker located: MAC-D1 circularity). **MAC-D1 fix landed 2026-08-28 (`8ec851a9`)** — the posture-gate circularity is de-circularised via validator-set election — but **no post-fix lab run exists yet**, so the cell is unblocked-for-rerun, NOT green. `live_anchor` was not dispatched (dropped with `--skip-linux-live-suite`). See MacCellsHarvest §2 | ⬛ never exercised |
| **exit** | 🔴 **elected-blocked → fix-landed-rerun-pending.** Elected 2026-08-28 (`livelab-1787913512-a5e93c8dd781`, **dirty** — diagnostic only, cannot count toward §5.4) — failed at `membership_init`: the macOS owner-key path constant pointed at a file that does not exist (blocker located: MAC-D2). No exit stage has ever dispatched. **MAC-D2 fix landed 2026-08-28 (`03619d0f`)** — the owner-pubkey constant now points at the genesis write path (`/usr/local/etc/rustynet/membership.owner.key.pub`) and the read fails loud — but **no post-fix lab run exists yet**, so the cell is unblocked-for-rerun, NOT green; and `DnsFailclosed` will stay red until the owner-gated enforcement-gap design lands (§5). See MacCellsHarvest §4 | 🔒 WinNAT hardware (§4) |
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

- **CP-1 (environmental — triaged 2026-08-29, see verdict below) — macOS `two_hop`
  (client↔client).** On macOS `--node`, `two_hop`
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

  **CP-1 TRIAGE VERDICT (2026-08-29) — ENVIRONMENTAL (lab network topology), NOT
  code.** Fresh triage on current evidence re-classifies CP-1 from *code* to
  *environmental*. The freshest real `two_hop` failure digest
  (`state/live-lab-ll-1784714940526-68753-0/failure_digest.json`, run
  `rust-1784714964`, 2026-07-22) shows the macOS node (`macos-utm-1`,
  mesh `100.64.181.171`) with **100% ping loss to and from every peer in both
  directions** while Linux↔Linux pairs pass — the macOS WG interface passes zero
  packets either way. The stale shared-socket hypothesis is disproven: the current
  macOS userspace-shared transport is implemented and tested end-to-end
  (`userspace_shared_macos/socket.rs` — authoritative UDP socket binds
  `0.0.0.0:listen_port`, dataplane egress tolerates transient refusal;
  `userspace_shared_macos/runtime.rs` — peer endpoints validated non-zero and
  non-unspecified, handshake initiation + tun/UDP worker loop present;
  `userspace_shared_macos/tun.rs:1057` — mesh route reconciliation programs
  `route -n add -inet <cidr> -interface utunX`; `third_party/rustynet-tun` — utun
  4-byte AF framing handled and unit-tested).

  **Root cause (measured live on the lab, 2026-08-29):** the macOS UTM guest and
  the Debian lab nodes sit on **mutually unreachable IP subnets, so WG endpoint
  packets can never arrive in either direction**. `macOS.utm/config.plist`
  declares a single NIC `Mode = Shared` — the guest's only address is
  `192.168.65.101/24` behind UTM's NAT (`192.168.65.1` default). The Debian lab
  guests (`debian-headless-2` @ `192.168.64.4`, `debian-headless-4` @
  `192.168.64.10`) live on the host bridge `bridge100` (`192.168.64.1/24`).
  Live probes with all daemons stopped, pure L3: `debian-headless-4 → ping
  192.168.65.101` = **0/2 received**; `macos-utm-1 → ping 192.168.64.10` =
  **0/2 received**; the host itself pings `192.168.64.10` fine over
  `bridge100`. There is no host forward/NAT between the UTM-shared subnet
  (192.168.65.0/24) and `bridge100` (192.168.64.0/24), and no return route from
  `bridge100` into the UTM-shared subnet — so a WG endpoint pointing either way
  is dead and no handshake can ever complete. This exactly reproduces the
  7/19–7/22 `two_hop` signature (both-direction 100% loss, default-deny
  INCONCLUSIVE "reached no mesh peer"), and also explains why post-7/22 macOS
  runs fail even earlier (`membership_init` / `validate_baseline_runtime` /
  `distribute_assignments`): the node cannot reach its peers at all in the
  current topology. (The `192.168.64.18` entry in the mac's inventory
  `live_ips` is a stale record from an era when the guest had a bridged NIC on
  that segment; the guest currently has no such interface — `en1` is
  `status: inactive`.)

  **Fix path (operator, not code):** give the macOS guest L3 adjacency with the
  Debian nodes — add/enable a second UTM NIC bridged onto the host's
  `bridge100`/192.168.64.0/24 segment (the attachment the stale
  `192.168.64.18` lease came from), or move the whole mac↔debian lab cell onto
  one profile-managed segment. Per the LiveLabVmConnectivityRulebook this is an
  explicit operator-authorized `prepare_lab_network` reconfiguration
  (`approve_reconfigure`), never an autonomous mutation. After re-attachment,
  re-run the focused macOS `two_hop` cell (`rebuild_nodes` fast path) and expect
  the WG handshake to complete with no further code change; if it does, CP-1
  closes as environmental and the §4 table row below flips accordingly.
  Residual code-side gap (optional hardening, not a blocker): the orchestrator
  can fail louder by pre-checking endpoint-subnet reachability before
  `traffic_test_matrix` so a partitioned topology fails with "no L3 path
  <src>→<endpoint>" instead of a dataplane-looking packet loss.
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
  `--macos-promote-exit`. **Progress 2026-08-28:** `anchor` and `exit` are
  elected (runs 47/48) and both of their located blockers are fixed in code —
  MAC-D1 `8ec851a9` (anchor posture gate de-circularised via validator-set
  election) and MAC-D2 `03619d0f` (membership owner-key path + fail-loud read)
  — and the macOS path-constant hardening landed (`a0851175`: all 21 daemon
  path constants + helper socket armed to the installer layout). Both cells are
  `fix-landed-rerun-pending`: the fixes are unverified in the lab until a
  post-fix run. **Standing caveat:** the DNS fail-closed **enforcement** gap is
  a known real leak, dispositioned design-only / owner-gated
  ([MacosDnsFailclosedEnforcementGap_2026-08-28.md](./MacosDnsFailclosedEnforcementGap_2026-08-28.md),
  `1278af04`) — the `DnsFailclosed` stage reds honestly today and will keep
  any macOS run red even after the MAC-D1/MAC-D2 re-runs, until that
  enforcement design lands. Sub-stream (b) still does **not** wait on CP-1: the ledger shows
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
| CP-1 `two_hop` client↔client | **environmental (triaged 2026-08-29)** | operator | macOS UTM guest (Shared-NAT 192.168.65.0/24) and Debian nodes (host bridge100 192.168.64.0/24) have no L3 path between them — WG endpoints mutually unreachable; needs a bridged NIC / profile re-attach (see CP-1 verdict above) |
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
  behind CP-4. Both macOS blockers located in the process
  (`MacCellsHarvest_2026-08-28.md`) are now **FIXED in code — the cells are
  unblocked for re-run but no post-fix lab run exists yet:**
  **(a) MAC-D1 — FIXED 2026-08-28 (`8ec851a9`).** The `Anchor`/`Admin`/`Relay`
  posture gate at `vm_lab/orchestrator/role.rs:68-70` was Linux-only while
  `anchor_validation.rs` gated its runtime substages on the same predicate and
  graded any reported skip as `Skipped`, so the green run required to lift the
  gate could not be produced by the stage the gate controls. The fix
  de-circularises the gate via validator-set election (the promotion route now
  comes from the `--anchor-platform macos` stage set,
  `live_lab_stage_registry.rs:1151,1158,1168`) — re-run pending.
  **(b) MAC-D2 — FIXED 2026-08-28 (`03619d0f`).** The macOS adapter read the
  owner pubkey from a path the genesis driver never writes
  (`/usr/local/var/rustynet/membership/membership.owner.key.pub`, bare `cat`)
  while the key is seeded at `/usr/local/etc/rustynet/membership.owner.key.pub`;
  the fix points `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` at the genesis write
  location, derives it from `ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH` (drift-
  pinned by test), reads via `sudo -n`, and fails loud with distinct errors for
  absent/unreadable/empty — re-run pending.
- **macOS DNS fail-closed — enforcement gap, `owner-gated-leak` (dispositioned
  2026-08-28, `1278af04`).** The validator now reds honestly
  (`validate_baseline_runtime` failed on `macos-utm-1/DnsFailclosed`), and the
  investigation confirmed a **real enforcement leak**: the posture is written
  to files the OS does not consult (`/etc/resolv.conf` is a configd-generated
  shim on macOS), dispositioned **design-only / owner-gated** in
  [MacosDnsFailclosedEnforcementGap_2026-08-28.md](./MacosDnsFailclosedEnforcementGap_2026-08-28.md).
  Consequence for the matrix: even once the MAC-D1/MAC-D2 cells re-run,
  `DnsFailclosed` stays red until that enforcement design lands — no macOS run
  can pass overall before it.
- **macOS path-constant hardening — LANDED 2026-08-28 (`a0851175`).** All 21
  daemon path constants + the helper socket are armed to the installer layout,
  removing the class of wrong-location constants that produced MAC-D2.
- **macOS mesh-status peer visibility — node-id-exact — LANDED 2026-08-29
  (`7d6f5c98`, no lab run yet).** The macOS mesh-status report previously
  exposed only the session snapshot's `peer_ids`, which hold ADVERTISED ROUTE
  CIDRS — so the anchor peer-visibility assertion could prove "some routes
  exist" but never that the right peers are visible. A separate, ADDITIVE
  `member_node_ids` field now carries the VERIFIED active roster node ids,
  read from the SIGNED membership snapshot via rustynet-control
  `load_membership_snapshot` (permission/digest/state verification before any
  node id is read; same primitive as `anchor-port-mapping-status-check`).
  STRICT fail-closed: an unreadable/unverifiable membership snapshot is a
  drift reason even with no node-id expectations requested; the field
  defaults to `Invalid` for pre-addition reports (never an empty roster);
  revoked/quarantined rows never satisfy an assertion; roster staleness is
  NOT time-checked (roster `updated_at_unix` measures last change, not
  liveness — node-view freshness stays on `max_age_seconds`). The
  orchestrator's typed macOS MeshStatus validator now dispatches the
  §4.7-challenged node id as `--expected-node-id`, and
  `evaluate_macos_mesh_status_report` rejects any report without a `Verified`
  roster — the assertion is node-id-exact while the CIDR-range check keeps
  working unchanged (`windows_mesh_status.rs` untouched; serialization is
  serde-default additive). Live-lab proof pending: next macOS anchor cell run
  must exercise the strengthened dispatch.
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

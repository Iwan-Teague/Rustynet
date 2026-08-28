# Never-Dispatched Linux Stages — Triage — 2026-08-27

**Status: INVESTIGATION COMPLETE. No code changed. Three owner decisions queued (§6).**

Scope: the three Linux entries that appear in the live-lab stage vocabulary but have
never once produced a non-`not_run` cell on the engine of record (the Rust `--node`
orchestrator):

1. `validate_linux_relay_forwards_frame`
2. `linux_stage_chaos`
3. `linux_membership_genesis`

This matters because `CrossPlatformRoleParityPlan_2026-06-21.md` treats Linux as the
"done reference" for the release-blocking parity mandate. A vocabulary entry that has
never dispatched is silently absent from that claim while still occupying a column in
the ledger that a reader charges to Linux.

Evidence base — code at `14faad7a` (branch `work/linux-stage-triage`, merged from `main`
2026-08-27) plus the two `--node` ledgers ONLY:

- `documents/operations/live_lab_node_run_matrix.csv` — **178 rows** (per-run columns)
- `documents/operations/live_lab_node_stage_results.csv` — **28,893 rows / 60 distinct
  stage names** (per-stage outcomes)

The frozen bash archive (`live_lab_run_matrix.csv`) is **not** used as evidence for the
`--node` engine anywhere below, per `AGENTS.md` §2 and `LiveLabRunMatrix.md`.

---

## 0. The one root cause behind two of the three

The `--node` plan is **not** built from `live_lab_stage_registry.rs`. It is built from
the typed catalog:

- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:121-126` — `StageId::ALL` is
  "the fully-enabled plan order"; the `define_stage_catalog!` rows at `:156-288` are the
  complete `--node` stage vocabulary (60 wire names).
- `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:262-266` — `PlanBuilder::build`
  iterates `StageId::ALL` and filters by each row's `StageSuite`. There is no other
  source of plan membership.

`live_lab_stage_registry.rs` is a **vocabulary/ledger-mapping table**, not a dispatch
table. It deliberately carries three dialects side by side: `--node` wire names (tagged
`state_machine_only: true`), the legacy bash names, and job-level pseudo-stages. A
registry row is *not* evidence that anything dispatches it.

`validate_linux_relay_forwards_frame` and `validate_linux_membership_genesis` are
**bash-dialect rows**. Their `special:` field maps a *bash* stage name onto a CSV column
(`live_lab_run_matrix.rs:4214`/`:4220`). The `--node` engine never emits those names, so
those columns are structurally unreachable on the engine of record.

This is the **same defect class** already recorded for `cross_network_daemon_path`
(registry `:2199-2215`; origin `documents/archive/TrackC_BashOrchestratorDefects_2026-07-13.md`
TRACKC-FIX-1): a bash-dialect registry row that survived the W5.7 bash-engine deletion
with no `--node` counterpart. It is also the root cause the
`LiveLabStageCoverageGapPlan_2026-08-10.md` G3 section names — "`special:` is declared on
the **bash-dialect** stage names, which the `--node` engine never emits".

Corroborating breadth: **40 columns** in the 178-row `--node` ledger are `not_run` in
every single row. The bash-dialect Linux security family
(`linux_runtime_acls`, `linux_service_hardening`, `linux_authenticode`,
`linux_key_custody`, `linux_membership_genesis`, `linux_mesh_status`,
`linux_hello_limiter_flood`, `linux_relay_forwards_frame`) is entirely inside that set.
Two of our three stages are not special cases — they are members of a family.

**Where the bash-dialect Linux validators DO still live.** They are not dead code. The
chainer `run_linux_orchestration_stages_with_options`
(`crates/rustynet-cli/src/vm_lab/mod.rs:23878`) runs all 24 of them and is reachable from
exactly one live caller: `run_validate_linux_security` (`vm_lab/mod.rs:24839`), which is
the `rustynet ops vm-lab-validate-linux-security` subcommand
(`crates/rustynet-cli/src/main.rs:4551`, `:9016`). That subcommand writes
`linux_security_validation.json` into its report dir and **appends no run-matrix row**.
The other caller, `run_linux_daemon_validators_for_aliases` (`vm_lab/mod.rs:24773`), is
explicitly quarantined:

> `#[allow(dead_code)] // W5.7 quarantine: unreachable since the bash-branch deletion; retained for the G2 native re-wire`

So the honest summary for these two is **"runnable by hand, never in a recorded run, and
invisible to every tool that reads the ledger"** — not "unimplemented".

---

## 1. `validate_linux_relay_forwards_frame`

### (a) What it was meant to prove

HP-3 / RPT-01: that a relay **actually forwards a frame**, and forwards it blind.
Implementation `exercise_linux_relay_forwards_frame` (`vm_lab/mod.rs:13841`):

- resolves its own relay/sender/receiver Linux nodes from the inventory (it does *not*
  assume the chainer's `linux_alias` is the relay);
- nft-blocks the two spare peers' direct UDP and restarts both daemons, forcing a
  relay-only path;
- polls each peer's own `rustynet status` until **both independently** report
  relay-routed;
- sends a marked ICMP payload;
- asserts the relay's own forwarded-frame/byte counters increased
  (`crates/rustynet-relay/src/main.rs::ForwardStats`/`record_forward`);
- asserts a `tcpdump` capture on the relay's own wire never contained the plaintext
  marker (**ciphertext-only**);
- always removes the firewall block and restarts both daemons.

Doc references: `repo_context.rs:2186` (the canonical stage-table row),
`LiveLabSecurityTestCoverage_2026-06-22.md:80` (RPT-01),
`ParallelAgentPrompts_2026-07-01/job1_hp3_relay_forwarding.md:62` (the job that authored it).

### (b) Why it never dispatches

| Step | Location | Fact |
|---|---|---|
| Registry row exists, bash dialect | `live_lab_stage_registry.rs:1852-1860` | `stream: Linux`, `special: Some("linux_relay_forwards_frame")`, `enable: LinuxLiveSuite` |
| No `--node` catalog row | `orchestrator/stage/mod.rs:156-288` | no `StageId` variant, no wire name |
| Plan cannot include it | `orchestrator/plan.rs:262-266` | plan = `StageId::ALL` filtered by suite |
| Only live execution path | `vm_lab/mod.rs:24703-24731` (chainer) ← `:24839` ← `main.rs:4551` | the standalone `ops vm-lab-validate-linux-security` subcommand, which appends no ledger row |
| Column mapping is on the bash name | `live_lab_run_matrix.rs:4220` | `"validate_linux_relay_forwards_frame" => Some("linux_relay_forwards_frame")` |

Ledger: `linux_relay_forwards_frame` = `not_run` in **178/178** rows; zero
`validate_linux_*` rows among 28,893 per-stage rows.

### (c) Is the coverage obtained elsewhere? — **NO**

`relay_validation` is **lifecycle-only** and says so in its own source:

> `orchestrator/role_validation/relay.rs:142-145` — "What this validator does NOT yet
> prove is the end-to-end forwarded-frame path: pushing a client→relay→peer frame and
> proving ciphertext-only / zero-ingress forwarding. That forwarded-frame proof is a
> Wave 4 (cross-network/dataplane) deliverable and is intentionally out of scope here."

What `--node` *does* prove (53 `pass` each for `deploy_relay_service` and
`relay_validation`): service active, datapath UDP port bound, health TCP port bound,
`/healthz` returns `ok`, stop asserts the inverse, restart succeeds
(`stage/relay_validation.rs:10-34`). That is presence and lifecycle, not forwarding, and
categorically not the ciphertext-only property.

`BashRetirementDispositions_2026-08-22.md` B5 is consistent with this — it splits
"lifecycle proof" from "HP-3" and records HP-3 as **parked**, not covered.

### (d) Disposition — **wire-it-in, owner-gated (NOT trivial)**

The validator body is written, tested and honest; what is missing is a `--node` stage.
Wiring it requires, at minimum:

1. a new `define_stage_catalog!` row, e.g.
   `RelayForwardsFrameValidation => "relay_forwards_frame_validation" @ Live / T1Role`
   (`stage/mod.rs`);
2. a new `stage/relay_forwards_frame_validation.rs` implementing `OrchestrationStage`
   with `dependencies() = [StageId::RelayValidation]` and `applies_to_roles() = [Relay]`,
   driving the logic through the adapter's cross-OS `RemoteShellHost` seam rather than
   the chainer's direct-SSH helpers (the existing impl is SSH-direct and Linux-only);
3. the compiler-enforced `PlanBuilder::build` arm (`plan.rs`);
4. a registry row with `state_machine_only: true` + `special`/`logical` so the ledger
   column is populated by the `--node` name;
5. updating the plan-size assertions (`plan.rs:456-530` pin exact stage counts: 61
   default / 70 chaos-enabled / 72 stacked).

**Not implemented here, deliberately.** This appends a stage to the **default** `Live`
suite, so it changes what every existing profile runs — explicitly outside this task's
mandate. It also injects an nft block and restarts two daemons mid-run, which is a
run-safety decision, not a wiring decision.

**Evidence gap admitted if deleted instead:** Rustynet would have no proof on any engine
that a relay forwards a frame at all, and no proof of the relay's blindness
(ciphertext-only) property. `LiveLabSecurityTestCoverage_2026-06-22.md` Tier 2 already
calls HP-3 "the single biggest looks-done-but-isn't gap". Deletion is not recommended.

---

## 2. `linux_stage_chaos`

### (a) What it was meant to prove

**It is a ledger COLUMN, not a stage.** It aggregates the nine `chaos_*` `--node` stages,
each of which carries `logical: Some("chaos")` (`live_lab_stage_registry.rs:2041-2113`),
so any of them populates `{platform}_stage_chaos`.

The nine (catalog rows `stage/mod.rs:262-272`, impls `stage/chaos.rs:67-131`):

| Stage | Tier | Targets | Binary |
|---|---|---|---|
| `chaos_clock_attack` | T4Security | Exit | `live_chaos_clock_attack_test` |
| `chaos_crash_recovery` | T2Resilience | Exit | `live_chaos_crash_recovery_test` |
| `chaos_daemon_fault` | T2Resilience | Exit+Client | `live_chaos_daemon_fault_test` |
| `chaos_daemon_sigstop_sigcont` | T2Resilience | Exit+Client | same, `--fault-mode sigstop-cont` |
| `chaos_membership_adversarial` | T4Security | **Offline** | `live_chaos_membership_adversarial_test` |
| `chaos_network_impairment` | T2Resilience | Exit+Client | `live_chaos_network_impairment_test` |
| `chaos_privileged_boundary` | T4Security | **Offline** | `live_chaos_privileged_boundary_test` |
| `chaos_resource_exhaustion` | T2Resilience | Exit+Client | `live_chaos_resource_exhaustion_test` |
| `chaos_signed_state_adversarial` | T4Security | **Offline** | `live_chaos_signed_state_adversarial_test` |

Collectively: disturbance injected, recovery/consistency asserted (T2), plus three
adversarial-input controls (T4). All nine binaries exist under
`crates/rustynet-cli/src/bin/`.

### (b) Why it never dispatches — TWO independent gates, both currently shut

**Gate 1 — opt-in flag never passed.**
`StageSuite::Chaos` is included only when `enable_chaos_suite` is true
(`plan.rs:254`), which comes from `--enable-chaos-suite`
(`crates/rustynet-cli/src/main.rs:4459`). In all **178** `--node` rows the recorded
`run_command` is the bare `vm-lab-orchestrate-live-lab` — **zero** runs carry the flag.

**Gate 2 — dependency mis-parenting. This is the real blocker.**
All nine declare, via the `chaos_stage!` macro:

```rust
// crates/rustynet-cli/src/vm_lab/orchestrator/stage/chaos.rs:48-50
fn dependencies(&self) -> &[StageId] {
    &[StageId::LiveMixedTopologyValidation]
}
```

`live_mixed_topology_validation` skips unless Linux **and** macOS **and** Windows are all
assigned nodes in the topology
(`stage/live_mixed_topology_validation.rs:49-53`: *"not every platform in the matrix is
assigned a node in this topology"*). Its lifetime record on `--node`:

- `live_lab_node_stage_results.csv`: **632 rows, 632 `skip`, 0 `pass`**
- `live_lab_node_run_matrix.csv` `linux_stage_mixed_topology`: **169 `skip` / 9 `not_run`** across 178 rows

The runner cascade-skips any stage whose dependency was skipped or failed
(`orchestrator/runner.rs:42-43` rule; `:247-257` implementation). So **flipping
`--enable-chaos-suite` today produces nine cascade-skips, not nine dispatches.**
Enabled ≠ dispatched.

This confirms, at 178 rows, the BLOCKER correction already recorded in
`LiveLabStageCoverageGapPlan_2026-08-10.md` §G4 (which found it at 106 rows).

The parenting is substantively wrong, not merely inconvenient: **no chaos stage has any
tri-OS requirement**, and three of the nine are `ChaosTargets::Offline`
(`stage/chaos.rs:101,115,129`) — they contact no guest at all, yet are gated on a tri-OS
topology.

Ledger: `linux_stage_chaos` (and `macos_`/`windows_stage_chaos`) = `not_run` in **178/178**
rows; **zero** `chaos_*` rows among 28,893 per-stage rows.

### (c) Is the coverage obtained elsewhere? — **NO**

- The T5 negative-control suite (`stage/negative_control.rs`) is a *different* claim
  (RED-for-the-right-reason adjudication), is likewise opt-in — but note it declares
  `NO_DEPS` (`negative_control.rs:112`, `:163`, `:212`, `:248`), so it would actually
  dispatch if enabled. It is the counter-example proving the chaos parenting is a bug and
  not a house style.
- `live_network_flap_validation` / `live_reboot_recovery_validation` /
  `live_enrollment_restart_validation` are the T2 resilience stages that *do* dispatch,
  but they cover flap / reboot / mid-enrollment restart — not clock rollback, OOM,
  SIGSTOP/SIGCONT, impairment, privileged-boundary stress, or adversarial signed state.
- **Do NOT claim `chaos_daemon_fault` covers the worker-death recovery path.** Per
  `QualityHardeningTodo_2026-07-25.md:3021-3031` (QH-54, re-checked at `dea73a75`), that
  stage kills or SIGSTOP/SIGCONTs the *whole* systemd daemon and observes service/socket
  recovery — which starts a **new** daemon and therefore cannot reach
  `recover_runtime_after_worker_exit`
  (`crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs:218`), reached only when
  a **still-running** backend gets the worker-unavailable control error. That doc
  explicitly forbids counting this stage as QH-54 proof. Nothing here changes that.

### (d) Disposition — **keep-but-document + ONE owner-approvable line**

The exact minimal change, for owner approval:

```rust
// crates/rustynet-cli/src/vm_lab/orchestrator/stage/chaos.rs:48-50
-        &[StageId::LiveMixedTopologyValidation]
+        &[StageId::TrafficTestMatrix]
```

Why this parent: `traffic_test_matrix` (T0Core) is the last stage that proves the mesh
actually carries traffic, which is the precondition a fault-injection stage genuinely
needs. It dispatches on Linux-only topologies, so the tri-OS coupling disappears.

Why this is **safe with respect to existing profiles**: the chaos suite is not in the
default plan at all (`plan.rs:254` — `StageSuite::Chaos => !skip_live_suite && enable_chaos_suite`),
so re-parenting changes **nothing** about what any current run executes. The existing
plan-shape tests keep pinning 61 default / 70 chaos-enabled / 72 stacked
(`plan.rs:456-530`); only the chaos assertion at `chaos.rs:262-265` needs updating.

Why it is **not implemented here anyway**: the nine binaries have never executed live
even once, and they inject real faults (OOM, SIGSTOP, clock rollback, network
impairment) against lab guests. Making them reachable is a run-safety call for the owner,
and the honest acceptance criterion — per `LiveLabStageCoverageGapPlan_2026-08-10.md`
§G4 — is *a chaos report artifact with a non-skipped outcome*, never a plan listing.

**Strictly better first step** (lower blast radius, recommended): re-parent and enable
only the three `ChaosTargets::Offline` stages — `chaos_membership_adversarial`,
`chaos_privileged_boundary`, `chaos_signed_state_adversarial`. They touch no guest,
carry the T4 security tier, and would convert `linux_stage_chaos` from a permanent
`not_run` to real evidence with zero risk to lab nodes.

---

## 3. `linux_membership_genesis`

### (a) What it was meant to prove

That the canonical membership files are **custodied correctly at rest** and yield a
readable signed snapshot. `build_linux_membership_genesis_check_script` /
`validate_linux_membership_genesis_output` (`vm_lab/mod.rs:15186-15226`) assert, over SSH
with `sudo -n`:

- `/var/lib/rustynet/membership.snapshot`, `.log` and `.watermark` each `stat` as
  exactly `600 rustynetd:rustynetd <path>`;
- `rustynet membership status --snapshot … --log …` emits `membership status:` with
  `network_id=`, `epoch=` and `active_nodes=` — i.e. the signed snapshot parses.

Doc references: `repo_context.rs:2180`;
`HeterogeneousLiveLabEvidence_2026-04-28.md:326` (L2);
`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md:591` (where it was added to the
Linux validator chain). A CI gate pins its existence and unit tests:
`scripts/ci/linux_exit_role_gates.sh:43,60`.

### (b) Why it never dispatches

Identical mechanism to §1:

| Step | Location | Fact |
|---|---|---|
| Registry row, bash dialect | `live_lab_stage_registry.rs:1793-1800` | `special: Some("linux_membership_genesis")`, `enable: LinuxLiveSuite` |
| No `--node` catalog row | `orchestrator/stage/mod.rs:156-288` | absent |
| Only live execution path | `vm_lab/mod.rs:24583-24628` (chainer) ← `:24839` ← `main.rs:4551` | `ops vm-lab-validate-linux-security`; appends no ledger row |
| Column mapping on the bash name | `live_lab_run_matrix.rs:4214` | `"validate_linux_membership_genesis" => Some("linux_membership_genesis")` |

Ledger: `linux_membership_genesis` = `not_run` in **178/178** rows.

Additional wrinkle worth recording: the chainer gates this stage behind
`validate_linux_runtime_acls` **and** `validate_linux_key_custody`
(`vm_lab/mod.rs:24589-24599`), so even the hand-run subcommand skips it whenever either
predecessor fails.

### (c) Is the coverage obtained elsewhere? — **PARTIALLY. The custody half is NOT.**

Proven on `--node`:

- the snapshot is **minted** — `membership_init` (178 rows) — and **distributed** —
  `distribute_membership` (667 rows); `linux_stage_membership` reads `pass` in 160 of 178
  rows;
- the snapshot is **read and parsed** by the anchor validator
  (`orchestrator/role_validation/anchor.rs:414`, path constant `:88`).

Not proven on `--node`:

- **the `600 rustynetd:rustynetd` mode/ownership of the three canonical membership
  files.** `key_custody_validation` covers the *WireGuard* key artifacts only
  (`role_validation/key_custody.rs:109` → `/var/lib/rustynet/keys`, encrypted private key,
  public key, credentials dir). The eight-entry Tier-0 audit catalog
  (`role_validation/security_audit.rs:42-83`) contains no membership-file custody audit.
  `service_hardening_validation` is unit-level daemon posture, not these paths.
- the `membership status:` readability assertion is *parsed* by
  `live_linux_mixed_topology_test.rs:580` — but that stage has never passed (§2b), so it
  contributes nothing.

### (d) Disposition — **wire-it-in (narrow), owner-gated; do NOT delete**

Two viable shapes, cheapest first:

1. **Fold the three-file custody assertion into an existing dispatching stage.** The
   natural home is `key_custody_validation` (already per-node, already Linux-live, already
   fail-closed on an explicit `overall_ok`), extending its Linux contract with the three
   membership paths. One new assertion, no new plan row, no change to plan-shape counts.
   Still an owner decision: it can turn a currently-green stage red on real guests.
2. A dedicated `MembershipGenesisValidation` `--node` stage (`@ Setup / T0Core`,
   `dependencies = [DistributeMembership]`). Cleaner ledger story, but adds a stage to the
   default plan → changes every profile → owner decision, plus the plan-count test updates
   at `plan.rs:456-530`.

**Not implemented here.** Both change what existing profiles run or what an existing
green stage asserts.

**Evidence gap admitted if deleted:** Rustynet would have no live proof that the signed
membership state is stored `0600` root-of-trust-owned on any OS. That is a
`SecurityMinimumBar`-adjacent at-rest custody claim, not a nice-to-have.

---

## 4. Stale ledger facts found

Verify-everything-against-code was the instruction; these did not survive it.

### 4.1 `BashRetirementDispositions_2026-08-22.md` B1.6 — **wrong equivalence, owner-approved**

> | B1.6 | `linux_membership_genesis` (2) | `linux_stage_membership` (136) | APPROVED 2026-08-26 (owner) |

B1 is defined as *"ledger-dialect FALSE gaps — the capability is `--node`-proven under the
column named"*. B1.1–B1.5 and B1.7–B1.12 each map a bash column onto a `--node` column
carrying the **same claim** (`linux_runtime_acls` → `linux_stage_runtime_acls_check`, etc.).

**B1.6 does not.** `linux_stage_membership` is fed by `membership_init` +
`distribute_membership` (`live_lab_stage_registry.rs:598-615`, `logical: Some("membership")`),
which prove *minting and distribution*. `linux_membership_genesis` asserted *file
mode/ownership custody + snapshot readability* (§3a). These are different claims about
different things. B1.6 is therefore a **real gap mis-filed as a dialect false gap**, and
the owner sign-off rests on that mis-statement.

The same equivalence is asserted upstream and inherits the error:
`documents/operations/done/BashOrchestratorRetirementProgram_2026-08-22.md:86`
("`linux_membership_genesis`→`linux_stage_membership` … not a real gap") and
`BashRetirementGapEnumeration_2026-08-22.md:45`.

**Recommended action for the owner:** re-file B1.6 out of B1 and into B6 (residual Linux
cells) with the §3d disposition, or accept it with the custody claim explicitly written
off. Not edited here — those are signed dispositions and the correction is the owner's.

### 4.2 Row counts stale everywhere (claims still hold; numbers do not)

| Doc | Says | Actual @ `14faad7a` |
|---|---|---|
| `LiveLabStageCoverageGapPlan_2026-08-10.md` | node ledger "106 rows" | **178 rows** |
| `CrossPlatformRoleParityRefresh_2026-07-23.md` (via `active/README.md:26`) | "88 rows", "`live_mixed_topology_validation` is 0-for-88" | **178 rows**, mixed-topology **0-for-178** (632 per-stage rows, all `skip`) |
| `BashRetirementGapEnumeration_2026-08-22.md` | node ledger 151 rows | **178 rows** |
| `BashRetirementDispositions_2026-08-22.md` B1 | "node ledger @ 151 rows" | **178 rows** |

Every *substantive* claim above re-verified as still true at 178 rows. Only the counts
are stale. Re-derive counts; do not cite them.

**Applied 2026-08-28.** All five documents carry dated in-place corrections to 178 rows
(re-derived at `34a9e6f8`); the substantive claims were left as written. The signed
disposition content in `BashRetirementDispositions_2026-08-22.md` was not touched — only
its counts — so §4.1's owner-gated B1.6 misfiling remains open.

### 4.3 `BashRetirementDispositions_2026-08-22.md` B6.2 — incomplete, not wrong

> **B6.2 `linux_stage_chaos`** — "deferred / out of mac-win-cross-OS program scope"

Accurate as a scoping decision, but it records chaos as *deferred* when the code state is
*blocked*: even an owner who un-defers it and passes `--enable-chaos-suite` gets nine
cascade-skips (§2b). The disposition's expiry ("the T2 resilience program") will therefore
be met by a no-op unless `chaos.rs:48-50` is re-parented first. Worth appending to that
entry when the T2 program opens.

### 4.4 `linux_stage_blind_exit` — the drift-correction note is confirmed

Checked in passing while enumerating always-`not_run` columns: `linux_blind_exit` is
`not_run` in 178/178, consistent with B6.1's "node deliberately skips it". No correction
needed. Recorded so a future sweep does not re-open it.

---

## 5. Cross-cutting: this is a family, not three incidents

The always-`not_run`-in-178-rows set (40 columns) decomposes cleanly:

| Class | Members | Root cause |
|---|---|---|
| Bash-dialect Linux security family | `linux_runtime_acls`, `linux_service_hardening`, `linux_authenticode`, `linux_key_custody`, **`linux_membership_genesis`**, `linux_mesh_status`, `linux_hello_limiter_flood`, **`linux_relay_forwards_frame`** | §0 — `special:` on names the `--node` engine never emits |
| macOS/Windows bash-dialect equivalents | `macos_*`/`windows_*` counterparts, `macos_pf_killswitch`, `macos_keychain_key_custody`, `windows_named_pipe_acl`, `windows_dpapi_key_custody` | same |
| Chaos aggregate | **`linux_stage_chaos`**, `macos_stage_chaos`, `windows_stage_chaos` | §2 — opt-in flag never passed **and** tri-OS dependency mis-parenting |
| Topology-absent | `macos_exit`, `macos_relay`, `windows_relay`, `windows_blind_exit`, `linux_blind_exit`, `cross_os_lan_toggle`, `cross_os_anchor_enrollment`, `*_stage_role_transition` | no such node/role ever elected — a real parity gap, tracked by the Refresh doc, not a wiring defect |

Six of the eight bash-dialect Linux security columns were already dispositioned as B1
false gaps on the strength of a genuinely equivalent `*_check` column. Only
`linux_membership_genesis` (§4.1) and `linux_relay_forwards_frame` (B5, correctly parked
as HP-3) are not covered by that argument. So the family view **narrows** the finding
rather than widening it — but it also means any future "wire the bash-dialect columns
back in" work should be scoped as one job, not three.

---

## 6. Owner decision queue

| # | Decision | Blast radius | Recommended |
|---|---|---|---|
| D-1 | Wire `relay_forwards_frame` in as a `--node` T1 `Live` stage (§1d) | adds a stage to the **default** plan; injects an nft block + restarts two daemons mid-run | **Yes**, HP-3 is the largest looks-done-but-isn't gap |
| D-2 | Re-parent chaos `dependencies()` off `LiveMixedTopologyValidation` (§2d one-liner) | **zero** for current runs (chaos is out of the default plan); makes `--enable-chaos-suite` meaningful | **Yes**, and start with the three `Offline` stages only |
| D-3 | Prove membership-file custody on `--node` — fold into `key_custody_validation` (§3d option 1) | can turn a currently-green stage red on real guests | **Yes**, option 1 |
| D-4 | Re-file `BashRetirementDispositions` B1.6 out of B1 (§4.1) | doc-only; re-opens one signed disposition | **Yes** |

Nothing in this triage was implemented. No code changed, so no §7 gate run was required.

## 7. Reproduction

```bash
# 178 rows; the three columns
python3 - <<'PY'
import csv
from collections import Counter
rows = list(csv.DictReader(open('documents/operations/live_lab_node_run_matrix.csv')))
print(len(rows), 'rows')
for c in ('linux_stage_chaos','linux_membership_genesis','linux_relay_forwards_frame'):
    print(c, dict(Counter((r[c] or '').strip() for r in rows)))
PY

# zero chaos_* and zero validate_linux_* among 28,893 per-stage rows
python3 - <<'PY'
import csv
rows = list(csv.DictReader(open('documents/operations/live_lab_node_stage_results.csv')))
print(len(rows), 'rows', len({r['stage'] for r in rows}), 'distinct stages')
print('chaos_*:', sum(r['stage'].startswith('chaos_') for r in rows))
print('validate_linux_*:', sum(r['stage'].startswith('validate_linux') for r in rows))
PY
```

`awk -F,` on these files is wrong by construction (quoted commas). Use a CSV reader.

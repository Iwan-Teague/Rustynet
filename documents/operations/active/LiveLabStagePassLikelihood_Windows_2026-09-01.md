# Live-Lab Stage Pass-Likelihood — Windows (Rust `--node` engine)

**Date:** 2026-09-01
**Engine of record:** the Rust `--node` orchestrator; evidence ledger
`documents/operations/live_lab_node_run_matrix.csv` (242 rows at the time of
this analysis, parsed quote-aware). The legacy bash archive
(`live_lab_run_matrix.csv`) is **not** consulted as evidence anywhere in this
document — the bash engine was deleted in W5.7 and its green Windows rows
(including the r49 17/17 run and 66 bash bootstrap passes) say nothing about
the `--node` engine.
**Scope:** docs-only analysis. No code changed, no gates run, and — because
the lab is currently DOWN — **no live pass is claimed anywhere in this
document.** Every pass-likelihood below is a prediction with citations, not an
observation.

---

## 1) Headline

**Windows on the `--node` engine is a bootstrap-gated cascade.** Of the ~30
Windows-scoped stages that have never passed, nearly every one is blocked
behind a chain that starts at one stage: `windows_stage_bootstrap` has a
lifetime record of **5 fail / 0 pass** on the `--node` ledger, and every
downstream Windows column is all-skip or all-not_run as a consequence
(skip-cascade: a planned-but-unmet prerequisite stage marks its dependents
`skip` in the same run). Behind that single gate sit two root causes worth
fixing (one code fix already landed but never lab-verified, one guest-side
remediation still pending), plus one hardware blocker, one design exclusion,
and one independent code defect that would keep an entire validator family
failing even after bootstrap goes green.

Nothing about the stage *implementations* is known-broken: the stages exist
and are wired (§3); the gap is running them green, on the engine of record.

## 2) Ledger facts (the 0-pass population)

Counted from the live ledger with a quote-aware CSV parser (never `awk -F,`;
QH-07):

| Column | Record | Note |
| --- | --- | --- |
| `windows_stage_bootstrap` | 5 fail / 237 not_run / **0 pass** | the gate |
| `windows_present` | 5 pass | presence detection works; bootstrap does not |
| `windows_stage_cleanup` | 3 pass / 2 fail | **the only Windows stage with passes** |
| every downstream `windows_stage_*` | 4 or 5 skip, else not_run, **0 pass** | skip-cascade from the 5 fail runs |
| `windows_stage_chaos`, `windows_stage_role_transition` | 242 not_run | never even planned past bootstrap |

The 5 failing runs:
`livelab-1784489499` / `-1784492387` / `-1784493982` (2026-07-19, commit
`db3ff1aa`, guest **windows-utm-1**, client slot) and `livelab-1785005557` /
`-1785006739` (2026-07-25, commit `b7667cce`, guest **windows-x86-1** on
remote host `ubuntu-kvm-1`, admin/exit/anchor slots). Local report
directories for the 07-19 runs are deleted; the 07-25 reports live on
`ubuntu-kvm-1` at `/home/ubuntu-server/lab-reports/winnat-*`, a host that is
itself unreachable at the time of writing (both tailnet `100.117.1.47` and
LAN `172.23.56.5` time out on TCP/22) — so failure #5's raw evidence is
presently unreadable.

**Per-run decomposition (from `WindowsNodeBootstrapTriageVerdict_2026-08-28.md`
§0):** only **3 of the 5 rows are real bootstrap failures**. Two died in the
run-scoped `preflight` stage before bootstrap was ever attempted (#1: topology
validation "exactly 1 Exit node found 0"; #4: guest clock skew 3602 s), and
the run-scoped preflight failure at the time poisoned every OS bootstrap
column in the row. That poisoning is fixed forward-only by W-FIX-3 (the
`run_scoped` flag, landed 2026-08-28): a run-scoped preflight failure no
longer writes a node-scoped bootstrap verdict. Forward rows are trustworthy;
the 5 historical rows are not evidence that `windows_stage_bootstrap` failed
five times.

## 3) Root-cause classes and pass-likelihood, per group

### 3.1 `windows_stage_bootstrap` — WIRING/GATE fix landed, UNVERIFIED; guest remediation pending

**Likelihood once remediated: MEDIUM. No live evidence today.**

The failing step is `Ensure-WingetConfigurationDependencies`
(`scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1248`), which runs
`winget configure --file` at :1256 (throw on failure at :1258) — a hard
dependency on the opt-in WinGet Configuration feature that the script's own
`Require-Winget` gate (:616-639) never enables or checks. (Line numbers are
the current tree; the 08-28 verdict cited the pre-W-FIX-1 positions
:1130/:1132/:548-571.) The code half is **landed**: W-FIX-1 adds
`Enable-WingetConfigurationFeature` (:1209-1247), called at :1255 immediately
before the configure, which runs `winget configure --enable` idempotently,
with a content-pin test
(`bootstrap_script_enables_winget_configuration_feature_before_configuring`)
in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs`;
W-FIX-2 landed the CLIXML/raw-stderr decode in `adapter/ssh.rs`
(`render_command_failure_detail`), fixing the §5 diagnosability defect that
made earlier failures unreadable. **But there are zero lab-verified runs
since** — the fix's effect on a real cold guest is unproven.

The guest half is the reason bootstrap cannot simply be re-run today:

- **windows-utm-1** (2026-08-28 health check, verdict §6): boots, ICMP ok,
  RPC/NetBIOS/SMB ports open, but TCP/22, 3389 and 5985 are CLOSED and no
  QEMU agent runs — there is **no remote management path at all**. Remediation
  requires the UTM console (enable sshd + firewall rule, `w32tm /resync` for
  the clock-skew class).
- **windows-x86-1**: on `ubuntu-kvm-1`, which is unreachable (above). Failure
  #5 (`Install-RustyNetWindows…` at char:108) is **UNRESOLVED** for want of
  its report.

One scope note that prevents misreading history: `winget configure` is a
**cold-guest path only**. Build-RustyNet guards it behind a toolchain-presence
check, and a `--node` run only invokes `-Phase build-release`
(`windows_install.rs:575`); the bash era never hit this branch at all (its 66
bootstrap passes rode pre-baked guest toolchains). This is why the bash
archive is not merely a different engine — it exercised a different code
path.

**Pass-likelihood rationale:** the single known code defect has a landed,
test-pinned fix; the remaining blockers are operational (console work on one
guest, host restore for the other). MEDIUM, not HIGH, because (a) nothing is
lab-verified and cold-guest WinGet behavior on these images is exactly what
kept failing, and (b) failure #5 is undiagnosed — it may name a second defect.

**Unblock sequence (W-FIX-4, verdict §7.1):** console-remediate
windows-utm-1 → re-run a minimal topology (`debian-headless-2:exit` +
`windows-utm-1:client`) for the first `--node` Windows pass → then the
AcceptanceSpec §5.4 3-of-3 stability gate. W-FIX-5 (restore `ubuntu-kvm-1`)
closes #5 and re-enables windows-x86-1.

### 3.2 The per-node self-check family (`windows_stage_*_check`) — bootstrap-gated now, then BLOCKED at the §4.7 identity gate

**Likelihood after bootstrap alone: LOW. Blocked until a Windows `status`
subcommand exists.**

The `_check` columns
(`windows_stage_dns_failclosed_check`, `_runtime_acls_check`,
`_service_hardening_check`, `_key_custody_check`, `_mesh_status_check`,
`_authenticode_check`, `ipv6_leak_check`, `exit_demotion_residue_check`,
`exit_dns_failclosed_check`, `exit_nat_lifecycle_check`,
`blind_exit_dataplane_check`) are written by the `state_machine_only` per-node
self-check stages in `live_lab_stage_registry.rs` (:753-916), each of which
runs a role validator through
`enforce_identity_challenge`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs:516-524`).
That gate is fail-closed by design: it rejects `Unverifiable`,
`NodeIdMismatch`, and `NotLiveAssertion` identity evidence **before** every
role validator runs, and the test
`challenge_gate_rejects_non_live_config_file_identity` (:685-697) proves a
Windows node asserting identity from a config file is rejected. The code
comment at the gate says it outright: *today only Windows, whose control CLI
has no `status` subcommand, a KNOWN deferred §4.7 gap.*

Consequence: even with a healthy mesh and a green bootstrap, the entire
RuntimeAcls / ServiceHardening / KeyCustody / DnsFailclosed / MeshStatus /
Authenticode validator family fails closed on Windows until the Windows
control CLI grows a `status` subcommand emitting the live-assertion evidence
every other platform already provides (the Refresh doc shows the macOS
blind_exit validator consuming `rustynet status` key=value output,
`node_role=blind_exit`, as its identity evidence).

**Fix (highest-leverage code item after W-FIX-4):** implement the `status`
subcommand on the Windows control CLI (live node identity + role emission,
matching the cross-platform key=value contract). Sized M. Must not be worked
around by widening the identity gate — the gate's fail-closed posture is the
control being tested.

### 3.3 Role-election cells (admin, anchor, relay_service_lifecycle, role_transition, mesh_join + the live-but-never-run specials)

**Likelihood: LOW-to-MEDIUM, staged — bootstrap first, identity gate second,
then ordinary defect-driving.**

Election is not a gap: the skip counts (4 or 5 skips on exactly the
WantsWindows columns, in exactly the 5 fail runs) prove the registry planned
the Windows stages whenever a Windows node was in the topology — the stages
skip-cascaded behind bootstrap. The special columns often misread as dead
(`windows_dpapi_key_custody`, `windows_membership_revoke_applies`,
`windows_membership_signature_forgery`, `windows_gossip_revoked_readmit`,
`windows_enrollment_replay`, `windows_hello_limiter_flood`,
`windows_mesh_status`, `windows_privileged_helper_allowlist`,
`windows_policy_default_deny`, `windows_revoked_peer_denied_e2e`,
`windows_blind_exit_reversal_denied`, `windows_named_pipe_acl`) are all
**live, wired stages** — each maps to a real registry stage
(`live_lab_stage_registry.rs` :1383-1675, `EnableRule::WantsWindows`) that
the `--node` writer populates via `set_special_stage_values`
(`live_lab_run_matrix.rs:2247-2258`). They are all-not_run because their
stages have never run, not because they are unwired. Expect them to become
runnable in the same order as §3.2, since the validator-backed ones share the
identity gate.

Two standing capability caps sit **behind** bootstrap and would block the
anchor/gossip-flavored cells even with CP-4 done (verdict §7.4): Windows has
**no gossip transport** (`adapter/windows.rs:158-160`,
`GossipIdentity::DeferredPlatform` — the daemon refuses the gossip secret and
the transport is unix-only) and **no self-issued signed bundles**
(`windows.rs:288-311`, ephemeral local mint). These are deferred-by-design
items with real engineering behind them; they cap anchor/gossip cells, not
client/bootstrap cells.

The Refresh doc's status rows agree: Windows client/admin/relay/anchor are
all ⬛ bootstrap-blocked, with the note that the stages exist and the gap is
running them green. `windows_stage_role_transition` has additionally never
run on **either** OS (242 not_run), so its Windows cell inherits a
Linux-unproven validator too.

### 3.4 Exit-family cells (`exit_handoff`, exit `_check` trio, cross-network exit scenarios) — HARDWARE-blocked (CP-3)

**Likelihood in the current lab: effectively ZERO.**

Windows exit is gated on WinNAT's UDP-source-port behavior, which cannot be
validated in a UTM guest on Apple Silicon; the Refresh doc marks it 🔒 CP-3,
needing a physical Windows 11 Pro/Enterprise ARM device. The
`promote_windows_exit_active` code path is complete — this is purely an
owner/hardware task, not a code task. Any Windows exit column
(`windows_stage_exit`, the exit `_check` trio, two-hop scenarios that route
through a Windows exit) stays 0-pass until that device exists. Note also the
Harvest-form caveat: `--skip-linux-live-suite` drops `live_anchor` +
`exit_*_validation` stages (61→19 stages), so exit cells additionally
require a full-suite run for their evidence to count.

### 3.5 `blind_exit` — DESIGN-EXCLUDED, not a defect

Windows blind_exit is excluded by design (a hard error in main.rs, per the
Refresh doc); `windows_stage_blind_exit` and
`windows_stage_blind_exit_dataplane_check` should never be expected to pass
on Windows and should not be counted as debt. `windows_blind_exit_reversal_denied`
may legitimately stay not_run for the same reason.

### 3.6 Mesh-dependent integration stages (two_hop, managed_dns, traversal, lan_toggle, mixed_topology, reboot_recovery, network_flap, enrollment_restart, secrets_not_in_logs, key_custody, extended_soak, chaos)

**Likelihood: LOW today; MEDIUM conditional on §3.1+§3.2 landing — with one
unknown that only a live run can retire.**

These are skip-cascaded behind bootstrap (§2) and additionally exercise the
data plane, so they inherit everything above plus one Windows-specific
unknown: **CP-1-class LAN reachability has never been measured for a Windows
guest.** The macOS two-hop record is 0-for-8 on UTM Shared-NAT against the
bridge100 no-L3-path failure; windows-utm-1 sits on the same
`192.168.64.x` Shared-NAT fabric and may hit the same wall. Do not assume
mesh-join success from bootstrap success — plan for this to be the next
defect surfaced.

## 4) Ranked highest-leverage fixes

1. **W-FIX-4 — guest remediation + first re-run** (verdict §7.1). UTM-console
   work on windows-utm-1 (sshd + firewall rule, `w32tm /resync`; `winget
   configure --enable` is already self-healing via W-FIX-1), then the minimal
   `debian-headless-2:exit` + `windows-utm-1:client` topology. Breaks the
   single gate that holds ~30 stages; also produces the first lab evidence
   for the landed-but-unverified W-FIX-1/2.
2. **Windows `status` subcommand** (§4.7, `node_adapter.rs:516-524`). Without
   it, bootstrap going green only moves the wall — the entire per-node
   validator family (all `_check` columns plus the validator-backed specials)
   fails closed at the identity gate. Sized M; keeps the gate fail-closed.
3. **W-FIX-5 — restore `ubuntu-kvm-1`** (tailnet + LAN both dead on :22).
   Unlocks failure #5's report (`winnat-*`), the windows-x86-1 guest, and
   the admin/exit/anchor slots it was elected to.
4. **CP-3 hardware owner task** — procure/allocate a physical Windows 11
   Pro/Ent ARM device. Unblocks the exit family; code is already complete.
5. **Windows gossip transport + self-issued signed bundles** (deferred,
   `adapter/windows.rs:158-160`, `:288-311`) — the last capability caps for
   anchor/gossip cells; largest engineering item, correctly sequenced last.

## 5) Summary table

| Group | Columns (representative) | Current `--node` status | Primary blocker | Pass-likelihood |
| --- | --- | --- | --- | --- |
| Bootstrap | `windows_stage_bootstrap` | 5 fail / 0 pass (3 real, 2 preflight-poisoned) | guest remediation; W-FIX-1 landed unverified | MEDIUM after W-FIX-4 |
| Self-checks | all `windows_stage_*_check` (11) | 0 pass, skip-cascaded | §4.7 identity gate (no Windows `status`) | LOW until `status` exists |
| Specials/roles | admin, anchor, relay, mesh_join, 12 special columns | 0 pass, skip-cascaded | bootstrap, then identity gate; anchor/gossip also capability-capped | LOW→MEDIUM staged |
| Exit family | `windows_stage_exit`, exit `_check` trio | 0 pass | CP-3 hardware (WinNAT/ARM device) | ~ZERO in current lab |
| blind_exit | `windows_stage_blind_exit`, `_dataplane_check` | 0 pass, by design | design-excluded on Windows | N/A — not debt |
| Integration mesh | two_hop, managed_dns, traversal, flap, soak, chaos… | 0 pass, skip-cascaded | everything above + unmeasured CP-1-class LAN reachability | LOW→MEDIUM conditional |

## 6) Evidence index

- Ledger: `documents/operations/live_lab_node_run_matrix.csv` (242 rows; quote-aware parse; column counts in §2).
- Root-cause verdict + fix plan: `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` (§0 run decomposition, §4 failure #5, §6 guest health, §7 fixes, §9.1-§9.3 landed-fix citations).
- Status of record: `CrossPlatformRoleParityRefresh_2026-07-23.md` (Windows role rows; CP-3; blind_exit exclusion; CP-1 caveat; Harvest-form caveat).
- Code citations: `live_lab_stage_registry.rs` :753-916, :1081, :1383-1675; `live_lab_run_matrix.rs` :1881-1966, :2247-2258; `node_adapter.rs` :516-524, :685-697; `windows_install.rs` (content-pin test :1765; build-release invocation :575); `adapter/windows.rs` :158-160, :288-311; `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` :616-639, :1209-1247, :1248-1258.
- Explicitly **not** evidence: `live_lab_run_matrix.csv` (bash archive, frozen W5.7; its green Windows rows rode pre-baked toolchains and a deleted engine).

No live pass is claimed in this document. The lab is down; the first
lab-verified `--node` Windows pass is still pending W-FIX-4.

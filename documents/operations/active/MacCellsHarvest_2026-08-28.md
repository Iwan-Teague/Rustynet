# MAC-CELLS — macOS `anchor` and `exit` election on the `--node` engine — 2026-08-28

**Scope.** Harvest tasks 7+8 of `CrossPlatformRoleParityRefresh_2026-07-23.md` §3
Track M sub-stream (b): elect the macOS guest as `anchor`, then as `exit`, on the
Rust `--node` orchestrator (the engine of record) and record what the parity
cells actually earn. Both cells were ⬛ *never elected on `--node`* before today.

**Result in one line.** Both roles were **elected live on `--node` for the first
time**; neither cell earns a green. The macOS `anchor` cell is blocked by a
deliberate posture gate that is **circular as written**, and the run reddened on
a genuine macOS DNS fail-closed gap that the QH-39 work newly exposes. Three
tonight-merged changes (QH-39 resolver observation, QH-39 mesh-status freshness
bound, the QH-40 shutdown-residue marker) got their first macOS exercise; the
residue marker **fired correctly and its checker then failed to find it**.

Triage only — **no code was changed** by this work.

---

## 1. Runs

All at commit `77ff1933885fcb6c86e27a3ffbe3013dddc6c6fe`, `git_dirty_state=clean`,
operator `iwan`, engine `--node`, `--skip-linux-live-suite --skip-cross-network`.

| # | Run id | Topology | Overall | First failed stage |
|---|---|---|---|---|
| 1 | `livelab-1787910442-77ff1933885f` | `macos-utm-1:anchor` only | fail | `preflight` |
| 2 | *(refused at launch gate — no run id)* | as #1 + exit + client | — | launch gate |
| 3 | `livelab-1787911937-77ff1933885f` | `macos-utm-1:anchor` + `lenovo-exit-1:exit` + `lenovo-client-1:client` | fail | `validate_baseline_runtime` |

Run 3 is the Cell-1 evidence run: 19 stages, **passed=15 failed=1 skipped=3**.
Report dir `state/mac-cells/anchor3-1787910672`. Ledger rows verified present for
runs 1 and 3 in `documents/operations/live_lab_node_run_matrix.csv`.

Run 2 never produced a run id: the launch gate correctly refused it because run
1's `preflight` failure had no recorded remedy. Both remedies are now recorded in
`documents/operations/live_lab_stage_triage.jsonl`.

---

## 2. Cell 1 — macOS `anchor`

### 2.1 Outcome: `anchor_validation = skip` (honest), cell stays unproven

Per §12.3's "row exists ≠ stage passed" rule the verdict is read from the stage's
own artifact, not the ledger column. The artifact
(`state/mac-cells/anchor3-1787910672/anchor_validation.reported_skips.json`)
records:

```json
"runtime_skipped_nodes": [ { "alias": "macos-utm-1", "platform": "Macos" } ]
```

What this means, precisely — and the distinction matters, because it is the
first real signal this cell has ever produced:

* The macOS anchor **did** run the capability-advertisement half, and it
  **passed**. In `crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs:170-176`
  a failing `validate_anchor_capability_advertisement` pushes to `failures` and
  `continue`s; the node instead reached the runtime-skip branch, which is only
  reachable *after* capability advertisement succeeds. So macOS advertises its
  full anchor capability set correctly over the live cross-OS shell seam.
* The **bundle-pull runtime substages** (`bundle_pull_loopback`,
  `invalid_token`, `log_redaction`) did not run. They are gated at
  `anchor_validation.rs:181` on `NodeRole::Anchor.is_supported_for_platform(&platform)`.
* `outcome_for` (`anchor_validation.rs:236-247`) grades any reported runtime-skip
  as `Skipped`, deliberately, so the run goes Partial rather than falsely green.

This is the code behaving exactly as documented. The cell is **not** red — it is
honestly unproven.

### 2.2 The posture gate is circular as written — CELL-BLOCKER

`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:68-70`:

```rust
NodeRole::Anchor | NodeRole::Admin | NodeRole::Relay => {
    matches!(platform, VmGuestPlatform::Linux)
}
```

The comment immediately above it (`role.rs:62-67`) states that macOS and Windows
"are promoted to supported here only once a green run is archived."

Those two facts cannot both be satisfied through this stage. `anchor_validation`
gates its runtime substages on `is_supported_for_platform`; the stage can only
reach `Passed` when no node reports a runtime skip; a macOS anchor always reports
one while the gate is Linux-only. **The green run required to lift the gate can
never be produced by the stage the gate controls.** The macOS `anchor` cell is
therefore unreachable via `anchor_validation` no matter how many times it is run.

This is a **macOS-specific code gap in the promotion path**, not an environmental
or role-election problem. It is not necessarily a defect in the gate itself — the
fail-closed default is right — but the promotion route has to come from
somewhere, and today it does not exist for `anchor`.

**The intended escape hatch is a different stage set.** The registry carries
macOS-specific anchor validators —
`deploy_macos_anchor_profile`, `validate_macos_anchor_bundle_pull`,
`validate_macos_anchor_port_mapping_authority`
(`crates/rustynet-cli/src/live_lab_stage_registry.rs:1151,1158,1168`) — which are
enabled by the `--anchor-platform macos` selector, **not** by the `--node
macos-utm-1:anchor` role election. Run 3 elected the role without the selector,
so none of those three dispatched. Electing the role and enabling the macOS
anchor validators are two independent switches, and the parity cell needs both.
That run is **still open** (see §5).

> **Disposition 2026-08-28 (MAC-D1 fix) — the circularity is broken in code;
> option (b) applied as a mechanical decoupling following the repo's own
> stage-gate precedent.** The defect was that `anchor_validation` gated its
> inline bundle-pull runtime substages on
> `NodeRole::Anchor.is_supported_for_platform` (`anchor_validation.rs:185`) —
> the one predicate whose promotion contract ("promoted only once a green run
> is archived") can never be satisfied by this stage for macOS, because the
> gate forces a reported runtime skip and `outcome_for` grades any skip as
> `Skipped` → `RunStatus::Partial`. The gate itself is NOT stale policy: it
> guards *posture promotion*, and the macOS anchor capability underneath it is
> genuinely implemented (daemon mapping `Admin|Anchor → "admin"` on macOS,
> platform-independent capability set — live-proven in §2.1 — and
> `AnchorRuntimeParams::for_platform` carries the macOS token path). What was
> wrong was the *evidence wiring*: `anchor_validation` is the only stage still
> consulting the posture predicate for its runtime gate, while its siblings
> (`deploy_relay` / `relay_validation`, `active_exit`) already key on
> per-capability predicates (`relay_lab_runtime_implemented`,
> `active_exit_runtime_implemented`). The fix applies the same pattern:
>
> * New `anchor_lab_runtime_implemented(platform)`
>   (`role_validation/anchor.rs`): true for Linux + macOS, false for Windows
>   (Phase 8 pending) and iOS/Android. The stage's runtime gate now keys on
>   this, never on `is_supported_for_platform`.
> * New pure `runtime_coverage(platform, macos_anchor_validators_elected)`
>   (`stage/anchor_validation.rs`): Linux ⇒ inline substages (unchanged);
>   macOS **with** the validator set elected in the same run
>   (`--anchor-platform macos`, threaded run-local as
>   `OrchestrationContext::macos_anchor_validators_elected` in
>   `orchestrator/native.rs`) ⇒ `DelegatedToMacosValidators` — recorded in
>   the side-car JSON under `runtime_delegated_nodes`, NOT counted as a skip,
>   so the combined run (validators green in the same invocation) can go
>   green; macOS **without** the set, and Windows ⇒ `ReportedSkip` —
>   fail-closed unchanged, the stage grades `Skipped` and the run stays
>   Partial. A resumed context reloads the election flag as `false`, which is
>   the fail-closed direction.
> * `role.rs`'s `is_supported_for_platform` arm itself is intentionally LEFT
>   Linux-only (Anchor/Admin/Relay) with the MAC-D1 evidence path documented
>   in its doc comment: the strictest-secure-default reading. The gate's own
>   contract ("promoted only once a green run is archived") is now reachable —
>   the §5 run (role election + `--anchor-platform macos` + full Linux live
>   suite, no `--skip-linux-live-suite`, per §2.3) produces exactly the
>   evidence it names — and the arm should be lifted in the follow-up commit
>   that archives that green, mirroring how Exit/macOS was promoted after its
>   blind_exit PF evidence. Lifting it preemptively, with zero archived
>   evidence, would violate the same fail-closed contract MAC-D1 preserves.
>
> Verification: fail-closed negatives pinned by unit tests —
> `runtime_coverage_macos_without_validators_is_reported_skip`,
> `runtime_coverage_windows_is_reported_skip`,
> `outcome_for_runtime_skip_with_no_failures_is_skipped` (existing),
> `anchor_lab_runtime_implemented_covers_linux_and_macos_only`; positive path
> pinned by `runtime_coverage_macos_delegates_only_when_validators_elected`,
> `outcome_for_delegated_macos_runtime_with_no_failures_is_passed`, and the
> `runtime_delegated_nodes` JSON assertion in
> `reported_skips_json_bytes_is_valid_json_naming_every_substage`.
> Gates: `cargo fmt --all -- --check`, `cargo clippy -p rustynet-cli -p
> rustynet-control --all-targets --all-features --locked -- -D warnings`, and
> `cargo test -p rustynet-cli -p rustynet-control --all-targets
> --all-features --locked` (one unrelated pre-existing failure on clean HEAD:
> `macos_doctor_custody_paths_are_installer_roots_not_linux_defaults`).
> **Cell status: UNBLOCKED for re-run** — the §5 run shape
> (`--node macos-utm-1:anchor` + `--anchor-platform macos` + full Linux live
> suite) now has a producible green; the posture arm lifts on its archived
> evidence.

### 2.3 `live_anchor` was excluded by `--skip-linux-live-suite`, not by dialect

**Correction to my own first reading, recorded rather than silently fixed.** My
initial conclusion was that `live_anchor` is a bash-dialect name that never
records on `--node`. **That is wrong.** `StageId::LiveAnchor` is a first-class
member of the Rust `--node` stage order — it is asserted in the canonical
order-of-stages test at `crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:653`
("orchestrator stage order is security-sensitive").

The real reason it is absent from both runs' resolved plans is the fast-path
flag. `--skip-linux-live-suite` drops **the entire post-baseline suite**:
`plan.rs:545-549` documents the arithmetic exactly —

> `skip_live_suite_drops_the_post_baseline_suite_but_keeps_setup_and_cleanup`
> … `// 61 total - 30 live-suite stages - 11 cross-network stages - 1 soak stage = 19.`

Both of my runs resolved to exactly **19 stages**, matching that count.

**This is the single most consequential finding for the harvest brief.** Of the
five stages the brief names, `--skip-linux-live-suite` structurally excludes
**four**:

| Harvest target | Dispatched under `--skip-linux-live-suite`? |
|---|---|
| `anchor_validation` | yes — it is a setup-tier stage |
| `live_anchor` | **no** — dropped with the live suite |
| `exit_nat_lifecycle_validation` | **no** — dropped with the live suite |
| `exit_demotion_residue_validation` | **no** — dropped with the live suite |
| `exit_dns_failclosed_validation` | **no** — dropped with the live suite |

All four are `state_machine_only: true` (`live_lab_stage_registry.rs:820,833,845`
and the `LiveAnchor` spec), i.e. **only** the `--node` plan dispatches them — so
there is no bash-archive substitute either. The runbook's fast-path form
(`skip_linux_live_suite`, which `ai_agent.rs` sets on *every* mac/win target key
`:1864-1892`) therefore **cannot** harvest these cells at all. Harvesting them
requires paying for the full Linux live suite.

That correction does not change Cell 1's verdict — `anchor_validation` did
dispatch and its skip is genuine — but it does mean the `live_anchor` half of
the cell is **untested today**, not unavailable.

> **MAC-D1 note (2026-08-28):** this §2.3 arithmetic is unchanged by the
> §2.2 disposition — the re-run that harvests the anchor cell must still pay
> for the full Linux live suite (`live_anchor`,
> `exit_nat_lifecycle_validation`, `exit_demotion_residue_validation`,
> `exit_dns_failclosed_validation` are all dropped by
> `--skip-linux-live-suite`). What the §2.2 fix changes is that the run is
> now *worth* paying for: `anchor_validation` can go green with the macOS
> runtime delegated to the elected validator set instead of structurally
> topping out at Partial.

> Disposition 2026-08-28 (updated same day): **every §2.4 arm is now fixed.**
> The `macos_anchor` arm was fixed first — it now calls `add_default_backbone`
> like `macos_exit` (pinned by
> `macos_anchor_target_carries_the_default_backbone_like_macos_exit`). The
> same-day sweep then audited **all ten** `target_from_key` arms
> (`crates/rustynet-mcp/src/bin/ai_agent.rs`) and fixed the six remaining
> missing-backbone arms the same way: `macos_admin`, `macos_blind_exit`,
> `macos_relay` (each `add_default_backbone(m, true)`, mirroring `macos_exit`'s
> exit+client+entry shape) and `windows_admin`, `windows_anchor`,
> `windows_relay` (each `add_default_backbone(m, false)`, mirroring
> `windows_exit`'s exit+client shape). Verified complete, no change needed:
> `macos_exit` and `windows_exit` (the reference shapes), and `full` (already
> carries the backbone with entry; macos/windows default to `client` and the
> Linux `exit_vm` still renders because no non-Linux exit selector is set —
> `non_linux_exit_selected` is false there). Preflight evidence:
> `stage/preflight.rs:139-149` counts only `NodeRole::Exit`, so an elected
> `admin`/`blind_exit`/`anchor`/`relay` node can never satisfy the
> exactly-one-exit requirement by itself — every single-role arm needed the
> Linux exit+client backbone. Pinned by two new loop-style equivalence tests
> (`macos_role_cell_targets_carry_the_default_backbone_like_macos_exit`,
> `windows_role_cell_targets_carry_the_default_backbone_like_windows_exit`)
> alongside the original anchor one. Not touched (out of scope, no defect
> found): the windows arms' absent explicit `rust_engine` key is harmless —
> `ai_agent.rs` defaults `rust_engine` to `true` (the W5.7 fail-closed
> default), so those arms still route through the Rust `--node` engine.

### 2.4 Role-election plumbing gap in the MCP driver

Run 1 died in `preflight` with `lab requires exactly 1 Exit node, found 0`.
That was an operator topology error on my part, but the same shape is reachable
from the sanctioned driver and would fail identically:

`crates/rustynet-mcp/src/bin/ai_agent.rs:1885-1892` — the `macos_anchor` target
sets `macos` + `anchor_platform` + `skip_linux_live_suite` + `rust_engine` but
never calls `add_default_backbone` (`:1932-1946`), unlike the sibling
`macos_exit` target at `:1864-1872` which does. `synthesize_rust_node_args`
(`:6267-6323`) then emits a single `macos-utm-1:anchor` assignment, and preflight
rejects the zero-exit topology. **Any `ai_lab_run` driven from the `macos_anchor`
target dies in preflight.** Same for `macos_blind_exit` (`:1875-1883`) and
`macos_relay`, which also omit the backbone.

Classification: **role-election plumbing**, driver-side, one missing call.

---

## 3. First macOS exercise of the tonight-merged work

### 3.1 QH-39 resolver observation — RED, and honestly so

`validate_baseline_runtime` failed: `macos-utm-1/DnsFailclosed: validation not
passed`. Per-op results from `validator_results.json`: `RuntimeAcls`,
`ServiceHardening`, `KeyCustody`, `Authenticode`, `MeshStatus` all pass;
`DnsFailclosed` alone fails. Both Linux nodes pass all six.

Reproduced by hand on the guest:

```
$ sudo /usr/local/bin/rustynetd macos-dns-failclosed-check
  "loopback_resolver_advertised": false
  "drift_reasons": [ "macOS loopback resolver is not advertised by
    /usr/sbin/scutil --dns (primary resolver is off-loopback, empty, or
    unreadable); DNS fail-closed posture cannot be verified" ]
exit: policy_reject (78)

$ cat /etc/resolv.conf
# rustynet protected-mode DNS fail-closed
nameserver 127.0.0.1

$ /usr/sbin/scutil --dns        # resolver #1 (the primary)
  nameserver[0] : 1.1.1.1
  nameserver[1] : 8.8.8.8
```

**Verdict: the check is correct and the finding underneath it is real.**
`/etc/resolv.conf` carries RustyNet's protected-mode marker claiming loopback-only
resolution, while macOS's actual resolver configuration points at two public
resolvers. On macOS `/etc/resolv.conf` is a configd-generated compatibility shim,
not the system resolver, so writing it does not redirect resolution.

This is exactly the false-green QH-39 was filed against. The pre-fix collector
hardcoded `loopback_resolver_advertised = true` whenever the file merely read;
the new code derives it from the independent `scutil --dns` source
(`crates/rustynetd/src/macos_dns_failclosed.rs:183-207`, read at `:230-246`) and
fails closed when scutil is unreadable (`:29`). QH-39's own acceptance criterion
— "the only derivations that carry new information come from an **independent**
source: `scutil --dns` … or probing that something answers on loopback:53" — is
met.

So the new check **reds honestly on its first macOS run**, and what it reveals is
a macOS DNS fail-closed **enforcement** gap: the posture is written to a file the
OS does not consult. That enforcement gap is the defect to fix; the validator is
now doing its job.

**Disposition 2026-08-28:** investigated and dispositioned **design-only,
owner-gated** —
[`MacosDnsFailclosedEnforcementGap_2026-08-28.md`](./MacosDnsFailclosedEnforcementGap_2026-08-28.md)
(root cause traced to `MacosCommandSystem::apply_dns_protection` writing only
the cosmetic `resolv.conf` + the `*.rustynet`-scoped `/etc/resolver/rustynet`
with no SystemConfiguration arm; M1 `networksetup` per-service vs M2 `scutil
State:/` override specified, M3 bind-`:53` rejected; QH-39 ledger carries the
same dated disposition). The red above stands as the honest expectation for
every protected macOS node until owner-approved enforcement lands.

Caveat recorded honestly: the by-hand reproduction above was taken *after* the
run's `cleanup` stage, so it is the post-run state, not the exact in-stage
snapshot. The in-stage verdict is the one in `validator_results.json`; the
by-hand output explains it and matches its drift reason verbatim.

### 3.2 QH-39 mesh-status freshness bound — ran, passed, bound NOT confirmed applied

`MeshStatus` returned `passed: true` on `macos-utm-1`. **This must not be read as
the freshness bound working.** QH-39's mesh-status half is precisely the defect
that `overall_ok: true` means "a state file exists and parses" when the probe is
dispatched without `--expected-peer-ids` / `--max-age-seconds`. A bare `pass` on
this op is the *same observable* as the false green QH-39 documented.

I did not confirm from this run's artifacts that the `--node` probe path actually
emitted the freshness flags, so the honest status is **unverified, not proven**.
Confirming it needs the dispatched argv for the `MeshStatus` `DaemonProbeOp` on
the `--node` path (`vm_lab/mod.rs:11420-11432`, `build_argv` at `:11338`) — that
is the plumbing QH-39 called for. Until that argv is observed carrying
`--max-age-seconds`, treat `macos MeshStatus = pass` as **not yet evidence**.

### 3.3 QH-40 shutdown-residue marker — FIRED CORRECTLY on macOS (first time)

The marker was written on the guest during run 3, at
`/usr/local/var/rustynet/rustynetd.state.shutdown-residue.json`:

```json
{ "schema_version": 1, "recorded_unix": 1787911895, "platform": "macos",
  "node_id": "macos-utm-1-bootstrap", "trigger": "unix_shutdown_signal",
  "rollback_error": "rollback failed: rollback dns protection: … privileged
    helper response read failed: truncated frame header …; backend shutdown: …
    Connection refused (os error 61); exit-mode rollback failed: …; cleanup
    failed: …; interface cleanup failed: …" }
```

This is the QH-40 signature reproduced in full — every teardown path failing
(DNS protection, firewall, backend shutdown, exit-mode rollback, cleanup,
interface cleanup) — but now, unlike every prior observation, it is **durably
recorded rather than invisible**. That was the whole point of the marker, and it
works on macOS.

Pointed at the real state path the exit-78 contract also works:

```
$ sudo rustynetd shutdown-residue-check --state /usr/local/var/rustynet/rustynetd.state
rustynetd shutdown left dataplane residue [policy_reject (78)]: shutdown rollback
failed (fail-closed): node_id=macos-utm-1-bootstrap trigger=unix_shutdown_signal
platform=macos …
```

The observed failure signature is `truncated frame header` followed by
`Connection refused (os error 61)` on
`/private/var/run/rustynet/rustynetd-privileged.sock` — consistent with the
QH-40-MEASURE §2 completion race (the helper is gone by the time the daemon's
rollback reaches it), not with the refuted I/O-timeout mechanism. Note the guest
still carries the **pre-fix** deployment with respect to the helper/client
timeout pair: the `work/helper-timeout-mismatch` change (client default 2000 →
3000 ms, derived from the helper's server default) renders at install time, and
this run's bootstrap deployed from `main`, which does not carry it. So this run
does **not** exercise the timeout-pair fix; it exercises the marker only.

### 3.4 DEFECT — `shutdown-residue-check` reports **clean** on macOS while a marker exists

```
$ sudo /usr/local/bin/rustynetd shutdown-residue-check
shutdown-residue-check: clean (no marker at /var/lib/rustynet/rustynetd.state.shutdown-residue.json)
```

…while the marker sits at `/usr/local/var/rustynet/rustynetd.state.shutdown-residue.json`.

Cause: `crates/rustynetd/src/main.rs:183` defaults the state path to
`DEFAULT_STATE_PATH`, and `crates/rustynetd/src/daemon.rs:169-170` defines it as

```rust
#[cfg(not(windows))]
pub const DEFAULT_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";
```

i.e. macOS silently inherits the Linux path. The asymmetry is visible three lines
up: `DEFAULT_SOCKET_PATH` **does** get a `#[cfg(target_os = "macos")]` arm
(`daemon.rs:163-164`) pointing at `/private/var/run/…`, while the state path does
not, and the macOS installer deploys state under `/usr/local/var/rustynet/`.

**Severity: this is a fail-closed check that fails OPEN on macOS.** A caller that
invokes `shutdown-residue-check` without `--state` gets exit 0 and the word
"clean" on a host that is carrying real dataplane residue — precisely the
invisible-residue condition QH-40 exists to eliminate, reintroduced one layer up
in the tool built to detect it. Any macOS residue assertion wired without an
explicit `--state` is worthless.

Classification: **macOS-specific code gap**, one missing cfg arm.
Remedy not applied (triage only): give `DEFAULT_STATE_PATH` a macOS arm matching
the installer's path, or make the residue-check subcommand resolve the platform
state path rather than the Linux constant.

> **DISPOSITION 2026-08-28 — FIXED.** `DEFAULT_STATE_PATH` gained a
> `#[cfg(target_os = "macos")]` arm at the installer's
> `/usr/local/var/rustynet/rustynetd.state`, and both the writer
> (`DaemonConfig::default`) and the checker (`shutdown-residue-check`'s
> implicit `--state`) now resolve through one shared
> `daemon::default_state_path()` function — no duplicated constant. The
> fail-closed posture is untouched (an unreadable marker still counts as
> residue). Pinned by three new unit tests (writer/checker identity,
> macOS-not-Linux-path cfg-gated, Linux-unchanged counterpart); see the QH-40
> entry's 2026-08-28 status in `QualityHardeningTodo_2026-07-25.md`.

---

## 4. Cell 2 — macOS `exit`

Run `livelab-1787913512-a5e93c8dd781`, report dir
`state/mac-cells/exit-1787912119`, topology
`macos-utm-1:exit` + `lenovo-exit-1:entry` + `lenovo-client-1:client` with
`--macos-promote-exit` (the Option-B shape: `synthesize_rust_node_args`
excludes a Linux exit whenever a non-Linux exit is selected,
`ai_agent.rs:6303-6315`). 19 stages, **passed=9 failed=1 skipped=9**.

**Provenance caveat, recorded honestly.** This run is at commit
`a5e93c8dd781adce0a99d629d347674b5fd5952a` with `git_dirty_state=dirty:recorded`
— *not* Cell 1's clean `77ff1933`. `main` advanced under the run (`work/leak-fix`
merged while it was in flight) and the working tree carried the ledger CSV
appends from the earlier runs. Under the AcceptanceSpec §5.4
"N-of-N at a single clean commit" rule this run **cannot** contribute to a
stability count. It is diagnostic evidence only.

### 4.1 Outcome: `membership_init = fail`; none of the three exit stages ran

```
membership_init fail: issue_membership_owner_key: protocol error:
  membership owner public key not found on remote; has membership been initialized?
```

Everything downstream skipped on the dependency. The three brief-named exit
stages (`exit_nat_lifecycle_validation`, `exit_demotion_residue_validation`,
`exit_dns_failclosed_validation`) were **never planned** in the first place per
§2.3, and would have been unreachable anyway behind this failure.

So the macOS `exit` cell yields **no exit-stage evidence at all**. It fails
earlier than the exit role: it fails at becoming the membership owner.

### 4.2 Root cause — the macOS owner-key path constant points at the wrong file

On the `--node` engine `membership_init` is role-gated to `exit`
(`node_stage_plan.json` records `"roles": ["exit"]`), so **electing macOS as exit
also makes macOS the membership owner**. `MembershipInitStage::execute`
(`stage/membership_init.rs:50,55`) calls `issue_membership_owner_key()` *before*
`init_membership_snapshot()`, so the owner pubkey must already exist on the host.

The macOS adapter reads the wrong path, with the wrong privilege:

`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs:29-34`
```rust
&format!("cat '{MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH}' 2>/dev/null || echo ''"),
```
where `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH`
(`adapter/macos_install.rs:27-28`) = `/usr/local/var/rustynet/membership/membership.owner.key.pub`.

Its Linux twin, `adapter/linux_membership.rs:25-31`, does this instead:
```rust
"sudo -n cat /etc/rustynet/membership.owner.key.pub 2>/dev/null || \
 sudo -n cat /var/lib/rustynet/membership.owner.key.pub 2>/dev/null || echo ''"
```

Measured on `macos-utm-1`:

```
$ cat /usr/local/var/rustynet/membership/membership.owner.key.pub
cat: …: Permission denied                     # dir is drwx------ rustynetd:rustynetd
$ sudo cat /usr/local/var/rustynet/membership/membership.owner.key.pub
cat: …: No such file or directory             # nothing there even with privilege
$ sudo find /usr/local/var/rustynet /etc/rustynet -name '*owner*'
/etc/rustynet/membership.owner.key.pub        # -rw-r--r-- root:wheel, 32 bytes
```

**A valid owner pubkey is present on the macOS host — at the same
`/etc/rustynet/membership.owner.key.pub` the Linux adapter looks in first — and
the macOS adapter never looks there.** Two independent defects, either of which
alone breaks the stage:

1. **Wrong path constant** (`macos_install.rs:27-28`) — the configured location
   holds no key; the key that exists is at the Linux-conventional path.
2. **Missing privilege escalation** (`macos_membership.rs:31`) — a bare `cat`
   where the Linux twin uses `sudo -n`. The configured directory is mode `0700`
   owned by `rustynetd` while the SSH user is `mac`, so even a correctly-placed
   key would read `Permission denied`, and `2>/dev/null || echo ''` converts that
   into the same indistinguishable empty-string result.

Defect 2 also degrades the diagnostic: a permission error and a genuinely absent
file both surface as "has membership been initialized?", which is why the message
points at initialization rather than at access.

**Classification: macOS-specific code gap**, in the membership adapter — not
environmental, not role-election plumbing. The role election itself worked: the
orchestrator accepted `macos-utm-1:exit`, preflight passed with exactly one exit,
and `bootstrap_hosts` deployed to all three nodes.

**Consequence for the parity matrix:** macOS cannot hold *any*
membership-owner role on `--node` until this is fixed. Since `membership_init`
is gated on `exit`, this blocks the macOS `exit` cell completely and would block
`blind_exit` under the same topology shape.

Honesty note on the `/etc/rustynet/membership.owner.key.pub` file: it is dated
`Jul 9 16:10`, i.e. it is a leftover from an earlier era of this guest, not
something today's bootstrap seeded. So this evidence proves the adapter reads the
wrong location; it does **not** prove that a fresh macOS install seeds the right
one. Whether the macOS install path seeds an owner key at all is a follow-up
question this run cannot answer.

#### §4.2 disposition — DONE 2026-08-28 (MAC-D2 fix)

The open question is answered from the code: **a fresh macOS install does seed
an owner key, at `/usr/local/etc/rustynet/membership.owner.key.pub`.** The lab
bootstrap path is `ops e2e-bootstrap-host` → the macOS genesis driver
`execute_ops_e2e_bootstrap_macos` (`ops_e2e.rs`, Track B B1.2), which runs
`rustynetd membership init --owner-signing-key /usr/local/etc/rustynet/
membership.owner.key`; `run_membership_init` writes the public key at
`{owner_signing_key_path}.pub`. Neither of the two locations probed on the
guest is it: `/usr/local/var/rustynet/membership/` holds only snapshot/log
state, and the guest's `/etc/rustynet/...` file is the Jul 9 leftover. (Tonight's
`find` also never searched `/usr/local/etc` — the seeded location — so the
key was likely present all along.) The fix therefore points the adapter at the
genesis write path rather than copying the Linux path:

* `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` (`macos_install.rs`) is now
  `/usr/local/etc/rustynet/membership.owner.key.pub`, derived as
  `{MACOS_OWNER_SIGNING_KEY_PATH}.pub`, with a macOS-gated test pinning the
  adapter constant to `ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH` so the read path
  and the write path cannot drift again.
* The read (`macos_membership::issue_membership_owner_key`) now uses `sudo -n`
  like the Linux twin and **fails loud with distinct, non-empty errors** for
  absent-file, unreadable-file (permission/sudo refusal — including a
  passwordless-sudo-unavailable guard), and empty-output, instead of
  collapsing all three into the same "has membership been initialized?"
  empty string.

Verified: `cargo test -p rustynet-cli --features vm-lab --lib
vm_lab::orchestrator::adapter` 268 passed; `xtask gates --skip-test -p
rustynet-cli` green. This unblocks the macOS exit cell (and blind_exit under
the same shape) for a live re-run — a lab task, not done here.

### 4.3 QH-39 / QH-40 / timeout-pair exercise in Cell 2 — none

The run died before `enforce_baseline_runtime`, so `validate_baseline_runtime`
never ran and neither QH-39 check was exercised in this run. The QH-40
observations in §3.3–§3.4 come from Cell 1 only. The macOS exit `pf` NAT path,
and therefore the §6 "equivalent-strength end-to-end egress assertion" the parity
doc requires of a macOS exit cell, was **not touched**.

---

## 5. Matrix cells — updated vs still open

**Updated** in `CrossPlatformRoleParityRefresh_2026-07-23.md` §1 — both cells move
off ⬛ *never elected*, because both roles were in fact elected and produced a
real signal. Neither moves to 🟢; both become 🔴 with a named blocker.

* macOS **anchor** — elected live on `--node` (`livelab-1787911937-77ff1933885f`,
  `77ff1933`, clean). Capability advertisement **passed**; bundle-pull runtime
  reported-skipped on the §2.2 posture gate.
* macOS **exit** — elected live on `--node` (`livelab-1787913512-a5e93c8dd781`,
  **dirty**). Fails at `membership_init` per §4.2, before any exit stage.

**Still open — nothing here earns a green:**

* macOS anchor **green** — needs the §2.2 circularity resolved *and* a run with
  `--anchor-platform macos` (so `validate_macos_anchor_bundle_pull` /
  `validate_macos_anchor_port_mapping_authority` dispatch) *and* a run without
  `--skip-linux-live-suite` (so `live_anchor` dispatches, §2.3). None run today.
* macOS exit — blocked on the §4.2 adapter defect. No exit stage has ever
  dispatched on macOS; the §6 end-to-end egress assertion remains untouched.
* `exit_nat_lifecycle_validation`, `exit_demotion_residue_validation`,
  `exit_dns_failclosed_validation` — **never dispatched**, on either the
  fast-path form (§2.3) or behind the §4.2 blocker.
* QH-39 mesh-status freshness bound — passed, but **not confirmed applied**
  (§3.2). Needs the dispatched argv observed.
* The helper/client timeout pair — not exercised; the guest carries the pre-fix
  install (§3.3).
* Stability — no cell has an N-of-N count. Cell 1 is n=1 at a clean commit;
  Cell 2 is n=1 at a dirty one and cannot count at all.

**Process observation.** The exit run's `membership_init` failure produced **no
stub** in `live_lab_stage_triage.jsonl` (verified by scanning for
`livelab-1787913512-*`), unlike the two earlier failures which did. The launch
gate keys on recorded stubs, so a failure with no stub is one the gate will not
ask about on the next launch. Flagged, not diagnosed.

## 6. Environmental note — QH-41 still in force, and it shaped the topology

`macos-utm-1` remains on the isolated Apple-Virtualization vmnet bridge
(192.168.65.101) while the local UTM Linux guests are on the QEMU bridge
(192.168.64.0/24). Measured today: mac → `192.168.64.4` **100% loss**. As QH-41's
2026-08-12 correction records, both sides are already `Mode = "Shared"` and the
split is a *backend* property, so no mode change or boot ordering merges them.

The local Debian guests are therefore unusable as the macOS run's peers. The
LAN-bridged Lenovo guests are reachable outbound from the mac
(`192.168.0.30/.31`, 0% loss) and were used instead. The reverse direction does
**not** work — `lenovo-exit-1 → 192.168.65.101` is 100% loss, the mac being
behind vmnet NAT — which is a standing constraint on any macOS cell whose proof
requires a peer to initiate toward the mac.

Per the §12.3.1 note, every reachability verdict here is from `nc`/`ping`/`ssh`
in the shell, not from an MCP probe.

---

## 7. Re-run after MAC-D1 + DNS M1 — 2026-08-28 (later session)

**Scope.** Re-run Cell 1 (macOS `anchor`) now that MAC-D1 (`8ec851a9`,
de-circularised the posture gate via validator-set election) and the macOS DNS
M1 enforcement (`f048918c`, `macos_dns_sc_protect.rs`) are on the deployed
source. Triage only — no code changed in this session.

### 7.1 Run

`livelab-1787959261-51746fdac765` (internal run id `rust-1787957920`), commit
`51746fda…` (this worktree's HEAD, carries MAC-D1 + DNS M1),
`git_tree_clean=true` at launch, engine `--node`, source `working-tree`,
`--anchor-platform macos` + explicit `--node lenovo-exit-1:exit --node
lenovo-client-1:client` (full 61-stage plan — **no** `--skip-linux-live-suite`,
per §2.3). Report dir `state/mac-cells/anchor4-1787957800`. Ledger row verified
present in `live_lab_node_run_matrix.csv` (id, commit, clean, branch recorded).

Invocation discovery, recorded because the runbook does not cover it post-W5.7:
the direct CLI **retired** `--*-platform` selectors only when they would be the
*sole* role source (`vm_lab/mod.rs:10296-10336` fails closed on empty
`node_assignments`). Passing the Linux backbone as explicit `--node` flags plus
`--anchor-platform macos` is accepted: `augment_assignments_from_platform_selectors`
(`native.rs:928`) elects the first *unassigned* macOS entry as anchor, and
`native.rs:260` sets `macos_anchor_validators_elected=true`. Combining
`--node macos-utm-1:anchor` **with** the selector errors (no unassigned macOS
entry remains). The QH-18 flock warning is real: `run_exclusion` cannot resolve
the selector-elected `macos-utm-1`, so only the two lenovo guests are
lock-protected (safe here — no concurrent run — but noted).

One launch aborted before any stage (`anchor4-1787957600`): the pre-run
readiness gate probed `ssh_port_open_count: 0` for **all seven** VMs while the
UTM bundle scan TCC-parked after 20s — the §12.3.1 blind-probe signature in a
TCC-degraded process context (mac answered `nc` :22 throughout). Re-launched
with `--trust-inventory-ready` after shell-verifying all three guests. The
readiness gate's post-restart probe then killed run 1 against a healthy mac.

### 7.2 Outcome: 16 pass / 1 fail / 44 skip — `anchor_validation` **PASSED** for the first time

Full setup ran green (`bootstrap_hosts`, `membership_init`,
`distribute_*`, `enforce_baseline_runtime` — so the MAC-D2 owner-key fix is
live-proven in passing: this run *is* a macOS node becoming membership owner
under `--anchor-platform` election). `anchor_validation` passed with the
side-car (`anchor_validation.reported_skips.json`) recording
`runtime_skipped_nodes: []` and
`runtime_delegated_nodes: [{ "alias": "macos-utm-1", "platform": "Macos" }]`.

**MAC-D1 verdict: LIVE-CONFIRMED for what it changed.** The stage that
structurally graded `Skipped` in run 3 (§2.1) now grades the macOS runtime
coverage as delegated evidence and passes. The circularity is gone.

### 7.3 NEW DEFECT (MAC-D3) — the delegation names a validator set that does not exist on `--node`

The delegation claims coverage by `deploy_macos_anchor_profile`,
`validate_macos_anchor_bundle_pull`,
`validate_macos_anchor_port_mapping_authority` "in the same run". Those stages
are **bash-era only**: they exist as registry specs
(`live_lab_stage_registry.rs:1190,1197,1204`, `EnableRule::AnchorPlatform`)
and stage functions under `vm_lab/mod.rs:12230+`, but the Rust `--node`
engine's `StageId` set (`stage/mod.rs`) contains no such variants — its only
anchor stages are `anchor_validation` and `live_anchor`. This run's
`stages.tsv` confirms none of the three dispatched. So on the engine of record,
`anchor_validation`'s green rests on a delegation with **no dispatching
validator behind it** — a bookkeeping green, not runtime evidence. Honest cell
status: `anchor_validation` gate unblocked (real), macOS anchor *runtime*
still unproven until either (a) the three validators are ported to `--node`
`StageId`s, or (b) `live_anchor` is confirmed to carry the macOS anchor
runtime proof — it skipped this run behind `validate_baseline_runtime`, so
today it is untested, not unavailable (same posture as §2.3).

Classification: macOS parity code gap, engine-of-record stage-set hole. Remedy
not applied (triage only).

### 7.4 `validate_baseline_runtime` red — both macOS ops fail for NEW, precise reasons

`macos-utm-1/MeshStatus` + `macos-utm-1/DnsFailclosed` red; both lenovos pass
all six ops. Per-op detail (`validator_results.json`) is terse; root causes
traced by hand on the guest:

* **DnsFailclosed — M1 deployed but never executed.** The guest binary is
  fresh (built this run, 16:19 PDT ≙ 23:19 UTC). `/etc/resolv.conf` still
  names `127.0.0.1` but `scutil --dns` primary remains `1.1.1.1`/`8.8.8.8`
  (same drift reason as §3.1), **and** the M1 machinery shows zero activity:
  `/private/var/run/rustynet/` is empty (no
  `networksetup-dns.failclosed.bak`), `networksetup -getdnsservers Ethernet`
  still returns `1.1.1.1`/`8.8.8.8`, and the unified log records **zero**
  `networksetup` invocations by the privileged helper. Cause: M1 lives in
  `MacosCommandSystem::apply_dns_protection` (`phase10.rs:4201`), which runs
  on protected-mode entry — and the **anchor role never enters DNS-protected
  mode** in this lab shape (the launchd profile omits
  `--dataplane-mode`/egress flags by audited omission,
  `macos_install.rs:1975-2001`). The validator demands a posture the anchor
  role never assumes. The task-brief expectation ("guest carries pre-fix
  deployment until the run redeploys") was *half* right: the redeploy
  happened; what is missing is any code path that *invokes* the enforcement
  for an anchor. Fix direction: either the anchor role applies DNS
  protection by default (default-deny reading), or the DnsFailclosed op is
  scoped to roles that enter protected mode, with the anchor's posture
  asserted by a role-appropriate check. Decision needed before code.
* **MeshStatus — the QH-39 freshness bound fired (honest red), bound
  CONFIRMED applied.** The native validator dispatches
  `macos-mesh-status-check --max-age-seconds 180`
  (`role_validation/mesh_status.rs:90`, `SNAPSHOT_MAX_AGE_SECONDS=180` at
  `:56`) — the argv QH-39 asked for, closing §3.2's "not yet evidence"
  caveat. The red means the anchor's state snapshot was missing or older
  than 180 s at validation time. Linux exit/client refresh snapshots via
  active dataplane and pass; the anchor is passive and its snapshot ages
  out. Post-run reproduction cannot distinguish missing vs stale (cleanup
  emptied `/usr/local/var/rustynet/`), so the open question is whether the
  anchor daemon refreshes its snapshot at all while idle. Candidate fix:
  periodic snapshot refresh on the anchor, or a role-aware freshness
  margin. Either way §3.2's caveat is now closed in the *opposite*
  direction: a macOS `MeshStatus` bare pass is no longer obtainable.

### 7.5 Cell status

macOS **anchor**: **partial, progressed**. `anchor_validation` went from
structurally-skipped (run 3) to passed-with-delegation (this run) — MAC-D1
LIVE-CONFIRMED. New blocker MAC-D3 (§7.3) means the green is not yet runtime
evidence; `live_anchor` remains the untested runtime proof. The run matrix
cell stays 🔴 with a named, narrow path to green: port the three macOS anchor
validators to `--node` (or bind the delegation to `live_anchor`), resolve the
§7.4 DnsFailclosed role/posture question, and re-run with the full suite.

Remedy recorded against stub
`livelab-1787959261-51746fdac765::validate_baseline_runtime` in
`live_lab_stage_triage.jsonl` so the next launch is not gated.

---

## 8. Re-run Cell 2 after MAC-D2 — 2026-08-28 (latest session)

**Scope.** Re-run Cell 2 (macOS `exit`) now that MAC-D2 (`03619d0f`, the macOS
membership owner-key read path fixed to the genesis location
`/usr/local/etc/rustynet/membership.owner.key.pub`, fail-loud read with
distinct absent/permission/empty errors) is on `main`. Triage only — no code
changed in this session. Run from a worktree on `e3585ffd` (MAC-D2 ancestor,
verified with `git merge-base --is-ancestor`), tree clean.

### 8.1 Run

`livelab-1787961892-e3585ffdf8ad`, commit `e3585ffdf8ad…`, branch
`ai-edit/edit-1787960287037-56044-31`, `git_dirty_state=clean`, engine
`--node`, full 61-stage plan (no `--skip-linux-live-suite`), topology
`macos-utm-1:exit` + `lenovo-exit-1:entry` + `lenovo-client-1:client`, report
dir `state/mac-cells/exit2-1787960643` (worktree-local). Ledger row verified
present in `live_lab_node_run_matrix.csv` (id, commit, clean, branch, topology
recorded).

**Invocation discovery, recorded because the brief's shape is retired.** The
direct CLI `--macos-promote-exit` selector **fails closed post-W5.7**
(`vm_lab/mod.rs:10316`: "the legacy bash orchestrator was retired …
--macos-vm / --macos-promote-exit (add the macOS node via --node
<alias>:<role>)"). The equivalent supported shape is explicit assignments:
`--node macos-utm-1:exit --node lenovo-exit-1:entry --node
lenovo-client-1:client` — the same topology the MCP driver synthesizes for
`macos_promote_exit`. `--trust-inventory-ready` was used after shell-verifying
all three guests over SSH (the readiness gate's raw TCP probe answered
`ssh-tcp-not-open` for the mac while `ssh mac@…` worked — the §12.3.1
blind-probe signature again; `nc -z` is likewise blind from this context, so
every reachability verdict here is from real `ssh` runs). A
`mkdir`-based lock on the exit-cell guests was held for the run's duration
(`flock` is unavailable on the orchestrating macOS host); no concurrent run
was in flight (`pgrep`).

### 8.2 Outcome: 9 pass / 1 fail / 51 skip — `membership_init` fails again, but DIFFERENTLY

```
membership_init fail: issue_membership_owner_key: protocol error:
  membership owner public key not found on remote at
  '/usr/local/etc/rustynet/membership.owner.key.pub'; has membership genesis
  been run? (rustynetd membership init seeds it at
  /usr/local/etc/rustynet/membership.owner.key.pub)
```

This is **MAC-D2's new fail-loud error, not the old one.** The run before the
fix said "membership owner public key not found on remote; has membership been
initialized?" (empty-string collapse, wrong path, no privilege). This run
names the exact path, distinguishes absence, and points at genesis. The fixed
adapter deployed and behaved exactly as coded. MAC-D2 as a *code* change:
**deployed and correct.** MAC-D2 as the *exit-cell unblocker*: **insufficient —
it exposed the next blocker (MAC-D4, §8.3).** The key genuinely is not there.

All three exit stages were again never planned to run: `active_exit` →
`exit_dns_failclosed_validation` → `exit_nat_lifecycle_validation` →
`exit_demotion_residue_validation` all skipped behind `membership_init`
(`stages.tsv` dependency chain, verified per stage). The exit-role DnsFailclosed
op never dispatched, so the M1 enforcement question for the *exit* role is
still untouched (the §7.4 red was the *anchor* role's posture). Linux setup
stages that ran all passed (`bootstrap_hosts` incl. both lenovo rebuilds,
`cross_network_substrate_setup`, `collect_pubkeys`).

### 8.3 NEW BLOCKER (MAC-D4) — the macOS `--node` bootstrap never seeds the membership owner key

Ground truth on `macos-utm-1` immediately after the run: `/usr/local/etc/rustynet/`
exists fresh (recreated during this run's bootstrap) containing **only**
`trust-evidence.key` — no `membership.owner.key`, no `.pub`. The freshly built
`rustynetd` is installed. So nothing on the macOS deploy path ever *writes*
the owner keypair:

1. The `--node` orchestrator's macOS install is
   `macos_install::install_daemon` (`macos_install.rs:73`), which runs
   `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` directly. That script
   has **no membership-genesis step at all** — no `rustynetd membership init`,
   no `--owner-signing-key`, anywhere. It creates the *state* membership dir
   (`:584`) and seeds `trust-evidence.key` (`:1131`); that is all.
2. §4.2's disposition assumed the genesis driver
   (`execute_ops_e2e_bootstrap_macos`, `ops_e2e.rs:1243`, which runs
   `rustynetd membership init --owner-signing-key
   /usr/local/etc/rustynet/membership.owner.key`) is on the lab bootstrap
   path. It is only reached via `ops e2e-bootstrap-host` — which the **Linux**
   bootstrap invokes (`linux_install.rs` BOOTSTRAP_SCRIPT, pinned by test at
   `:598`) but the macOS adapter never does.
3. The Linux twin stays correct end-to-end because its bootstrap re-seeds
   `/etc/rustynet/membership.owner.key.pub` on every install; its wholesale
   uninstall `rm -rf /etc/rustynet` (`linux_install.rs:395`) is therefore
   safe. The macOS uninstall does the same wholesale remove
   (`sudo -n rm -rf … /usr/local/etc/rustynet …`, `macos_install.rs:629`) with
   **no re-seed anywhere** — so on the engine of record a fresh macOS deploy
   can never hold an owner key.

**Correction to §7.2, recorded honestly:** the anchor re-run did *not*
"live-prove MAC-D2 in passing". `membership_init` is role-gated to `exit`
with fanout `once` (`node_stage_plan.json`), and in that run the exit role sat
on `lenovo-exit-1` — so its PASS came from the *Linux* owner-key read. The
macOS read path was first exercised by *this* run (mac elected `exit`), and
its first live exercise is what surfaced MAC-D4.

**Classification: macOS parity code gap** — missing genesis/owner-key seeding
in the macOS `--node` bootstrap path (the same class as the §4.2 honesty note
feared: "whether the macOS install path seeds an owner key at all" — answer:
it does not). Fix direction: seed the owner keypair during the macOS
bootstrap/genesis (mirror Linux: invoke `rustynetd membership init
--owner-signing-key /usr/local/etc/rustynet/membership.owner.key` from
`Bootstrap-RustyNetMacos.sh` or wire the macOS install through
`ops e2e-bootstrap-host`), keeping the MAC-D2 test that pins the adapter read
path to `ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH` as the drift guard. Secondary
hazard to fix in the same stroke: `macos_install.rs:629`'s uninstall wipes the
genesis location, so any seed must live *below* the bootstrap, not as a
one-time manual guest fix.

No triage stub was produced for this failure either (same as
`livelab-1787913512`; §5's process observation stands — the stub-append path
does not cover `membership_init` failures).

### 8.4 Cell status

macOS **exit**: **still 🔴 blocked**, but the failure has moved one level
deeper and is now a single named fix: the guest *install* never creates the
key MAC-D2's reader (correctly) demands. No exit stage has yet dispatched on
macOS; the §6 egress assertion remains untouched. Path to green: implement
MAC-D4 seeding → re-run this exact cell shape.
## 8. MAC-D3 disposition — 2026-08-29 (isolated edit branch)

### 8.1 Part (a) — FIXED: the three macOS anchor validators are now engine-of-record stages

The remedy chosen was to port the delegation into the `--node` engine rather
than re-bind it to `live_anchor` (whose live cell also gates on
`validate_baseline_runtime` and the Linux live suite, and which cannot prove
the macOS-specific bundle-pull/port-authority checks). Each bash-era validator
now has a first-class `StageId` in
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs`, wired names kept
identical to the legacy registry vocabulary so the run-matrix stage columns
align:

- `MacosAnchorProfileDeploy` => `deploy_macos_anchor_profile`
  (`stage/macos_anchor_profile_deploy.rs`, deps `[validate_baseline_runtime]`)
- `MacosAnchorBundlePullValidation` => `validate_macos_anchor_bundle_pull`
  (`stage/macos_anchor_bundle_pull_validation.rs`, deps
  `[deploy_macos_anchor_profile]`)
- `MacosAnchorPortMappingAuthorityValidation` =>
  `validate_macos_anchor_port_mapping_authority`
  (`stage/macos_anchor_port_mapping_authority_validation.rs`, deps
  `[deploy_macos_anchor_profile]`)

All three are `Live`-suite / `T1Role` / fanout-once stages placed after
`live_anchor` in the canonical pipeline order. Their `execute` shells into the
previously-quarantined bash-era helpers `deploy_macos_anchor_profile`,
`exercise_macos_anchor_bundle_pull_live` (which still writes its live report
with the loopback / token-gate / LAN-refused / secrets-hygiene sub-checks) and
`exercise_macos_anchor_port_mapping_authority_live` in `vm_lab/mod.rs`, now
`pub(crate)` with the W5.7 `#[allow(dead_code)]` quarantine attributes removed
— this wiring IS the G2 native re-wire those attributes were retained for.

Skip semantics stay fail-closed: with no macOS node assigned the anchor role,
or when the validator set is not elected, each stage returns
`StageOutcome::Skipped(<reason>)` (a graded skip, never a silent pass). The
helpers need the inventory path, so `OrchestrationContext` gained a run-local
`inventory_path: Option<PathBuf>` (never serialized; a resumed context reloads
`None` and the stages then FAIL rather than silently skip — fail-closed).

**MAC-D1 election tightened (the bookkeeping-green defect, closed).**
`native.rs` previously set `macos_anchor_validators_elected` purely from
`--anchor-platform macos`, so `anchor_validation` graded the macOS bundle-pull
runtime as "delegated" even when nothing would dispatch. The flag is now set
only when the anchor platform is elected AND all three validator stage ids are
present in the built plan (`skip_live_suite` / setup-only runs therefore drop
the election to false and `anchor_validation` grades a **reported skip**).
The MAC-D1 `runtime_coverage` gate is preserved: delegation now means
"first-class stages in this same run", not "names that go nowhere".

Tests: `plan::tests::macos_anchor_validator_stages_follow_the_live_suite_gate`
(full plan contains the three ids; `with_skip_live_suite(true)` drops them),
per-stage `stage_metadata_matches_the_catalog` +
`skips_when_no_node_is_assigned_the_anchor_role`, and the updated plan-count
asserts (61 → 64 stages; chaos/negative-control/soak counts moved accordingly).

### 8.2 Part (b) — validate_baseline_runtime red on macOS anchor: OWNER-GATED

Not fixed in code; this is a security-posture design decision (per the
harvest rule: do not guess what protected-mode posture a macOS ANCHOR should
carry).

**Question for the owner:** should the macOS `anchor` role enter DNS-protected
mode (and which posture), given that in the current lab shape it serves the
bundle-pull on loopback and runs no exit dataplane?

Options, as identified in §7.4:

1. **Anchor applies DNS protection by default** (default-deny reading): the
   launchd profile for the anchor role gains the `--dataplane-mode` /
   egress flags (today audited-omitted, `macos_install.rs:1975-2001`), so
   `apply_dns_protection` (M1, `phase10.rs:4201`) runs on protected-mode
   entry and the `DnsFailclosed` op has something real to assert. Stronger
   posture; changes anchor behavior on every OS unless scoped, and needs the
   anchor's own egress requirements (mesh membership, bundle-pull) verified
   against the protected DNS path before rollout.
2. **Scope the `DnsFailclosed` op to roles that actually enter protected
   mode**, and assert the anchor's posture with a role-appropriate check
   (e.g. anchor identity/capability advertisement + bundle-pull liveness)
   instead of DNS fail-closed evidence. No behavior change; the validation
   set becomes role-aware. Must be written so it does not read as "skip the
   security op on macOS" — the substitution has to be a named,
   anchor-appropriate control, not an omission.

Either option resolves the red; the choice (and whether the anchor's
DNS-protected posture should differ per OS) is owner-gated. Until decided,
the macOS anchor cell stays blocked at `validate_baseline_runtime` even
though part (a) unblocks the three validator stages themselves.

Adjacent, NOT part of MAC-D3: the `MeshStatus` red is the QH-39 freshness
bound firing honestly on a passive anchor (§7.4, SNAPSHOT_MAX_AGE_SECONDS =
180) — separate question (periodic snapshot refresh vs role-aware margin),
tracked under QH-39, not fixed here.

### 8.3 Cell status after this fix

macOS **anchor**: part (a) closed — the three validators dispatch as
engine-of-record stages and the delegation is honest. The cell can PROGRESS
on the next lab run (the validator stages will go live), but it cannot go
GREEN until the owner answers §8.2: `validate_baseline_runtime` still fails
on the macOS anchor (DnsFailclosed + MeshStatus). Recommended next run:
`--anchor-platform macos` with the full live suite (no
`--skip-linux-live-suite`, so the validator stages are in-plan), expecting
the three new stages to dispatch and `validate_baseline_runtime` to remain
red until the §8.2 decision lands.

### 8.4 Gate evidence note — 2026-08-29

All gates pass on the edit branch (fmt, clippy `--workspace --all-targets
--all-features --locked -D warnings` 0 findings, check, audit, deny; scoped
tests: rustynet-cli lib 2653 passed / 0 failed, plan + anchor + new-stage
tests green) with one pre-existing exception: rustynetd
`phase10::tests::macos_assert_dns_protection_requires_active_dns_rules`
fails on THIS host right now for a reason unrelated to MAC-D3 — the test
enumerates the host's real `networksetup` services and one network service
is currently disabled, so
`read_networksetup_service_dns` (`phase10.rs:3883`) gets status=4 with the
disabled-service artifact as the "service name" (`parse_networksetup_service_list`
does not filter disabled services out of the enumeration). Zero rustynetd
files are touched by this branch, so the failure is identical at HEAD; it is
host-state dependent, not a MAC-D3 regression. Recording it here so the next
agent does not re-derive it: candidate fix is filtering
disabled (asterisk-flagged) services in
`macos_dns_sc_protect::parse_networksetup_service_list` — owner review
required since it is fail-closed DNS code.

## 9. Anchor cell re-run after MAC-D3 — 2026-08-29 (latest session)

Run `livelab-1787964361-9e1b877d6b31` (internal `rust-1787964361`), commit
`9e1b877d` (the MAC-D3 merge), branch `ai-edit/edit-1787962758946-56044-34`,
tree clean, report dir `state/mac-cells/anchor5-1787962990`. Same proven
invocation as §7: `ops vm-lab-orchestrate-live-lab --anchor-platform macos
--node lenovo-exit-1:exit --node lenovo-client-1:client --trust-inventory-ready`
with the FULL live suite (no `--skip-linux-live-suite`), 3 nodes, lenovo pair
as backbone. Ledger row appended to
`documents/operations/live_lab_node_run_matrix.csv` and verified
(id, commit, clean, branch, 64 stages, fail=`validate_baseline_runtime`,
passed=16 failed=1 skipped=47). Remedy stub recorded against
`livelab-1787964361-9e1b877d6b31::validate_baseline_runtime` in
`documents/operations/live_lab_stage_triage.jsonl`.

**MAC-D3 part (a) is LIVE-CONFIRMED.** The plan grew 61 → 64 stages and all
three macOS anchor validator stages are now engine-of-record stages:

- `deploy_macos_anchor_profile` — in plan, graded **skipped** ("dependency
  `validate_baseline_runtime` did not pass, so this stage never ran")
- `validate_macos_anchor_bundle_pull` — in plan, graded **skipped** (dependency
  `deploy_macos_anchor_profile` did not pass)
- `validate_macos_anchor_port_mapping_authority` — in plan, graded **skipped**
  (same dependency reason)

This is exactly the §8.2-predicted shape: the tightened MAC-D1 election saw
the anchor platform elected and the three ids present, so they dispatch; each
skips FAIL-CLOSED with an explicit dependency reason (with a per-stage log
artifact), never silently. Per the §8.2 rule a skip-with-reason is acceptable
evidence the stages are in the plan — the task-level question "do the
validators now dispatch" is answered yes. Their live outcomes remain gated
behind the §8.2 owner decision.

`anchor_validation` PASSED again (delegation machinery healthy).
`validate_baseline_runtime` remains the sole hard failure, red on
macos-utm-1 with both expected op verdicts — `MeshStatus: validation not
passed` (QH-39 freshness bound, `--max-age-seconds 180`,
`mesh_status.rs:90`, passive anchor snapshot ages out) and `DnsFailclosed:
validation not passed` (the anchor role never enters DNS-protected mode; the
launchd profile audited-omits `--dataplane-mode`,
`macos_install.rs:1975-2001`) — identical to the anchor4 run, NOT a new
blocker. Everything downstream of it skipped with dependency reasons
(expected cascade; both lenovos' own ops all passed, admin_issue/blind_exit
skipped as no-role-in-topology as before).

**Cell status: PARTIAL — progressed.** MAC-D3 (a) closed with live evidence;
MAC-D3 (b) / §8.2 remains the single owner gate between this cell and green
(remediate DNS-protected-mode entry, then the validator stages run live on
the next re-run).
## 9. MAC-D4 disposition — 2026-08-29 (isolated edit branch)

### 9.1 FIXED: the macOS `--node` bootstrap now seeds the membership genesis

`Bootstrap-RustyNetMacos.sh` gained `seed_membership_genesis()` (wired into
BOTH main paths — full install and `SKIP_BUILD=1` — between
`seed_trust_evidence` and `install_launchd_service`). It mirrors the Linux
bootstrap's per-install re-seed: `clear_residual_state` wipes `membership/`
signed state on every bootstrap, so genesis re-runs with `--force` each
install, which also self-heals the §8.3 secondary hazard
(`macos_install.rs:629` wholesale uninstall wipe — the next bootstrap
re-seeds, no manual guest fix).

What it seeds:

- `rustynetd membership init --snapshot …/membership.snapshot --log …
  --watermark … --owner-signing-key /usr/local/etc/rustynet/
  membership.owner.key --owner-signing-key-passphrase-file … --node-id …
  --network-id … --force` — the same genesis the Linux bootstrap reaches via
  `e2e-bootstrap-host`. `membership init` itself generates the keypair and
  writes the `.pub` sibling (`rustynetd/src/main.rs:4524`) — exactly the
  file MAC-D2's fail-loud adapter read path demands
  (`macos_membership::issue_membership_owner_key`, reads via `sudo -n cat`,
  so the directory tightening below does not block it).
- A 64-hex-char passphrase via the same atomic-write protocol as the
  wireguard passphrase (chmod-before-write tmpfile in `BOOTSTRAP_DIR`).
- The canonical System.keychain unwrap item (service
  `signing_key_passphrase`, account `membership-owner-signing-key`) via the
  same idempotent delete-then-add `/usr/bin/security` provisioning
  `execute_ops_e2e_bootstrap_macos::provision_macos_membership_signing_keychain_item`
  performs, so membership-mutation ops can unwrap.
- Daemon-service ownership restore (`chown rustynetd:rustynetd`) on the
  genesis snapshot/log — the same restore
  `ops_e2e::set_membership_state_permissions_for` applies after root-run
  membership mutations; the launchd daemon runs as the `rustynetd` service
  account and rewrites snapshot/log (and creates the absent watermark) at
  runtime, so root-owned genesis state would otherwise fail-closed it.

Fail-closed: the script runs under `set -euo pipefail`; any failed genesis
step aborts the whole bootstrap — a node can never ship without a seeded
owner key. Drift guard: new test
`bootstrap_script_seeds_membership_owner_key_at_canonical_genesis_path`
(`macos_install.rs`) pins the genesis invocation, canonical owner-key path
(`==` the MAC-D2-pinned `MACOS_OWNER_SIGNING_KEY_PATH` via the existing
`owner_signing_key_path_matches_macos_genesis_driver`), `.pub` ownership/
mode, ownership restore, keychain descriptor, both-path wiring, and no
`|| true` softening.

### 9.2 Custody posture (no owner gate needed — no posture weakened)

- The owner SIGNING (private) key is NEVER plaintext at rest:
  `membership init` → `persist_owner_signing_key_encrypted`
  (`main.rs:4560`) writes an Argon2+XChaCha20 passphrase-sealed envelope,
  mode 0600, symlink-refusing, and tightens the containing directory to
  0700. This is the daemon's own reviewed encrypted-at-rest custody; the
  seed simply invokes it. (Directory tightening of
  `/usr/local/etc/rustynet` from 0750→0700 is safe: the daemon reads
  nothing from CONFIG_ROOT — `trust-evidence.key` there is read only by
  root-run `rustynet ops refresh-signed-trust`.)
- The passphrase is a bootstrap artifact in `BOOTSTRAP_DIR` (0600,
  root-owned, outside `keys/` so `macos-key-custody-check` does not flag
  it) — identical posture to the reviewed wireguard passphrase — AND is
  provisioned into the System.keychain descriptor. This is exactly the
  reviewed production macOS genesis driver's contract (`ops_e2e` stages the
  passphrase file 0600 and provisions the keychain item from it); Linux
  keeps its signing credential file at rest 0600 the same way.
- Only the PUBLIC half (`.pub`) is world-readable (0644 root:rustynetd) —
  it is the MAC-D2 read target and carries no secret.

Known runtime exposure, recorded honestly (not a new decision): the
signing-key keychain item is created by `/usr/bin/security` without
`-A`/owned-identity binding, matching the reviewed `ops_e2e` provisioner
verbatim. The Phase-26 WG lesson (`Bootstrap-RustyNetMacos.sh`
generate_wireguard_keys comment) found `-A` items unreadable cross-session
on macOS 26; whether the security-tool-created signing descriptor is
readable by `rustynetd` membership ops at runtime will be proven (or
fail-loud) on the next macOS exit/anchor run — membership mutations fail
closed if not. If it proves unreadable, the owner-gated follow-up is
re-provisioning the signing descriptor via the owned-identity
`rustynetd key store-passphrase` path (as the WG passphrase already does).

### 9.3 Gate evidence — 2026-08-29

fmt pass; clippy `--workspace --all-targets --all-features --locked -D
warnings` pass; check pass; audit + deny pass; secrets_hygiene_gates.sh
pass (18 checks); scoped tests rustynet-cli + rustynetd
(`--all-targets --all-features --locked`): 92 test binaries ok, rustynetd
lib 2259 passed / 1 failed. The single failure is the SAME pre-existing
host-environment failure §8.4 already recorded
(`phase10::tests::macos_assert_dns_protection_requires_active_dns_rules`,
real-`networksetup` enumeration vs this host's disabled network service);
verified identical at HEAD via stash (fails without this branch's
changes) — unrelated to MAC-D4. A pre-existing import-order fmt drift in
`macos_install.rs` (at base) was fixed by `cargo fmt -p rustynet-cli` to
unblock the fmt gate. No lab run per scope.

### 9.4 Next step

Re-run the Cell-2 shape from §8.1 (`--node macos-utm-1:exit --node
lenovo-exit-1:entry --node lenovo-client-1:client`). `membership_init`
should now pass on macOS (genesis seeds the `.pub` at the exact path the
MAC-D2 reader demands); the §8.2 skip chain
(`active_exit` → `exit_dns_failclosed_validation` →
`exit_nat_lifecycle_validation` → `exit_demotion_residue_validation`)
then runs for the first time. Watch §9.2's keychain-unwrap exposure in any
membership-mutation stage.

## 10. Exit cell re-run after MAC-D4 — 2026-08-29 (latest session)

Re-ran the §8.1 Cell-2 shape after MAC-D4 (owner-key seed in the macOS
bootstrap) landed. Worktree `ai-edit/edit-1787965142039-56044-35`, commit
`494dc61437ef1479037932f73d41a238a290cbbf` (MAC-D4 merge `06f828a7`
confirmed ancestor), tree clean.

> Doc drift note: this file now carries **two** `## 9` headings (the
> MAC-D4 disposition §9 above and the anchor re-run §9 in the previous
> session). Headings below resume at §10; the drift is left as-is and
> should be renumbered by whoever next restructures this document.

### 10.1 Run

- Run id `livelab-1787967356-494dc61437ef`, report
  `state/mac-cells/exit3-20260829-021133` (worktree-local; also in
  `documents/operations/live_lab_node_run_matrix.csv` via the automatic
  ledger row — verified, commit + topology correct).
- Shape (orchestrator now also demands `--known-hosts-file` when
  `--node` flags are present, `native.rs:104`):
  `ops vm-lab-orchestrate-live-lab --node macos-utm-1:exit --node
  lenovo-exit-1:entry --node lenovo-client-1:client
  --trust-inventory-ready --ssh-identity-file ~/.ssh/rustynet_lab_ed25519
  --known-hosts-file ~/.ssh/known_hosts`.
- 64 stages / 3 nodes: **9 pass / 1 fail / 54 skip**; overall fail,
  `first_failed_stage = membership_init`; elapsed 19m58s. Profile
  `mgmt_shared_smoke_v1` (derived, not enforced).
- Passed: preflight, prepare_source_archive, verify_ssh_reachability,
  cleanup_hosts, **bootstrap_hosts (18m11s — fresh bootstrap re-ran on
  macos-utm-1)**, cross_network_substrate_setup, collect_pubkeys; the
  Linux/lenovo setup stages all green as in §8.

### 10.2 MAC-D2 + MAC-D4: LIVE-CONFIRMED (seed level)

- `issue_membership_owner_key` — the exact MAC-D2 reader — **passed** on
  macos-utm-1: the guest now has
  `/usr/local/etc/rustynet/membership.owner.key.pub`, readable via
  `sudo -n cat` (observed key
  `980eb930fbedffe3d7639f5c79d59cbd1510ef79eeddf3b87699d46bf17a2e84`).
- Before this run the guest had no `membership.owner.key` at all; the
  fresh `bootstrap_hosts` run exercised MAC-D4's `seed_membership_genesis`
  end-to-end (full-install path) and the genesis landed. MAC-D2's §8
  failure signature ("pub key absent — seed never written") is gone.
- §9.2's keychain-custody exposure **did not bite**: the stage moved past
  owner-key read and failed on an env-var, not on an unwrap.

### 10.3 NEW BLOCKER — membership_init (macOS adapter)

`membership_init` FAIL rc=1:

```
init_membership_snapshot: remote command failed (exit Some(1)): (stderr
empty; stdout tail) error [generic_failure (1)]: membership node id is
required (RUSTYNET_NODE_ID)
```

Root cause (file:line): `crates/rustynet-cli/src/vm_lab/orchestrator/
adapter/macos_membership.rs:117-123` — the macOS
`init_membership_snapshot` runs

```
env RUSTYNET_NODE_ROLE=admin sudo <rustynet> ops init-membership
```

and **never sets `RUSTYNET_NODE_ID`**. The Linux twin
(`linux_membership.rs:54-64`) sets
`RUSTYNET_NODE_ROLE=admin RUSTYNET_NODE_ID='{exit_node_id_arg}'`,
sourcing the id from the exit peer
(`peers.iter().find(|p| p.role == NodeRole::Exit).node_id`); the daemon
fails closed when NODE_ID is missing. Secondary suspect: `env` placed
before `sudo` may be stripped by sudo's `env_reset`, so even ROLE may not
survive. Fix shape (owner-gated): mirror the Linux branch —
`sudo -n env RUSTYNET_NODE_ROLE=admin RUSTYNET_NODE_ID=<exit-node-id>
<rustynet> ops init-membership`.

Consequence: the whole §8.2 skip chain re-arms — all four macOS exit
stages (`active_exit`, `exit_dns_failclosed_validation`,
`exit_nat_lifecycle_validation`, `exit_demotion_residue_validation`) plus
`distribute_membership`/`exit_handoff` graded **skip** behind
`membership_init` (54 skips). The exit cell's green still has **never**
been reached; DnsFailclosed remains unexercised on macOS exit.

Triage stub appended:
`livelab-1787967356-494dc61437ef::membership_init` in
`documents/operations/live_lab_stage_triage.jsonl`.

### 10.4 Verdict

Exit cell: **BLOCKED-partial** — MAC-D2/MAC-D4 live-confirmed (membership
genesis seed + read path both work on a fresh macOS bootstrap), but the
cell's first stage beyond the seed fails on the macOS membership adapter's
missing `RUSTYNET_NODE_ID`. Next step after the owner fixes
`macos_membership.rs`: re-run this exact §10.1 shape; membership_init
should then pass and the exit stages run for the first time.

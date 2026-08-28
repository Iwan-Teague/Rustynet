# Linux Live-Lab Validation of `main` @ `e13132cb` (2026-08-28)

**Status: NO RUN EXECUTED. The suite was refused at launch by the fail-closed stage-triage
remedy gate, before any stage dispatched. No ledger row was appended, and none should have
been — there is no run to attribute.** The refusal is itself the primary evidence recorded
here, together with two orchestrator defects found while getting to it and a full recovery of
the UTM fleet.

This was intended to be the first end-to-end proof on the ten branches merged into `main`
tonight (CN-1/CN-2/CN-4 substrate work including the topology-level endpoint seam, the QH-18
per-guest flock, the QH-04 reconcile atomicity fix, the QH-40 residue marker, and the D-3
enrollment capability gate). **None of those merges has live evidence as a result of this
session.** They remain unproven on hardware.

## 1) What was attempted

| field | value |
|---|---|
| target commit | `e13132cb` — *Merge work/cn4-substrates: NAT modifiers, double-NAT CGNAT chain, slirp verification substrate, NatProfileId CLI tightening* |
| worktree dirty state | `dirty:worktree` — 3 ledger files only (see §5) |
| guests | UTM fleet only: `ubuntu-utm-1:client`, `rocky-utm-1:admin`, `debian-headless-4:exit`, `fedora-utm-1:relay`, `debian-headless-2:anchor` |
| excluded | `lenovo-client-1` / `lenovo-exit-1` — in use by the concurrent QH-51 flap capture (locks held by pid 44489 throughout; never touched) |
| planned stages | 61 (dry-run validated; baseline runs planned 59 — the +2 is consistent with stages added tonight) |
| network profile | `mgmt_shared_smoke_v1`, digest `sha256:ab06a230…f4f67e4` — identical to the baseline runs |
| run id | **none issued** — the gate rejected before run-id allocation |

Topology was chosen to match `livelab-1787825655-3afd39b18164` (2026-08-27T09:55Z,
`passed=42 failed=0 skipped=17`), the best-covered recent UTM-only run, so the result would
have been directly comparable.

## 2) The launch refusal (primary finding)

The documented ops entry
(`ops vm-lab-orchestrate-live-lab … --node …`) passed discovery cleanly:

```
PASS discover_local_utm: selected aliases readiness:
  ready=ubuntu-utm-1, rocky-utm-1, debian-headless-4, fedora-utm-1, debian-headless-2; unready=none
```

and was then refused:

```
error [policy_reject (78)]: live-lab launch refused: 1 planned stage(s) have a failure with no recorded remedy.
Record what you changed BEFORE re-running them, otherwise the run cannot be attributed to anything.
  - livelab-1787849060-86f633c907cf::bootstrap_hosts (stage bootstrap_hosts, failed 2026-08-27T16:44:19Z)
There is no bypass flag by design (see enforce_launch_gate docs).
  hint: fail-closed policy gate rejected the operation; DO NOT retry without operator review
```

The blocking stub is the last line of `documents/operations/live_lab_stage_triage.jsonl`:
`livelab-1787849060-86f633c907cf::bootstrap_hosts`, with `patch: None`.

**The gate behaved correctly.** It was not overridden, and no disposition was recorded — see
§6 for why that decision belongs to an owner and not to this pass.

### 2.1 The underlying failure it is holding open

The recorded error, on `debian-headless-2`, `lenovo-client-1` and `lenovo-exit-1`, is that
`install-systemd` refuses during e2e bootstrap:

```
install-systemd failed during e2e bootstrap: status=1
  error [generic_failure (1)]: egress interface does not exist: rustynet-vx0
```

- The rejection is `ensure_interface_exists` at
  `crates/rustynet-cli/src/ops_install_systemd.rs:2051`.
- `rustynet-vx0` is `VXLAN_LINK_NAME` at
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/substrate.rs:34` — the
  VXLAN link owned by the cross-network substrate.

So bootstrap asked systemd to install against a substrate-owned egress link that did not exist
on the guest at that moment — an ordering/lifecycle relationship between substrate bring-up
and `install-systemd`, not a daemon fault.

### 2.2 Attribution: pre-existing, NOT from tonight's merges

This is the load-bearing conclusion, and it is decided by commit ordering:

| commit | authored | contains |
|---|---|---|
| `86f633c907cf` (the failing run's commit) | 2026-08-27 17:21:23 +0100 | — |
| `4f3a3b43` (CN-4 vxlan NAT boundary, netns CGNAT, slirp substrate) | 2026-08-28 03:18:17 +0100 | — |
| `e13132cb` (CN-4 merge, tonight's `main`) | 2026-08-28 03:20:07 +0100 | — |

`git merge-base --is-ancestor 4f3a3b43 86f633c907cf` → **false**. The CN-4 substrate work was
authored roughly ten hours *after* the run that failed. The blocking failure therefore **cannot
be a regression from tonight's merges**; it predates all ten of them.

Supporting context from the adjacent stubs: a separate vxlan effort was already in flight
earlier on 2026-08-27 — `livelab-1787843764-14faad7a56ea::gossip_convergence_validation` is
dispositioned against "`8abea28b` vxlan MAC fix — clone machine-id ⇒ identical persistent MACs
⇒ kernel decap self-drop", and `86f633c907cf`'s own subject is *"triage: disposition
acceptance-5 stubs against the vxlan clone-MAC fix"*. The `rustynet-vx0` bootstrap failure is
the next failure in that same pre-existing thread.

## 3) Orchestrator defects found (triage only — no code changed)

### D1 — MCP `start_live_lab_run` drags the macOS guest into a Linux-only run, and wedges

Launching the same 5 Linux nodes through the `rustynet-lab-state` MCP wrapper produced:

```
run exclusion: vm-lab-orchestrate-live-lab holds 7 guest lock(s):
  debian-headless-2, debian-headless-4, fedora-utm-1, macos-utm-1, rocky-utm-1, ubuntu-utm-1, windows-utm-1
```

Seven locks for a five-node Linux run: the wrapper appends `--windows-vm windows-utm-1
--macos-vm macos-utm-1` defaults even when `nodes` names only Linux guests. The identical run
launched directly from the shell without those flags took **5** locks and advanced past
discovery.

Pulling `macos-utm-1` into readiness is what wedged the run. `utmctl ip-address` is
unsupported on the Apple Virtualization backend, so resolution falls through to the ARP
fallback, and the process blocked there permanently. Two independent threads, sampled twice
ten minutes apart, both stuck in kernel `open`:

```
execute_rust_native_orchestration (native.rs:387)
 → readiness::run (readiness.rs:57)
 → execute_ops_vm_lab_discover_local_utm (vm_lab/mod.rs:6901)
 → resolve_controller_live_host (vm_lab/mod.rs:30101)
 → resolve_local_utm_live_host_via_arp (vm_lab/mod.rs:30138)
 → mac_address_from_utm_config_plist (vm_lab/mod.rs:30170)
 → std::fs::read_to_string → open  [BLOCKED]

Thread "utm-bundle-scan": __opendir2 → open$NOCANCEL  [BLOCKED]
```

Every one of those files reads instantly from a normal shell (all nine `.utm` bundles plus the
UTM container path were verified byte-readable in well under a second). The block is specific
to the MCP-spawned process context — a sandbox/TCC-scoped file access that hangs indefinitely
instead of returning an error.

### D2 — The readiness path has no timeout, and it runs *after* the QH-18 flock is taken

D1 is only severe because of the ordering. The QH-18 per-guest flock is acquired **before**
readiness resolution, so a process wedged in `mac_address_from_utm_config_plist` holds locks on
the entire UTM fleet — all 7 guests — indefinitely, with no timeout and no self-recovery. The
lab is not merely slow in that state; it is closed to every other agent.

The asymmetry is visible in one function pair. The `utmctl` branch is bounded:

- `resolve_local_utm_live_host_via_utmctl` (`vm_lab/mod.rs:30142`) wraps its call in
  `run_output_with_timeout(…, Duration::from_secs(DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS))`
  at `vm_lab/mod.rs:30153` (the constant is 30 s, `vm_lab/mod.rs:62`).

Its sibling fallback on the same `or_else` chain (`vm_lab/mod.rs:30128-30129`) is not:

- `mac_address_from_utm_config_plist` (`vm_lab/mod.rs:30169`) calls bare
  `fs::read_to_string` at `vm_lab/mod.rs:30170`, and the `utm-bundle-scan` thread calls bare
  `opendir`. Neither has any deadline.

Suggested owner fixes, in priority order: (a) bound the bundle/plist I/O the way the `utmctl`
sibling already is; (b) acquire guest locks after readiness, or make lock ownership expire; (c)
stop the MCP wrapper injecting `--windows-vm`/`--macos-vm` when `nodes` contains no guest of
that platform. None applied here — this pass is triage only.

Recovery performed: the wedged job was cancelled (it was this session's own job, not another
agent's), which released all 7 UTM locks. The QH-51 lenovo locks were verified still held by
pid 44489 before and after, and were never touched.

## 4) Lab environment: degraded on arrival, fully recovered

`preflight_check` could not be used — it timed out repeatedly against the MCP client limit, as
did `update_inventory` (which left a stuck process, since reaped). Per-guest probing found the
whole UTM Linux fleet unavailable:

| guest | on arrival | action | after |
|---|---|---|---|
| `debian-headless-2` | UP but unreachable (stale nft killswitch) | `reset_vm_network` | TCP/22 open |
| `debian-headless-4` | UP but unreachable (stale nft killswitch) | `reset_vm_network` | TCP/22 open |
| `fedora-utm-1` | powered off | `power_on_vm` | TCP/22 open |
| `ubuntu-utm-1` | powered off | `power_on_vm` | TCP/22 open |
| `rocky-utm-1` | powered off | `power_on_vm` | TCP/22 open |

All five ended reachable at their existing inventory IPs — no IP drift, so no inventory update
was needed. This is environmental, matches the known stale-killswitch pattern in the
probe-and-recover runbook, and is unrelated to tonight's merges. The orchestrator's own
`discover_local_utm` subsequently reported `unready=none`, independently confirming the fleet
was fit to run.

Host disk fell from 97 GiB to 84 GiB free (91% used) across the session's build activity. Not
a blocker, worth watching.

## 5) Ledger confirmation

**No ledger row exists for this session, and that is the correct outcome.**
`documents/operations/live_lab_node_run_matrix.csv` holds 180 rows; the last is the
pre-existing `livelab-1787849060-86f633c907cf` (`fail` / `bootstrap_hosts`). The `--node`
orchestrate wrapper appends a row only for a run that dispatches stages; this launch was
refused before that point, so there is nothing to append. Any row claiming to validate
`e13132cb` would be fabricated.

The three files modified in the `main` working tree —
`live_lab_node_run_matrix.csv`, `live_lab_node_stage_results.csv`,
`live_lab_stage_triage.jsonl` — were already dirty when this session began and belong to
another agent's in-flight run. They were not written to here. `what_will_deploy` confirmed
they are the *only* delta from `HEAD`, so the code that would have been deployed is exactly
`e13132cb`.

## 6) What is still unproven, and the owner decision required

Unproven on hardware, unchanged by this session: **all ten of tonight's merges.** The one
comparison worth carrying forward is that the last green UTM-only Linux evidence remains
`livelab-1787825655-3afd39b18164` / `livelab-1787835449-4b1d946795ad`, both `passed=42
failed=0`, both from *before* tonight's merges.

The gate needs a disposition on `livelab-1787849060-86f633c907cf::bootstrap_hosts` before any
Linux run can start. That was deliberately **not** recorded here, for two reasons:

1. Nothing was changed to remedy it, so the only honest entry is a `none: …` declination — and
   declining another track's open defect is an owner call, not a validator's.
2. The stub covers `lenovo-client-1` and `lenovo-exit-1`, which were under active investigation
   by the concurrent QH-51 capture while this pass ran. Dispositioning it would have written a
   verdict over another agent's live work.

Owner decision: either record the remedy for the `rustynet-vx0` bootstrap ordering defect, or
record an explicit declination — then re-run this exact 5-node UTM topology against `e13132cb`.

## 7) Reproduction

```
ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --report-dir state/live-lab-validate-20260828 \
  --node ubuntu-utm-1:client --node rocky-utm-1:admin --node debian-headless-4:exit \
  --node fedora-utm-1:relay --node debian-headless-2:anchor
```

Run it from a shell, not through the MCP wrapper, until D1 is fixed. Partial artifacts from the
refused attempt (discovery + network evidence only, no stages) are under
`state/live-lab-validate-20260828/`.

## 8) Follow-up: D1 and D2 fixed on `work/launch-path-fixes`

Both defects triaged in §3 are now closed in code. No lab run was performed for this
work — the fixes are pinned by unit tests, not by hardware, and the §6 owner decision
on `livelab-1787849060-86f633c907cf::bootstrap_hosts` is still outstanding and still
blocks any Linux run.

*(This file was brought onto `work/launch-path-fixes` from `work/live-validate` so the
follow-up could live with the triage it answers. It is the same blob plus this section;
the branches were NOT merged.)*

### D1 — the MCP launcher no longer injects mac/windows VM flags into a Linux-only run

`start_live_lab_run` (`crates/rustynet-mcp/src/bin/lab_state.rs`) filled
`--windows-vm` / `--macos-vm` from the inventory whenever `auto_topology` was on
(the default), regardless of what `nodes` asked for. Two changes:

- Auto-topology is now scoped to the case it was written for — a request that names
  NO topology. When `nodes` is set, that list is the complete guest set, exactly as
  it is on the shell path, and nothing extends it (`auto_topology_vm_aliases`).
- An *explicit* `windows_vm` / `macos_vm` next to `nodes` is now REFUSED rather than
  silently dropped, matching the existing rejection of the role-platform selectors.
  Under the `--node` engine such an alias assigns no role but is not inert: it claims
  that guest's QH-18 flock (`run_exclusion::guest_refs_for_orchestrate`) and flips
  `wants_windows` / `wants_macos` in `orchestrator::evidence`, planning stages for an
  OS the topology does not contain.

Negative test: `a_linux_only_node_topology_renders_no_windows_or_macos_vm_flags`
renders the argv for the exact five-node Linux topology from §7 with both aliases
resolvable from the inventory, and asserts no `--windows-vm` / `--macos-vm` appears
and exactly five `--node` flags do. `auto_topology_still_fills_both_when_no_nodes_are_given`
pins that 3-OS coverage runs are unaffected;
`explicit_windows_or_macos_vm_next_to_nodes_is_refused` pins the refusal.

### D2(a) — the UTM bundle read is bounded

`mac_address_from_utm_config_plist` (`vm_lab/mod.rs`) called bare
`fs::read_to_string`; its sibling `resolve_local_utm_live_host_via_utmctl` was already
bounded by `run_output_with_timeout`. The plist read now goes through a new
`read_to_string_with_timeout` on the same `DEFAULT_UTM_IP_DISCOVERY_TIMEOUT_SECS`
constant. The worker thread is not joined on timeout — a thread blocked in an
uninterruptible kernel `open()` cannot be cancelled, and leaking it is what lets the
caller return and drop the fleet's locks.

Failure classification is the load-bearing part, and it is fail-closed:

- a plain I/O miss (no bundle, no `config.plist`) stays `Ok(None)` — the historical
  best-effort "this guest has no ARP fallback";
- an unexpected I/O error is additionally named on stderr rather than dropped;
- a **timeout** returns `Err` naming the path, and readiness turns that into
  `ProbeState::Error` instead of falling through to `inventory.last_known_ip`. The
  guest is reported NOT ready. A host that cannot read its own bundles cannot vouch
  for the guest's address either, so dressing an unknown up as a `Fallback` — which
  is what the old chain did — let a wedged host look ready.

Tests: `a_read_that_never_completes_is_bounded_and_names_the_path` drives the bound
against a writer-less FIFO (same never-completing `open()` shape as the live wedge)
and asserts both the deadline and that the message names the path;
`a_timed_out_bundle_read_fails_closed_rather_than_reading_as_a_clean_miss` pins the
Timeout-vs-Io classification the readiness path depends on.

### D2(b) — lock ordering: KEPT as lock-then-probe, deliberately

§3 D2 suggested acquiring guest locks after readiness. Examined and rejected;
the reasoning is recorded in the doc comment on `resolve_controller_live_host`
so it is not silently re-litigated:

1. The flock is taken at the single `execute_ops` dispatch chokepoint, which also
   covers `vm-lab-setup-live-lab` / `vm-lab-run-live-lab` — including when the
   orchestrator calls them in-process as its own phases. Probing first would mean
   hoisting readiness into the dispatcher, i.e. redesigning the chokepoint.
2. Readiness is not read-only. With `--update-inventory-live-ips` it WRITES the
   shared inventory (`persist_local_utm_ready_states_to_inventory`) and power-probes
   guests; a probe-then-lock shape leaves that write in the unlocked window — the
   exact concurrent mutation the flock exists to prevent.
3. It would not have helped here anyway: the claim set is derived from the run's
   config before any probing, so probing first narrows no lock set. The
   seven-locks-for-five-guests symptom was an argv defect, and is fixed at the argv
   (D1 above).

Self-recovery therefore comes from (a): every branch of the readiness resolver now
has a deadline, so a wedged host releases its locks by failing that guest's readiness
rather than by holding the fleet indefinitely.

### §4 `preflight_check` / `update_inventory` timeouts — structural, not fixed here

Both were checked. Neither is a case of over-generous per-guest timeouts:

- `preflight_check`'s own per-node probe is already tight (`tcp_reachable` at 2 s).
  Its cost is `controller_status_map` → `discovered_hosts_json`, which shells out to
  `cargo run … ops vm-lab-discover-hosts` with a **120 s** budget — a cargo build
  plus a fleet-wide discovery.
- `update_inventory` is `run_ops("vm-lab-discover-local-utm-summary", …)` at
  **600 s**, likewise behind a `cargo run`.

Both per-call budgets already exceed a typical MCP client limit before any guest is
touched, so trimming per-guest timeouts cannot bring them under it; the fix is
structural (pre-build the CLI, or make these async jobs like `start_live_lab_run`)
and is left for the owner of that surface. One contributing cause IS closed here:
`update_inventory` runs the discovery path that wedged in the unbounded plist read,
so that particular non-return is gone.

### Gates

Run from the `work/launch-path-fixes` worktree with a worktree-local
`CARGO_TARGET_DIR`. Results are recorded in the branch's commit trailer.

---

## 9) Attempt 2 — the suite RAN. `livelab-1787903378-068b29ebc54b`, overall `fail` at `bootstrap_hosts`

**Status: a real run executed and a real ledger row landed. It failed at
`bootstrap_hosts` on `debian-headless-2` with the *same* `rustynet-vx0` error the
§2 gate was holding open — because the remedy that cleared the gate had only ever
been applied to the two lenovo guests, and `debian-headless-2` still carried the
stale environment file.** The launch gate was dispositioned (§9.2), the run
dispatched 61 planned stages, and 54 of them skipped behind the one failure. The
failure is **environmental and pre-existing** — not a regression from any of the
seven merges that landed on `main` after `e13132cb` (§9.5).

### 9.1 What ran

| field | value |
|---|---|
| run id | `livelab-1787903378-068b29ebc54b` |
| started / finished | 2026-08-28T07:34:15Z → 07:49:38Z (15 min 23 s) |
| commit recorded | `068b29ebc54b` on `work/live-validate`, `git_dirty_state=clean` |
| relationship to `main` | **code byte-identical to `main` @ `22e707b2`** — `git diff main -- ':!documents'` is empty on that commit; the only non-`main` delta in the tree is documentation |
| guests | `ubuntu-utm-1:client`, `rocky-utm-1:admin`, `debian-headless-4:exit`, `fedora-utm-1:relay`, `debian-headless-2:anchor` — the documented §7 topology |
| planned stages | 61 (dry-run confirmed `5 node(s), 61 planned stage(s)`) |
| result | `passed=6 failed=1 skipped=54`, `overall_result=fail`, `first_failed_stage=bootstrap_hosts` |
| network profile | `mgmt_shared_smoke_v1`, digest `sha256:ab06a230…f4f67e4` — identical to attempt 1 and to the baseline runs |
| report dir | `state/live-lab-validate2-20260828b/` |
| ledger row | **confirmed** — row 184 of `documents/operations/live_lab_node_run_matrix.csv` |

The six stages that ran to completion:

| stage | result |
|---|---|
| `preflight` | pass |
| `prepare_source_archive` | pass |
| `verify_ssh_reachability` | pass |
| `cleanup_hosts` | pass |
| `bootstrap_hosts` | **fail** |
| `cross_network_substrate_teardown` | pass |
| `cleanup` | pass |

Everything between `bootstrap_hosts` and teardown — all 54 remaining stages —
reports `skipped: dependency … did not pass`. That is the fail-closed dependency
graph behaving correctly, not 54 separate defects.

Not a blocker but worth recording: the run also reported **36 historical unfilled
triage stubs deferred by `TRIAGE_GATE_HISTORICAL_WATERMARK_UTC` (2026-07-28)**.
They did not gate this launch; they are the retirement backlog named in that
constant's rustdoc.

### 9.2 The launch gate: dispositioned, and the disposition was justified

The gate refused again, verbatim, on `livelab-1787849060-86f633c907cf::bootstrap_hosts`
(`policy_reject (78)`, `patch: null`). Per the owner decision recorded in §6, a
disposition was recorded — not invented, but anchored to the root cause the QH-51
track had already isolated on `livelab-1787884299-4b0d18aa668d::bootstrap_hosts`:
a stale `/etc/default/rustynetd` pinning `RUSTYNET_EGRESS_INTERFACE=rustynet-vx0`,
which `install-systemd` prefers over live detection.

Recorded with the documented tool, against the worktree ledger, and committed as
`068b29eb` before launching so the run's own dirty-state reading stayed `clean`:

```
rustynet ops live-lab-record-stage-patch \
  --ledger …/documents/operations/live_lab_stage_triage.jsonl \
  --stub-id 'livelab-1787849060-86f633c907cf::bootstrap_hosts' \
  --patch 'environment gap, not code — root cause isolated and remedied downstream. …'
```

The relaunch cleared the gate and dispatched stages. **The disposition was
correct about the root cause and wrong about the remedy's coverage** — see next.

### 9.3 The failure: the same stale egress pin, on a guest the remedy never touched

```
bootstrap_hosts fail: debian-headless-2: remote command failed (exit Some(1))
  error [generic_failure (1)]: install-systemd failed during e2e bootstrap: status=1
    stdout=error [generic_failure (1)]: egress interface does not exist: rustynet-vx0
```

Probed all five guests directly afterwards. The isolation is clean — **exactly one
guest is affected, and it is the one the QH-51 remedy did not cover**:

| guest | `/etc/default/rustynetd` mtime | `RUSTYNET_EGRESS_INTERFACE` | link present? |
|---|---|---|---|
| **`debian-headless-2`** | **2026-08-27T14:56:54Z** | **`rustynet-vx0`** | **MISSING** (only `lo`, `enp0s1`) |
| `debian-headless-4` | 2026-08-28T07:42Z | `enp0s1` | exists |
| `ubuntu-utm-1` | 2026-08-28T07:38Z | `enp0s1` | exists |
| `rocky-utm-1` | 2026-08-28T07:40Z | `enp0s1` | exists |
| `fedora-utm-1` | 2026-08-28T07:46Z | `enp0s1` | exists |

Two things follow directly from that table:

1. **The four healthy guests were rewritten by *this run*** (mtimes 07:38–07:46Z,
   inside the run window) with the correct `enp0s1`. So `install-systemd` derives
   the right interface whenever no stale pin exists — the code is not choosing
   `rustynet-vx0`, it is *obeying a file*. `debian-headless-2`'s bootstrap aborted
   before its own rewrite, which is why its file still reads 14:56:54Z.
2. **The residue's timestamp is the tell.** 2026-08-27T14:56:54Z is the same
   14:57Z cross-network run named in the `livelab-1787884299` disposition as the
   source of the lenovo residue. One cross-network run left the pin on *at least
   three* guests; only two of them were cleaned.

The failing code path is unchanged and old:
- `ensure_interface_exists` — `crates/rustynet-cli/src/ops_install_systemd.rs:2049`
- the precedence that prefers the stale file over live detection —
  `ops_install_systemd.rs:497-498`, where `existing_env.get("RUSTYNET_EGRESS_INTERFACE")`
  is consulted as a `resolve_egress_interface` input
- `VXLAN_LINK_NAME = "rustynet-vx0"` —
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/substrate.rs:34`

`git log -L 494,506:crates/rustynet-cli/src/ops_install_systemd.rs` puts the last
change to that precedence chain at **`8578a25b`, 2026-05-18** — three months
before tonight's merges.

`cleanup_hosts` passed at 07:34:27Z and did **not** remove the file. That is the
`cleanup_hosts` gap already flagged as a follow-up on the `1787884299` stub; this
run is independent evidence that the gap affects UTM guests, not only the lenovo
pair.

### 9.4 Comparison against the most recent comparable run

The closest comparable is `livelab-1787825655-3afd39b18164` (2026-08-27T09:55Z) —
identical five-guest UTM topology, identical network profile:

| | `1787825655` (baseline) | `1787903378` (this run) |
|---|---|---|
| overall | `partial` | `fail` |
| linux stage columns | 27 pass / 0 fail / 9 skip | 1 pass / 1 fail / 34 skip |
| `bootstrap` | pass | **fail** |

**This is a regression in outcome and not a regression in the software.** The
baseline ran at 09:55Z; the residue that breaks this run was written at 14:56Z,
five hours *after* that baseline finished. The same code that passed at 09:55Z
would pass now against a clean guest — as the four healthy guests in §9.3
demonstrate within this very run.

Against the historical ledger (183 prior rows, 145 `fail` / 38 `partial`, zero
overall `pass`), this run adds no improvement and no new class of failure.

### 9.5 Regression attribution: none of the seven merges is implicated

Seven merges (22 commits) landed on `main` between `e13132cb` and `22e707b2`:

| merge | authored | code touched |
|---|---|---|
| `f11bcd89` | 03:49 | `privileged_helper.rs`, `daemon.rs`, `main.rs`, macOS install adapter |
| `2676d4a8` | 04:04 | cross-network scenario port (`stage/cross_network/scenario/**`) |
| `4b96cb1f` | 04:24 | `linux_firewalld_zone.rs`, `phase10.rs` |
| `028341c6` | 08:16 | `live_lab_run_matrix.rs`, stage registry, overnight executor, netns scripts |
| `3c6a489b` | 08:18 | `vm_lab/mod.rs`, `rustynet-mcp/src/bin/lab_state.rs` |
| `22e707b2` | 08:24 | docs only |

`git diff --name-only e13132cb 22e707b2 -- crates/rustynet-cli/src/ops_install_systemd.rs
crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/substrate.rs`
returns **nothing**. Neither file in the failure path was touched by any of them.
Combined with the 2026-05-18 blame date on the precedence chain and the guest-side
mtime of 2026-08-27T14:56:54Z, there is no route by which tonight's merges caused
this.

**They also remain unproven.** The run never reached membership, assignments,
baseline runtime, exit handoff, relay, DNS, or any of the security-check stages, so
the QH-52 firewalld unbind, the helper IPC timeout pair, and the CN-3 scenario port
still have no live evidence.

### 9.6 Environment notes

- **Disk.** The host was at **97% used / 32 GiB free** on arrival (down from the
  84 GiB recorded in §4). `prune_jobs(keep=40)` removed **42 finished job records
  and their logs**, report directories preserved. The real consumers are build
  caches — `target/` 33 G, `target-livelab/` 9.7 G, `state/` 3.6 G — none of which
  is safe to prune blind. The run completed without a disk failure, but this needs
  an owner decision before a full-length suite.
- **The §12.3.1 MCP LAN false-negative is back.** `check_vm_reachable` reported
  **UP but UNREACHABLE for all five guests**; `nc -z -G3 <ip> 22` from the shell
  returned **OPEN on all five**, and the orchestrator's own `discover_local_utm`
  reported `unready=none`. Per §12.3.1 this is the sandbox permission, hits every
  node identically, and must not be chased per-VM — no recovery was performed and
  none was needed.
- **The §8 D1 fix is NOT live in the running MCP server.** `start_live_lab_run`
  still rendered
  `--windows-vm windows-utm-1 --macos-vm macos-utm-1` into a Linux-only `--node`
  argv. `bin/rustynet-mcp-lab-state` is dated **2026-08-13**, fifteen days behind
  its source, which does contain `auto_topology_vm_aliases`. This is exactly the
  silent `bin/` rot described in CLAUDE.md §12.5 — the fix is real, the deployed
  binary is stale, and no reconnect is possible in a non-interactive session. The
  run was therefore launched from the shell (the §7 reproduction), which took
  **5 guest locks, not 7**, confirming the shell path was never affected.
- The lenovo pair was not used. The suite topology is UTM-only by §7.

### 9.7 What is blocked, and what the owner must decide

**The remedy could not be applied.** Clearing `debian-headless-2`'s stale
`/etc/default/rustynetd` — either removing the file as the QH-51 track did on the
lenovo guests, or repointing the pin to `enp0s1` — was attempted twice and
**refused by this session's command-permission policy** (remote `rm` and remote
`sed -i` on a system config were both denied). No lab tool substitutes for it:
`reset_vm_network`, `recover_stuck_vms`, and `ensure_lab_ready` all operate on
networking and power state, not on guest config residue. That is precisely the
missing capability the `cleanup_hosts` gap describes.

**The new stub was deliberately left undispositioned.**
`livelab-1787903378-068b29ebc54b::bootstrap_hosts` carries `patch: null` and will
refuse the next Linux launch. That is the correct fail-closed state: the condition
is real, understood, and **not remedied**, so a disposition would unblock a run
that is guaranteed to fail identically. Do not fill it with a declination to get
past the gate.

Two things unblock the next attempt, in order:

1. Clear the stale pin on `debian-headless-2` (remove `/etc/default/rustynetd`, or
   set `RUSTYNET_EGRESS_INTERFACE=enp0s1`) and re-probe all five guests with the
   table in §9.3 — the residue came from one cross-network run and has now been
   found on three guests, so assume any guest that ever hosted that run is
   suspect until probed.
2. Record the disposition on `livelab-1787903378-068b29ebc54b::bootstrap_hosts`
   naming that clearance, then re-run the §7 topology unchanged.

The underlying defect worth an owner's attention is not the residue but the
asymmetry that makes it fatal: `install-systemd` trusts a previous run's env file
over live interface detection, and `cleanup_hosts` does not remove that file. Either
half alone would make this class of failure impossible.

### 9.8 Reproduction

```
cd .claude/worktrees/mgr-live-validate
CARGO_TARGET_DIR=…/target-livelab \
cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --report-dir state/live-lab-validate2-20260828b \
  --node ubuntu-utm-1:client --node rocky-utm-1:admin --node debian-headless-4:exit \
  --node fedora-utm-1:relay --node debian-headless-2:anchor
```

Note the orchestrator refuses a non-empty `--report-dir` outright (no silent
reuse); each attempt needs a fresh directory or the provenance-bound resume path.

---

## 10) Attempt 3 — `bootstrap_hosts` PASSES. `livelab-1787904828-2307d6731123`, stopped early on disk exhaustion

**Status: the §9.3 diagnosis is confirmed. With the stale env file removed from
`debian-headless-2`, `bootstrap_hosts` went `fail` → `pass` with no code change of
any kind. The run was then stopped deliberately at 510 MB of free host disk,
before it could reach the stages that matter. `passed=7 failed=0 skipped=54`,
overall `partial`, zero failures.**

### 10.1 The clearance, verified

The manager session removed `/etc/default/rustynetd` from `debian-headless-2`. Re-probed
all five guests before launching:

| guest | file | pin | link |
|---|---|---|---|
| `debian-headless-2` | **absent (clean)** | — | — |
| `debian-headless-4`, `ubuntu-utm-1`, `rocky-utm-1`, `fedora-utm-1` | present | `enp0s1` | exists |

Stub `livelab-1787903378-068b29ebc54b::bootstrap_hosts` was dispositioned naming that
clearance and committed (`2307d673`) before launch, so the run's dirty state read `clean`.

### 10.2 What ran

| field | value |
|---|---|
| run id | `livelab-1787904828-2307d6731123` |
| window | 2026-08-28T08:01:04Z → 08:13:48Z |
| commit | `2307d67311235e77954069ea27ae7889b855ae1a`, `work/live-validate`, `clean` |
| result | `overall_result=partial`, **`first_failed_stage` empty**, `passed=7 failed=0 skipped=54` |
| ledger row | **confirmed** — row 185 |

| stage | attempt 2 | attempt 3 |
|---|---|---|
| `preflight` … `cleanup_hosts` | pass | pass |
| **`bootstrap_hosts`** | **fail** | **pass** (12 min 17 s) |
| `cross_network_substrate_teardown`, `cleanup` | pass | pass |

**That single flip is the whole finding.** Identical topology, identical network
profile digest, identical code — the only delta between the two runs is one file
deleted on one guest. It closes §9 conclusively: the failure was guest state, and
nothing in the seven merges was ever implicated.

### 10.3 Why it stopped, and why that was the right call

Host free space collapsed *during* the run: 8.4 GiB → 6.5 → 2.35 → **504 MiB**. At
the 1.2 GiB threshold the run was stopped with `SIGTERM`, which let the orchestrator
unwind properly — `cross_network_substrate_teardown` and `cleanup` both ran and
passed, all five guest flocks released, and the ledger row was still appended. A
`SIGKILL` or a disk-full would have produced neither.

**The run was not the consumer.** Its total host footprint is 520 KiB of report
artifacts, and `target-livelab` did not grow at all (10 G before and after). The
consumer is elsewhere:

```
.claude/worktrees   258 GB  →  272 GB   (during this run)
```

**Twenty-five sibling worktrees are each carrying their own multi-gigabyte `target/`:**
`mgr-cn3-scenario-port` 25 G, `mgr-qh39-macos-greens` 18 G, `mgr-cn2-netns-substrate`
18 G, `mgr-stop-pgrep-and-harness` 15 G, `mgr-small-fixes` 15 G, `mgr-enrollment-listener`
15 G, and so on. That is a quarter of a terabyte of build cache, and it is growing while
other sessions work. Nothing in `state/` (3.6 G), `target/` (33 G) or `artifacts/` (6.5 G)
comes close, and `prune_jobs` cannot touch any of it.

**This is now the binding constraint on live validation, ahead of any code defect.**
The lab cannot complete a full 61-stage suite until worktree build caches are
consolidated onto a shared `CARGO_TARGET_DIR` or pruned. This validation worktree
already shares `target-livelab`, which is why it contributes nothing.

### 10.4 What is proven, and what still is not

Proven on hardware for the first time since `e13132cb`: source archive preparation,
SSH reachability, host cleanup, **full five-guest bootstrap including
`install-systemd` on every guest**, cross-network substrate teardown, and run
cleanup — all green, on code byte-identical to `main` @ `22e707b2`.

Still unproven: everything downstream of bootstrap — membership, assignments,
baseline runtime, anchor, relay, exit handoff, DNS, traversal, and all security-check
stages. The seven merges (QH-52 firewalld unbind, helper IPC timeout pair, CN-3
scenario port, and the rest) therefore **still have no live evidence**, exactly as at
the end of §9. No new stub was created — there were no failures to stub.

### 10.5 Next attempt

1. **Reclaim host disk first.** Consolidate or prune the worktree `target/` caches;
   a full suite needs headroom in the tens of gigabytes, not hundreds of megabytes.
2. Re-probe the five guests with the §9.3 table (the residue has now been found on
   three separate guests, so treat any guest that ever hosted a cross-network run as
   suspect).
3. Relaunch the §7 topology unchanged into a fresh report dir. The launch gate is
   currently clear — no undispositioned stub blocks it.

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

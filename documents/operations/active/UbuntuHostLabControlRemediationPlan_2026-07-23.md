# Ubuntu VM-Host — Lab-Control Remediation Plan (2026-07-23)

**Status: DESIGN / PATCH PLAN — no code written.** This is the fix design for the
five findings in `UbuntuHostLabControlFindings_2026-07-23.md`, surfaced while
verifying agent-driven lab control on `ubuntu-kvm-1` (libvirt/KVM host). It goes
file:line-deep so an implementer can pick it up cold, but nothing here is
implemented yet — the findings doc is the evidence, this is the remedy.

Owning program: `LinuxVmHostPlan_2026-07-14.md`. Read its §2 (the two-plane
split) and §11 (increments 1–4 that made the *standalone* lifecycle commands
libvirt-aware) before touching BUG-BOX-5 — the fix is "finish increment 3's job
in the one place it didn't reach."

## 0. Shared principles (apply to every fix below)

1. **One hardened path, no weaker branch (`CLAUDE.md` §3).** The libvirt readiness
   path must apply the *same* execution-readiness bar as the UTM path (SSH auth +
   exec probe), not a coarser "running + has IP" check. A second, weaker
   readiness notion is exactly what §3 forbids.
2. **Mirror the dispatch that already exists.** `execute_ops_vm_lab_start`
   (`mod.rs`, increment 2) already branches per controller kind — *"utmctl is only
   required when at least one selected target is UTM-backed."* Every fix here
   copies that shape rather than inventing a parallel one.
3. **Fail closed, fail loud.** Unknown/unreadable state → error naming the fix,
   never a silent pass. A launch that self-destructs later (BUG-BOX-4) is worse
   than a launch refused up front.
4. **None of these are security-sensitive.** They are lab-tooling defects (arg
   plumbing, controller dispatch, a flag-name typo). They do **not** touch crypto,
   trust-state, ACL, killswitch, exit-NAT, DNS-failclosed, or the privileged
   helper, so the §13.2 security-review gate does not gate them — but the full §7
   gate list (fmt/clippy/check/test) still does, and each fix ships with a test.
5. **Intersection watch (`RNQ-15`/`RNQ-17`).** All of this lives in the 49k-line
   `vm_lab/mod.rs`, which RNQ-15 is extracting and RNQ-17 is feature-splitting.
   Keep each fix cohesive and cross-reference the RNQ ledger, so it moves wholesale.

---

## 1. BUG-BOX-5 — HIGH — orchestrate readiness gate is UTM-only

**The one that actually blocks running a lab on the box. Fix this first.**

> **CORRECTED 2026-07-23 after adversarial review — the original draft of this
> section named the WRONG code path.** It cited `mod.rs:12222`/`:12478`, but those
> are the **legacy bash orchestrator's** readiness gate, which `--node` runs
> **never reach**: `execute_ops_vm_lab_orchestrate_live_lab` early-returns into
> `execute_rust_native_orchestration` at **`mod.rs:12089-12090`** the moment
> `config.node_assignments` is non-empty (i.e. any `--node` flag), so everything
> below `mod.rs:12152` is bash-only. Patching the `mod.rs` gate would leave the box
> still broken and could "pass" a legacy `--exit-vm`/`--client-vm` run while
> `--node` stays dead. The real `--node` gate is in the extracted module
> `orchestrator/readiness.rs`. The `mod.rs` locations are real code — just the
> wrong path for this bug.

### Current behaviour (verified)
The `--node` path is `execute_rust_native_orchestration`
(`orchestrator/native.rs:28`), whose readiness gate is
**`orchestrator/readiness.rs::run`**. It calls, unconditionally:

```rust
let initial_discovery = execute_ops_vm_lab_discover_local_utm(discover_config.clone())?; // readiness.rs:57
let initial_readiness =
    selected_local_utm_readiness_from_report(initial_discovery.as_str(), selected_aliases)?; // readiness.rs:61
```

`execute_ops_vm_lab_discover_local_utm` (`mod.rs:8015`) is a UTM bundle-scan +
`utmctl` discovery that **does not enumerate libvirt guests at all** (increment 3
left it UTM-only by design). So for libvirt aliases the report omits them, and
`selected_local_utm_readiness_from_report` (`mod.rs:9680`) hits its missing-aliases
branch and errors at **`mod.rs:9714`**:

> `local UTM discovery did not report the selected aliases: linux-x86-client-1, linux-x86-exit-1`

The run aborts before setup. The **post-restart rediscovery** at
**`readiness.rs:165`/`:169`** has the identical UTM-only assumption and must be
fixed in the same pass.

Confirmed live: run `claude-boxproof-2` (pid 2992) reached the network-profile
stage then died here. Zero `linux-x86` rows have ever reached the box ledgers.

### Two facts the adversarial review established (they narrow + de-risk the fix)
1. **The restart sub-step is ALREADY libvirt-capable.** When aliases probe unready,
   `readiness.rs:114` calls `execute_ops_vm_lab_restart`, which increment 2 made
   controller-aware. So only the **discovery + readiness probe** is UTM-only — the
   restart is not. The fix is narrower than the original draft implied.
2. **A real, same-bar libvirt readiness observer ALREADY EXISTS.**
   `observe_local_utm_target_ready` (`mod.rs:32817`) has a `VmController::Libvirt`
   arm (power via `libvirt_domain_running` `:32853`, IP via `resolve_libvirt_live_host`
   `:32860`) **and** a controller-agnostic SSH exec-auth probe (`ssh_auth_status`
   via `run_remote_shell_command`, `:32899`) that applies the *same* bar to libvirt
   as to UTM. So Option A's "reuse the observer, same readiness bar" is not
   aspirational — the observer is already wired for libvirt; the orchestrate gate
   just never invokes it for those aliases.

### Fix options

- **Option A — controller-kind dispatch in `readiness.rs::run` (RECOMMENDED).**
  Partition `selected_aliases` by their inventory controller kind. UTM-backed
  aliases keep `execute_ops_vm_lab_discover_local_utm` unchanged. Libvirt-backed
  aliases are probed per-target via the **existing** `observe_local_utm_target_ready`
  (fact 2 — do **not** write a second probe), and their `LocalUtmReadyState`s are
  folded into the same `LocalUtmSelectedReadinessSummary` the UTM path produces.
  Apply identically at the initial gate (`readiness.rs:57`) and the post-restart
  rediscovery (`readiness.rs:165`). The restart branch needs no change (fact 1).
  - *Pro:* smallest change; mirrors the proven `execute_ops_vm_lab_start` dispatch;
    UTM path byte-identical; same readiness bar both kinds; confined to the small
    extracted `readiness.rs` (not the 49k-line `mod.rs`).
  - *Con:* the readiness types keep the `LocalUtm*` name while serving libvirt — a
    misnomer. Mitigate with a comment now, a rename later (Option B).

- **Option A0 — honor `--trust-inventory-ready` for missing aliases (STOPGAP).**
  `selected_local_utm_readiness_from_report` errors on missing-from-discovery
  aliases (`mod.rs:9714`) *before* the `--trust-inventory-ready` blind-trust branch
  (`readiness.rs:95`) is ever reached — so that flag, which already exists to skip
  the readiness probe on trust, does **not** currently rescue a libvirt run. A
  minimal change is to make the missing-aliases case non-fatal under
  `--trust-inventory-ready` (treat as unready-but-trusted, matching the flag's
  existing "bootstrap/live SSH will fail loudly if unreachable" contract).
  - *Pro:* very small; reuses an existing contract; unblocks the box immediately.
  - *Con:* **weaker** — no readiness probe at all for libvirt; a powered-off guest
    is not caught until bootstrap SSH fails later. A legitimate stopgap, **not the
    destination.** If shipped, ship it *with* Option A queued, not instead of it.

- **Option B — unify into a controller-agnostic `discover_selected_nodes`** +
  rename `LocalUtm*` → `SelectedNode*`. Cleaner end-state; larger blast radius.
  Defer until RNQ-15's `mod.rs` extraction settles.

- **Option C — reuse `discover_hosts` wholesale.** Its `ready = running &&
  ip.is_some()` is *coarser* than `execution_ready` (no SSH exec) → **under-checks**
  libvirt guests (§0.1 violation). Rejected as a standalone fix.

### Recommendation
**Option A.** The observer it depends on is already libvirt-wired (fact 2) and the
restart is already controller-aware (fact 1), so A is both the smallest *correct*
change and the one that preserves the readiness bar. Use **Option A0 only as a
same-day unblock** if a box run is needed before A lands, and never as the final
state. Fold the `SelectedNode*` rename in only if it stays a pure rename.

### Test
`readiness_gate_accepts_libvirt_backed_aliases` (in `readiness.rs`): feed a
synthetic inventory with a libvirt controller + a stub observer reporting
running/IP/exec-ready; assert `run` returns a `ready` outcome, not the
missing-aliases error. Negative: a powered-off libvirt guest must land in
`unready_entries` with a reason code, **not** silently pass (guards against Option
A0's weakness leaking into A).

### Blast radius / effort
Medium, but **confined to `orchestrator/readiness.rs`** + one synthesize helper,
reusing the existing libvirt observer — smaller than the original draft's
"two `mod.rs` call sites". No security surface. Gates: full §7 + the acceptance
proof is a completed **`--node`** run (not a legacy `--*-vm` run — the mislocation
above is exactly why the verification must use `--node`) producing a `linux-x86`
row in the box's `live_lab_node_run_matrix.csv` (LinuxVmHostPlan Tier-1 DoD).

---

## 2. BUG-BOX-4 — MEDIUM — `launch_live_lab_on_host` omits `--known-hosts-file`

### Current behaviour (verified)
`execute_ops_vm_lab_launch_on_host` (`mod.rs:5734`) renders the detached run from
the template at **`mod.rs:5007`**:

```
exec cargo run --quiet -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --report-dir '__REPORT_DIR__' --ssh-identity-file __ORCH_IDENTITY__ __ORCH_ARGS__
```

It injects `--ssh-identity-file` (default `"$HOME/.ssh/id_ed25519"`, `mod.rs:5798`)
but **not** `--known-hosts-file`. The `--node` orchestrator hard-requires the
latter, so unless the caller smuggles it through `orchestrator_args` the run
compiles, then dies at arg-validation with *"--known-hosts-file is required when
--node flags are present"* — leaving no report dir, so a later `host_run_status`
reads the *previous* run and the failure is easy to miss. Confirmed live:
`launch-1784820652687` (pid 2229) died in seconds.

### Fix
Mirror the `orch_identity` handling exactly (`mod.rs:5796-5807`):
- Add `host_known_hosts: Option<String>` to `VmLabLaunchOnHostConfig`
  (`mod.rs:5035` area) and a `--host-known-hosts` flag in the `main.rs:3757`
  parser block.
- Default to `"$HOME/.ssh/known_hosts"` (double-quoted, host `$HOME` expands),
  an override single-quoted + `ensure_script_safe_value`-validated + no-single-quote,
  identical to `orch_identity`.
- Add a `__ORCH_KNOWN_HOSTS__` placeholder to the `mod.rs:5007` template and pass
  `--known-hosts-file __ORCH_KNOWN_HOSTS__` alongside `--ssh-identity-file`.
- Thread it through the MCP `launch_live_lab_on_host` tool as an optional param.

**Also fix at launch time, not just later:** before detaching, if
`orchestrator_args` contains any `--node` and no known-hosts is resolvable, the
call already knows enough to **refuse loudly** rather than emit a run that
self-destructs. Add that pre-check.

**Secondary (worth doing here):** the template runs `cargo run` (a *debug*
recompile on the host) even though `bootstrap build-release` already produced the
release binary. Prefer exec'ing `target/release/rustynet-cli` when present, or
`cargo run --release`, so the launcher isn't a cold debug build every time. Flag
as a sub-item; not required for correctness.

### Operational note (not a code fix)
The box's `~/.ssh/known_hosts` was missing `linux-x86-exit-1`'s key (that guest
had only ever been reached from the Mac). The default `$HOME/.ssh/known_hosts`
only works if both guests are pinned. Either the launcher or a preflight should
verify the selected guests are present in the known-hosts file and say so, rather
than letting `StrictHostKeyChecking=yes` fail mid-run. Consider folding a
"known-hosts covers selected guests" check into `host_preflight`.

### Test
`launch_on_host_injects_known_hosts_default_and_override`: assert the rendered
script contains `--known-hosts-file "$HOME/.ssh/known_hosts"` by default and the
single-quoted validated override otherwise; injection cases (quote, metachar,
newline) refused — mirroring the existing `orch_identity` tests.

### Blast radius / effort
Small. One config field, one flag, one template placeholder, one MCP param, one
pre-check. No security surface.

---

## 3. BUG-BOX-1 — MEDIUM — `get_vm_diagnostics` wrong flag → artifacts always fail

### Current behaviour (verified)
MCP `get_vm_diagnostics` (`crates/rustynet-mcp/src/bin/lab_state.rs:5889`) calls:

```rust
let artifacts = self.run_ops(
    "vm-lab-collect-artifacts",
    &["--vm", alias, "--report-dir", &report_dir],   // :5891
    600,
);
```

but the CLI parser (`crates/rustynet-cli/src/main.rs:4820`) requires
`--output-dir` (`parser.required_path("--output-dir")`). Result: exit 64
(`missing required option: --output-dir`) on every guest and host. The
daemon-status half (`vm-lab-status`, `:5878`) still works, so diagnostics are
degraded, not dead.

### Fix
One line: change `--report-dir` → `--output-dir` at `lab_state.rs:5891`. The MCP
binary must then be **rebuilt and atomically installed** (`cp x.new && mv -f`,
never in-place `cp` — the client keeps it mmap'd), then the client reconnected —
per `CLAUDE.md §12.5` and `scripts/ci/check_mcp_binaries_fresh.sh`.

### Decision to confirm
Two directions, pick one:
- **(a) Fix the caller** (recommended): the CLI's `--output-dir` is the
  established name across `vm-lab-collect-artifacts`; align the MCP to it.
- **(b) Add a `--report-dir` alias** to the CLI parser: broader, but invites
  drift between two names for one path. Prefer (a) unless another caller depends
  on `--report-dir` here (grep says none does).

### Test
`get_vm_diagnostics_collect_artifacts_uses_output_dir`: assert the args vector the
handler builds contains `--output-dir`. (Unit-level on the arg construction; the
end-to-end is the live box re-run.)

### Blast radius / effort
Trivial (one line) + the mandatory MCP rebuild/reinstall/reconnect dance.

---

## 4. BUG-BOX-2 — LOW-MED — manual `restart-runtime` assumes a pre-existing unit

### Current behaviour (verified)
The manual bootstrap chain: `install-release` (`mod.rs:40167`) only runs
`install -m 0755 target/release/rustynet{d,-cli} /usr/local/bin/…` — it never
installs a systemd unit. `restart-runtime` (`mod.rs:40199`) then does
`systemctl restart rustynetd.service`, which fails **status 5** ("unit not found")
on a guest that never had the unit. Confirmed live on `linux-x86-client-1`:
binary present, `systemctl status rustynetd` → *"Unit could not be found."*

The **primary** deploy path (`vm-lab-orchestrate-live-lab` via
`orchestrator/adapter/linux_install.rs`) installs the unit itself and is
unaffected — so this only breaks the manual convenience chain.

### Fix
Two parts, both small:
- **Install the unit in `install-release`.** Reuse the existing single hardened
  installer — there is already a Rust bin `install_rustynetd_service`
  (`scripts/systemd/install_rustynetd_service.sh` → `cargo run --bin
  install_rustynetd_service`) and the unit template `scripts/systemd/rustynetd.service`.
  `install-release` should invoke that same path on the guest rather than
  hand-rolling a second unit-install (one hardened path, §0.2).
- **Make `restart-runtime` fail loud, not opaque.** If the unit is absent, emit
  *"rustynetd.service is not installed — run bootstrap phase install-release
  (which now installs it), or use vm-lab-orchestrate-live-lab"* instead of a bare
  status-5. Cheap guard: `systemctl cat rustynetd.service >/dev/null 2>&1 ||`
  → the clear message.

### Decision to confirm
Should the *manual* bootstrap chain install a full production systemd unit at all,
or is the manual chain intended only for a foreground/dev daemon? If the latter,
the honest fix is to have `restart-runtime` say "no unit; the manual chain does
not install one — use orchestrate" rather than silently implying a service exists.
Owner call: **install the unit** (parity with the Mac path) vs **document the
manual chain as unit-less**. Recommend installing the unit for real parity.

### Test
`restart_runtime_reports_missing_unit_clearly`: on a target with no unit, assert
the error names the remediation, not status-5. Plus, if we install: assert
`install-release` renders the `install_rustynetd_service` invocation.

### Blast radius / effort
Small–medium. Limited to the manual bootstrap phase handlers; the orchestrate
path is untouched.

---

## 5. BUG-BOX-3 — LOW — MCP tool calls time out client-side at ~60s

### Current behaviour (verified)
Any slow `lab-state` MCP tool (`bootstrap_vm` sync/build, `sync_host`, provision)
times out at the **MCP client** at ~60s regardless of the `timeout_secs`
argument. The underlying CLI keeps running (confirmed via `ps aux`: a timed-out
`sync-source` completed successfully after the tool "failed").

### Nature
This is a **client request-timeout ceiling**, not a repo-code defect — there is
no server-side fix that lengthens the client's patience. So the "fix" is
containment, not a code patch:
- **Document + make discoverable.** The workaround (drive the CLI directly via
  Bash for slow ops) is already in `CLAUDE.md §12.3`; ensure the slow MCP tools'
  descriptions say so explicitly ("for runs >60s, prefer the CLI / expect a
  client timeout while the run continues").
- **Prefer async-launch shapes.** Where a tool wraps a long op, prefer the
  detached-launch + poll pattern (`launch_live_lab_on_host` + `host_run_status`)
  over a blocking one-shot, so the tool returns in ~1s and the work continues.
  `bootstrap_vm` build-release is the obvious candidate for a detached variant.
- **Do not** paper over it by having the tool lie "succeeded" before the work
  finishes — that reintroduces the fail-open the rest of this plan removes.

### Decision to confirm
Is a detached `bootstrap_vm` (launch-and-poll, like the orchestrate launcher)
worth building, or is CLI-direct for slow ops an acceptable standing workaround?
Recommend: leave as documented workaround now; revisit if the box loop makes slow
`bootstrap_vm` calls frequent.

### Blast radius / effort
Doc-only now; optional medium effort if a detached `bootstrap_vm` is pursued.

---

## 6. Recommended sequencing

1. **BUG-BOX-5** (HIGH) — unblocks the whole point of the box; everything else is
   polish until a run can complete. Its acceptance test *is* the first green
   `--node` run on box guests.
2. **BUG-BOX-4** (MEDIUM) — needed for the run to *launch* cleanly without the
   manual `--known-hosts-file` smuggle; pairs naturally with #1's live proof.
3. **BUG-BOX-1** (MEDIUM) — one line + MCP reinstall; restores diagnostics used
   while iterating #1/#2.
4. **BUG-BOX-2** (LOW-MED) — manual-chain parity; independent of the above.
5. **BUG-BOX-3** (LOW) — doc/description containment now; detached `bootstrap_vm`
   only if warranted.

#1 + #2 together are the critical path to the LinuxVmHostPlan Tier-1 DoD (a live
`--node` run producing a run-matrix row on box guests). #3–#5 are quality.

## 7. Verification plan (how each fix is *proven*, not asserted)

- **BUG-BOX-5 / -4:** a real (non-dry) `launch_live_lab_on_host` on `ubuntu-kvm-1`
  with `--node linux-x86-client-1:client --node linux-x86-exit-1:exit` that runs
  to completion and appends a `linux-x86` row to the box's
  `live_lab_node_run_matrix.csv`. Read it back via `host_run_status` /
  `fetch_host_artifact`. (Stage pass/fail is a *separate* concern — the finding is
  "can a run execute at all," which this proves.)
- **BUG-BOX-1:** `get_vm_diagnostics` on a box guest returns a populated artifacts
  section (exit 0), not exit 64, after MCP rebuild + reconnect.
- **BUG-BOX-2:** on a freshly-provisioned guest, the manual chain
  install→restart→verify completes, or (if unit-less by decision) restart-runtime
  emits the clear message. `systemctl is-active rustynetd` → `active`.
- **BUG-BOX-3:** description change visible; if detached `bootstrap_vm` built, a
  build launches and polls without a client timeout.

## 8. Open questions for the owner

1. BUG-BOX-5: ship Option A now, or wait for RNQ-15's `mod.rs` extraction and do
   Option B's clean rename on the smaller file? (Recommend A now; A does not block B.)
2. BUG-BOX-1: align MCP to `--output-dir` (recommended) vs add a `--report-dir`
   CLI alias?
3. BUG-BOX-2: install a real systemd unit in the manual chain (parity) vs document
   the manual chain as unit-less?
4. BUG-BOX-3: build a detached `bootstrap_vm`, or keep CLI-direct as the standing
   workaround for slow ops?
5. Landing: these touch core `vm_lab/mod.rs` — land on the same branch the other
   agent is consolidating, or a dedicated `fix/box-lab-control` branch merged
   after? (No security surface, so no §13.2 gate; full §7 gates still apply.)

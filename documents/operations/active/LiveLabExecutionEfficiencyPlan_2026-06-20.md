# Live-Lab Execution Efficiency Plan — 2026-06-20

Permanent execution-strategy doc for the same-LAN "drive defects to zero" loop.
Goal: iron out **all same-LAN kinks** (Linux, macOS, Windows, cross-OS) as fast as
possible **without weakening security or reliability**. Security is the priority;
speed comes from parallel compute and not repeating work, never from skipping a
control or a verification.

Cross-network (D2–D4, D5.1 substrate) is **deferred** until all same-LAN is green.

Owning ledgers: the loop journal (`state/mcp-loop-journal.jsonl`) and the run matrix
(`documents/operations/live_lab_run_matrix.csv`). This doc is the *method*; those are
the *evidence*.

---

## 0. The problem this fixes

A full 3-OS orchestrate run is ~40–50 min wall-clock (bootstrap alone ~12 min). The
loop was running the **entire** pipeline (cleanup → bootstrap → all stages) for every
single fix — so a fix to stage N paid ~30–60 min re-running stages 1..N-1 just to reach
N again, only to find the *next* defect. That is the single biggest waste in the loop,
and it compounds across the ~20–35 h of remaining same-LAN work.

Two levers eliminate it: **(A)** re-run only what the fix touched (one node, one stage),
and **(B)** never idle the operator during a run — always pull the next section's work
forward.

---

## 1. Confirmed efficiency primitives (verified in code 2026-06-20)

| Primitive | Mechanism | Valid when | Saves |
|---|---|---|---|
| **Setup/run split** | MCP `start_live_lab_run mode=setup` once → `mode=run --skip-setup`; or CLI `--skip-setup` | daemon source unchanged, or redeployed via per-node rebuild | ~12–25 min/iter (skips cleanup+bootstrap) |
| **Per-node rebuild** | MCP `start_live_lab_run` with `nodes=[topology] rebuild_nodes=[patched] skip_soak` — redeploys ONLY patched node, others keep state | a daemon fix that affects specific node(s) | (full multi-node rebuild) − (one node) |
| **Rust-native `--node` engine** | CLI `ops vm-lab-orchestrate-live-lab --node <alias>:<role> ...` — deterministic DAG-based StateMachineRunner with realtime stages.tsv, skip-cascade, always-run teardown, SIGTERM handler (default since 2026-07-06) | any role×OS combination; `--rebuild-nodes` for per-node fast re-verify | per-stage timing recorded; no false-green from empty assignments (returns Skipped) |
| **Single-stage bash re-run** | invoke the stage wrapper directly: `scripts/e2e/live_<os>_<stage>_test.sh` against the live mesh (the bash orchestrator calls these per stage, e.g. `stage_run_live_two_hop` → `live_linux_two_hop_test.sh`). For Rust-native: `--rerun-stage <stage>` against a setup-proven report dir. | mesh is up + setup intact; retrying the one failed stage | ~30–60 min (skips all prior stages) |
| **Skip Linux live suite** | CLI `--skip-linux-live-suite` on `vm-lab-orchestrate-live-lab`, or `deepseek_lab_run skip_linux_live_suite=true` (pair with a role-platform selector to target ONE mac/win cell) | iterating a mac/win cell from a fresh run | ~30–45 min (skips the whole Linux live-validation suite; setup still runs) |
| **Deploy preview** | MCP `what_will_deploy` (tracked-vs-HEAD that WILL ship + untracked that will NOT) | before every run | prevents silently shipping stale code / leaving a new file behind |
| **Setup-stage resume** | CLI `--resume-from <stage>` / `--rerun-stage <stage>` (SETUP stages only: cleanup/bootstrap/membership/assignments/baseline) | a setup stage failed; reuse provenance-bound report dir | re-bootstrap avoided for setup re-tries |

Notes:
- The **Rust-native `--node` engine** (`StateMachineRunner` + `PlanBuilder`, default
  since 2026-07-06) is the preferred path. It runs all 66 stages in a deterministic
  DAG with realtime stages.tsv, skip-cascade, per-stage timing, and SIGTERM graceful
  teardown. The legacy bash orchestrator (`--legacy-bash-orchestrator`) remains
  available for parity diff and existing matrix-row continuity.
- `--resume-from` / `--rerun-stage` are **setup-scoped only** (validated against
  `setup_stage_names()`); they do **not** jump into runtime stages. For runtime, use
  Rust-native `--rerun-stage` with an existing setup-proven report dir, or the
  single-stage bash wrappers.
- MCP `deepseek_lab_run` defaults to `rust_engine=true`; MCP `start_live_lab_run`
  routes to Rust when `nodes` array is passed.
- Standalone stage bins exist (`crates/rustynet-cli/src/bin/live_linux_*_test.rs`) and
  are driven by the wrapper scripts. Some harness-coupled stages (chaos, soak) do **not**
  run cleanly standalone — fall back to a scoped `mode=run` for those.
- `--skip-linux-live-suite` is the cleanest lever when the cell under test is a **mac/win**
  one: it runs setup (bootstrap + membership + signed-bundle distribution + baseline) then
  jumps straight to the mac/win role stages, skipping the entire Linux live-validation
  suite. Setup is kept on purpose — the mac/win stages gate on setup's `distribute_*`
  outcomes, not on the Linux suite, so the targeted cell stays fully exercised. Do **not**
  confuse it with `--windows-only`, which skips Linux **including** membership (breaks
  `mesh_join` unless the Windows guest is already joined from a prior run).

---

## 2. The fast inner loop (per defect)

1. **Triage** the FIRST failed stage: stage log + `diagnose_live_lab_failure` + SSH the
   guest for the real daemon error (`journalctl -u rustynetd` / launchd / Event Log).
2. **Root-cause** in code via repo-context MCP; classify:
   a. real defect → patch; b. env/lab flake → recover + retry, no code change;
   c. correct fail-closed the test mis-expects → fix the test, never the control.
3. **Patch** — smallest correct change. No `unwrap`/`expect`/`panic` on prod paths;
   propagate `Result`; fail closed on missing/invalid/stale trust state.
4. **Local gates (targeted)**: `cargo fmt` + `cargo clippy -p <crate>` + the touched
   crate's tests (~1–2 min). The full `--all-targets` + `audit` + `deny` suite is
   **batched in the background** (see §5), not run per-fix.
5. **Deploy ONLY what changed:**
   - Daemon (`rustynetd`) fix → `rebuild_nodes=[affected node(s)]` (incremental); mesh,
     membership, and signed bundles stay intact.
   - Orchestrator/test (`rustynet-cli`) fix → rebuild the **local** binary only; nothing
     ships to guests.
6. **Re-run ONLY the failed stage** via its wrapper against the live mesh; confirm green
   on real guests.
7. **Commit** (one logical change). **Push after the stage is green on the live mesh.**
8. **Continue to the next failed stage on the SAME mesh** — do not tear down.

---

## 3. Periodic FULL validation (reliability gate — mandatory)

The fast loop reuses a mesh, so cross-stage interactions and setup-time regressions can
hide. Therefore:

- After a **section** (e.g. all Linux runtime) goes green via fast iteration, run **one
  clean full orchestrate** (fresh cleanup + bootstrap → all stages, using the Rust-native
  `--node` engine by default) and append the matrix
  row. That clean run is the authoritative evidence.
- **A section is DONE only when a clean full run is green AND the matrix row is recorded.**
  Fast single-stage green is necessary but not sufficient.

---

## 4. Reliability / security guardrails (never trade for speed)

- **Stale-bundle hazard:** `--skip-setup` / single-stage re-run reuse the existing
  membership + signed bundles. This is valid ONLY for **daemon-internal** fixes. If a fix
  changes a **bundle format, signature/AAD scheme, wire protocol, or trust-state schema**,
  do a **full re-setup** — reusing stale bundles would test the wrong thing or mask a
  break.
- **Confirm the fix is actually on the guest** before trusting a re-run: `what_will_deploy`
  + a `strings`/version check on the deployed binary (this session caught a "binary not
  rebuilt" footgun this way).
- **No control weakening, ever:** never loosen a fail-closed, default-deny, signature,
  freshness/replay, perm, or rate-limit check to get green. Correct fail-closed that a
  test mis-expects ⇒ fix the test.
- **Fast green ≠ done.** Done = clean full run green + matrix row + local gates +
  enforcement point + verification test (incl. negative path) + journal note.

---

## 5. Parallel-work protocol (never idle during a lab run)

A run is a ~40 min sink during which the operator has nothing on the *critical path*.
ALWAYS pull one of these forward instead:

- **Windows front-load** (§6).
- **Pre-stage the next section's fixes**: read the owning code, draft patches in the
  working tree. Safe because runs deploy **committed HEAD** + the already-loaded
  orchestrator binary — working-tree edits don't perturb an in-flight run.
- **Batch the heavy gates**: `cargo test --workspace --all-targets`, `cargo audit`,
  `cargo deny` (~48 min) so they're done by the time the inner loop needs them.
- **Sibling-bug audits**: e.g. the `create_new` lockfile-as-mutex sweep — find latent
  defects before the lab does.
- **Titan research** for upcoming stages (DPAPI, named-pipe ACL, NRPT/resolver, launchd).
- **Journal + this plan upkeep.**

RULE: commit prep work at coordination points; **rebuild the orchestrator binary before
any run that must use a test-harness change**, and verify with `what_will_deploy`.

---

## 6. Windows front-load track (parallel, off critical path)

The Windows VM (`windows-utm-1`, 192.168.0.45) is idle during Linux/macOS runs — use it.

1. **Seed the Windows cargo cache** (no egress on the guests): tar the host registry cache
   → `C:\Users\windows\.cargo\registry\cache\index.crates.io-1949cf8c6b5b557f\`. Verify
   `tar.exe` (bsdtar ships on Win10+) and the extraction method first; fall back to a
   per-crate copy if tar paths misbehave.
2. **Pre-stage Windows fixes** from the known queue so the Windows lab run is one-shot:
   - `windows_stage_bootstrap` regression (currently 🔴, 18 pass / 3 fail).
   - DPAPI key custody (RSA-0002 / RSA-0025 — non-unix ACL no-op + `.enc` DACL at write).
   - Named-pipe ACL hardening.
   - `windows_managed_dns` (NRPT via `reg.exe` argv, never passed).
   Draft + local-gate each; do **not** ship until the Windows lab is reached.
3. The Windows lab needs a **Linux exit/relay backbone** → it shares Debian nodes with the
   Linux/macOS mesh. Run it after Linux is green (nodes free) or on a disjoint split (§7).

---

## 7. Concurrent-lab parallelism (advanced — guarded, default OFF)

One long-lived mesh is the default. A **second disjoint-node mesh** (e.g. 2 Debian +
Windows) may run concurrently with the Linux/macOS mesh ONLY IF **all** hold:
disjoint node sets, separate report dirs, Bash-direct invocation (no shared MCP job slot),
and host CPU/disk headroom. Turn this on only when the timeline demands it and never at
the cost of run reliability or evidence integrity.

---

## 8. Execution order (same-LAN, security-first)

1. **Linux runtime → green** (nearly there: `two_hop` cross-UID fix validating in r6;
   then re-confirm the tail: lan_toggle, managed_dns, network_flap, reboot, secrets,
   key_custody, enrollment).
2. **macOS-as-client** (mesh_join validated; keychain `key_custody`; remaining client
   stages — many should pass first try).
3. **Windows** (front-loaded prep → bootstrap → runtime → DPAPI / named-pipe / NRPT).
4. **cross-OS same-LAN** (`mixed_topology` → membership convergence → peer visibility →
   direct/exit paths → role_switch — the 16-fail historical hard nut).

---

## 9. Definition of done (per section)

- A **clean full orchestrate** run green on the real target guests + matrix row (exact
  commit, correct per-cell status, never blank).
- Local gates pass for the touched scope (incl. the section's `scripts/ci` gate).
- Each fix has an enforcement point + a verification test (incl. the negative path).
- No fail-closed / default-deny / crypto / freshness control weakened.
- Loop journal updated; this plan followed (and amended here if a primitive changes).

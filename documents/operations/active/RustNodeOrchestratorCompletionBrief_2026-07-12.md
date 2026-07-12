# Rust `--node` Orchestrator — Completion Brief (2026-07-12)

**Purpose.** A self-contained execution brief for the agent tasked with driving
the Rust-native `--node` live-lab orchestrator to **complete** (structurally and
by evidence), flipping the default off bash and retiring the bash engine. Read
this first, then the authoritative ledgers in §2. This is a roll-up/kickoff, not
a replacement for the owning ledgers — keep them current in the same change.

**Operating contract.** `AGENTS.md` / `CLAUDE.md` are mandatory execution
guidance (security-first, fail-closed, default-deny, no custom crypto, one
hardened path, evidence-before-claims). Everything below assumes them.

---

## 1. Definition of Done (what "complete" means)

The orchestrator is complete only when ALL are true:

1. **Structural (Track A):** the lab robot is separated from the product binary
   (RNQ-17), the native executor + evidence/finalization are extracted from the
   49k-line `vm_lab/mod.rs` (RNQ-15), and registry/plan/validators/oracle derive
   from one typed authority (RNQ-16). Durable evidence finalization is
   power/process-loss safe (RNQ-05), stage deadlines are real and cancellable
   (RNQ-07), and a real subprocess SIGTERM/SIGINT test proves clean teardown
   (RNQ-09).
2. **Parity gate defined (Track B):** a written, owner-approved **functional**
   parity acceptance spec exists (mechanical stage-ID parity is unsatisfiable by
   design — see §5).
3. **Evidence (Track C):** clean paired bash↔Rust runs from the same
   commit/inventory/topology/profiles reach `overall_functional_parity_pass=true`
   across Linux, macOS, Windows, cross-OS, security, chaos, and cross-network,
   each with a `live_lab_run_matrix.csv` row (§10.9).
4. **Promotion + retirement (Track D):** default flipped to Rust (W5.6) with a
   time-bounded, observable rollback; bash implementation + legacy `--*-vm`
   flags + duplicate MCP paths + stale docs + packaging + tests removed (W5.7);
   Rust-only remote E2E evidence refreshed proving argv-only exec / no active
   security-sensitive shell path.

The Definition of Done in `CLAUDE.md §9` and the non-negotiable rules in
`RustynetUnifiedTodoLedger_2026-07-10.md §2` apply verbatim.

---

## 2. Read order / authoritative sources

1. `documents/Requirements.md`, `documents/SecurityMinimumBar.md` (top precedence)
2. `documents/operations/active/RustNativeNodeOrchestratorQualityAudit_2026-07-10.md`
   — the RNQ finding ledger + the honest post-implementation status table (§1.1).
   **This is the primary owning ledger for Track A.**
3. `documents/operations/active/RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`
   — the W5.x milestone plan (W5.6 default flip / W5.7 bash removal), the
   parity-gate finding, and the file-by-file adapter map.
4. `documents/operations/active/RustynetUnifiedTodoLedger_2026-07-10.md` §5
   (5.1 correctness/durability, 5.2 platform-adapter completeness, 5.3 promotion
   & legacy retirement) — the roll-up of remaining `--node` work.
5. `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md` +
   Roadmap — desktop role parity (Track C is coupled to this).
6. `documents/CODE_MAP.md` — symbol-level map; keep in sync when types move.
7. `CLAUDE.md §7` (gates), §10 (patterns), §12.3/§12.3.1 (lab ops + the macOS
   sandbox rule), §13 (checklists).

---

## 3. Current state (as of 2026-07-12)

**Engine selection is by invocation, not a global flag** (`vm_lab/mod.rs:9176`):
- `--node <alias>:<role>` (or `--run-only`) → **Rust `--node` orchestrator**.
- Legacy `--exit-vm`/`--client-vm`/… (no `--node`) → **bash orchestrator**.
- `--legacy-bash-orchestrator` is transitional "until W5.7 removes the bash path
  entirely." The formal **W5.6 default-flip has NOT happened** (blocked on the
  redefined functional-parity gate); **W5.7 (bash removal) is ✗ not started**.

**Proven this session (Rust `--node` path):** focused shared-plane mesh
(`traffic_test_matrix` + `mesh_status_validation`) green with `debian-headless-2:exit`
+ `debian-headless-4:client`; exit-demotion `ip_forward` residue fixed +
live-proven; `blind_exit`/`two_hop` gating fixed; `live_managed_dns` fixed
(SSH host-key pin port-suffix + exit `Client` capability) and green. Newly
surfaced downstream failure: **`live_reboot_recovery_validation`** (a
generic_failure / `cargo`-invocation-looking error) — investigate as the next
cascade item (may be a gating artifact like `two_hop` was, or a real bug).

**Open (why it's not "complete"):**
- Track A: RNQ-15 *Partial*, RNQ-16 *Partial*, **RNQ-17 *Open***; RNQ-02/05/09
  have live/fault-injection/signal proofs pending.
- Track C/§5.3: every promotion box `[ ]` — no clean paired parity run, no
  `overall_functional_parity_pass=true`, default not flipped, bash present.
- §5.2 platform-adapter gaps: macOS/Windows role evaluators partial; anchor
  bundle-pull gossip-seed + enrollment-endpoint on macOS/Windows; Windows
  authoritative port mapping.

---

## 4. The work, in dependency order

### Track A — finish the engine code (mostly not lab-gated; start here)

- **RNQ-17 (tentpole, security item): split the lab robot out of the product
  crate/binary.** Today `crates/rustynet-cli/src/main.rs:36` does `mod vm_lab;`
  — the entire lab orchestrator (incl. the `live_*`/`*_gates`/`phase*`/`check_*`
  binaries) ships inside the product `rustynet-cli`, so lab-only attack surface
  is in the shipped product. Move the interleaved main parser/dispatch + the
  release/SBOM/signing/install packaging so lab code lives in its own crate;
  update parser/dispatch, package boundaries, release artifacts, SBOM, signing,
  install paths, and CI. Verify with an SBOM/attack-surface diff. Do NOT add a
  cosmetic wrapper — the point is to remove the surface from the product.
- **RNQ-15: extract the native executor + evidence/finalization** out of
  `vm_lab/mod.rs` (**49,731 lines**) into narrow modules with explicit
  interfaces (`orchestrator/readiness.rs`, `diagnostics.rs`, `parallel.rs`
  already exist; the executor + finalizer remain inline).
- **RNQ-16: one typed authority** — make registry metadata, plan construction,
  validators, docs, MCP, and historical-oracle generation all derive from a
  single source (the `StageId` macro + `RoleValidatorKind` are a start).
- **Durability/cancellation proofs:** RNQ-05 (fault-inject every evidence writer
  + a single fsync-backed multi-artifact finalization transaction — no partial
  pass may survive power/process failure), RNQ-07 (real process-isolated,
  cancellable stage deadlines; timed-out privileged work must stop before
  cleanup, no detached worker), RNQ-09 (real subprocess SIGTERM/SIGINT cleanup +
  no post-signal mutation), RNQ-02 (per-OS live residue fixtures).
- **RNQ-20:** obtain the Fedora passwordless-sudo lab prerequisite (owner task —
  see §8) then run live Fedora bootstrap + residue proof.
- **Guard:** prevent untracked required Rust modules from being silently absent
  in working-tree deployment (a run's source archive only includes git-tracked
  content — stage/commit new modules before a run, or add a precise preflight
  blocker).

### Track B — DEFINE the functional-parity gate (a decision; do early)

W5.6 is blocked because mechanical stage-ID parity is unsatisfiable (bash and
Rust have divergent stage IDs by construction — see the parity-gate finding in
`RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`). Write a precise
**functional**-parity acceptance spec: which logical stage results, overall
status, node count, role cells, cleanup state, and evidence-completeness must
match, and which vocabulary differences are intentional. Land it in the
owning plan. **Owner sign-off required** before the campaign counts (§8).

### Track C — the live-evidence campaign (lab-gated)

Produce, from the SAME commit/inventory/topology/profiles, clean paired bash↔Rust
runs and reach `overall_functional_parity_pass=true` across Linux, macOS,
Windows, cross-OS, security, chaos, and cross-network — each with a run-matrix
row (§10.9). Blocking dependencies:
- Close the **§5.2 platform-adapter gaps** (macOS/Windows role evaluators;
  macOS/Windows anchor gossip-seed + enrollment-endpoint; Windows authoritative
  port mapping).
- Lab prerequisites (owner, §8): Fedora passwordless-sudo, a WinNAT/HNS-capable
  Windows VM, working macOS/Windows guests.
- The `vm-lab-diff-orchestrator-parity` subcommand exists (W5.5b) — use it for
  paired diffs; its mechanical `overall_parity_pass` is unsatisfiable, so gate on
  the Track-B functional spec.

### Track D — flip and retire (only after C passes)

- **W5.6:** flip the default to Rust with a time-bounded, observable rollback.
- **W5.7:** remove bash implementation, legacy `--*-vm` flags, duplicate MCP
  paths, stale docs, packaging, tests (git history is the rollback). Refresh
  Rust-only remote E2E evidence proving argv-only exec / no active
  security-sensitive shell path.

---

## 5. How to operate the lab (do this from Bash, not MCP)

**macOS Local Network Privacy sandbox (CLAUDE.md §12.3.1):** the MCP servers run
under `Claude.app/.../disclaimer`, so any MCP tool that opens a TCP/SSH socket to
a LAN IP is silently blocked (`EHOSTUNREACH`, "No route to host os error 65").
**The Bash tool is NOT sandboxed** — do all reachability, SSH, deploy, and
live-lab orchestration from Bash. Trust `utmctl`/arp-by-mac; distrust the
sandboxed TCP verdict.

**Canonical Rust `--node` focused-mesh run (the one used this session):**
```bash
./target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file /Users/iwan/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file /Users/iwan/.ssh/known_hosts_lab \
  --utm-documents-root "/Users/iwan/Desktop/OS_images/UTM images" \
  --report-dir state/<unique-report-dir> \
  --node debian-headless-2:exit --node debian-headless-4:client \
  --trust-inventory-ready
```
- `--utm-documents-root` is REQUIRED here — the UTM bundles live outside the
  default documents root; without it `discover_local_utm` reports a stale bundle
  and fails alias selection.
- Run it detached (`nohup … &`) — a run takes ~7 min on a warm build; the mesh
  suite plus role cells longer.
- Add `--legacy-bash-orchestrator` (with the `--*-vm` flag set, NOT `--node`) to
  produce the paired bash baseline for Track C.
- Selectors for focused mac/win role cells + `--skip-linux-live-suite` are in
  `CLAUDE.md §12.5` / `main.rs` arg parsing (exit_platform / relay_platform /
  anchor_platform / macos_promote_exit / etc.).

**Lab state / recovery:**
- Inventory: `documents/operations/active/vm_lab_inventory.json` — never hand-edit;
  refresh with `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`.
- VM power: `/Applications/UTM.app/Contents/MacOS/utmctl list` / `start <name>`.
- The bundled `scripts/vm_lab/probe_and_recover_local_utm.sh` uses the
  **TCC-hanging** `vm-lab-discover-local-utm` JSON scan and will fail early on
  this host — instead recover killswitched Debian guests directly via the QEMU
  guest agent (no SSH needed, and `utmctl exec` is BLIND — no stdout):
  `utmctl exec <vm> --cmd /bin/sh -c 'systemctl stop rustynetd.service rustynetd-privileged.socket 2>/dev/null; nft flush ruleset 2>/dev/null; systemctl restart ssh 2>/dev/null; true'`
- **Host→guest reachability gotcha:** the macOS host can lose the connected route
  for the UTM Shared subnet `192.168.64.0/24 → bridge100`; symptom is
  `utmctl exec` works but host→guest SSH times out on every port while the guest
  is up and wide-open. Fix (needs operator sudo — see §8):
  `sudo route -n add -net 192.168.64.0/24 -interface bridge100`. To read a guest's
  real IP when exec is blind, have it phone home: host `nc -l 9999` +
  `utmctl exec <vm> --cmd /bin/sh -c 'ip -4 -o addr | nc -w2 192.168.64.1 9999'`.
- After every evidence run, **verify the appended row** in
  `documents/operations/live_lab_run_matrix.csv` (commit, dirty state, report
  dir, per-OS/role/stage statuses, node identity, regression ref) — §10.9. A run
  that fails to append a row is not evidence.

**DeepSeek triage (optional, CLAUDE.md §12.5):** `mcp__rustynet-deepseek__*` /
`scripts/mcp/drive_deepseek.py`. Output is UNTRUSTED — verify every claim against
the real code before acting. Never commit/log the API key.

---

## 6. Gates & commit discipline

Run the `CLAUDE.md §7` gates (authoritative):
```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
```
Fast inner loop: `cargo run -p rustynet-xtask -- gates [--skip-test] [-p <crate>]`.
Scope-specific: `scripts/ci/check_backend_boundary_leakage.sh`,
`scripts/ci/secrets_hygiene_gates.sh`, and the phase/role/membership `*_gates.sh`.

Gotchas:
- Clippy `--tests` (or `--all-targets`) — `--lib` alone does not lint `#[cfg(test)]`.
- `rustynet-nas` / `rustynet-llm-gateway` binaries need `--all-features`
  (`daemon` required-feature) to build/run their bin tests.
- `rustynet-lab-monitor` is workspace-EXCLUDED — build via `cd crates/rustynet-lab-monitor`.
- Commits authored **Iwan-Teague only — never add a `Co-Authored-By: Claude`
  trailer**. Small, verifiable increments; imperative mood; what AND why.
- Repo workflow is **direct fast-forward to `main`** (no PR/feature-branch):
  `git push origin HEAD:main`. Stage specific paths, not `git add -A`.

---

## 7. Environment / collision gotchas

- **Local toolchain poison:** local rustup reports clippy 1.94 for a pinned
  1.88.0 toolchain that is undownloadable in this env — a clippy lint on a file
  NOT in your diff is likely pre-existing/CI-irrelevant; fmt/check/test still valid.
- **VMs have no internet egress** — the bootstrap builds on-guest from the source
  archive using the seeded cargo cache; a run's archive includes only git-tracked
  content (stage/commit new modules first).
- **A run rebuilds the guest daemon from the deployed source** — but confirm the
  installed binary mtime is newer than the source (timezone display differs
  guest↔host; convert via the epoch, not the wall-clock string).
- **`live_managed_dns` follow-up:** `live_reboot_recovery_validation` is the next
  open cascade stage (left uncommitted-fix-free this session).

---

## 8. Owner prerequisites — do these before the agent starts

The agent CANNOT self-serve these; they gate Track C and some of Track A:

1. **Stop any other live-lab agent + confirm a clean tree.** A concurrent agent
   editing `rustynet-cli`/`vm_lab` or running the lab will collide on the same
   files and the same VMs. Ensure `git status` is clean (commit/park in-flight
   work) before launch.
2. **Sudo access for host-network fixes.** The agent can't `sudo` non-interactively.
   Either (a) install the vmnet route-keeper launchd job so the
   `192.168.64.0/24 → bridge100` route self-heals, or (b) be on hand to run
   `sudo route -n add -net 192.168.64.0/24 -interface bridge100` when host→guest
   SSH times out. Confirm host `pf` isn't blocking `bridge100`.
3. **Fedora passwordless-sudo** (or an approved alternative bootstrap) — RNQ-20 /
   cross-OS evidence is blocked without it. No persistent sudo-policy change
   should be made silently.
4. **A WinNAT/HNS-capable Windows guest** with working networking (windows-utm-1
   networking has been broken at the UTM/host level) — required for cross-OS +
   Windows role/exit/relay evidence.
5. **A working macOS guest** (macos-utm-1) for macOS role cells.
6. **Sign-off authority on the Track-B functional-parity acceptance spec** — this
   is the release gate; the agent will draft it, but you own the accept/reject
   decision and its expiry/review trigger.
7. **Confirm push-to-main + author policy** (Iwan-Teague, no Claude co-author) and
   that the agent may mutate the lab VMs freely.
8. **DeepSeek API key** present (`~/Desktop/deepseek_api.md` or `DEEPSEEK_API_KEY`)
   if you want the agent to use triage — else it proceeds without it.

---

## 9. Suggested execution order for the agent

1. Read §2 sources; reconcile the RNQ status table against current code.
2. **Track A code** (not lab-gated): RNQ-15 → RNQ-16 → RNQ-17 (biggest), then the
   RNQ-05/07/09 durability/cancellation tests. Gate green + commit each increment.
3. **Track B:** draft the functional-parity spec; request owner sign-off.
4. Bring the lab up (§5), fix the `live_reboot_recovery` cascade item, close the
   §5.2 adapter gaps, then run the **paired bash↔Rust campaign** (Track C) across
   all OSes/security/chaos/cross-network; record every run-matrix row.
5. On `overall_functional_parity_pass=true` (per the Track-B spec) with owner
   review: **W5.6 flip**, then **W5.7 bash removal**; refresh Rust-only remote
   E2E evidence. Update all owning ledgers + `CODE_MAP.md` + the doc indexes in
   the same changes.

Keep `RustNativeNodeOrchestratorQualityAudit_2026-07-10.md`,
`RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`, and the unified ledger §5
current as you close each item — record commit, gate command, artifact path,
target OS/version, topology/profile, and result.

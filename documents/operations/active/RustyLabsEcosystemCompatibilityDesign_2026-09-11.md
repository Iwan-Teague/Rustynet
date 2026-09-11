# RustyLabs — ecosystem compatibility meta-repo (design, 2026-09-11)

**Status:** owner-requested design, not yet built. Home for now is this repo's
active docs; **move this file into `rustylabs/` when that repo is created.**
Owner decisions taken (2026-09-11): the stack is named **rustylabs**; its job is
to **build and test cross-project compatibility** with **rustynet as the
mandatory P2P substrate every other project depends on**; compatibility tests
run on the **real lab (UTM/KVM)**.

## 1) What rustylabs is (and is not)

rustylabs is a **meta-repo**, not a monorepo and not a release bundle. Each
project — `rustynet`, `rustyai`, `rustyfin`, `rustytorrent`, `rustydns`, and any
future rusty* — stays its own independently-edited, independently-pushed repo.
rustylabs references each at a pinned commit and adds the one thing no child repo
can hold on its own: **the harness that proves they still work together over
rustynet.**

The load-bearing fact the owner stated: *everything relies on the peer-to-peer
transport rustynet provides.* So rustynet is not a peer of the others in this
repo — it is the **substrate**, and "compatibility" means "project X's core
function still works when its only network is a rustynet mesh."

## 2) Repo shape

```
rustylabs/
  Cargo.toml              # [workspace]; members = crates by path into submodules
  projects/               # git submodules — each stays its own repo
    rustynet/             #   the substrate
    rustyai/  rustyfin/  rustytorrent/  rustydns/
  integration/            # the compatibility harness — lives HERE, not in a child
    Cargo.toml
    src/                  # mesh bring-up helpers, per-project drivers
    tests/
      mesh_substrate.rs         # stand up a rustynet mesh, assert it is up
      rustydns_over_mesh.rs
      rustytorrent_over_mesh.rs
      rustyfin_over_mesh.rs
      rustyai_over_mesh.rs
  .github/workflows/
    nightly-compat.yml    # bump submodules -> gate -> real-lab compat -> commit if green
  compat-matrix.md        # known-good (rustynet x project) commit tuples + last-green
  README.md
```

**Why git submodules + a Cargo workspace, not subtree or bare git-deps.**
- Submodules keep each project fully independent and editable in place; the
  pinned pointer is a reproducible commit, so "latest" is always a deliberate,
  recorded bump, never a moving target under a build.
- The workspace `Cargo.toml` references each project's crates by
  `path = "projects/<name>/crates/..."`, so an incompatible rustynet API change
  breaks the child's **compile** inside rustylabs CI — caught before runtime.
- Subtree (vendored copies) makes child-side edits round-trip awkwardly — the
  opposite of "individual repos stay editable." Bare Cargo git-deps can't hold
  the non-crate parts (daemons, scripts, assets) some projects carry; submodules
  hold anything.
- Non-Rust or mixed projects still fit: they are submodules like the rest; only
  their Rust crates (if any) join the workspace, and their compatibility is
  proven at **runtime** by the harness rather than at compile time.

## 3) The compatibility contract (dependency direction)

Every project depends on a **stable rustynet integration surface**, and that
dependency edge IS the compatibility contract. Candidates already in rustynet:
- `rustynet-control` — identity, membership bundles, roles/capabilities.
- `rustynet-backend-userspace` — a userspace boringtun tunnel with no kernel
  module (how a project opens the mesh transport in-process).
- the `rustynet-llm-gateway` **identity-from-tunnel** pattern — a service
  authenticating a peer purely by its tunnel source identity, no API key. This is
  the template for how rustyai/rustyfin/rustytorrent expose a service to mesh
  peers under signed default-deny access.

**Action item for rustynet (separate from rustylabs):** decide and freeze the
public "mesh SDK" surface the ecosystem consumes — most cheaply a thin
`rustynet-mesh`/`rustynet-sdk` facade crate re-exporting exactly the identity +
transport + service-access types a peer app needs, so children depend on one
semver'd crate instead of reaching into internals. Without this, every child
pins deep internal types and every rustynet refactor is a false compatibility
break. This crate is the seam the whole meta-repo turns on.

## 4) How compatibility is verified — reuse the `--node` live-lab (real lab)

rustynet already stands up real meshes on UTM/KVM via the `--node` orchestrator
(`crates/rustynet-cli/src/vm_lab/**`, the live-lab run matrix, the lab hosts
lenovo-bot + katana). rustylabs does not reinvent this — it **adds an
application-compatibility phase after the mesh is proven up.** Flow of one
compat run:

1. **Substrate phase** — the existing `--node` setup + a minimal live suite
   brings up a 2–3 node mesh on real guests and proves the tunnel/gossip/
   membership are healthy. If the substrate is not green, the run stops here and
   reports SUBSTRATE-FAIL (a rustynet regression, not a project incompatibility —
   the distinction matters for triage).
2. **Per-project compat phase** — for each project, deploy its binary onto mesh
   nodes and run its core operation with **rustynet as the only network**, judged
   by an **independent observation** (tough-policy rule 2 — never the app's own
   self-report):
   - **rustydns** — a client resolves a managed name; proof = the resolved
     address is reached over the tunnel and an off-mesh probe of the same name
     fails (fail-closed, no leak).
   - **rustytorrent** — a file transfers peer→peer across the mesh; proof =
     byte-exact hash match at the receiver and the bytes crossed the WireGuard
     interface (capture on the peer), not a LAN shortcut.
   - **rustyfin** — its core operation between two mesh peers; proof = the
     operation's result verified by the second node, over the tunnel only.
   - **rustyai** — an inference/transcription call authenticated purely by tunnel
     identity (the llm-gateway path); proof = the call succeeds for an authorized
     mesh peer and is refused for an unauthorized one (the negative control).
3. **Evidence** — every compat stage declares a `File` witness (an inversion or
   transcript artifact) exactly like the `--node` engine's QH-83 stages, appends
   a row to a rustylabs compat matrix, and the run is reproducible from the
   pinned submodule tuple.

**Substrate choice — real lab.** Per the owner decision, compat runs on the
actual UTM/KVM lab for full-fidelity P2P (real NAT, real WireGuard, real gossip),
not a localhost simulation. Consequence for cadence: a real-lab run is minutes
and needs lab hardware, so it is a **nightly / on-demand** job, not per-push
(§5). A cheap per-push **compile-compatibility** gate (does the workspace still
build against the current rustynet SDK surface) can still run in ordinary CI
without the lab, catching the API-break class early; the lab run catches the
behavioural class.

## 5) "Latest" — nightly gate-then-commit bump bot

`.github/workflows/nightly-compat.yml` (scheduled):
1. `git submodule update --remote` — bump every project to its upstream tip.
2. `cargo build`/`clippy`/`test` the workspace (compile-compatibility).
3. Trigger a real-lab compat run (§4) on the lab hosts.
4. **If all green:** commit the new pinned submodule tuple + update
   `compat-matrix.md` with the last-green tuple and timestamp.
5. **If red:** do NOT move the pointers; open an issue naming the exact child
   commit that broke compile or behavioural compatibility, with the failing
   stage's evidence artifact linked.

Result: rustylabs always sits at *the latest of every project that still
interoperates with rustynet*, with a paper trail of when and what broke. Manual
bump is the same workflow run by hand. Floating to bare latest is rejected for
the reason rustynet already rejects it everywhere: an upstream push could
silently break the mesh contract with no record — pin + auto-bump-when-green
keeps "latest" without losing reproducibility.

## 6) Inherited constraints (non-negotiable)

- **Tunnel-only + default-deny** for every project's mesh-exposed service; a
  compat test that reaches a service off-tunnel is a FAIL, not a pass.
- **Independent detection** for every compat verdict (rule 2): the app never
  grades its own compatibility.
- **Fail closed:** substrate down, unverifiable, or app unreachable ⇒ the run
  fails, never silently downgrades to "assume compatible."
- **No secrets in the repo:** lab passwords stay in the sidecar pattern
  (`vm_lab_inventory.secrets.json`), never in rustylabs; the public-repo secrets
  gate runs before any rustylabs push too.
- **Submodule pinning is the reproducibility guarantee** — a compat claim always
  names the exact (rustynet, project) commit tuple it was proven at.

## 7) Open decisions before build

1. **The rustynet SDK surface (§3).** Freeze a `rustynet-sdk`/`rustynet-mesh`
   facade crate, or let children depend on `rustynet-control` +
   `rustynet-backend-userspace` directly for v0? (Recommendation: thin facade;
   it is the seam.)
2. **Per-project core-op definition.** For each of rustyfin/rustytorrent/
   rustyai/rustydns, the owner/app author names the ONE core operation whose
   success = "compatible." §4 lists proposals; confirm each.
3. **Lab footprint for compat.** Reuse the existing lab node roles, or a
   dedicated rustylabs topology (e.g. 3 nodes: one exit/anchor + two clients)?
4. **Which projects are Rust-crate members vs runtime-only submodules** (drives
   whether their break shows at compile time or only in the harness).
5. **Repo host + submodule auth** — the lab hosts have limited GitHub auth
   (lenovo-bot has none; Mac pushes for it, per memory). The nightly bot needs a
   token that can read every child and push rustylabs.

## 8) Bootstrap sequence (when approved)

1. Freeze the rustynet SDK facade crate (§7.1) inside the rustynet repo.
2. `git init rustylabs`; add each project as a submodule under `projects/`.
3. Workspace `Cargo.toml` + a compile-only `mesh_substrate` bring-up helper on
   the userspace backend (fast local smoke, no lab) to prove the SDK wiring.
4. Port the `--node` substrate bring-up into `integration/` as the first real-lab
   stage; add one per-project compat stage at a time (rustydns first — smallest).
5. Add `nightly-compat.yml` once ≥1 project compat stage is green on the lab.
6. Move this design doc into `rustylabs/` and de-index it here.

## 9) Cross-references
- `documents/operations/active/ComputeJobRolesVision_2026-09-11.md` — the
  compute/job roles that make rustyai-style workers first-class on the mesh; a
  natural rustylabs compat target.
- `LlmNodeRoleDesign_2026-06-11.md` — the identity-from-tunnel service pattern the
  per-project harness reuses.
- `documents/operations/active/*ParityPlan*/RustynetDataplaneExecutionPlan*` — the
  `--node` engine and dataplane the substrate phase stands on.
- `NodeEngineToughPolicy_2026-09-11.md` — the evidence standard the compat stages
  inherit (independent detection, fail-closed, named skips).

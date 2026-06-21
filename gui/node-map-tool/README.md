# Rustynet Node Map — native Rust GUI tool

A native desktop application (no browser, no webview) that renders a Rustynet
network as glowing "balls of light" in a 3D space: a node's colour encodes its
**role**, its **status** drives brightness/pulse/fade, and glowing lines with
travelling particles show the **data path** between connected nodes
(e.g. client → anchor → relay → exit).

Built with **egui/eframe** — pure Rust, immediate-mode GUI, light dependency
tree. The 3D scene is software-projected and drawn with egui's painter (no GPU
3D engine), which keeps it portable and easy to fold into a future
egui-based Rustynet GUI.

## Build & run

```sh
cd gui/node-map-tool
cargo run                       # built-in demo data + simulated live updates
cargo run -- sample-topology.json   # load a real topology (see data-contract)
```

A native window opens (Linux/macOS/Windows). First build fetches the egui
dependency tree; subsequent builds are a few seconds.

> Linux note: rendering uses OpenGL (the `glow` backend) and a windowing system
> (X11 or Wayland), loaded at runtime — so a desktop session is required to
> *run* it, but no extra system `-dev` packages are needed to *build* it.

## Controls
The view is a fixed oblique top-down map (no free orbit): the camera angle stays
constant and you pan + zoom around it.
- **Drag**: pan · **scroll**: zoom
- **Hover** a node for a tooltip; **click** it for an inspector panel
- **Click a galaxy** to drill in (zoomed view of its nodes, with names); use
  **← Back to overview** to return
- **Legend** (right): click a role to show/hide it
- **Controls** (left): toggle labels, data-path animation, galaxy borders, live
  demo updates; reset view (re-frames the whole network)

## Layout & crossing minimisation

Nodes are grouped into **galaxies** — one per `(hub, role)`, e.g. the clients on
`anchor-eu` form their own galaxy, distinct from the clients on `anchor-us`.
Within a galaxy, members are spread evenly with Vogel's Fibonacci-sunflower disc
model, leaving a clear margin to the polygon border.

Galaxies and backbone nodes are then placed by a **layered (Sugiyama) layout**
that explicitly minimises connection-line crossings — the layout the user keeps
asking about ("no needless overlaps"). The pipeline, in order:

1. **Layering by flow rank** — sources (clients/nas/llm/admin) → anchor → relay →
   exit become left-to-right columns, matching the real data path.
2. **Dummy nodes on skip-layer edges** — an edge that jumps layers (e.g. an
   anchor egressing straight to an exit, or an admin control link to a relay)
   gets virtual waypoints in the intermediate layers, so it can be routed
   *between* other nodes instead of slicing across them.
3. **Deterministic forest ordering (primary)** — with dummies in place the data
   path is (near-)tree-shaped, so each subtree is laid out contiguously via a
   rooted DFS. This is the textbook crossing-free tree drawing and resolves the
   coupled cases (multi-parent relay fan-ins, long edges past a hub) that local
   moves alone can't.
4. **Barycenter + pairwise local search + multi-start (repair)** — cleans up any
   genuinely non-tree edges (e.g. an admin control star). Crossing minimisation
   is NP-hard, so this targets the minimum rather than proving it; for the
   network shapes Rustynet produces it reaches **zero**.

Everything is deterministic (fixed-seed), so the same topology always lays out
the same way, at any size. The overview distance auto-fits the world bounds.
Regression tests in `src/main.rs` assert zero edge crossings on the demo plus
stress topologies (`cargo test`). Run the binary with `RUSTYNET_DEBUG_XINGS=1`
to print any residual crossing pairs to stderr.

## Isolation / why it's a separate crate

This is its **own workspace** (note the empty `[workspace]` table in
`Cargo.toml`) and is excluded from the main Rustynet workspace
(`exclude = ["gui"]` in the root `Cargo.toml`). GUI stacks pull in large
transitive dependency trees with assorted licenses; keeping this crate isolated
means it never conflicts with the security-gated workspace's strict license
allowlist or `unsafe_code = "forbid"` policy. It builds and lints cleanly on its
own (`cargo build`, `cargo clippy --all-targets`, `cargo fmt -- --check`).

## Data contract & wiring to the real daemon

Input JSON matches [`DATA_CONTRACT.md`](DATA_CONTRACT.md):

```jsonc
{
  "nodes": [ { "id", "label?", "role", "status", "position?", "meta?" } ],
  "edges": [ { "from", "to", "kind?", "active?" } ]
}
```

- **Roles**: `client`, `admin`, `anchor`, `relay`, `exit`, `blind_exit`,
  `nas`, `llm` (unknown → grey).
- **Statuses**: `online`, `connecting`, `offline`, `powered_off`.
- **Edge kinds**: `data_path` (animated flow), `control`, `potential`.

See [`DATA_CONTRACT.md`](DATA_CONTRACT.md) for the full shape + suggested wiring.

To make it live later, have `rustynetd` emit this JSON (a file, a local socket,
or a command) and replace `load_graph()` / the `simulate()` demo loop with a
real feed. All role/status/edge/colour/layout styling is isolated in the CONFIG
section at the top of `src/main.rs` for easy retheming.

## Visual design (Claude handoff)

The visual language is being refined with Claude. [`CLAUDE_DESIGN_BRIEF.md`](CLAUDE_DESIGN_BRIEF.md)
is a self-contained, copy-paste brief: paste the whole file into Claude and it
returns (a) an HTML mockup to eyeball and (b) paste-ready Rust that drops over
the CONFIG section here. The brief encodes the egui painter constraints so the
design stays 1:1 portable to this app.

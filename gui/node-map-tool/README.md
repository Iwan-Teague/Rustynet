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

Connections are always drawn as **straight lines**. Galaxies and backbone nodes
are placed by a **layered (Sugiyama) layout** that computes the **provable
minimum** number of straight-line crossings — not merely "a low number".

Crossing minimisation is **NP-hard** (Garey & Johnson; Eades & Wormald proved
even the two-layer case is hard), so there is no polynomial closed-form formula.
The established route to the exact optimum is ILP / branch-and-bound (cf. Jünger
& Mutzel; the OGDF library). For the small *per-layer tile counts* Rustynet
produces, we compute that exact optimum and **certify** it. Pipeline:

1. **Layering by flow rank** — sources (clients/nas/llm/admin) → anchor → relay →
   exit become left-to-right bands, matching the real data path.
2. **Dummy nodes on skip-layer edges** make every edge span one layer, turning
   the problem into the classic layered crossing number (a sum of adjacent-layer
   inversions).
3. **Strong heuristic incumbent** — optimal per-layer reordering (the Linear
   Ordering Problem, solved exactly by Held-Karp subset DP) iterated in up/down
   sweeps, seeded from a deterministic forest (DFS) ordering, with fixed-seed
   multi-start.
4. **Branch-and-bound** over layer permutations with incumbent pruning and a
   budget gate. When it completes it **proves** the global minimum; the layout
   prints `crossings = N (proven minimum)`. (Huge instances that blow the budget
   keep the heuristic result, printed as `best found`.)

Because a polyline (via dummies) can only avoid crossings a straight line would
have, when the straight-line count equals the certified layered minimum the
straight drawing is itself provably minimal — which holds for the shapes
Rustynet produces. A K₃,₃ block, for example, certifies its true minimum of 9.

To stay "like a universe" rather than a grid, the layout is curved: each leaf
galaxy (client/nas/llm) is swung onto a **radial arc around its anchor** — flow
layer → radius, within-layer order → angle over a limited fan (never a full
circle) — so the leaves wrap their anchors in a rounded spread. Because the
optimiser aligned each leaf with its anchor by rank, those spokes stay
near-radial, so curving the leaves adds no crossings; the crossing-critical
backbone (anchor/relay/exit + the control plane) keeps its spine. Each galaxy
also gets its own rotation and a polygon whose vertex count grows with its node
count (a pentagon for the smallest, capped so big galaxies stay round). Finally,
once the non-overlapping spacing is fixed, **every tile gets its own
deterministic "gutter" nudge** (the backbone singletons — anchor/relay/exit —
get a larger budget so they don't sit in a rigid line), applied greedily and
kept only as far as it adds **zero rendered (node-to-node) crossings** and keeps
clear space to every other tile. So the proven minimum and the spacing both hold,
and the amount of scatter adapts to each network. Within a galaxy, nodes fill the
disc via Vogel's sunflower with predetermined, evenly-spaced node↔node and
node↔border gaps.

Everything is deterministic (fixed-seed) and repeatable at any size; the overview
camera auto-fits the world bounds. Regression tests in `src/main.rs` assert zero
edge crossings on the demo plus stress topologies, the polygon-growth rule, and
the data-flow schedule (`cargo test`). Run the binary with `RUSTYNET_DEBUG_XINGS=1`
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

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
- **Drag**: orbit · **scroll**: zoom · **right-drag**: pan
- **Hover** a node for a tooltip; **click** it for an inspector panel
- **Legend** (right): click a role to show/hide it
- **Controls** (left): toggle labels, data-path animation, auto-rotate, live
  demo updates; reset camera

## Isolation / why it's a separate crate

This is its **own workspace** (note the empty `[workspace]` table in
`Cargo.toml`) and is excluded from the main Rustynet workspace
(`exclude = ["gui"]` in the root `Cargo.toml`). GUI stacks pull in large
transitive dependency trees with assorted licenses; keeping this crate isolated
means it never conflicts with the security-gated workspace's strict license
allowlist or `unsafe_code = "forbid"` policy. It builds and lints cleanly on its
own (`cargo build`, `cargo clippy --all-targets`, `cargo fmt -- --check`).

## Data contract & wiring to the real daemon

Input JSON matches `../node-map-prototype/data-contract.md`:

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

To make it live later, have `rustynetd` emit this JSON (a file, a local socket,
or a command) and replace `load_graph()` / the `simulate()` demo loop with a
real feed. All role/status/edge/colour/layout styling is isolated in the CONFIG
section at the top of `src/main.rs` for easy retheming.

## Relationship to the browser prototype

`../node-map-prototype/` is the original zero-build HTML/Three.js reference
(GPU bloom in a browser). **This** crate is the native Rust implementation of
the same idea and the same data contract. Use the browser one for quick visual
experiments; use this one as the basis for the shipped GUI.

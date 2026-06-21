# gui/ — Rustynet GUI prototypes

Visualisations and GUI experiments for Rustynet. These are intentionally
**isolated from the main Rust workspace** (`exclude = ["gui"]` in the root
`Cargo.toml`): GUI stacks pull in large dependency trees with assorted licenses
that would conflict with the security-gated workspace's strict license allowlist
and `unsafe_code = "forbid"` policy. Each subproject stands alone.

## Contents

| Folder | What | Stack |
|--------|------|-------|
| [`node-map-tool/`](node-map-tool/) | **Native desktop app** — 3D node map of a Rustynet (roles as glowing orbs, statuses as brightness, data paths as flowing lines). The basis for the shipped GUI. | Rust · egui/eframe |
| [`node-map-prototype/`](node-map-prototype/) | Zero-build **browser** reference of the same idea (GPU bloom). Quick visual experiments + the design prompt. | HTML · Three.js |

Both consume the **same JSON data contract**
([`node-map-prototype/data-contract.md`](node-map-prototype/data-contract.md)),
so either can be wired to a real `rustynetd` topology feed without changing the
backend.

## Quick start (native tool)

```sh
cd gui/node-map-tool
cargo run                          # demo data + simulated live updates
cargo run -- sample-topology.json  # load a topology file
```

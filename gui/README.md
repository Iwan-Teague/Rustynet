# gui/ — Rustynet GUI

The Rustynet desktop GUI work. This is intentionally **isolated from the main
Rust workspace** (`exclude = ["gui"]` in the root `Cargo.toml`): GUI stacks pull
in large dependency trees with assorted licenses that would conflict with the
security-gated workspace's strict license allowlist and `unsafe_code = "forbid"`
policy. It stands alone with its own workspace and `Cargo.lock`.

## Contents

| Folder | What | Stack |
|--------|------|-------|
| [`node-map-tool/`](node-map-tool/) | **Native desktop app** — a 3D node map of a Rustynet (roles as glowing orbs, statuses as brightness, data paths as flowing lines). | Rust · egui/eframe |

## Quick start

```sh
cd gui/node-map-tool
cargo run                          # demo data + simulated live updates
cargo run -- sample-topology.json  # load a topology file
```

## Visual design

The look is being refined with Claude. The full, copy-paste handoff brief lives
at [`node-map-tool/CLAUDE_DESIGN_BRIEF.md`](node-map-tool/CLAUDE_DESIGN_BRIEF.md):
paste it into Claude to get a redesign whose output drops straight back into
`node-map-tool/src/main.rs`.

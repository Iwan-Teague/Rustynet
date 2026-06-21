# Rustynet Node Map — visual prototype

A 3D, "balls of light in space" visualisation of a Rustynet network: every node
is a glowing orb coloured by its **role**, dimmed/pulsed by its **status**, with
glowing lines and travelling particles showing the **data paths** between nodes
(e.g. client → anchor → relay → exit).

This is a **design prototype / reference**, not yet part of the shipped GUI. It
is intentionally self-contained and backend-agnostic so it can be folded into
the real Rustynet GUI later without rework.

## Run it

No build step. Either:

- Open `index.html` directly in a modern browser, **or**
- Serve the folder (avoids any CDN/file-origin quirks):

  ```sh
  cd gui/node-map-prototype
  python3 -m http.server 8080
  # then visit http://localhost:8080
  ```

Three.js (`0.160.0`) loads from a CDN, so this needs network access on first
load. It ships with demo data and simulated live status changes so you can see
the look immediately.

> Note: this prototype lives outside the Rust workspace and is not wired into
> the cargo gates. It has no Rust code and no dependencies to audit.

### Controls
- Drag: orbit · Scroll: zoom · Right-drag: pan
- Hover a node for a tooltip; click it for an inspector panel
- Legend (top-right): click a role to show/hide it
- Toggles (bottom-left): labels, data-path animation, auto-rotate, live demo

## Files
- `index.html` — the whole prototype (config at the top, sectioned + commented).
- `data-contract.md` — the JSON graph shape + the `RustynetNodeMap` runtime API
  to wire it to the real daemon.
- `DESIGN_PROMPT.md` — a ready-to-paste prompt to regenerate/iterate the design
  in Claude, plus quick-tweak pointers.

## How to make it real later
1. Have `rustynetd` expose a topology feed (WebSocket/SSE, or a Tauri command)
   that emits the JSON graph in `data-contract.md`: a `snapshot` on connect,
   then `node_update` deltas.
2. Replace the `setGraph(demoGraph())` call and delete the simulated-updates
   interval at the bottom of `index.html`.
3. Theme by editing the `ROLES` / `STATUS` / `EDGE_KINDS` / `CFG` blocks.

Everything Rustynet-specific (roles, statuses, edge kinds, colours, layout
tunables) is isolated in the CONFIG block so visuals and data can evolve
independently.

# Design prompt — Rustynet node map

Paste the prompt below into Claude (claude.ai → "Artifacts" / any code-capable
chat) to regenerate or iterate on the visualisation as a single self-contained
artifact. It is written so the output drops straight into the Rustynet GUI and
matches the data contract in `data-contract.md`.

---

## Prompt

> Build a single self-contained HTML file (no build step, no npm) that renders a
> **3D node map of a mesh VPN network** called *Rustynet*. Load Three.js and its
> addons from a CDN via an ES-module `importmap`. The file must run by just
> opening it in a browser. Target a dark, "nodes floating in space" aesthetic.
>
> **Nodes** are glowing balls of light. Use bloom post-processing
> (`UnrealBloomPass` via `EffectComposer`) plus an additive radial-gradient glow
> sprite so each node reads as a soft orb. A node's **colour encodes its role**
> and its **status changes how it glows**.
>
> Drive everything from a CONFIG block near the top of the file so it is trivial
> to retheme:
> - `ROLES`: a map of role → `{ color, label, desc, size }`. Roles:
>   `client` (green), `admin` (cyan), `anchor` (yellow), `relay` (purple),
>   `exit` (orange), `blind_exit` (red), `nas` (blue), `llm` (violet). Unknown
>   roles fall back to grey. Colours are placeholders; one-line changes.
> - `STATUS`: a map of status → visual behaviour. `online` = bright + gentle
>   pulse + full colour; `connecting` = flickering + slightly desaturated;
>   `offline` = dim + mostly grey; `powered_off` = very faint. Status must only
>   change appearance, never remove the node.
> - `EDGE_KINDS`: `data_path` (bright line with travelling flow particles),
>   `control` (thin steady line), `potential` (very faint line).
>
> **Edges** are glowing lines between nodes representing the path data travels
> (e.g. client → anchor → relay → exit). On `data_path` edges, animate small
> glowing particles flowing from source to destination — but only when both
> endpoints are `online` and the edge is active, so the animation reflects real
> reachability. Blend each line's colour from its two endpoint colours.
>
> **Layout**: position nodes with a light 3D force-directed simulation
> (spring attraction along edges + inverse-square repulsion + mild gravity to
> centre), settling after new data, so the operator never hand-places nodes.
> Allow an optional explicit `position` per node to pin it.
>
> **Camera / interaction**: `OrbitControls` — drag to orbit, scroll to zoom,
> right-drag to pan. Raycast hover shows a tooltip (name · role · status);
> click opens an inspector panel with address, OS, last seen, and connection
> count. Add a subtle starfield background and exponential fog for depth.
>
> **HUD overlays** (HTML/CSS, glassy translucent panels):
> - top-left: title + live stats (total / online / offline / data paths)
> - top-right: a legend generated from the roles actually present, where
>   clicking a role toggles its visibility; plus a status key
> - bottom-left: toggles for labels, data-path animation, auto-rotate, and a
>   "reset camera" button
> - bottom-right: the node inspector (hidden until a node is clicked)
>
> **Data contract** — decouple the view from any data source. Consume one JSON
> graph and expose a tiny API on `window.RustynetNodeMap`:
> ```js
> RustynetNodeMap.setGraph({ nodes:[{id,label,role,status,position?,meta?}],
>                            edges:[{from,to,kind?,active?}] });
> RustynetNodeMap.updateNode(id, { status?, role?, meta? }); // patch in place; role change recolours
> ```
> Include realistic demo data (admin, two anchors, a home relay, an exit, a
> blind_exit, a nas, an llm, and several clients on linux/macOS/Windows/iOS with
> a mix of statuses) showing the example path client → anchor → relay → exit.
> Add a small interval that randomly flips node statuses so the demo feels live,
> clearly marked as removable.
>
> Keep the code clean, commented, and organised into sections: CONFIG, renderer/
> scene, graph state, public data API, visual refresh, force layout, UI, render
> loop, demo data. No external assets beyond the Three.js CDN.

---

## Iterating

Things you'll most likely tweak after first generation:

- **Colours / roles** — edit the `ROLES` map only.
- **Status feel** — edit `STATUS` (pulse amplitude, glow, desaturation).
- **Glow intensity** — `CFG.bloom` (`strength`, `radius`, `threshold`).
- **Layout spread** — `CFG.linkDistance`, `CFG.charge`, `CFG.gravity`.
- **New edge meaning** — add to `EDGE_KINDS`.

When you want a genuinely different look (2D, geo-map, hierarchical tree), keep
the same `RustynetNodeMap.setGraph/updateNode` contract so the backend wiring
never changes.

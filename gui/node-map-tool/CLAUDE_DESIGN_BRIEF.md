# Claude Design Brief — Rustynet Node Map (visual redesign)

> **How to use this file:** copy this *entire* document into Claude (claude.ai)
> and send it. It contains everything Claude needs to redesign or improve the
> visuals of my node map, and it tells Claude to return its work in a format
> that drops straight back into my Rust app. Then follow **§8 "What you get
> back"** to paste the results into `src/main.rs`.
>
> You usually don't need to attach anything else. If you want, you can also
> paste `src/main.rs` for full context, but this brief is self-contained.

---

## 1. The ask (TL;DR)

I have a working native desktop app that draws a live map of all nodes on a
**Rustynet** network (a mesh VPN). Each node is a glowing "ball of light"
floating in a 3D space; its **colour = its role**, its **brightness/animation =
its status**, and glowing **lines = the data paths** between nodes
(e.g. `client → anchor → relay → exit`).

**It works, but I want it to look genuinely premium** — like a high-end network
operations console / a "fiber-optic constellation." I want you to **redesign the
visual language** (palette, glow, depth, lines, background, HUD styling,
typography) and hand me back values I can paste into my code.

This is a **visual** task. Do **not** change the data model, the roles, or the
behaviour — only how it *looks*.

---

## 2. HARD CONSTRAINT — read this before designing anything

The app is **native Rust using egui's 2D painter**. I fake 3D by projecting
points to 2D myself, and I fake glow by stacking translucent shapes. The painter
can **only** draw:

- **filled circles** (centre, radius, RGBA)
- **circle strokes** (centre, radius, width, RGBA)
- **line segments** (p1, p2, width, RGBA)
- **filled rectangles / rounded rectangles** (RGBA)
- **text** (position, font size, RGBA)

That's it. There is **NO**:

- ❌ CSS, `box-shadow`, `filter: blur()`, SVG filters
- ❌ GPU shaders, real bloom, real blur, real gaussian glow
- ❌ native gradients (linear/radial) — a gradient must be **faked** as a stack
  of discrete solid-colour shapes with stepped alpha
- ❌ raster images / textures for the look

**Therefore every effect you design must be expressible as layered
circles/lines/rects/text in solid RGBA.** This is the whole reason the design
will port cleanly. When you design the glow, the depth fade, the background,
etc., describe them as **"draw N shapes with these radii and these alpha
values."** Give me the **exact numbers**.

### 2.1 The exact painter API (so your numbers map 1:1)

These are the only drawing calls I have. Design against them directly:

```rust
// colour: alpha is STRAIGHT (not premultiplied) via from_rgba_unmultiplied.
let c = Color32::from_rgb(r, g, b);                 // opaque
let c = Color32::from_rgba_unmultiplied(r, g, b, a); // a = 0..=255 alpha

painter.circle_filled(center: Pos2, radius: f32, fill: Color32);
painter.circle_stroke(center: Pos2, radius: f32, Stroke::new(width: f32, color: Color32));
painter.line_segment([p1: Pos2, p2: Pos2], Stroke::new(width: f32, color: Color32));
painter.rect_filled(rect: Rect, rounding: f32, fill: Color32);
painter.rect_stroke(rect: Rect, rounding: f32, Stroke::new(width, color));
painter.text(pos: Pos2, anchor: Align2, text, FontId::proportional(sz) | FontId::monospace(sz), color);
```

egui facts that affect your design:
- **Draw order = call order.** Whatever is painted later sits on top. So
  background → edges → glow halos → node cores → labels → HUD.
- **Anti-aliasing is on**, so thin lines and small circles look smooth.
- **Coordinates are pixels, y-down**, origin top-left.
- **Blending is normal alpha over** (NOT additive). So a glow built from
  stacked low-alpha circles *lightens* toward the centre on a dark background,
  which is exactly the effect we want — design for normal alpha.
- **Fonts:** default proportional + monospace only (no custom font files).
  Sizes are in points (~px). Labels are currently `FontId::monospace(11.0)`.
- **`perspective_scale`** (used to size nodes) ranges roughly **0.3 (far) →
  3.0 (near)** in normal use; node core radius is then clamped to 2–26 px. Keep
  your radius formulas sane across that range.

### 2.2 So that I can SEE your design before I port it
Build me a **single self-contained `index.html`** mockup that renders your design
on an HTML `<canvas>` — but **only using the canvas equivalents of the painter
primitives above**: `arc()`+`fill()` (circles), `fillRect`/`roundRect`,
`moveTo/lineTo`+`stroke` (lines), `fillText`, and solid `rgba()` colours.

**In the canvas mockup you must NOT use** `shadowBlur`, `createRadialGradient`,
`createLinearGradient`, `filter`, or `globalCompositeOperation` for the node
glow — because none of those exist in egui. Fake the glow by drawing **several
concentric `arc()` fills with decreasing alpha**, exactly as my app does. If the
mockup looks good under that restriction, it will look identical in my app.

> Do **not** use `globalCompositeOperation = 'lighter'` (additive). egui blends
> with normal alpha, so additive in the mockup would lie to me. Plain layered
> alpha on the dark background is the honest, 1:1 preview.

---

## 3. The domain model (so colours and states mean something)

### Roles (node types) — colour encodes the role
There are two "families": **infrastructure** (always-on, fewer, important) and
**endpoints/services**. A good palette should make that hierarchy feel intuitive.

| role         | family         | meaning                     |
|--------------|----------------|-----------------------------|
| `client`     | endpoint       | a user's device             |
| `admin`      | infrastructure | control / operator node     |
| `anchor`     | infrastructure | coordination anchor         |
| `relay`      | infrastructure | zero-ingress relay          |
| `exit`       | infrastructure | internet egress             |
| `blind_exit` | infrastructure | egress with no plaintext    |
| `nas`        | service        | storage service             |
| `llm`        | service        | inference service           |
| (unknown)    | —              | fallback for any other role |

Requirements for the palette:
- All role colours must be **clearly distinguishable** from each other on a
  near-black background, including for common colour-blindness (see §10).
- `exit` vs `blind_exit` should feel related (both egress) but distinct (blind =
  more "sealed/secure"). Today they're orange vs red.
- Infra roles can feel cooler/more authoritative; clients warmer/lighter; this
  is a suggestion, not a rule — surprise me if you have something better.
- Each role also has a relative **`size`** multiplier (infra bigger than
  clients). Keep that hierarchy; tune the numbers if it helps.

### Statuses — brightness/animation encodes the status
| status        | meaning                          | current feel              |
|---------------|----------------------------------|---------------------------|
| `online`      | up and reachable                 | bright, gently pulsing    |
| `connecting`  | handshaking / coming up          | flickering, slightly grey |
| `offline`     | known but unreachable            | dim, mostly grey          |
| `powered_off` | known but powered down           | very faint                |

A node never disappears when it goes down — it stays on the map, dimmed. Status
must be **legible at a glance** without reading the label. The status knobs I
have are: `brightness` (core/overall), `glow` (halo opacity), `pulse` (sine
amplitude on brightness), `desat` (lerp toward grey), `flicker` (random
brightness jitter, used for `connecting`).

### Edge kinds — lines encode the connection type
| kind        | meaning                       | current feel                       |
|-------------|-------------------------------|------------------------------------|
| `data_path` | active traffic path           | bright line + travelling particles |
| `control`   | signalling / control link     | thin steady line                   |
| `potential` | known but idle link           | very faint line                    |

Flow particles only travel when **both endpoints are `online`** (and the edge is
active). A down edge is dimmed to 25% opacity.

### Data contract (the JSON the app consumes; don't change it)
```jsonc
{
  "nodes": [ { "id", "label?", "role", "status", "position?", "meta?{address,os,lastSeen}" } ],
  "edges": [ { "from", "to", "kind?", "active?" } ]
}
```

---

## 4. Where this lives on screen (layout to design)

A single **1200×800** window, dark background:
- **Centre:** the 3D node scene (the main event).
- **Left panel (egui side panel, ~210 px):** title "Rustynet", a subtitle,
  live stats (Nodes / Online / Offline / Data paths), and view toggles
  (labels, animate paths, auto-rotate, live demo) + a "Reset camera" button.
  Style this panel too.
- **Right panel (~200 px):** a **legend** (role colour swatches + name + short
  description, click to show/hide a role) and a **status key**.
- **Bottom-right floating window:** an **inspector** shown when a node is
  clicked (id, status, role, address, OS, last seen, connection count).
- **On hover:** a small tooltip near the cursor (a role dot + "name · role ·
  status").

You can restyle these panels (background fill, border, spacing, the swatch
shapes, the stat-row layout, fonts). They're drawn with egui widgets + painter,
so the same primitive rules apply. egui exposes a `Visuals` theme — if you want
panel/border/selection colours changed, give them to me as a short list (e.g.
`window_fill`, `panel_fill`, `extreme_bg_color`, `widgets stroke`), and I'll set
them in `Visuals`.

---

## 5. The CURRENT design (your starting point — improve on this)

This is what the app does today. Treat it as a baseline to beat, not a
constraint.

**Background:** solid `rgb(5, 7, 13)` + 220 random faint star dots
(`rgb(159,179,217)` at alpha 0.15–0.5, radius 0.3–1.4 px).

**Node glow recipe (per node), as actually coded:**
```
core_r   = clamp(role.size * 1.7 * perspective_scale * 0.1, 2.0, 26.0)   // px
glow_a   = status.glow * max(brightness, 0.08)
for layer in 0..6:
    radius = core_r * (1.4 + layer * 0.95)
    alpha  = glow_a * (0.16 / (layer * 0.5 + 1.0))      // halo, low alpha, fades out
    draw filled circle(center, radius, role_colour @ alpha)
hot_colour = lerp(role_colour, white, 0.55 * brightness)
draw filled circle(center, core_r, hot_colour @ (0.65 + 0.35*brightness))   // bright core
```
**Pulse:** `brightness += sin(time*2.5 + node.x) * status.pulse`.
**Desaturation when down:** `colour = lerp(role_colour, grey(90,96,114), status.desat)`.

**Edges:** one line segment, width = `kind.width`, colour =
`lerp(roleA, roleB, 0.5)`, alpha = `kind.base_opacity * (live ? 1.0 : 0.25)`.

**Flow particles (data_path only, when live):** 3 particles per edge at
`t = (time*0.18 + k/3) mod 1` along the 3D segment; each draws a halo circle
(radius `r*1.8`, alpha 0.12) + a near-white core (radius `r`, alpha 0.95).

**Current CONFIG values (Rust — these are exactly what you'll be replacing):**
```rust
// role_style(role) -> { color, label, desc, size }
client     = rgb(61,220,132)  size 1.00
admin      = rgb(95,208,255)  size 1.15
anchor     = rgb(255,210,63)  size 1.20
relay      = rgb(180,107,255) size 1.20
exit       = rgb(255,140,59)  size 1.25
blind_exit = rgb(255,77,77)   size 1.25
nas        = rgb(77,184,255)  size 1.10
llm        = rgb(157,123,255) size 1.10
unknown    = rgb(138,151,173) size 1.00

// status_style(status) -> { brightness, glow, pulse, desat, flicker }
online      = { 1.00, 1.00, 0.18, 0.00, 0.0 }
connecting  = { 0.75, 0.70, 0.00, 0.30, 0.6 }
offline     = { 0.28, 0.22, 0.00, 0.85, 0.0 }
powered_off = { 0.12, 0.06, 0.00, 1.00, 0.0 }

// edge_kind_style(kind) -> { width, flow, base_opacity }
data_path = { 1.6, true,  0.55 }
control   = { 1.0, false, 0.28 }
potential = { 0.8, false, 0.14 }

// layout / look constants
LINK_DISTANCE = 14.0   CHARGE = -260.0   GRAVITY = 0.015   DAMPING = 0.86
GREY = rgb(90,96,114)  BG = rgb(5,7,13)
```

---

## 6. What I want you to improve

Aim for **"premium network ops console / fiber-optic constellation in deep
space."** Sleek, dark, calm, legible, a little bit alive. Reference vibe:
Tailscale's admin map, a clean SRE/NOC dashboard, sci-fi starmaps — but
restrained, not a gamer-RGB explosion. Specifically:

1. **A better role palette** — more harmonious and more distinguishable on
   near-black, with the infra/endpoint/service hierarchy readable. Give hex/RGB.
2. **A more convincing "ball of light"** using only layered alpha circles —
   tune the layer count, radius multipliers, and alpha falloff so the glow has a
   soft, luminous core-to-halo gradient. Consider a subtle 2-tone (warm/white
   core → role-coloured halo). Make the falloff smooth, not banded.
3. **Clearer status encoding** — make online/connecting/offline/powered_off
   instantly distinct (brightness, halo size, pulse speed/curve, desaturation,
   flicker). Consider a slow "breathing" pulse for online vs a faster nervous
   one for connecting.
4. **Nicer data paths** — line styling, the colour blend, and especially the
   **flow particle** look (size, count, spacing, and a faked trailing fade — a
   few stamped circles of decreasing alpha behind each particle).
5. **Depth cues** without GPU — fade/shrink/desaturate distant nodes, maybe a
   faint depth "fog" faked by tinting toward the background colour by distance.
6. **Background** — keep it dark; improve the starfield and/or add a very subtle
   faked radial vignette or grid (layered shapes only). Maybe 2–3 star
   brightness tiers for parallax feel.
7. **HUD styling** — panel fill/border colours, stat-row layout, the legend
   swatch shape, the status-key, the inspector, the hover tooltip, and label
   typography (size, colour, when to show / fade distant labels).
8. **Selection & hover affordances** — how a selected/hovered node reads (ring,
   brighter halo, dim-the-rest, highlight its edges, etc.).

**Avoid:** neon overload, looking like a toy, low-contrast text, anything that
relies on blur/bloom/gradients/shadows that I can't reproduce.

**Performance note:** glow is `layers × nodes` circle draws every frame, plus
`particles × edges`. Keep glow layers ≲ 8 and particle trail stamps ≲ 5 so a
100-node graph stays smooth. If you want a richer halo, prefer slightly larger
radii over many more layers.

---

## 7. Deliverables (return ALL of these)

**(A) An interactive `index.html` canvas mockup** — single self-contained file,
no libraries, obeying the canvas restrictions in §2. Render the **demo dataset
in §9** (covers every role + every status + all three edge kinds, including the
`client → anchor → relay → exit` path) with the flow particles animating, so I
can see the design in motion. Include the left/right HUD panels and a sample
inspector + tooltip so I can see the whole composition. (Camera controls
optional — a slow auto-rotate or a static 3/4 view is fine.)

**(B) A paste-ready Rust block** that fills in the exact functions/structs below
with your new values. Match these signatures **exactly** so I can paste it over
the existing `role_style` / `status_style` / `edge_kind_style` and the constants
in `src/main.rs`:

```rust
struct RoleStyle { color: Color32, label: &'static str, desc: &'static str, size: f32 }
fn role_style(role: &str) -> RoleStyle { /* one arm per role + unknown fallback */ }

struct StatusStyle { brightness: f32, glow: f32, pulse: f32, desat: f32, flicker: f32 }
fn status_style(status: &str) -> StatusStyle { /* online/connecting/offline/powered_off + fallback */ }

struct EdgeKindStyle { width: f32, flow: bool, base_opacity: f32 }
fn edge_kind_style(kind: &str) -> EdgeKindStyle { /* data_path/control/potential + fallback */ }

const LINK_DISTANCE: f32 = ..; const CHARGE: f32 = ..; const GRAVITY: f32 = ..; const DAMPING: f32 = ..;
const GREY: Color32 = ..; const BG: Color32 = ..;
```
Use `Color32::from_rgb(r, g, b)`.

**(C) If you changed the glow/edge/particle *recipe*** (layer count, radius
multipliers, alpha falloff, particle math, depth-fade formula, background), give
me those as a clearly labelled list of **named constants + the drawing formula
in pseudocode**, so I can wire them into the render loop. Example format:
```
GLOW_LAYERS = 7
GLOW_RADIUS_STEP = 0.8     // radius = core_r * (1.3 + layer * GLOW_RADIUS_STEP)
GLOW_ALPHA_FALLOFF = ...   // alpha = glow_a * (BASE / (layer + 1))
DEPTH_FADE_START = ...     // tint toward BG beyond this depth
... etc, with the formula for each.
```

**(D) A short rationale** (a few sentences): the palette logic and the key
visual moves, so I understand what to tweak later.

**(E) Optional but welcome:** a compact **design-tokens table** (every colour as
hex + RGB, plus the glow/edge/status numbers) so I have a single reference.

---

## 8. What you get back / how I port it (for me, not Claude)

1. Open Claude's `index.html` to eyeball the look; iterate with Claude until I
   like it ("make exit more amber", "calmer pulse", "tighter glow", etc.).
2. Paste deliverable **(B)** over the matching functions/constants in
   `src/main.rs` (the CONFIG section at the top).
3. If there's a **(C)**, update the render loop's glow/edge/particle/background
   code with the new constants + formulas (search `core_r`, `glow_a`,
   `for layer in 0..6`, the flow-particle block, `draw_starfield`).
4. `cargo run` and compare against the mockup. Tweak numbers to taste.

---

## 9. Demo dataset (use this in the mockup so it matches my app)

13 nodes covering every role and status, with all three edge kinds and the
`client → anchor → relay → exit` example path:

```jsonc
nodes:
  admin-01    role=admin       status=online      os=linux
  anchor-eu   role=anchor      status=online      os=linux
  anchor-us   role=anchor      status=online      os=linux
  relay-home  role=relay       status=online      os=linux
  exit-nl     role=exit        status=online      os=linux
  exit-blind  role=blind_exit  status=online      os=linux
  nas-vault   role=nas         status=online      os=linux
  llm-box     role=llm         status=connecting  os=linux
  laptop-mac  role=client      status=online      os=macos
  pc-win      role=client      status=online      os=windows
  phone       role=client      status=connecting  os=ios
  pi-sensor   role=client      status=offline     os=linux
  old-server  role=client      status=powered_off os=linux

edges (kind):
  laptop-mac → anchor-eu   data_path     # the example path, part 1
  anchor-eu  → relay-home  data_path     # part 2
  relay-home → exit-nl     data_path     # part 3
  pc-win     → anchor-us   data_path
  anchor-us  → exit-blind  data_path
  phone      → anchor-eu   data_path
  laptop-mac → nas-vault   data_path
  pc-win     → llm-box     data_path
  admin-01   → anchor-eu   control
  admin-01   → anchor-us   control
  admin-01   → relay-home  control
  anchor-eu  → anchor-us   control
  pi-sensor  → anchor-eu   potential
```

---

## 10. Accessibility & legibility

- Target **colour-blind distinguishability**: don't rely on red-vs-green alone
  to separate two important roles. `client` (currently green) and `exit`
  (orange/red) are the riskiest pair — make them differ in brightness/shape-of-
  glow too, not just hue.
- Body/label text should stay **WCAG-ish readable** on the dark background
  (light grey ~`rgb(215,224,240)` works today).
- Don't encode meaning in motion alone — a paused frame should still read.
- Keep `powered_off` faint but **not invisible** (it must still be findable).

---

## 11. Acceptance criteria

- Looks premium and intentional on a near-black background.
- Every role is distinguishable; every status is legible at a glance.
- The entire look is reproducible with **layered solid-RGBA circles/lines/
  rects/text only** (no blur/bloom/gradients/shadows).
- Deliverable (B) compiles against the signatures in §7 with no other changes.
- Scales visually to ~100+ nodes without becoming noise.

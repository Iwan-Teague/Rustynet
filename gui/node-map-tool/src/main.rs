//! Rustynet Node Map — native Rust 3D network visualisation (egui/eframe).
//!
//! Renders a Rustynet network as glowing "balls of light" in a 3D space: a
//! node's colour encodes its role, its status drives brightness/pulse/fade, and
//! glowing lines with travelling particles show the data path between connected
//! nodes (e.g. client -> anchor -> relay -> exit).
//!
//! The 3D scene is software-projected and drawn with egui's painter, so the
//! whole thing is pure Rust with a light dependency tree and no GPU 3D engine.
//!
//! Usage:
//!   rustynet-node-map [topology.json]
//! With no argument it shows built-in demo data + simulated live updates.
//! The JSON shape matches DATA_CONTRACT.md.
//!
//! Everything Rustynet-domain-specific (roles, statuses, edge kinds, colours,
//! layout tunables) lives in the CONFIG section so it is easy to retheme and to
//! keep in sync with the daemon.

use std::collections::{BTreeMap, HashMap, HashSet};

use eframe::egui;
use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, Vec2};
use serde::Deserialize;

// ===========================================================================
// CONFIG — Rustynet-domain styling. Change freely.
// ===========================================================================

/// Visual identity for a node role.
struct RoleStyle {
    color: Color32,
    label: &'static str,
    desc: &'static str,
    size_mult: f32,
}

/// Role registry. Keys must match the `role` field in the data feed. Mirrors the
/// Rustynet role + capability set (client, admin, anchor, exit, blind_exit,
/// relay, + service roles nas/llm). Colours/sizes from the visual design pass.
fn role_style(role: &str) -> RoleStyle {
    match role {
        "client" => RoleStyle {
            color: Color32::from_rgb(120, 224, 168), // mint
            label: "Client",
            desc: "Endpoint device",
            size_mult: 0.85,
        },
        "admin" => RoleStyle {
            color: Color32::from_rgb(149, 134, 244), // violet
            label: "Admin",
            desc: "Control / operator",
            size_mult: 1.25,
        },
        "anchor" => RoleStyle {
            color: Color32::from_rgb(82, 150, 240), // azure
            label: "Anchor",
            desc: "Coordination anchor",
            size_mult: 1.40,
        },
        "relay" => RoleStyle {
            color: Color32::from_rgb(64, 198, 210), // cyan
            label: "Relay",
            desc: "Zero-ingress relay",
            size_mult: 1.20,
        },
        "exit" => RoleStyle {
            color: Color32::from_rgb(242, 162, 74), // amber
            label: "Exit",
            desc: "Internet egress",
            size_mult: 1.30,
        },
        "blind_exit" => RoleStyle {
            color: Color32::from_rgb(226, 92, 104), // crimson
            label: "Blind exit",
            desc: "Egress, no plaintext",
            size_mult: 1.30,
        },
        "nas" => RoleStyle {
            color: Color32::from_rgb(198, 182, 132), // sand
            label: "NAS",
            desc: "Storage service",
            size_mult: 1.05,
        },
        "llm" => RoleStyle {
            color: Color32::from_rgb(222, 116, 198), // magenta
            label: "LLM",
            desc: "Inference service",
            size_mult: 1.10,
        },
        _ => RoleStyle {
            color: Color32::from_rgb(150, 162, 184), // slate
            label: "Unknown",
            desc: "Unrecognised role",
            size_mult: 0.90,
        },
    }
}

/// Roles offered in the legend, in display order. The legend only shows the ones
/// actually present in the current graph.
const ROLE_ORDER: &[&str] = &[
    "client",
    "admin",
    "anchor",
    "relay",
    "exit",
    "blind_exit",
    "nas",
    "llm",
];

/// How a status makes the node glow behave. (Body colour comes from
/// `status_body_color`; the smooth lit ramp comes from `lit_target`.)
struct StatusStyle {
    glow: f32,    // halo opacity
    pulse: f32,   // gentle glow breathing amplitude
    desat: f32,   // legend status-key swatch only
    flicker: f32, // nervous glow jitter (connecting)
}

fn status_style(status: &str) -> StatusStyle {
    match status {
        "online" => StatusStyle {
            glow: 1.00,
            pulse: 0.10,
            desat: 0.00,
            flicker: 0.00,
        },
        "connecting" => StatusStyle {
            glow: 0.62,
            pulse: 0.05,
            desat: 0.30,
            flicker: 0.14,
        },
        "powered_off" => StatusStyle {
            glow: 0.15,
            pulse: 0.00,
            desat: 0.90,
            flicker: 0.00,
        },
        // "offline" and anything unknown -> dim, grey (fail-visible).
        _ => StatusStyle {
            glow: 0.30,
            pulse: 0.00,
            desat: 0.78,
            flicker: 0.00,
        },
    }
}

/// How a connection line is drawn. Flow particles are drawn for `data_path`
/// edges only (see `edge_has_flow`).
struct EdgeKindStyle {
    width: f32,
    base_opacity: f32,
}

fn edge_kind_style(kind: &str) -> EdgeKindStyle {
    match kind {
        "data_path" => EdgeKindStyle {
            width: 2.6,
            base_opacity: 0.55,
        },
        "control" => EdgeKindStyle {
            width: 1.6,
            base_opacity: 0.30,
        },
        "potential" => EdgeKindStyle {
            width: 1.1,
            base_opacity: 0.12,
        },
        _ => EdgeKindStyle {
            width: 1.4,
            base_opacity: 0.20,
        },
    }
}

/// Only active traffic paths carry travelling flow particles.
fn edge_has_flow(kind: &str) -> bool {
    kind == "data_path"
}

/// Galaxy layout tunables. Placement is deterministic (no force sim). Backbone
/// nodes (anchor/relay/exit/admin) are spread across a roomy 2D grid; leaf nodes
/// (client/nas/llm) form per-(hub, role) "galaxies" that orbit their hub. The
/// map is intentionally larger than the viewport so it can be panned around.
const NODE_GAP: f32 = 26.0; // packing spacing of nodes within a galaxy (roomy)
const SINGLETON_RADIUS: f32 = 44.0; // tile radius for a lone backbone node
const CLUSTER_GAP: f32 = 30.0; // gap between packed tiles (keep them close)
const GALAXY_PAD: f32 = 30.0; // screen px padding between nodes and the galaxy border

// Camera zoom levels: overview vs drilled-into-a-galaxy.
const OVERVIEW_DISTANCE: f32 = 820.0;
const GALAXY_VIEW_DISTANCE: f32 = 230.0;

/// Leaf roles orbit the node their data travels to; backbone roles are the skeleton.
fn is_leaf_role(role: &str) -> bool {
    matches!(role, "client" | "nas" | "llm")
}

/// Ordering rank so similar roles cluster together on the grid (operator →
/// sources → anchor → relay → exit), giving each type its own screen region.
fn galaxy_col(role: &str) -> i32 {
    match role {
        "admin" => 0,
        "client" | "nas" | "llm" => 1,
        "anchor" => 2,
        "relay" => 3,
        "exit" | "blind_exit" => 4,
        _ => 1,
    }
}

/// Small stable ordinal per role, used to build a (hub, role) galaxy key.
fn role_ord(role: &str) -> u64 {
    match role {
        "client" => 1,
        "nas" => 2,
        "llm" => 3,
        _ => 4,
    }
}

// ----------------------- THEME / GLOBAL CONSTANTS ----------------------
const BG: Color32 = Color32::from_rgb(82, 87, 97); // window background (grey)
const NEBULA: Color32 = Color32::from_rgb(104, 110, 124); // faked center-lift tint
const WARM_WHITE: Color32 = Color32::from_rgb(255, 248, 236); // glow highlight
const FIBER: Color32 = Color32::from_rgb(176, 206, 236); // edge/particle tint
const GREY_DOWN: Color32 = Color32::from_rgb(120, 126, 142); // desaturation target
const TEXT_HI: Color32 = Color32::from_rgb(232, 238, 248);

// ------------------------------ GLOW -----------------------------------
// A light, smooth glow built from many thin layers whose radius shrinks AND
// whose alpha fades from the core outward, so they blend into a soft aura
// rather than reading as discrete rings.
const GLOW_LAYERS: usize = 14;
const GLOW_OUTER: f32 = 1.9; // outermost halo radius (x core_r)
const GLOW_INNER: f32 = 1.0; // innermost halo radius (meets the core)
const GLOW_PEAK: f32 = 0.06; // strongest per-layer alpha (light glow)
const GLOW_FALLOFF: f32 = 2.6; // higher = faster fade outward (fainter halo)
const GLOW_WARM: f32 = 0.12; // how much the inner glow warms toward WARM_WHITE
const CORE_R_MULT: f32 = 0.9; // node ball radius (x core_r)

// ------------------------------ DEPTH ----------------------------------
// DEPTH_FOG_MAX = how far edges fade toward BG with distance. REF_DISTANCE maps
// camera-space depth onto the design's perspective_scale band (~0.5 far .. 2.6
// near), tuned so the default view produces pleasing node sizes and depth.
// (Node bodies are NOT depth-tinted, so same-role nodes keep a consistent shade;
// depth is conveyed by size.)
const DEPTH_FOG_MAX: f32 = 0.45;
const REF_DISTANCE: f32 = 760.0;

// ------------------------------ PULSE ----------------------------------
// Pulses propagate as a synchronized wave toward the exit: a node emits its
// downstream blobs only after every upstream blob has melted in, then waits
// PULSE_PAUSE before firing. One blob per edge per cycle.
const PULSE_TRAVEL: f32 = 2.5; // seconds for a blob to cross one hop
const PULSE_PAUSE: f32 = 5.0; // seconds a node waits after receiving all, before emitting
const PULSE_HALO_MULT: f32 = 2.2;
const PULSE_HALO_A: f32 = 0.12;
const PULSE_CORE_A: f32 = 0.95;

/// Position along the path to the exit: leaves (0) -> anchor (1) -> relay (2)
/// -> exit (3). Pulses flow from low rank to high rank (toward the exit).
fn role_flow_rank(role: &str) -> i32 {
    match role {
        "client" | "nas" | "llm" => 0,
        "anchor" => 1,
        "relay" => 2,
        "exit" | "blind_exit" => 3,
        _ => 1, // admin/unknown (control edges don't pulse anyway)
    }
}

/// Normalised perspective scale (~0.3 far .. 3.2 near) from camera-space depth.
fn pscale_of(depth: f32) -> f32 {
    (REF_DISTANCE / depth).clamp(0.3, 3.2)
}

/// Node core radius in pixels for a given role size + camera-space depth.
fn core_r_of(size_mult: f32, depth: f32) -> f32 {
    (7.0 * size_mult * pscale_of(depth)).clamp(2.0, 26.0)
}

/// Depth blend factor 0 (far) .. 1 (near), used for fog/fade/label sizing.
fn depth_t_of(depth: f32) -> f32 {
    ((pscale_of(depth) - 0.5) / (2.6 - 0.5)).clamp(0.0, 1.0)
}

// ===========================================================================
// 3D MATH
// ===========================================================================

#[derive(Clone, Copy, Default)]
struct V3 {
    x: f32,
    y: f32,
    z: f32,
}

impl V3 {
    fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }
    fn add(self, o: V3) -> V3 {
        V3::new(self.x + o.x, self.y + o.y, self.z + o.z)
    }
    fn sub(self, o: V3) -> V3 {
        V3::new(self.x - o.x, self.y - o.y, self.z - o.z)
    }
    fn scale(self, s: f32) -> V3 {
        V3::new(self.x * s, self.y * s, self.z * s)
    }
    fn dot(self, o: V3) -> f32 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }
    fn cross(self, o: V3) -> V3 {
        V3::new(
            self.y * o.z - self.z * o.y,
            self.z * o.x - self.x * o.z,
            self.x * o.y - self.y * o.x,
        )
    }
    fn len(self) -> f32 {
        self.dot(self).sqrt()
    }
    fn norm(self) -> V3 {
        let l = self.len();
        if l > 1e-6 {
            self.scale(1.0 / l)
        } else {
            V3::new(0.0, 0.0, 1.0)
        }
    }
}

/// Fixed angled top-down camera. Rotation is disabled (the view stays a
/// controlled isometric-style map); only pan + zoom are allowed.
struct Camera {
    target: V3,
    yaw: f32,
    pitch: f32,
    distance: f32,
    fov: f32,
}

impl Default for Camera {
    fn default() -> Self {
        Self {
            target: V3::default(),
            yaw: 0.0,
            pitch: 0.62, // oblique top-down angle (clearly tilted, not straight down)
            distance: OVERVIEW_DISTANCE,
            fov: 50_f32.to_radians(),
        }
    }
}

/// A point successfully projected to the screen.
struct Projected {
    screen: Pos2,
    /// Depth in front of the camera (smaller = nearer). Drives perspective
    /// sizing + depth fog via `pscale_of` / `core_r_of` / `depth_t_of`.
    depth: f32,
}

impl Camera {
    fn position(&self) -> V3 {
        let (cp, sp) = (self.pitch.cos(), self.pitch.sin());
        let (cy, sy) = (self.yaw.cos(), self.yaw.sin());
        self.target
            .add(V3::new(cp * sy, sp, cp * cy).scale(self.distance))
    }

    /// Project a world point. Returns None if behind the camera.
    fn project(&self, p: V3, rect: Rect) -> Option<Projected> {
        let cam = self.position();
        let forward = self.target.sub(cam).norm();
        let world_up = V3::new(0.0, 1.0, 0.0);
        let right = forward.cross(world_up).norm();
        let up = right.cross(forward);

        let rel = p.sub(cam);
        let z = rel.dot(forward);
        if z <= 0.1 {
            return None;
        }
        let x = rel.dot(right);
        let y = rel.dot(up);

        let focal = (rect.height() * 0.5) / (self.fov * 0.5).tan();
        let sx = rect.center().x + focal * x / z;
        let sy = rect.center().y - focal * y / z;
        Some(Projected {
            screen: Pos2::new(sx, sy),
            depth: z,
        })
    }
}

// ===========================================================================
// GRAPH MODEL
// ===========================================================================

struct Node {
    id: String,
    label: String,
    role: String,
    status: String,
    meta: BTreeMap<String, String>,
    pos: V3,
    /// True when the position came from the data feed (don't auto-place it).
    pinned: bool,
    /// Smoothly-ramped "lit" factor (0..1) that eases toward the status target
    /// so a node fading up on connect/online doesn't pop.
    lit: f32,
    /// Galaxy id (hub, role) for leaf nodes that orbit a hub; None for backbone
    /// / unattached nodes (no border drawn).
    galaxy: Option<u64>,
}

/// Steady-state lit target per status (drives the smooth ramp).
fn lit_target(status: &str) -> f32 {
    match status {
        "online" => 1.0,
        "connecting" => 0.55,
        "powered_off" => 0.10,
        _ => 0.18, // offline + unknown
    }
}

/// Bold, consistent node body colour by status: full role colour when online,
/// grey when offline/unknown, partly desaturated while connecting, dark grey
/// when powered off. Deliberately independent of depth so same-role online
/// nodes always read as the same shade.
fn status_body_color(role_col: Color32, status: &str) -> Color32 {
    match status {
        "online" => role_col,
        "connecting" => lerp_color(role_col, GREY_DOWN, 0.30),
        "powered_off" => lerp_color(GREY_DOWN, BG, 0.45),
        _ => GREY_DOWN, // offline + unknown -> grey
    }
}

struct Edge {
    a: usize,
    b: usize,
    kind: String,
    active: bool,
}

#[derive(Default)]
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// Per-node emit time within a pulse cycle (seconds). A node fires its
    /// downstream blobs at this offset; computed as a longest-path over the
    /// flow DAG so a node only emits after all upstream blobs have melted in.
    fire_at: Vec<f32>,
    /// Total length of one pulse cycle (seconds).
    cycle_len: f32,
}

impl Graph {
    fn from_dto(dto: GraphDto) -> Self {
        let mut nodes = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for nd in dto.nodes.into_iter() {
            let pinned = nd.position.is_some();
            let pos = match &nd.position {
                Some(p) => V3::new(p.x, p.y, p.z),
                None => V3::default(), // placed by layout_galaxies()
            };
            index.insert(nd.id.clone(), nodes.len());
            let status = nd.status.unwrap_or_else(|| "offline".into());
            let lit = lit_target(&status); // start settled, no first-frame fade-in
            nodes.push(Node {
                label: nd.label.unwrap_or_else(|| nd.id.clone()),
                id: nd.id,
                role: nd.role.unwrap_or_else(|| "client".into()),
                status,
                meta: nd.meta,
                pos,
                pinned,
                lit,
                galaxy: None,
            });
        }
        let mut edges = Vec::new();
        for ed in dto.edges {
            if let (Some(&a), Some(&b)) = (index.get(&ed.from), index.get(&ed.to)) {
                edges.push(Edge {
                    a,
                    b,
                    kind: ed.kind.unwrap_or_else(|| "data_path".into()),
                    active: ed.active.unwrap_or(true),
                });
            }
        }

        let mut graph = Graph {
            nodes,
            edges,
            fire_at: Vec::new(),
            cycle_len: 0.0,
        };
        graph.layout_galaxies();
        graph.compute_pulse_schedule();
        graph
    }

    /// Each leaf node's hub = the connected node nearest the exit (its next hop).
    fn leaf_hub(&self, i: usize) -> Option<usize> {
        if !is_leaf_role(&self.nodes[i].role) {
            return None;
        }
        let my = role_flow_rank(&self.nodes[i].role);
        let mut best: Option<(i32, usize)> = None;
        for e in &self.edges {
            let other = if e.a == i {
                Some(e.b)
            } else if e.b == i {
                Some(e.a)
            } else {
                None
            };
            if let Some(o) = other {
                let r = role_flow_rank(&self.nodes[o].role);
                if r > my && best.is_none_or(|(br, _)| r > br) {
                    best = Some((r, o));
                }
            }
        }
        best.map(|(_, o)| o)
    }

    /// Deterministic layout. Every galaxy (a same-role leaf group) and every
    /// backbone node is a tile; tiles are shelf-packed tightly in flow order,
    /// each anchor kept next to its galaxies. Compact, no overlap, and the
    /// anchor stays a separate tile so galaxy borders never cover it.
    fn layout_galaxies(&mut self) {
        use std::collections::BTreeMap as Map;
        let n = self.nodes.len();
        let hub: Vec<Option<usize>> = (0..n).map(|i| self.leaf_hub(i)).collect();

        // A tile is one packed unit: either a galaxy (a disc of same-role leaves)
        // or a single backbone/unattached node. Tiles are shelf-packed.
        struct Tile {
            members: Vec<(usize, V3)>, // (node idx, offset from tile centre)
            radius: f32,
        }

        // Group leaves by (hub, role).
        let mut by_hub: Map<usize, Map<String, Vec<usize>>> = Map::new();
        for (i, h) in hub.iter().enumerate() {
            if self.nodes[i].pinned {
                continue;
            }
            if let Some(h) = *h {
                by_hub
                    .entry(h)
                    .or_default()
                    .entry(self.nodes[i].role.clone())
                    .or_default()
                    .push(i);
            }
        }

        // Build a galaxy tile: pack same-role leaves into a disc (phyllotaxis).
        let galaxy_tile = |nodes: &mut [Node], mem: &[usize], gid: u64| -> Tile {
            let mut members = Vec::with_capacity(mem.len());
            let mut maxr = 0.0_f32;
            for (k, &idx) in mem.iter().enumerate() {
                let a = k as f32 * 2.399_963_2; // golden angle
                let rr = NODE_GAP * (k as f32).sqrt();
                let off = V3::new(rr * a.cos(), 0.0, rr * a.sin());
                members.push((idx, off));
                maxr = maxr.max(rr);
                nodes[idx].galaxy = Some(gid);
            }
            Tile {
                members,
                radius: maxr + NODE_GAP, // interior breathing room
            }
        };

        // Emit tiles in flow order, keeping each anchor next to its galaxies.
        let mut tiles: Vec<Tile> = Vec::new();
        let mut hub_keys: Vec<usize> = by_hub.keys().copied().collect();
        hub_keys.sort_by_key(|&h| (galaxy_col(&self.nodes[h].role), h));
        for h in &hub_keys {
            tiles.push(Tile {
                members: vec![(*h, V3::default())],
                radius: SINGLETON_RADIUS,
            });
            for (role, mem) in &by_hub[h] {
                let gid = (*h as u64) * 16 + role_ord(role);
                let t = galaxy_tile(&mut self.nodes, mem, gid);
                tiles.push(t);
            }
        }
        // Remaining backbone / unattached singletons, in flow order.
        let mut singles: Vec<usize> = (0..n)
            .filter(|&i| {
                !(self.nodes[i].pinned
                    || by_hub.contains_key(&i)
                    || (is_leaf_role(&self.nodes[i].role) && hub[i].is_some()))
            })
            .collect();
        singles.sort_by_key(|&i| (galaxy_col(&self.nodes[i].role), i));
        for i in singles {
            tiles.push(Tile {
                members: vec![(i, V3::default())],
                radius: SINGLETON_RADIUS,
            });
        }

        // Shelf-pack tiles into a roughly-square area with small gaps.
        let total_w: f32 = tiles.iter().map(|t| 2.0 * t.radius + CLUSTER_GAP).sum();
        let rows = ((tiles.len() as f32).sqrt()).round().max(1.0);
        let target_w = (total_w / rows).max(1.0);
        let mut cx = 0.0;
        let mut cy = 0.0;
        let mut row_h = 0.0;
        let mut centers: Vec<V3> = Vec::with_capacity(tiles.len());
        let (mut min_x, mut max_x, mut min_z, mut max_z) = (f32::MAX, f32::MIN, f32::MAX, f32::MIN);
        for t in &tiles {
            let w = 2.0 * t.radius + CLUSTER_GAP;
            if cx > 0.0 && cx + w > target_w {
                cx = 0.0;
                cy += row_h;
                row_h = 0.0;
            }
            let center = V3::new(cx + t.radius, 0.0, cy + t.radius);
            centers.push(center);
            min_x = min_x.min(center.x - t.radius);
            max_x = max_x.max(center.x + t.radius);
            min_z = min_z.min(center.z - t.radius);
            max_z = max_z.max(center.z + t.radius);
            cx += w;
            row_h = row_h.max(2.0 * t.radius + CLUSTER_GAP);
        }
        let mid = V3::new((min_x + max_x) * 0.5, 0.0, (min_z + max_z) * 0.5);

        // Apply, centring the whole map at the origin.
        for (t, center) in tiles.iter().zip(centers) {
            let base = center.sub(mid);
            for &(idx, off) in &t.members {
                self.nodes[idx].pos = base.add(off);
            }
        }
    }

    /// Orient a data-path edge upstream -> downstream (lower flow rank -> higher,
    /// i.e. toward the exit). Returns (upstream_idx, downstream_idx).
    fn oriented(&self, e: &Edge) -> (usize, usize) {
        if role_flow_rank(&self.nodes[e.a].role) <= role_flow_rank(&self.nodes[e.b].role) {
            (e.a, e.b)
        } else {
            (e.b, e.a)
        }
    }

    /// Compute the wave schedule: each node's emit time within a cycle is the
    /// latest upstream blob arrival (fire_at[u] + TRAVEL) plus PULSE_PAUSE, found
    /// by longest-path relaxation over the flow DAG. Sources fire at t=0.
    fn compute_pulse_schedule(&mut self) {
        let n = self.nodes.len();
        let mut fire_at = vec![0.0f32; n];
        let oriented: Vec<(usize, usize)> = self
            .edges
            .iter()
            .filter(|e| edge_has_flow(&e.kind))
            .map(|e| self.oriented(e))
            .collect();
        // Relax up to n times (DAG by rank; the cap also guards against cycles).
        let hop = PULSE_TRAVEL + PULSE_PAUSE;
        for _ in 0..n.max(1) {
            let mut changed = false;
            for &(u, v) in &oriented {
                if fire_at[u] + hop > fire_at[v] + 1e-3 {
                    fire_at[v] = fire_at[u] + hop;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        // Cycle ends after the last blob has melted, plus a trailing pause.
        let mut cycle = PULSE_TRAVEL + PULSE_PAUSE;
        for &(u, _) in &oriented {
            cycle = cycle.max(fire_at[u] + PULSE_TRAVEL + PULSE_PAUSE);
        }
        self.fire_at = fire_at;
        self.cycle_len = cycle;
    }

    /// World-space centroid of a galaxy's member nodes (for camera framing).
    fn galaxy_centroid(&self, gid: u64) -> V3 {
        let mut sum = V3::default();
        let mut count = 0.0f32;
        for nd in &self.nodes {
            if nd.galaxy == Some(gid) {
                sum = sum.add(nd.pos);
                count += 1.0;
            }
        }
        if count > 0.0 {
            sum.scale(1.0 / count)
        } else {
            V3::default()
        }
    }
}

// ===========================================================================
// DATA CONTRACT (input DTOs) — matches DATA_CONTRACT.md
// ===========================================================================

#[derive(Deserialize, Default)]
struct GraphDto {
    #[serde(default)]
    nodes: Vec<NodeDto>,
    #[serde(default)]
    edges: Vec<EdgeDto>,
}

#[derive(Deserialize)]
struct NodeDto {
    id: String,
    label: Option<String>,
    role: Option<String>,
    status: Option<String>,
    position: Option<PosDto>,
    #[serde(default)]
    meta: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct PosDto {
    x: f32,
    y: f32,
    z: f32,
}

#[derive(Deserialize)]
struct EdgeDto {
    from: String,
    to: String,
    kind: Option<String>,
    active: Option<bool>,
}

// ===========================================================================
// COLOUR HELPERS
// ===========================================================================

fn lerp_color(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

/// Scalar linear interpolation.
fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Smooth Hermite step between two edges (0 below e0, 1 above e1).
fn smoothstep(e0: f32, e1: f32, x: f32) -> f32 {
    let t = ((x - e0) / (e1 - e0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Interpolate between two screen points.
fn lerp_pos(a: Pos2, b: Pos2, t: f32) -> Pos2 {
    Pos2::new(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t)
}

fn with_alpha(c: Color32, a: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (a.clamp(0.0, 1.0) * 255.0) as u8)
}

// ===========================================================================
// APP
// ===========================================================================

struct App {
    graph: Graph,
    cam: Camera,
    show_labels: bool,
    animate_flow: bool,
    show_galaxies: bool,
    live_sim: bool,
    hidden_roles: HashSet<String>,
    selected: Option<usize>,
    /// When Some, we're drilled into a galaxy (zoomed-in view of one galaxy).
    focused_galaxy: Option<u64>,
    /// Smooth camera move goal (target, distance); cleared on manual pan/zoom.
    view_anim: Option<(V3, f32)>,
    sim_accum: f32,
    rng: u64,
}

impl App {
    fn new(graph: Graph) -> Self {
        Self {
            graph,
            cam: Camera::default(),
            show_labels: true,
            animate_flow: true,
            show_galaxies: true,
            live_sim: true,
            hidden_roles: HashSet::new(),
            selected: None,
            focused_galaxy: None,
            view_anim: None,
            sim_accum: 0.0,
            rng: 0x9e3779b97f4a7c15,
        }
    }

    /// Enter a galaxy: frame the camera on it at a fixed zoom.
    fn enter_galaxy(&mut self, gid: u64) {
        self.focused_galaxy = Some(gid);
        self.selected = None;
        let center = self.graph.galaxy_centroid(gid);
        self.view_anim = Some((center, GALAXY_VIEW_DISTANCE));
    }

    /// Back to the spread-out overview.
    fn exit_galaxy(&mut self) {
        self.focused_galaxy = None;
        self.selected = None;
        self.view_anim = Some((V3::default(), OVERVIEW_DISTANCE));
    }

    /// Tiny xorshift RNG so we avoid an extra dependency.
    fn rand(&mut self) -> f32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 11) as f32 / (1u64 << 53) as f32
    }

    /// Randomly flip a node's status so the demo feels alive.
    fn simulate(&mut self) {
        if self.graph.nodes.is_empty() {
            return;
        }
        let idx = (self.rand() * self.graph.nodes.len() as f32) as usize % self.graph.nodes.len();
        let role = self.graph.nodes[idx].role.clone();
        // Don't churn infrastructure roles as aggressively.
        if matches!(role.as_str(), "admin" | "anchor" | "relay") && self.rand() < 0.7 {
            return;
        }
        const STATES: [&str; 4] = ["online", "connecting", "offline", "powered_off"];
        let s = STATES[(self.rand() * 4.0) as usize % 4];
        self.graph.nodes[idx].status = s.to_string();
    }

    fn visible(&self, role: &str) -> bool {
        !self.hidden_roles.contains(role)
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Continuous animation.
        ctx.request_repaint();
        let dt = ctx.input(|i| i.stable_dt).min(0.05);
        let time = ctx.input(|i| i.time) as f32;

        // Live demo status churn (layout is now static/deterministic).
        if self.live_sim {
            self.sim_accum += dt;
            if self.sim_accum >= 1.8 {
                self.sim_accum = 0.0;
                self.simulate();
            }
        }

        // Smoothly ramp each node's "lit" toward its status target.
        let k = (dt * 2.2).min(1.0);
        for node in &mut self.graph.nodes {
            let target = lit_target(&node.status);
            node.lit += (target - node.lit) * k;
        }

        // Smoothly fly the camera toward a view goal (enter/exit a galaxy).
        if let Some((tgt, dist)) = self.view_anim {
            let a = (dt * 6.0).min(1.0);
            self.cam.target = self.cam.target.add(tgt.sub(self.cam.target).scale(a));
            self.cam.distance += (dist - self.cam.distance) * a;
            if tgt.sub(self.cam.target).len() < 0.5 && (dist - self.cam.distance).abs() < 0.5 {
                self.cam.target = tgt;
                self.cam.distance = dist;
                self.view_anim = None;
            }
        }

        // Escape leaves a galaxy view.
        if self.focused_galaxy.is_some() && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.exit_galaxy();
        }

        self.side_panels(ctx);
        self.scene(ctx, time);
    }
}

// ----- UI panels ------------------------------------------------------------

impl App {
    fn side_panels(&mut self, ctx: &egui::Context) {
        // Left: title, stats, controls.
        egui::SidePanel::left("hud")
            .resizable(false)
            .default_width(210.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading("Rustynet");
                ui.label(
                    egui::RichText::new("Node Map · live topology")
                        .weak()
                        .small(),
                );
                ui.add_space(10.0);

                if self.focused_galaxy.is_some() {
                    if ui.button("← Back to overview").clicked() {
                        self.exit_galaxy();
                    }
                    ui.label(
                        egui::RichText::new("Esc or click outside to exit")
                            .weak()
                            .small(),
                    );
                    ui.add_space(10.0);
                }

                let vis: Vec<&Node> = self
                    .graph
                    .nodes
                    .iter()
                    .filter(|n| self.visible(&n.role))
                    .collect();
                let total = vis.len();
                let online = vis.iter().filter(|n| n.status == "online").count();
                let offline = vis
                    .iter()
                    .filter(|n| matches!(n.status.as_str(), "offline" | "powered_off"))
                    .count();
                let paths = self.graph.edges.iter().filter(|e| e.active).count();
                stat_row(
                    ui,
                    "Nodes",
                    &total.to_string(),
                    Color32::from_rgb(215, 224, 240),
                );
                stat_row(
                    ui,
                    "Online",
                    &online.to_string(),
                    Color32::from_rgb(87, 224, 138),
                );
                stat_row(
                    ui,
                    "Offline",
                    &offline.to_string(),
                    Color32::from_rgb(255, 107, 107),
                );
                stat_row(
                    ui,
                    "Data paths",
                    &paths.to_string(),
                    Color32::from_rgb(215, 224, 240),
                );

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(egui::RichText::new("VIEW").weak().small());
                ui.checkbox(&mut self.show_labels, "Labels");
                ui.checkbox(&mut self.animate_flow, "Animate data paths");
                ui.checkbox(&mut self.show_galaxies, "Galaxy borders");
                ui.checkbox(&mut self.live_sim, "Live demo updates");
                ui.add_space(6.0);
                if ui.button("Reset view").clicked() {
                    self.cam = Camera::default();
                }
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new("Drag: pan · scroll: zoom · click a node to inspect.")
                        .weak()
                        .small(),
                );
            });

        // Right: legend (roles present) + status key.
        egui::SidePanel::right("legend")
            .resizable(false)
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("ROLES").weak().small());
                let present: HashSet<&str> =
                    self.graph.nodes.iter().map(|n| n.role.as_str()).collect();
                for &role in ROLE_ORDER {
                    if !present.contains(role) {
                        continue;
                    }
                    let st = role_style(role);
                    let hidden = self.hidden_roles.contains(role);
                    let resp = ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
                        let c = if hidden {
                            with_alpha(st.color, 0.3)
                        } else {
                            st.color
                        };
                        ui.painter().circle_filled(rect.center(), 6.0, c);
                        ui.vertical(|ui| {
                            let mut t = egui::RichText::new(st.label);
                            if hidden {
                                t = t.weak();
                            }
                            ui.label(t);
                            ui.label(egui::RichText::new(st.desc).weak().small());
                        });
                    });
                    if resp.response.interact(Sense::click()).clicked() {
                        if hidden {
                            self.hidden_roles.remove(role);
                        } else {
                            self.hidden_roles.insert(role.to_string());
                        }
                    }
                    ui.add_space(2.0);
                }

                ui.add_space(10.0);
                ui.label(egui::RichText::new("STATUS").weak().small());
                status_key(ui, "online", "bright, pulsing");
                status_key(ui, "connecting", "flickering");
                status_key(ui, "offline", "dim, grey");
                status_key(ui, "powered_off", "faint");
            });
    }

    // ----- 3D scene ---------------------------------------------------------

    fn scene(&mut self, ctx: &egui::Context, time: f32) {
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG))
            .show(ctx, |ui| {
                let (response, painter) =
                    ui.allocate_painter(ui.available_size(), Sense::click_and_drag());
                let rect = response.rect;

                // ----- camera interaction (pan + zoom only; no rotation) -----
                if response.dragged() {
                    self.view_anim = None; // manual control cancels any fly-to
                    let d = response.drag_delta();
                    // Pan: slide the target in the camera's screen plane.
                    let cam = self.cam.position();
                    let forward = self.cam.target.sub(cam).norm();
                    let right = forward.cross(V3::new(0.0, 1.0, 0.0)).norm();
                    let up = right.cross(forward);
                    let k = self.cam.distance * 0.0016;
                    self.cam.target = self
                        .cam
                        .target
                        .add(right.scale(-d.x * k))
                        .add(up.scale(d.y * k));
                }
                if response.hovered() {
                    let scroll =
                        ctx.input(|i| i.smooth_scroll_delta.y + (i.zoom_delta() - 1.0) * 200.0);
                    if scroll != 0.0 {
                        self.view_anim = None; // manual zoom cancels any fly-to
                        self.cam.distance =
                            (self.cam.distance * (1.0 - scroll * 0.0015)).clamp(60.0, 1600.0);
                    }
                }

                // ----- background -----
                draw_background(&painter, rect, time);

                // ----- project visible nodes -----
                struct Drawn {
                    idx: usize,
                    p: Projected,
                }
                let mut drawn: Vec<Drawn> = Vec::with_capacity(self.graph.nodes.len());
                for (idx, node) in self.graph.nodes.iter().enumerate() {
                    if !self.visible(&node.role) {
                        continue;
                    }
                    if let Some(p) = self.cam.project(node.pos, rect) {
                        drawn.push(Drawn { idx, p });
                    }
                }

                // ----- galaxy boxes (one square-ish region per (hub, role) group) -----
                struct GalScreen {
                    gid: u64,
                    bounds: Rect, // node bounding box + interior padding
                    color: Color32,
                    label: &'static str,
                }
                let mut galaxies: Vec<GalScreen> = Vec::new();
                {
                    let mut groups: std::collections::BTreeMap<u64, (Vec<Pos2>, &str)> =
                        std::collections::BTreeMap::new();
                    for d in &drawn {
                        if let Some(g) = self.graph.nodes[d.idx].galaxy {
                            groups
                                .entry(g)
                                .or_insert_with(|| {
                                    (Vec::new(), self.graph.nodes[d.idx].role.as_str())
                                })
                                .0
                                .push(d.p.screen);
                        }
                    }
                    for (gid, (pts, role)) in groups {
                        // Bounding box of the group's nodes, padded on all sides so
                        // nodes never touch the border.
                        let mut bb = Rect::from_min_max(pts[0], pts[0]);
                        for p in &pts {
                            bb.extend_with(*p);
                        }
                        let bounds = bb.expand(GALAXY_PAD);
                        let rs = role_style(role);
                        galaxies.push(GalScreen {
                            gid,
                            bounds,
                            color: rs.color,
                            label: rs.label,
                        });
                    }
                }

                // ----- node hover pick -----
                let mp = response.hover_pos();
                let mut hover_idx: Option<usize> = None;
                if let Some(mp) = mp {
                    let mut best = f32::MAX;
                    for d in &drawn {
                        let rs = role_style(&self.graph.nodes[d.idx].role);
                        let core_r = core_r_of(rs.size_mult, d.p.depth);
                        let dist = d.p.screen.distance(mp);
                        if dist <= core_r + 4.0 && dist < best {
                            best = dist;
                            hover_idx = Some(d.idx);
                        }
                    }
                }

                // ----- galaxy hover (overview only): smallest box under cursor -----
                let mut hovered_gal: Option<u64> = None;
                if self.focused_galaxy.is_none() {
                    if let Some(mp) = mp {
                        let mut best = f32::MAX;
                        for g in &galaxies {
                            if g.bounds.contains(mp) && g.bounds.area() < best {
                                best = g.bounds.area();
                                hovered_gal = Some(g.gid);
                            }
                        }
                    }
                }

                // ----- click: drill in/out of a galaxy, or select a node -----
                if response.clicked() {
                    if self.focused_galaxy.is_some() {
                        if hover_idx.is_some() {
                            self.selected = hover_idx;
                        } else {
                            let inside = mp.is_some_and(|mp| {
                                galaxies.iter().any(|g| {
                                    Some(g.gid) == self.focused_galaxy && g.bounds.contains(mp)
                                })
                            });
                            if !inside {
                                self.exit_galaxy();
                            }
                        }
                    } else {
                        // Overview: a backbone node selects; a galaxy drills in.
                        let backbone = hover_idx.filter(|&i| self.graph.nodes[i].galaxy.is_none());
                        if let Some(i) = backbone {
                            self.selected = Some(i);
                        } else if let Some(g) = hovered_gal {
                            self.enter_galaxy(g);
                        } else {
                            self.selected = None;
                        }
                    }
                }

                // ----- galaxy borders: square-ish (rounded-rect) regions -----
                if self.show_galaxies {
                    for g in &galaxies {
                        let hl = hovered_gal == Some(g.gid) || self.focused_galaxy == Some(g.gid);
                        let rounding = 12.0;
                        painter.rect_filled(
                            g.bounds,
                            rounding,
                            with_alpha(g.color, if hl { 0.12 } else { 0.06 }),
                        );
                        painter.rect_stroke(
                            g.bounds,
                            rounding,
                            Stroke::new(
                                if hl { 2.6 } else { 1.4 },
                                with_alpha(g.color, if hl { 0.95 } else { 0.5 }),
                            ),
                        );
                        painter.text(
                            Pos2::new(g.bounds.center().x, g.bounds.top() - 4.0),
                            Align2::CENTER_BOTTOM,
                            g.label,
                            FontId::monospace(if hl { 13.0 } else { 11.0 }),
                            with_alpha(g.color, if hl { 1.0 } else { 0.85 }),
                        );
                    }
                }

                // Per-node emphasis: galaxy view uses node hover/selection; the
                // overview only emphasises standalone (non-galaxy) nodes.
                let focus = if self.focused_galaxy.is_some() {
                    hover_idx.or(self.selected)
                } else {
                    hover_idx
                        .filter(|&i| self.graph.nodes[i].galaxy.is_none())
                        .or(self.selected)
                };
                let focused = focus.is_some();

                // ----- edges (behind nodes) -----
                for e in &self.graph.edges {
                    if !self.visible(&self.graph.nodes[e.a].role)
                        || !self.visible(&self.graph.nodes[e.b].role)
                    {
                        continue;
                    }
                    let (a, b) = (&self.graph.nodes[e.a], &self.graph.nodes[e.b]);
                    let (pa, pb) =
                        match (self.cam.project(a.pos, rect), self.cam.project(b.pos, rect)) {
                            (Some(pa), Some(pb)) => (pa, pb),
                            _ => continue,
                        };
                    let kind = edge_kind_style(&e.kind);
                    let live = a.status == "online" && b.status == "online" && e.active;
                    let ca = role_style(&a.role).color;
                    let cb = role_style(&b.role).color;
                    // Blend the two endpoint colours, then tint toward FIBER and fog by depth.
                    let mut col = lerp_color(lerp_color(ca, cb, 0.5), FIBER, 0.30);
                    let fog_t = (depth_t_of(pa.depth) + depth_t_of(pb.depth)) * 0.5;
                    col = lerp_color(BG, col, lerp(1.0 - DEPTH_FOG_MAX, 1.0, fog_t));
                    let mut alpha = kind.base_opacity * if live { 1.0 } else { 0.25 };
                    let mut width = kind.width;
                    if focused {
                        if focus == Some(e.a) || focus == Some(e.b) {
                            alpha *= 1.6;
                            width *= 1.4;
                        } else {
                            alpha *= 0.28;
                        }
                    }
                    painter.line_segment(
                        [pa.screen, pb.screen],
                        Stroke::new(width, with_alpha(col, alpha)),
                    );

                    // ----- pulse: wave blob for this hop. It only travels while
                    // the upstream node is "firing" (fire_at..+TRAVEL), so a node
                    // emits downstream only after all its upstream blobs melted in
                    // (+ a PULSE_PAUSE), giving a staged flow toward the exit. -----
                    if edge_has_flow(&e.kind)
                        && live
                        && self.animate_flow
                        && self.graph.cycle_len > 0.0
                    {
                        // Upstream endpoint (nearer the source) + its emit time.
                        let up_is_a = role_flow_rank(&a.role) <= role_flow_rank(&b.role);
                        let (src, dst, up_idx) = if up_is_a {
                            (pa.screen, pb.screen, e.a)
                        } else {
                            (pb.screen, pa.screen, e.b)
                        };
                        let emit = self.graph.fire_at[up_idx];
                        let ct = time % self.graph.cycle_len;
                        if ct >= emit && ct <= emit + PULSE_TRAVEL {
                            let t = (ct - emit) / PULSE_TRAVEL;
                            let cra = core_r_of(role_style(&a.role).size_mult, pa.depth);
                            let crb = core_r_of(role_style(&b.role).size_mult, pb.depth);
                            let pr = ((cra + crb) * 0.5 * 0.40).clamp(1.6, 4.6);
                            // Envelope: emerge from the source, melt into the receiver.
                            let env = smoothstep(0.0, 0.12, t) * (1.0 - smoothstep(0.6, 1.0, t));
                            if env > 0.01 {
                                let p = lerp_pos(src, dst, t);
                                let rr = pr * (0.45 + 0.55 * env);
                                painter.circle_filled(
                                    p,
                                    rr * PULSE_HALO_MULT,
                                    with_alpha(FIBER, PULSE_HALO_A * env),
                                );
                                painter.circle_filled(
                                    p,
                                    rr,
                                    with_alpha(
                                        Color32::from_rgb(248, 252, 255),
                                        PULSE_CORE_A * env,
                                    ),
                                );
                            }
                        }
                    }
                }

                // ----- nodes (painter's algorithm: far first) -----
                drawn.sort_by(|x, y| {
                    y.p.depth
                        .partial_cmp(&x.p.depth)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                for d in &drawn {
                    let node = &self.graph.nodes[d.idx];
                    let rs = role_style(&node.role);
                    let st = status_style(&node.status);

                    // Bold, consistent body colour by status (online = full role
                    // colour, offline = grey). NOT tinted by depth, so all
                    // same-role online nodes read as the same shade.
                    let body = status_body_color(rs.color, &node.status);

                    // Glow opacity only: a light breathing glow (online slow,
                    // connecting nervous + flicker). The core stays steady.
                    let pulse_speed = if node.status == "connecting" {
                        5.5
                    } else {
                        1.6
                    };
                    let seed = d.idx as f32 * 12.9898;
                    let mut glow_op = (st.glow + (time * pulse_speed + seed).sin() * st.pulse)
                        .max(0.0)
                        * lerp(0.4, 1.0, node.lit);
                    if st.flicker > 0.0 {
                        glow_op *= 0.7 + self_rand_static(time, d.idx) * st.flicker;
                    }
                    // Core opacity eases in with the status ramp (no pop on change).
                    let mut ball_a = 0.55 + 0.45 * node.lit;

                    // Focus mode: emphasise the focused node, dim the rest.
                    if focused {
                        if focus == Some(d.idx) {
                            glow_op *= 1.3;
                        } else {
                            glow_op *= 0.4;
                            ball_a *= 0.55;
                        }
                    }

                    let core_r = core_r_of(rs.size_mult, d.p.depth);

                    // Light glow: many thin layers, radius + alpha falling off
                    // from the core outward (soft aura, no rings).
                    for i in 0..GLOW_LAYERS {
                        let t = i as f32 / (GLOW_LAYERS - 1) as f32;
                        let r = core_r * (GLOW_INNER + (GLOW_OUTER - GLOW_INNER) * (1.0 - t));
                        let a = GLOW_PEAK * t.powf(GLOW_FALLOFF) * glow_op;
                        let col = lerp_color(body, WARM_WHITE, t * GLOW_WARM);
                        painter.circle_filled(d.p.screen, r, with_alpha(col, a));
                    }
                    // Bold core rendered as a simple 3D-looking sphere.
                    draw_ball(&painter, d.p.screen, core_r * CORE_R_MULT, body, ball_a);

                    // Selection / hover ring.
                    let ring_r = core_r * GLOW_OUTER + 4.0;
                    if self.selected == Some(d.idx) {
                        painter.circle_stroke(
                            d.p.screen,
                            ring_r,
                            Stroke::new(1.6, with_alpha(Color32::from_rgb(235, 242, 255), 0.85)),
                        );
                    } else if hover_idx == Some(d.idx) {
                        painter.circle_stroke(
                            d.p.screen,
                            ring_r,
                            Stroke::new(1.1, with_alpha(FIBER, 0.5)),
                        );
                    }
                }

                // ----- labels: in the overview only standalone nodes are named
                // (galaxy contents are nameless until you drill in); inside a
                // galaxy view, that galaxy's nodes (and the backbone) are named. -----
                if self.show_labels {
                    for d in &drawn {
                        let node = &self.graph.nodes[d.idx];
                        if node.status == "powered_off" {
                            continue;
                        }
                        let show_name = match self.focused_galaxy {
                            Some(fg) => node.galaxy == Some(fg) || node.galaxy.is_none(),
                            None => node.galaxy.is_none(),
                        };
                        if !show_name {
                            continue;
                        }
                        let is_focus = focus == Some(d.idx);
                        let depth_t = depth_t_of(d.p.depth);
                        let mut label_alpha = ((depth_t - 0.15) / 0.5).clamp(0.0, 1.0);
                        if is_focus {
                            label_alpha = 1.0;
                        }
                        if label_alpha < 0.06 {
                            continue;
                        }
                        let core_r = core_r_of(role_style(&node.role).size_mult, d.p.depth);
                        let font =
                            FontId::monospace((10.5 * (0.8 + depth_t * 0.5)).clamp(9.0, 14.0));
                        // Translucent white name floating just below the node,
                        // with no background plate.
                        let pos = d.p.screen + Vec2::new(0.0, core_r + 6.0);
                        let color = if is_focus { Color32::WHITE } else { TEXT_HI };
                        painter.text(
                            pos,
                            Align2::CENTER_TOP,
                            &node.label,
                            font,
                            with_alpha(color, label_alpha),
                        );
                    }
                }

                // ----- tooltip -----
                if let Some(i) = hover_idx {
                    draw_tooltip(
                        &painter,
                        response.hover_pos().unwrap_or(rect.center()),
                        &self.graph.nodes[i],
                    );
                }
            });

        // Inspector window (only when a node is selected).
        if let Some(i) = self.selected {
            let mut open = true;
            // Snapshot for display before borrowing mutably elsewhere.
            let node = &self.graph.nodes[i];
            let rs = role_style(&node.role);
            let conns = self
                .graph
                .edges
                .iter()
                .filter(|e| e.a == i || e.b == i)
                .count();
            egui::Window::new("Inspector")
                .open(&mut open)
                .resizable(false)
                .anchor(Align2::RIGHT_BOTTOM, Vec2::new(-16.0, -16.0))
                .show(ctx, |ui| {
                    ui.label(egui::RichText::new(&node.label).monospace().strong());
                    ui.label(egui::RichText::new(rs.label).color(rs.color).strong());
                    ui.separator();
                    kv(ui, "ID", &node.id);
                    kv(ui, "Status", &node.status);
                    kv(ui, "Role", &node.role);
                    kv(
                        ui,
                        "Address",
                        node.meta.get("address").map(|s| s.as_str()).unwrap_or("—"),
                    );
                    kv(
                        ui,
                        "OS",
                        node.meta.get("os").map(|s| s.as_str()).unwrap_or("—"),
                    );
                    let seen = node.meta.get("lastSeen").map(|s| s.as_str()).unwrap_or(
                        if node.status == "online" {
                            "now"
                        } else {
                            "—"
                        },
                    );
                    kv(ui, "Last seen", seen);
                    kv(ui, "Connections", &conns.to_string());
                });
            if !open {
                self.selected = None;
            }
        }
    }
}

/// Deterministic per-node flicker without storing RNG state on the node.
fn self_rand_static(time: f32, idx: usize) -> f32 {
    let v = (time * 37.0 + idx as f32 * 11.3).sin() * 43758.547;
    v.fract().abs()
}

// ----- small UI helpers -----------------------------------------------------

fn stat_row(ui: &mut egui::Ui, k: &str, v: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(k).weak());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(v).monospace().color(color));
        });
    });
}

fn status_key(ui: &mut egui::Ui, status: &str, desc: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(22.0, 8.0), Sense::hover());
        let st = status_style(status);
        let c = lerp_color(Color32::WHITE, GREY_DOWN, st.desat);
        ui.painter()
            .rect_filled(rect, 3.0, with_alpha(c, st.glow.max(0.25)));
        ui.label(
            egui::RichText::new(format!("{status} · {desc}"))
                .weak()
                .small(),
        );
    });
}

fn kv(ui: &mut egui::Ui, k: &str, v: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(k).weak());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(v).monospace());
        });
    });
}

/// Draw a node core as a simple faked 3D sphere: a dark base rim, the bold body
/// offset toward the light, then a highlight and a small specular (light from
/// the upper-left). Four solid circles only — minimal, no gradients.
fn draw_ball(painter: &egui::Painter, c: Pos2, r: f32, color: Color32, alpha: f32) {
    let dir = Vec2::new(-0.40, -0.52); // light from upper-left (screen y is down)
    let shadow = lerp_color(color, Color32::BLACK, 0.50);
    let hi = lerp_color(color, Color32::WHITE, 0.38);
    let spec = lerp_color(color, Color32::WHITE, 0.72);
    painter.circle_filled(c, r, with_alpha(shadow, alpha));
    painter.circle_filled(c + dir * (r * 0.14), r * 0.86, with_alpha(color, alpha));
    painter.circle_filled(c + dir * (r * 0.34), r * 0.52, with_alpha(hi, alpha));
    painter.circle_filled(c + dir * (r * 0.50), r * 0.22, with_alpha(spec, alpha));
}

fn draw_tooltip(painter: &egui::Painter, at: Pos2, node: &Node) {
    let rs = role_style(&node.role);
    let text = format!("{} · {} · {}", node.label, rs.label, node.status);
    let pos = at + Vec2::new(14.0, 14.0);
    let galley = painter.layout_no_wrap(
        text,
        FontId::monospace(12.0),
        Color32::from_rgb(215, 224, 240),
    );
    let pad = Vec2::new(8.0, 5.0);
    let bg = Rect::from_min_size(pos, galley.size() + pad * 2.0);
    painter.rect_filled(bg, 6.0, Color32::from_rgba_unmultiplied(8, 11, 18, 235));
    painter.rect_stroke(bg, 6.0, Stroke::new(1.0, Color32::from_rgb(40, 50, 70)));
    // Small role dot.
    painter.circle_filled(
        pos + Vec2::new(6.0, galley.size().y * 0.5 + pad.y),
        4.0,
        rs.color,
    );
    painter.galley(pos + pad + Vec2::new(10.0, 0.0), galley, Color32::WHITE);
}

/// Deep-space backdrop: BG fill + a faked nebula centre-lift + a 3-tier
/// (parallax) starfield + corner vignette. All deterministic so stars don't
/// jitter frame-to-frame (positions are reproduced from a fixed seed).
fn draw_background(painter: &egui::Painter, rect: Rect, time: f32) {
    // 1) base fill.
    painter.rect_filled(rect, 0.0, BG);

    // 2) nebula centre-lift: a few big, very faint circles (kept barely-there so
    //    it reads as a smooth lift, not concentric bands, on the grey backdrop).
    let base = rect.height().min(rect.width()) * 0.18;
    let nebula_r = [3.4, 2.4, 1.5, 0.8];
    let nebula_a = [0.008, 0.010, 0.012, 0.014];
    for i in 0..4 {
        painter.circle_filled(
            rect.center(),
            base * nebula_r[i],
            with_alpha(NEBULA, nebula_a[i]),
        );
    }

    // 3) starfield, 3 tiers (far/mid/near) for a sense of parallax.
    let star = Color32::from_rgb(150, 170, 210);
    let warm = Color32::from_rgb(222, 214, 196);
    let tier =
        |seed0: u64, count: usize, a_lo: f32, a_hi: f32, r_lo: f32, r_hi: f32, warm_frac: f32| {
            let mut seed = seed0;
            let mut next = move || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 11) as f32 / (1u64 << 53) as f32
            };
            for _ in 0..count {
                let x = rect.left() + next() * rect.width();
                let y = rect.top() + next() * rect.height();
                let twinkle_seed = next() * std::f32::consts::TAU;
                let mut a = a_lo + next() * (a_hi - a_lo);
                a *= 1.0 + (time * 1.3 + twinkle_seed).sin() * 0.1; // gentle twinkle
                let r = r_lo + next() * (r_hi - r_lo);
                let col = if next() < warm_frac { warm } else { star };
                painter.circle_filled(Pos2::new(x, y), r, with_alpha(col, a));
            }
        };
    tier(0x1234_5678, 150, 0.10, 0.22, 0.3, 0.8, 0.0); // far
    tier(0x9e37_79b9, 70, 0.26, 0.46, 0.7, 1.2, 0.0); // mid
    tier(0xa5a5_f00d, 26, 0.50, 0.80, 1.1, 1.8, 0.25); // near

    // 4) corner vignette: faint dark circles centred on each corner. Pushed
    //    large so only the gentle interior darkening shows (no hard arc band).
    let vmax = rect.width().max(rect.height());
    let corners = [
        rect.left_top(),
        rect.right_top(),
        rect.left_bottom(),
        rect.right_bottom(),
    ];
    for c in corners {
        for _ in 0..2 {
            painter.circle_filled(
                c,
                vmax * 0.85,
                with_alpha(Color32::from_rgb(2, 3, 8), 0.035),
            );
        }
    }
}

// ===========================================================================
// DEMO DATA + ENTRY POINT
// ===========================================================================

fn demo_graph() -> GraphDto {
    fn node(id: &str, role: &str, status: &str, addr: &str, os: &str) -> NodeDto {
        let mut meta = BTreeMap::new();
        meta.insert("address".to_string(), addr.to_string());
        meta.insert("os".to_string(), os.to_string());
        NodeDto {
            id: id.to_string(),
            label: Some(id.to_string()),
            role: Some(role.to_string()),
            status: Some(status.to_string()),
            position: None,
            meta,
        }
    }
    fn edge(from: &str, to: &str, kind: &str) -> EdgeDto {
        EdgeDto {
            from: from.to_string(),
            to: to.to_string(),
            kind: Some(kind.to_string()),
            active: None,
        }
    }
    GraphDto {
        nodes: vec![
            node("admin-01", "admin", "online", "100.64.0.1", "linux"),
            node("anchor-eu", "anchor", "online", "100.64.0.10", "linux"),
            node("anchor-us", "anchor", "online", "100.64.0.11", "linux"),
            node("relay-home", "relay", "online", "100.64.0.20", "linux"),
            node("exit-nl", "exit", "online", "100.64.0.30", "linux"),
            node("exit-blind", "blind_exit", "online", "100.64.0.31", "linux"),
            node("nas-vault", "nas", "online", "100.64.0.40", "linux"),
            node("nas-cache", "nas", "online", "100.64.0.42", "linux"),
            node("llm-box", "llm", "connecting", "100.64.0.41", "linux"),
            node("llm-edge", "llm", "online", "100.64.0.43", "linux"),
            node("laptop-mac", "client", "online", "100.64.0.50", "macos"),
            node("pc-win", "client", "online", "100.64.0.51", "windows"),
            node("phone", "client", "connecting", "100.64.0.52", "ios"),
            node("pi-sensor", "client", "offline", "100.64.0.53", "linux"),
            node(
                "old-server",
                "client",
                "powered_off",
                "100.64.0.54",
                "linux",
            ),
            // Extra endpoints so the local grouping (satellites orbiting their
            // hub) is visible: several clients on each anchor.
            node("eu-phone", "client", "online", "100.64.0.60", "android"),
            node("eu-tablet", "client", "online", "100.64.0.61", "ios"),
            node("eu-desktop", "client", "online", "100.64.0.62", "linux"),
            node("us-laptop", "client", "online", "100.64.0.63", "macos"),
            node("us-phone", "client", "connecting", "100.64.0.64", "android"),
            node("us-tablet", "client", "online", "100.64.0.65", "ios"),
        ],
        edges: vec![
            // Example data path: client -> anchor -> relay -> exit.
            edge("laptop-mac", "anchor-eu", "data_path"),
            edge("anchor-eu", "relay-home", "data_path"),
            edge("relay-home", "exit-nl", "data_path"),
            edge("pc-win", "anchor-us", "data_path"),
            edge("anchor-us", "exit-blind", "data_path"),
            edge("phone", "anchor-eu", "data_path"),
            // Service nodes (nas/llm) hang off anchors; clients reach them via
            // the anchor rather than connecting to them directly.
            edge("nas-vault", "anchor-eu", "data_path"),
            edge("nas-cache", "anchor-eu", "data_path"),
            edge("llm-box", "anchor-us", "data_path"),
            edge("llm-edge", "anchor-us", "data_path"),
            // Extra client groups orbiting their anchor.
            edge("eu-phone", "anchor-eu", "data_path"),
            edge("eu-tablet", "anchor-eu", "data_path"),
            edge("eu-desktop", "anchor-eu", "data_path"),
            edge("us-laptop", "anchor-us", "data_path"),
            edge("us-phone", "anchor-us", "data_path"),
            edge("us-tablet", "anchor-us", "data_path"),
            // Control-plane links.
            edge("admin-01", "anchor-eu", "control"),
            edge("admin-01", "anchor-us", "control"),
            edge("admin-01", "relay-home", "control"),
            edge("anchor-eu", "anchor-us", "control"),
            // Idle/known link.
            edge("pi-sensor", "anchor-eu", "potential"),
        ],
    }
}

fn load_graph() -> Graph {
    let mut args = std::env::args().skip(1);
    if let Some(path) = args.next() {
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<GraphDto>(&text) {
                Ok(dto) => {
                    eprintln!("loaded topology from {path}");
                    return Graph::from_dto(dto);
                }
                Err(e) => eprintln!("failed to parse {path}: {e}; falling back to demo data"),
            },
            Err(e) => eprintln!("failed to read {path}: {e}; falling back to demo data"),
        }
    }
    Graph::from_dto(demo_graph())
}

fn main() -> eframe::Result<()> {
    let graph = load_graph();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Rustynet — Node Map")
            .with_inner_size([1200.0, 800.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Rustynet Node Map",
        options,
        Box::new(|cc| {
            let mut v = egui::Visuals::dark();
            v.window_fill = Color32::from_rgb(10, 13, 22);
            v.panel_fill = Color32::from_rgb(10, 13, 22);
            v.extreme_bg_color = Color32::from_rgb(6, 8, 15);
            v.window_stroke = Stroke::new(1.0, Color32::from_rgb(40, 50, 72));
            v.selection.bg_fill = Color32::from_rgb(82, 150, 240);
            cc.egui_ctx.set_visuals(v);
            Ok(Box::new(App::new(graph)))
        }),
    )
}

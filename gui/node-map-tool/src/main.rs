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
// All spacing is world-space so node<->node, node<->border and border<->border
// gaps hold at any zoom. NODE_GAP doubles as the node spacing AND the interior
// pad (nodes to border); CLUSTER_GAP is the gap between galaxy/backbone tiles.
const NODE_GAP: f32 = 34.0; // spacing of nodes within a galaxy + interior padding
const SINGLETON_RADIUS: f32 = 46.0; // tile radius for a lone backbone node
const CLUSTER_GAP: f32 = 40.0; // gap between packed tiles
const LAYER_GAP: f32 = 96.0; // gap between flow layers (Sugiyama columns)
const DUMMY_R: f32 = 12.0; // routing-lane radius for a virtual node on a skip-layer edge

// Camera zoom levels: overview vs drilled-into-a-galaxy.
const OVERVIEW_DISTANCE: f32 = 1040.0;
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

/// Flow layer for the layered (Sugiyama) layout: leaves/admin sources feed the
/// backbone columns toward the exit. Mirrors role_flow_rank so the layout's
/// columns match the conceptual data path (sources -> anchor -> relay -> exit).
fn flow_layer(role: &str) -> usize {
    role_flow_rank(role).max(0) as usize
}

/// True iff the open segments p1p2 and p3p4 properly intersect in the xz plane.
/// Shared endpoints and collinear touching deliberately do NOT count, so this
/// reports only genuine line-over-line crossings.
fn segments_cross(p1: V3, p2: V3, p3: V3, p4: V3) -> bool {
    fn orient(a: V3, b: V3, c: V3) -> f32 {
        (b.x - a.x) * (c.z - a.z) - (b.z - a.z) * (c.x - a.x)
    }
    let d1 = orient(p3, p4, p1);
    let d2 = orient(p3, p4, p2);
    let d3 = orient(p1, p2, p3);
    let d4 = orient(p1, p2, p4);
    ((d1 > 0.0 && d2 < 0.0) || (d1 < 0.0 && d2 > 0.0))
        && ((d3 > 0.0 && d4 < 0.0) || (d3 < 0.0 && d4 > 0.0))
}

// --------------------- LAYERED CROSSING MINIMISATION -------------------
// Helpers for the exact (provably minimum) Sugiyama crossing minimisation used
// by Graph::layout_galaxies. With dummy units on long edges, every edge spans
// one layer, so the crossing number is the sum over adjacent layers of the
// inversions between them; the minimum is found by branch-and-bound seeded with
// a strong heuristic incumbent.

/// Straight-line crossings between tile-to-tile connections, given tile centres.
/// Connections sharing a tile never count.
fn straight_crossings(tedges: &[(usize, usize)], centers: &[V3]) -> usize {
    let mut c = 0;
    for i in 0..tedges.len() {
        for j in (i + 1)..tedges.len() {
            let (a, b) = tedges[i];
            let (p, q) = tedges[j];
            if a == p || a == q || b == p || b == q {
                continue;
            }
            if segments_cross(centers[a], centers[b], centers[p], centers[q]) {
                c += 1;
            }
        }
    }
    c
}

/// Lexicographic next permutation in place; false once `a` is the last
/// (descending) permutation. Used to enumerate a layer's orderings in B&B.
fn next_perm(a: &mut [usize]) -> bool {
    if a.len() < 2 {
        return false;
    }
    let mut i = a.len() - 1;
    while i > 0 && a[i - 1] >= a[i] {
        i -= 1;
    }
    if i == 0 {
        return false;
    }
    let mut j = a.len() - 1;
    while a[j] <= a[i - 1] {
        j -= 1;
    }
    a.swap(i - 1, j);
    a[i..].reverse();
    true
}

/// Crossings between two adjacent layer orderings: the number of inverted pairs
/// among the edges running between them (`below[u]` lists u's lower-layer
/// neighbours). Edges sharing an endpoint never count.
fn bilayer_x(upper: &[usize], lower: &[usize], below: &[Vec<usize>]) -> usize {
    let mut es: Vec<(usize, usize)> = Vec::new();
    for (ru, &u) in upper.iter().enumerate() {
        for &w in &below[u] {
            if let Some(rw) = lower.iter().position(|&x| x == w) {
                es.push((ru, rw));
            }
        }
    }
    let mut c = 0;
    for i in 0..es.len() {
        for j in (i + 1)..es.len() {
            let (a, b) = (es[i], es[j]);
            if a.0 != b.0 && a.1 != b.1 && (a.0 < b.0) != (a.1 < b.1) {
                c += 1;
            }
        }
    }
    c
}

/// Branch-and-bound recursion: assign an ordering to each layer in turn, adding
/// the crossings of each freshly-completed adjacent layer pair, pruning any
/// branch that already reaches the incumbent. Returns false if the node budget
/// is exhausted (search incomplete → result not certified).
#[allow(clippy::too_many_arguments)]
fn bnb_rec(
    l: usize,
    chosen: &mut Vec<Vec<usize>>,
    partial: usize,
    layer_sets: &[Vec<usize>],
    below: &[Vec<usize>],
    n_layers: usize,
    incumbent: &mut usize,
    best: &mut Vec<Vec<usize>>,
    budget: &mut u64,
) -> bool {
    if l == n_layers {
        if partial < *incumbent {
            *incumbent = partial;
            best.clone_from(chosen);
        }
        return true;
    }
    let mut perm = layer_sets[l].clone();
    perm.sort_unstable();
    loop {
        if *budget == 0 {
            return false;
        }
        *budget -= 1;
        let added = if l > 0 {
            bilayer_x(&chosen[l - 1], &perm, below)
        } else {
            0
        };
        let np = partial + added;
        if np < *incumbent {
            chosen[l].clone_from(&perm);
            if !bnb_rec(
                l + 1,
                chosen,
                np,
                layer_sets,
                below,
                n_layers,
                incumbent,
                best,
                budget,
            ) {
                return false;
            }
        }
        if !next_perm(&mut perm) {
            break;
        }
    }
    true
}

/// Exact, provably-minimum layered crossing number via branch-and-bound, seeded
/// with a heuristic incumbent. Returns `Some((min, order))` once the search
/// completes within budget (the minimum is then *certified*), or `None` if the
/// instance is too large to prove optimality (caller keeps the heuristic result).
fn bnb_min(
    incumbent_order: &[Vec<usize>],
    below: &[Vec<usize>],
    n_layers: usize,
    incumbent_val: usize,
) -> Option<(usize, Vec<Vec<usize>>)> {
    // Skip instances whose permutation space is hopeless even with pruning.
    let mut est: u128 = 1;
    for s in incumbent_order {
        let mut f: u128 = 1;
        for k in 1..=s.len() as u128 {
            f = f.saturating_mul(k);
        }
        est = est.saturating_mul(f);
        if est > 5_000_000_000 {
            return None;
        }
    }
    let mut budget: u64 = 8_000_000;
    let mut incumbent = incumbent_val;
    let mut best = incumbent_order.to_vec();
    let mut chosen = vec![Vec::new(); n_layers];
    let completed = bnb_rec(
        0,
        &mut chosen,
        0,
        incumbent_order,
        below,
        n_layers,
        &mut incumbent,
        &mut best,
        &mut budget,
    );
    if completed {
        Some((incumbent, best))
    } else {
        None
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

/// A galaxy's world-space footprint (a disc on the y=0 plane). The border is
/// drawn by projecting this, and the layout packs these with a world gap, so
/// node↔border and border↔border spacing is guaranteed regardless of zoom.
struct GalaxyBox {
    gid: u64,
    center: V3,
    radius: f32,
    role: String,
    /// Number of polygon vertices for the border. Grows with the member count
    /// (more nodes → rounder galaxy), starting at a pentagon for the smallest.
    sides: usize,
    /// Deterministic per-galaxy rotation (radians) so borders look varied, not
    /// like a stamped grid.
    rot: f32,
}

/// Polygon vertex count for a galaxy of `count` nodes: a pentagon for the
/// smallest (≈2 nodes), growing one side per extra node up to a cap so larger
/// galaxies read as rounder.
fn galaxy_sides(count: usize) -> usize {
    (count + 3).clamp(5, 16)
}

/// Deterministic per-galaxy rotation (radians) from its id, so galaxies look
/// individually oriented rather than like stamped, aligned copies.
fn galaxy_rot(gid: u64) -> f32 {
    let mut h = gid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= h >> 29;
    (h % 100_000) as f32 / 100_000.0 * std::f32::consts::TAU
}

/// Deterministic per-tile (x, z) world nudge used to scatter the layout off its
/// rigid grid. Bounded to a fraction of the inter-layer / inter-tile gaps so
/// galaxies never merge; the caller still verifies it adds no crossings.
fn tile_jitter(t: usize) -> (f32, f32) {
    let mut h = (t as u64)
        .wrapping_add(1)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= h >> 31;
    let ux = (h % 1000) as f32 / 1000.0 * 2.0 - 1.0;
    h = h.wrapping_mul(0x2545_F491_4F6C_DD1D);
    h ^= h >> 29;
    let uz = (h % 1000) as f32 / 1000.0 * 2.0 - 1.0;
    (ux * LAYER_GAP * 0.28, uz * CLUSTER_GAP * 0.35)
}

#[derive(Default)]
struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// World-space footprint of each galaxy (for borders + hit-testing).
    galaxies: Vec<GalaxyBox>,
    /// Per-node emit time within a pulse cycle (seconds). A node fires its
    /// downstream blobs at this offset; computed as a longest-path over the
    /// flow DAG so a node only emits after all upstream blobs have melted in.
    fire_at: Vec<f32>,
    /// Total length of one pulse cycle (seconds).
    cycle_len: f32,
    /// Camera distance that frames the whole layout in the overview, derived
    /// from the world-space bounds so the default view fits any network size.
    overview_distance: f32,
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
            galaxies: Vec::new(),
            fire_at: Vec::new(),
            cycle_len: 0.0,
            overview_distance: OVERVIEW_DISTANCE,
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
            members: Vec<(usize, V3)>,   // (node idx, offset from tile centre)
            radius: f32,                 // world footprint radius (incl. padding)
            info: Option<(u64, String)>, // Some((gid, role)) for galaxy tiles
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

        // Build a galaxy tile: distribute same-role leaves evenly in a disc using
        // Vogel's Fibonacci sunflower model (r = R*sqrt((k+0.5)/N), theta = k*137.5deg)
        // — the standard even/blue-noise disc fill — then leave a NODE_GAP margin
        // out to the border so nodes never crowd the edge.
        // Predetermined galaxy dimensions (all derived from node count, so the
        // result is deterministic): nodes fill a disc of radius `inner` via
        // Vogel's sunflower (even neighbour spacing ≈ NODE_GAP), and the border
        // sits a fixed margin beyond the outermost node — giving even node↔node
        // AND node↔border spacing while using the galaxy's space.
        const GAL_MARGIN: f32 = NODE_GAP * 0.62; // node ring → border gap
        let galaxy_tile = |nodes: &mut [Node], mem: &[usize], gid: u64, role: &str| -> Tile {
            let count = mem.len();
            // Spread so the outermost node sits ~`inner` out and neighbour gaps
            // stay ≈ NODE_GAP (the 0.72 factor fills the disc rather than
            // clustering at the centre).
            let inner = if count <= 1 {
                0.0
            } else {
                NODE_GAP * (count as f32).sqrt() * 0.72
            };
            let mut members = Vec::with_capacity(count);
            for (k, &idx) in mem.iter().enumerate() {
                let frac = if count <= 1 {
                    0.0
                } else {
                    (k as f32 + 0.5) / count as f32
                };
                let rr = inner * frac.sqrt();
                // Golden-angle sunflower, rotated per-galaxy so discs look varied.
                let a = k as f32 * 2.399_963_2 + galaxy_rot(gid);
                members.push((idx, V3::new(rr * a.cos(), 0.0, rr * a.sin())));
                nodes[idx].galaxy = Some(gid);
            }
            Tile {
                members,
                radius: (inner + GAL_MARGIN).max(NODE_GAP),
                info: Some((gid, role.to_string())),
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
                info: None,
            });
            for (role, mem) in &by_hub[h] {
                let gid = (*h as u64) * 16 + role_ord(role);
                let t = galaxy_tile(&mut self.nodes, mem, gid, role);
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
                info: None,
            });
        }

        // ----- Layered (Sugiyama) layout with barycenter crossing reduction -----
        // The standard, general way to minimise edge crossings on a flow graph:
        // put each tile in a layer by flow rank, then repeatedly reorder each
        // layer by the average position of its neighbours (the barycenter
        // heuristic, as used by Graphviz `dot`). Works for any topology/size.
        let m = tiles.len();
        let mut node_tile = vec![0usize; n];
        for (ti, t) in tiles.iter().enumerate() {
            for &(idx, _) in &t.members {
                node_tile[idx] = ti;
            }
        }
        let layer_of: Vec<usize> = tiles
            .iter()
            .map(|t| {
                let role = match &t.info {
                    Some((_, r)) => r.as_str(),
                    None => self.nodes[t.members[0].0].role.as_str(),
                };
                flow_layer(role)
            })
            .collect();
        let n_layers = layer_of.iter().copied().max().unwrap_or(0) + 1;

        // The unique tile-to-tile connection list (deduped).
        let mut tedges: Vec<(usize, usize)> = Vec::new();
        {
            let mut seen: HashSet<(usize, usize)> = HashSet::new();
            for e in &self.edges {
                let (ta, tb) = (node_tile[e.a], node_tile[e.b]);
                if ta != tb {
                    let key = if ta < tb { (ta, tb) } else { (tb, ta) };
                    if seen.insert(key) {
                        tedges.push(key);
                    }
                }
            }
        }

        // Proper Sugiyama requires every edge to span a single layer, so an edge
        // that skips layers gets *dummy* units inserted in the intermediate
        // layers and becomes a chain through them. Ordering the dummies
        // alongside the real tiles lets the optimiser route a long edge between
        // others without crossing — the standard fix for skip-layer edges (e.g.
        // an anchor egressing straight to an exit, or an admin control link to a
        // relay). Real tiles are units 0..m; dummies are appended after.
        let mut unit_layer: Vec<usize> = layer_of.clone();
        let mut unit_radius: Vec<f32> = tiles.iter().map(|t| t.radius).collect();
        let mut chains: Vec<Vec<usize>> = Vec::with_capacity(tedges.len());
        for &(a, b) in &tedges {
            let (la, lb) = (layer_of[a], layer_of[b]);
            let (lo_u, hi_u, lo, hi) = if la <= lb {
                (a, b, la, lb)
            } else {
                (b, a, lb, la)
            };
            if hi - lo <= 1 {
                chains.push(vec![lo_u, hi_u]);
            } else {
                let mut chain = vec![lo_u];
                for l in (lo + 1)..hi {
                    let d = unit_layer.len();
                    unit_layer.push(l);
                    unit_radius.push(DUMMY_R);
                    chain.push(d);
                }
                chain.push(hi_u);
                chains.push(chain);
            }
        }
        let n_units = unit_layer.len();

        // Adjacency over the layered graph (real + dummy), one entry per chain
        // segment — what the barycenter heuristic operates on.
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n_units];
        for chain in &chains {
            for w in chain.windows(2) {
                adj[w[0]].push(w[1]);
                adj[w[1]].push(w[0]);
            }
        }
        let mut layer_tiles: Vec<Vec<usize>> = vec![Vec::new(); n_layers];
        for (u, &l) in unit_layer.iter().enumerate() {
            layer_tiles[l].push(u);
        }

        // Layer x-offsets depend only on each layer's widest unit, not on the
        // within-layer order, so compute them once.
        let mut layer_x = vec![0.0f32; n_layers];
        {
            let mut x = 0.0;
            let mut prev_maxr = 0.0;
            for l in 0..n_layers {
                let maxr = layer_tiles[l]
                    .iter()
                    .map(|&u| unit_radius[u])
                    .fold(0.0, f32::max);
                if l > 0 {
                    x += prev_maxr + maxr + LAYER_GAP;
                }
                layer_x[l] = x;
                prev_maxr = maxr;
            }
        }

        // Lay units out along z by their current per-layer order (sized so
        // nothing overlaps), returning every unit's centre.
        let assign = |layer_tiles: &[Vec<usize>]| -> Vec<V3> {
            let mut centers = vec![V3::default(); n_units];
            for (l, lt) in layer_tiles.iter().enumerate() {
                let total_h: f32 = lt.iter().map(|&u| 2.0 * unit_radius[u] + CLUSTER_GAP).sum();
                let mut z = -total_h * 0.5;
                for &u in lt {
                    z += unit_radius[u];
                    centers[u] = V3::new(layer_x[l], 0.0, z);
                    z += unit_radius[u] + CLUSTER_GAP;
                }
            }
            centers
        };
        // Count genuine line-over-line crossings between chain segments. Two
        // segments that share a unit (e.g. edges from one anchor) never count;
        // segments in disjoint layer gaps cannot meet, so only same-gap
        // crossings are found.
        let segs: Vec<(usize, usize)> = chains
            .iter()
            .flat_map(|c| c.windows(2).map(|w| (w[0], w[1])))
            .collect();
        let count = |centers: &[V3]| -> usize {
            let mut x = 0;
            for i in 0..segs.len() {
                for j in (i + 1)..segs.len() {
                    let (a, b) = segs[i];
                    let (c, d) = segs[j];
                    if a == c || a == d || b == c || b == d {
                        continue;
                    }
                    if segments_cross(centers[a], centers[b], centers[c], centers[d]) {
                        x += 1;
                    }
                }
            }
            x
        };

        // ---- Exact layered crossing minimisation ----
        // With dummies inserted, every connection spans exactly one layer, so
        // the only crossings are *inversions between adjacent layers*: edges
        // (u->a) and (v->b) cross iff u,v and a,b are oppositely ordered. The sum
        // over adjacent layers is the well-studied layered (Sugiyama) crossing
        // number. Minimising it is NP-hard (Garey & Johnson; Eades & Wormald for
        // the two-layer case), so there is no polynomial closed-form "formula" —
        // but the established method (ILP / branch-and-bound, cf. Jünger & Mutzel
        // and the OGDF library) computes the exact minimum, and for the small
        // per-layer tile counts Rustynet produces we both reach it and *certify*
        // it. Pipeline: (1) a strong heuristic incumbent — optimal per-layer
        // reordering (the Linear Ordering Problem, solved exactly by Held-Karp
        // subset DP) iterated in up/down sweeps with deterministic multi-start;
        // then (2) branch-and-bound over layer permutations which, when it
        // finishes within budget, proves the global minimum.

        // above[u]/below[u] = connected units one layer up / down.
        let mut above: Vec<Vec<usize>> = vec![Vec::new(); n_units];
        let mut below: Vec<Vec<usize>> = vec![Vec::new(); n_units];
        for u in 0..n_units {
            for &w in &adj[u] {
                if unit_layer[w] == unit_layer[u] + 1 {
                    below[u].push(w);
                } else if unit_layer[w] + 1 == unit_layer[u] {
                    above[u].push(w);
                }
            }
        }
        let total_cross = |order: &[Vec<usize>]| -> usize {
            (0..n_layers.saturating_sub(1))
                .map(|l| bilayer_x(&order[l], &order[l + 1], &below))
                .sum()
        };

        // Exact optimal ordering of one layer with both neighbours fixed: the
        // Linear Ordering Problem on the pairwise crossing matrix, solved by
        // Held-Karp subset DP (O(2^k * k^2)). Layers wider than DP_MAX are left
        // as-is (the sweeps and B&B still drive the global result down).
        const DP_MAX: usize = 12;
        let optimal_layer = |order: &mut Vec<Vec<usize>>, l: usize| {
            let units = order[l].clone();
            let n = units.len();
            if !(2..=DP_MAX).contains(&n) {
                return;
            }
            let mut rank = vec![usize::MAX; n_units];
            if l > 0 {
                for (i, &u) in order[l - 1].iter().enumerate() {
                    rank[u] = i;
                }
            }
            if l + 1 < n_layers {
                for (i, &u) in order[l + 1].iter().enumerate() {
                    rank[u] = i;
                }
            }
            // cost when x is placed left of y: crossings between their edges to
            // the (fixed) neighbour layers.
            let cost_dir = |x: usize, y: usize| -> usize {
                let mut c = 0;
                for nbr in [&below, &above] {
                    for &a in &nbr[x] {
                        let ra = rank[a];
                        if ra == usize::MAX {
                            continue;
                        }
                        for &b in &nbr[y] {
                            let rb = rank[b];
                            if rb != usize::MAX && rb < ra {
                                c += 1;
                            }
                        }
                    }
                }
                c
            };
            let mut kk = vec![vec![0usize; n]; n];
            for i in 0..n {
                for j in 0..n {
                    if i != j {
                        kk[i][j] = cost_dir(units[i], units[j]);
                    }
                }
            }
            let size = 1usize << n;
            let mut dp = vec![usize::MAX; size];
            let mut choice = vec![usize::MAX; size];
            dp[0] = 0;
            for mask in 0..size {
                if dp[mask] == usize::MAX {
                    continue;
                }
                for j in 0..n {
                    if mask & (1 << j) != 0 {
                        continue;
                    }
                    let mut add = 0;
                    let mut mm = mask;
                    while mm != 0 {
                        let i = mm.trailing_zeros() as usize;
                        add += kk[i][j];
                        mm &= mm - 1;
                    }
                    let nm = mask | (1 << j);
                    let cand = dp[mask] + add;
                    if cand < dp[nm] {
                        dp[nm] = cand;
                        choice[nm] = j;
                    }
                }
            }
            let mut seq = Vec::with_capacity(n);
            let mut mask = size - 1;
            while mask != 0 {
                let j = choice[mask];
                seq.push(units[j]);
                mask &= !(1 << j);
            }
            seq.reverse();
            order[l] = seq;
        };

        // Iterated optimal sweeps to a fixed point.
        let sweep_optimize = |order: &mut Vec<Vec<usize>>| -> usize {
            let mut prev = total_cross(order);
            for _ in 0..8 {
                for l in 0..n_layers {
                    optimal_layer(order, l);
                }
                for l in (0..n_layers).rev() {
                    optimal_layer(order, l);
                }
                let c = total_cross(order);
                if c >= prev {
                    break;
                }
                prev = c;
            }
            total_cross(order)
        };

        // Incumbent: seed from the deterministic forest (DFS) ordering — with
        // dummies the data path is (near-)tree-shaped, and contiguous-subtree
        // placement is the textbook crossing-free tree drawing — then optimal-
        // sweep it, then diversify with a fixed-seed multi-start.
        let mut best_order = {
            let mut children: Vec<Vec<usize>> = vec![Vec::new(); n_units];
            let mut has_parent = vec![false; n_units];
            for u in 0..n_units {
                for &v in &above[u] {
                    if !children[v].contains(&u) {
                        children[v].push(u);
                    }
                    has_parent[u] = true;
                }
            }
            for ch in children.iter_mut() {
                ch.sort_unstable();
            }
            let mut roots: Vec<usize> = (0..n_units).filter(|&u| !has_parent[u]).collect();
            roots.sort_by_key(|&u| (std::cmp::Reverse(unit_layer[u]), u));
            let mut order_layers: Vec<Vec<usize>> = vec![Vec::new(); n_layers];
            let mut visited = vec![false; n_units];
            let mut stack: Vec<usize> = Vec::new();
            for r in roots {
                if visited[r] {
                    continue;
                }
                stack.push(r);
                while let Some(u) = stack.pop() {
                    if visited[u] {
                        continue;
                    }
                    visited[u] = true;
                    order_layers[unit_layer[u]].push(u);
                    for &c in children[u].iter().rev() {
                        if !visited[c] {
                            stack.push(c);
                        }
                    }
                }
            }
            for u in 0..n_units {
                if !visited[u] {
                    order_layers[unit_layer[u]].push(u);
                }
            }
            order_layers
        };
        let mut best_cross = sweep_optimize(&mut best_order);

        let mut seed: u64 = (m as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (tedges.len() as u64).wrapping_add(0xD1B5_4A32_D192_ED03);
        let mut next_rand = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut trial = best_order.clone();
        for _ in 0..40 {
            if best_cross == 0 {
                break;
            }
            trial.clone_from(&best_order);
            for lt in trial.iter_mut() {
                for i in (1..lt.len()).rev() {
                    let j = (next_rand() % (i as u64 + 1)) as usize;
                    lt.swap(i, j);
                }
            }
            let c = sweep_optimize(&mut trial);
            if c < best_cross {
                best_cross = c;
                best_order.clone_from(&trial);
            }
        }

        // Certify (or improve) with branch-and-bound. If it completes within
        // budget, the result is the proven global minimum for this layering.
        let certified = match bnb_min(&best_order, &below, n_layers, best_cross) {
            Some((minv, order)) => {
                best_cross = minv;
                best_order = order;
                true
            }
            None => false,
        };
        layer_tiles = best_order;

        let mut centers = assign(&layer_tiles);
        // The layered (polyline) crossing number the optimiser certified.
        debug_assert_eq!(
            best_cross,
            count(&centers),
            "combinatorial and geometric crossing counts must agree"
        );
        // What a STRAIGHT-LINE render actually shows: crossings between the
        // direct tile-to-tile segments. For a fixed ordering the polyline (via
        // dummies) can only avoid crossings a straight line would have, so
        // best_cross <= straight <= straight-optimum; hence when straight equals
        // the certified best_cross, the straight drawing is itself provably
        // minimal. (They coincide for the layouts Rustynet produces, because the
        // optimiser places each dummy on its edge's straight path.)
        let crossings = straight_crossings(&tedges, &centers);
        let certified = certified && crossings == best_cross;

        // Organic scatter: nudge each tile off the rigid grid (deterministically,
        // by id) so the map reads like a scattered universe rather than aligned
        // columns — but only keep the largest nudge scale that adds NO straight-
        // line crossing, so the proven minimum is preserved. Bounds are small
        // enough that galaxies never merge.
        {
            let clean = centers.clone();
            let mut scale_used = 0.0f32;
            for &scale in &[1.0f32, 0.7, 0.45, 0.25] {
                for t in 0..m {
                    let (jx, jz) = tile_jitter(t);
                    centers[t] = V3::new(clean[t].x + jx * scale, 0.0, clean[t].z + jz * scale);
                }
                if straight_crossings(&tedges, &centers) == crossings {
                    scale_used = scale;
                    break;
                }
            }
            if scale_used == 0.0 {
                centers = clean; // no safe nudge; keep the clean layout
            }
        }

        // Centre on the real tiles only (dummy units are routing artefacts).
        let mut mid = V3::default();
        for c in &centers[..m] {
            mid = mid.add(*c);
        }
        mid = mid.scale(1.0 / m.max(1) as f32);
        eprintln!(
            "[layout] tile connections = {}, crossings = {crossings} ({})",
            tedges.len(),
            if certified {
                "proven minimum"
            } else {
                "best found (instance too large to certify)"
            }
        );
        if std::env::var("RUSTYNET_DEBUG_XINGS").is_ok() {
            let desc = |u: usize| -> String {
                if u < m {
                    match &tiles[u].info {
                        Some((_, r)) => format!("G[{}]L{}", r, unit_layer[u]),
                        None => {
                            format!("{}L{}", self.nodes[tiles[u].members[0].0].id, unit_layer[u])
                        }
                    }
                } else {
                    format!("dummy#{u}L{}", unit_layer[u])
                }
            };
            for i in 0..segs.len() {
                for j in (i + 1)..segs.len() {
                    let (a, b) = segs[i];
                    let (c, d) = segs[j];
                    if a == c || a == d || b == c || b == d {
                        continue;
                    }
                    if segments_cross(centers[a], centers[b], centers[c], centers[d]) {
                        eprintln!(
                            "[xing] {}--{}  X  {}--{}",
                            desc(a),
                            desc(b),
                            desc(c),
                            desc(d)
                        );
                    }
                }
            }
        }

        // Apply, centring the whole map at the origin; record galaxy world boxes.
        self.galaxies.clear();
        for (t, center) in tiles.iter().zip(centers) {
            let base = center.sub(mid);
            for &(idx, off) in &t.members {
                self.nodes[idx].pos = base.add(off);
            }
            if let Some((gid, role)) = &t.info {
                self.galaxies.push(GalaxyBox {
                    gid: *gid,
                    center: base,
                    radius: t.radius,
                    role: role.clone(),
                    sides: galaxy_sides(t.members.len()),
                    rot: galaxy_rot(*gid),
                });
            }
        }

        // Frame the whole layout: take the world-space half-extents (nodes plus
        // galaxy footprints) and pick a camera distance that fits them. The view
        // is an oblique top-down, so the x span maps to screen width and the z
        // span (foreshortened) to height; scale by whichever is binding so the
        // default overview fits networks of any size. Calibrated against the
        // demo so small graphs keep comfortable margins.
        let mut hx = 1.0f32;
        let mut hz = 1.0f32;
        for nd in &self.nodes {
            hx = hx.max(nd.pos.x.abs());
            hz = hz.max(nd.pos.z.abs());
        }
        for g in &self.galaxies {
            hx = hx.max(g.center.x.abs() + g.radius);
            hz = hz.max(g.center.z.abs() + g.radius);
        }
        // x dominates width directly; z is foreshortened by the oblique angle.
        let extent = (hx).max(hz * 1.6);
        self.overview_distance = (extent * 1.25 + 220.0).clamp(540.0, 6000.0);
    }

    /// Count line-over-line crossings among the laid-out edges, using final node
    /// positions in the xz plane. Edges that share an endpoint (e.g. a galaxy's
    /// members all reaching one anchor) never count. This is the ground-truth
    /// the layout minimises; exercised by the crossing-regression tests.
    #[cfg(test)]
    fn edge_crossings(&self) -> usize {
        let segs: Vec<(usize, usize)> = self.edges.iter().map(|e| (e.a, e.b)).collect();
        let mut c = 0;
        for i in 0..segs.len() {
            for j in (i + 1)..segs.len() {
                let (a, b) = segs[i];
                let (p, q) = segs[j];
                if a == p || a == q || b == p || b == q {
                    continue;
                }
                if segments_cross(
                    self.nodes[a].pos,
                    self.nodes[b].pos,
                    self.nodes[p].pos,
                    self.nodes[q].pos,
                ) {
                    c += 1;
                }
            }
        }
        c
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

/// Sample a screen-space polyline at parameter t in [0,1] by arc length.
fn poly_sample(path: &[Pos2], t: f32) -> Pos2 {
    if path.len() < 2 {
        return path.first().copied().unwrap_or(Pos2::ZERO);
    }
    let total: f32 = path.windows(2).map(|w| w[0].distance(w[1])).sum();
    if total <= 1e-4 {
        return path[0];
    }
    let mut target = t.clamp(0.0, 1.0) * total;
    for w in path.windows(2) {
        let seg = w[0].distance(w[1]);
        if target <= seg {
            let f = if seg > 1e-4 { target / seg } else { 0.0 };
            return lerp_pos(w[0], w[1], f);
        }
        target -= seg;
    }
    *path.last().unwrap()
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
        let cam = Camera {
            distance: graph.overview_distance,
            ..Camera::default()
        };
        Self {
            graph,
            cam,
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
        self.view_anim = Some((V3::default(), self.graph.overview_distance));
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
                    self.cam = Camera {
                        distance: self.graph.overview_distance,
                        ..Camera::default()
                    };
                    self.focused_galaxy = None;
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

                // ----- galaxy polygons: project each galaxy's WORLD footprint to
                // an N-gon (straight edges, vertices marked with white dots). The
                // vertex count grows with the galaxy's node count and each galaxy
                // has its own rotation, so borders look varied rather than like a
                // grid of identical stamps. The world packing guarantees
                // node<->border and border<->border gaps. -----
                struct GalScreen {
                    gid: u64,
                    poly: Vec<Pos2>,
                    bounds: Rect,
                    color: Color32,
                    label: &'static str,
                }
                let mut galaxies: Vec<GalScreen> = Vec::new();
                for gb in &self.graph.galaxies {
                    if !self.visible(&gb.role) {
                        continue;
                    }
                    let sides = gb.sides;
                    let mut poly: Vec<Pos2> = Vec::with_capacity(sides);
                    let mut bounds: Option<Rect> = None;
                    let mut ok = true;
                    for s in 0..sides {
                        let ang = std::f32::consts::TAU * s as f32 / sides as f32
                            - std::f32::consts::FRAC_PI_2
                            + gb.rot;
                        let wp = gb.center.add(V3::new(
                            gb.radius * ang.cos(),
                            0.0,
                            gb.radius * ang.sin(),
                        ));
                        match self.cam.project(wp, rect) {
                            Some(p) => {
                                poly.push(p.screen);
                                bounds = Some(match bounds {
                                    Some(mut r) => {
                                        r.extend_with(p.screen);
                                        r
                                    }
                                    None => Rect::from_min_max(p.screen, p.screen),
                                });
                            }
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if let (true, Some(bounds)) = (ok, bounds) {
                        let rs = role_style(&gb.role);
                        galaxies.push(GalScreen {
                            gid: gb.gid,
                            poly,
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

                // ----- galaxy borders: polygons with white vertex dots -----
                if self.show_galaxies {
                    for g in &galaxies {
                        let hl = hovered_gal == Some(g.gid) || self.focused_galaxy == Some(g.gid);
                        // Faint fill.
                        painter.add(egui::Shape::convex_polygon(
                            g.poly.clone(),
                            with_alpha(g.color, if hl { 0.12 } else { 0.06 }),
                            Stroke::NONE,
                        ));
                        // Straight polygon edges.
                        let stroke = Stroke::new(
                            if hl { 2.4 } else { 1.4 },
                            with_alpha(g.color, if hl { 0.95 } else { 0.55 }),
                        );
                        for k in 0..g.poly.len() {
                            painter
                                .line_segment([g.poly[k], g.poly[(k + 1) % g.poly.len()]], stroke);
                        }
                        // White dots at each polygon vertex.
                        let dot = with_alpha(Color32::WHITE, if hl { 1.0 } else { 0.85 });
                        for &v in &g.poly {
                            painter.circle_filled(v, if hl { 3.0 } else { 2.4 }, dot);
                        }
                        painter.text(
                            Pos2::new(g.bounds.center().x, g.bounds.top() - 5.0),
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

                // ----- edges (behind nodes), routed around obstacles -----
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
                    // Connections are always straight lines (node to node): the
                    // layout already minimises straight-line crossings, so no
                    // detour routing is needed or wanted.
                    let spath: [Pos2; 2] = [pa.screen, pb.screen];
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
                    let stroke = Stroke::new(width, with_alpha(col, alpha));
                    for w in spath.windows(2) {
                        painter.line_segment([w[0], w[1]], stroke);
                    }

                    // ----- pulse: wave blob for this hop, along the straight line.
                    // It only travels while the upstream node is "firing"
                    // (fire_at..+TRAVEL), so a node emits downstream only after all
                    // its upstream blobs melted in (+ a PULSE_PAUSE). -----
                    if edge_has_flow(&e.kind)
                        && live
                        && self.animate_flow
                        && self.graph.cycle_len > 0.0
                    {
                        let up_is_a = role_flow_rank(&a.role) <= role_flow_rank(&b.role);
                        let up_idx = if up_is_a { e.a } else { e.b };
                        // Path oriented upstream -> downstream.
                        let mut flow = spath;
                        if !up_is_a {
                            flow.reverse();
                        }
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
                                let p = poly_sample(&flow, t);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dto(nodes: &[(&str, &str)], edges: &[(&str, &str, &str)]) -> GraphDto {
        GraphDto {
            nodes: nodes
                .iter()
                .map(|(id, role)| NodeDto {
                    id: (*id).into(),
                    label: None,
                    role: Some((*role).into()),
                    status: Some("online".into()),
                    position: None,
                    meta: BTreeMap::new(),
                })
                .collect(),
            edges: edges
                .iter()
                .map(|(a, b, k)| EdgeDto {
                    from: (*a).into(),
                    to: (*b).into(),
                    kind: Some((*k).into()),
                    active: None,
                })
                .collect(),
        }
    }

    #[test]
    fn segments_cross_basic() {
        let a = V3::new(0.0, 0.0, 0.0);
        let b = V3::new(2.0, 0.0, 2.0);
        let c = V3::new(0.0, 0.0, 2.0);
        let d = V3::new(2.0, 0.0, 0.0);
        assert!(segments_cross(a, b, c, d), "an X should cross");
        // Parallel, shifted: must not cross.
        let e = V3::new(0.0, 0.0, 5.0);
        let f = V3::new(2.0, 0.0, 7.0);
        assert!(!segments_cross(a, b, e, f));
        // Sharing a touch point only at an endpoint is not a proper crossing.
        assert!(!segments_cross(a, b, b, V3::new(4.0, 0.0, 0.0)));
    }

    #[test]
    fn demo_layout_has_no_edge_crossings() {
        let g = Graph::from_dto(demo_graph());
        assert_eq!(
            g.edge_crossings(),
            0,
            "the demo layout must be drawn without edge crossings"
        );
    }

    #[test]
    fn linear_flow_has_no_crossings() {
        // client galaxy -> anchor -> relay -> exit, many clients on one anchor.
        let mut nodes = vec![("a1", "anchor"), ("r1", "relay"), ("e1", "exit")];
        let mut edges = vec![("a1", "r1", "data_path"), ("r1", "e1", "data_path")];
        let clients: Vec<String> = (0..8).map(|i| format!("c{i}")).collect();
        for c in &clients {
            nodes.push((c.as_str(), "client"));
            edges.push((c.as_str(), "a1", "data_path"));
        }
        let g = Graph::from_dto(dto(&nodes, &edges));
        assert_eq!(g.edge_crossings(), 0);
    }

    #[test]
    fn multi_anchor_relay_fanin_has_no_crossings() {
        // Two relays each serving two anchors (a many-to-one fan-in) plus a
        // skip edge — the coupled case the tree ordering must resolve.
        let g = Graph::from_dto(dto(
            &[
                ("a1", "anchor"),
                ("a2", "anchor"),
                ("a3", "anchor"),
                ("a4", "anchor"),
                ("r1", "relay"),
                ("r2", "relay"),
                ("e1", "exit"),
                ("e2", "blind_exit"),
                ("c1", "client"),
                ("c2", "client"),
                ("c3", "client"),
                ("c4", "client"),
            ],
            &[
                ("c1", "a1", "data_path"),
                ("c2", "a2", "data_path"),
                ("c3", "a3", "data_path"),
                ("c4", "a4", "data_path"),
                ("a1", "r1", "data_path"),
                ("a2", "r1", "data_path"),
                ("a3", "r2", "data_path"),
                ("a4", "r2", "data_path"),
                ("r1", "e1", "data_path"),
                ("r2", "e2", "data_path"),
                ("a1", "e1", "data_path"),
            ],
        ));
        assert_eq!(g.edge_crossings(), 0);
    }

    #[test]
    fn layout_is_deterministic() {
        let a = Graph::from_dto(demo_graph());
        let b = Graph::from_dto(demo_graph());
        let pa: Vec<(f32, f32)> = a.nodes.iter().map(|n| (n.pos.x, n.pos.z)).collect();
        let pb: Vec<(f32, f32)> = b.nodes.iter().map(|n| (n.pos.x, n.pos.z)).collect();
        assert_eq!(pa, pb, "layout must be repeatable run-to-run");
    }

    #[test]
    fn galaxy_polygon_sides_grow_with_nodes() {
        assert_eq!(galaxy_sides(2), 5, "smallest galaxy is a pentagon");
        assert!(
            galaxy_sides(5) > galaxy_sides(2),
            "more nodes => more sides"
        );
        assert!(
            galaxy_sides(50) <= 16,
            "sides are capped so big galaxies stay round"
        );
        assert!(galaxy_sides(3) >= 5 && galaxy_sides(1) >= 5);
    }

    #[test]
    fn data_flow_schedule_is_present() {
        // The pulse wave (client -> ... -> exit) must still be scheduled.
        let g = Graph::from_dto(demo_graph());
        assert!(g.cycle_len > 0.0, "a pulse cycle must exist");
        assert_eq!(g.fire_at.len(), g.nodes.len());
        // A source (client) fires before a downstream exit.
        let client = g.nodes.iter().position(|n| n.role == "client").unwrap();
        let exit = g.nodes.iter().position(|n| n.role == "exit").unwrap();
        assert!(
            g.fire_at[client] <= g.fire_at[exit],
            "data flows downstream, source emits no later than the exit"
        );
    }
}

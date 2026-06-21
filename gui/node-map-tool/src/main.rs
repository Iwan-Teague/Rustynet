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

/// How a status makes the "ball of light" behave.
struct StatusStyle {
    brightness: f32,
    glow: f32,
    pulse: f32,
    desat: f32,
    flicker: f32,
}

fn status_style(status: &str) -> StatusStyle {
    match status {
        "online" => StatusStyle {
            brightness: 1.00,
            glow: 1.00,
            pulse: 0.10,
            desat: 0.00,
            flicker: 0.00,
        },
        "connecting" => StatusStyle {
            brightness: 0.72,
            glow: 0.62,
            pulse: 0.05,
            desat: 0.30,
            flicker: 0.14,
        },
        "powered_off" => StatusStyle {
            brightness: 0.24,
            glow: 0.15,
            pulse: 0.00,
            desat: 0.90,
            flicker: 0.00,
        },
        // "offline" and anything unknown -> dim, mostly grey (fail-visible).
        _ => StatusStyle {
            brightness: 0.42,
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

/// Layout tunables.
const CHARGE: f32 = -180.0; // base node repulsion (scaled per-role below)
const GRAVITY: f32 = 0.011; // pull toward centre
const DAMPING: f32 = 0.86;
const MAX_SPEED: f32 = 5.0; // per-step velocity clamp (stops blow-ups)

// Spring rest lengths: leaves hug their hub (tight orbit), backbone spreads out.
const LEAF_LINK: f32 = 10.0;
const BACKBONE_LINK: f32 = 26.0;
// Collision/separation: nodes never overlap. World radius = size_mult * this,
// and every pair is kept at least (r_a + r_b + NODE_MARGIN) apart.
const NODE_WORLD_R: f32 = 2.6;
const NODE_MARGIN: f32 = 7.5;
const COLLISION_K: f32 = 0.5;
// Cohesion: leaves sharing a hub are pulled toward their group's centre so they
// clump into one local group (instead of spreading into a ring around the hub).
const COHESION_K: f32 = 0.06;

/// Leaf roles orbit the node their path follows; backbone roles form the skeleton.
fn is_leaf_role(role: &str) -> bool {
    matches!(role, "client" | "nas" | "llm")
}

/// Per-role repulsion weight: backbone pushes harder so each hub's cluster ends
/// up in a distinct location; leaves push gently so they stay near their hub.
fn role_repulsion(role: &str) -> f32 {
    if is_leaf_role(role) {
        0.6
    } else {
        1.7
    }
}

/// World-space collision radius for a role.
fn role_world_radius(role: &str) -> f32 {
    role_style(role).size_mult * NODE_WORLD_R
}

/// Spring rest length for an edge (short when a leaf is involved).
fn edge_rest_length(kind: &str, leaf_either: bool) -> f32 {
    let base = if leaf_either {
        LEAF_LINK
    } else {
        BACKBONE_LINK
    };
    match kind {
        "control" => base * 1.1,
        "potential" => base * 1.35,
        _ => base,
    }
}

/// Spring strength per edge kind: the actual data path binds tightest.
fn edge_spring_k(kind: &str) -> f32 {
    match kind {
        "data_path" => 0.07,
        "control" => 0.04,
        "potential" => 0.015,
        _ => 0.035,
    }
}

// ----------------------- THEME / GLOBAL CONSTANTS ----------------------
const BG: Color32 = Color32::from_rgb(64, 69, 80); // window background (grey)
const NEBULA: Color32 = Color32::from_rgb(86, 92, 108); // faked center-lift tint
const WARM_WHITE: Color32 = Color32::from_rgb(255, 248, 236); // glow highlight
const FIBER: Color32 = Color32::from_rgb(176, 206, 236); // edge/particle tint
const GREY_DOWN: Color32 = Color32::from_rgb(120, 126, 142); // desaturation target
const TEXT_HI: Color32 = Color32::from_rgb(232, 238, 248);
const TEXT_DIM: Color32 = Color32::from_rgb(186, 194, 210);

// ------------------------------ GLOW -----------------------------------
// A smooth, faint glow built from many thin layers whose radius shrinks AND
// whose alpha fades from the core outward, so they blend into a soft aura
// rather than reading as discrete rings.
const GLOW_LAYERS: usize = 14;
const GLOW_OUTER: f32 = 1.8; // outermost halo radius (x core_r)
const GLOW_INNER: f32 = 1.0; // innermost halo radius (meets the core)
const GLOW_PEAK: f32 = 0.085; // strongest per-layer alpha (nearest the core)
const GLOW_FALLOFF: f32 = 2.6; // higher = faster fade outward (fainter halo)
const GLOW_WARM: f32 = 0.15; // how much the inner glow warms toward WARM_WHITE
const CORE_R_MULT: f32 = 0.72;
const CORE_ALPHA: f32 = 0.95;

// ------------------------------ DEPTH ----------------------------------
// DEPTH_FADE_MIN = far-node opacity floor; DEPTH_FOG_MAX = far-node tint toward
// BG. REF_DISTANCE maps camera-space depth onto the design's perspective_scale
// band (~0.5 far .. 2.6 near), tuned so the default camera view produces
// pleasing node sizes and a usable depth gradient.
const DEPTH_FADE_MIN: f32 = 0.5;
const DEPTH_FOG_MAX: f32 = 0.45;
const REF_DISTANCE: f32 = 135.0;

// ------------------------------ PULSE ----------------------------------
// One slow pulse per active data path, travelling downstream (toward the exit)
// and melting into the receiving node as it arrives.
const PULSE_SPEED: f32 = 0.14; // cycles/sec along the segment (low = slow)
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

/// Orbit camera around a target point.
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
            yaw: 0.6,
            pitch: 0.35,
            distance: 95.0,
            fov: 55_f32.to_radians(),
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
    vel: V3,
    pinned: bool,
    /// Smoothly-ramped "lit" factor (0..1) that eases toward the status target
    /// so a node fading up on connect/online doesn't pop.
    lit: f32,
    /// For leaf nodes: the index of the upstream hub (anchor) they attach to.
    /// Leaves sharing a hub form one local group (they cohere, don't repel).
    hub: Option<usize>,
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
}

impl Graph {
    fn from_dto(dto: GraphDto) -> Self {
        let mut nodes = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let n_total = dto.nodes.len().max(1);
        for (i, nd) in dto.nodes.into_iter().enumerate() {
            let pinned = nd.position.is_some();
            let pos = match &nd.position {
                Some(p) => V3::new(p.x, p.y, p.z),
                None => {
                    // Scatter on a ring so the force layout has somewhere to start.
                    let t = (i as f32 / n_total as f32) * std::f32::consts::TAU;
                    let r = 18.0 + (i as f32 * 2.3).sin().abs() * 14.0;
                    V3::new(t.cos() * r, ((i as f32) * 1.7).sin() * 10.0, t.sin() * r)
                }
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
                vel: V3::default(),
                pinned,
                lit,
                hub: None,
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

        // Assign each leaf node its hub: the connected node nearest the exit
        // (highest flow rank). Leaves sharing a hub form one local group.
        for i in 0..nodes.len() {
            if !is_leaf_role(&nodes[i].role) {
                continue;
            }
            let my_rank = role_flow_rank(&nodes[i].role);
            let mut best: Option<(i32, usize)> = None;
            for e in &edges {
                let other = if e.a == i {
                    Some(e.b)
                } else if e.b == i {
                    Some(e.a)
                } else {
                    None
                };
                if let Some(o) = other {
                    let r = role_flow_rank(&nodes[o].role);
                    if r > my_rank && best.is_none_or(|(br, _)| r > br) {
                        best = Some((r, o));
                    }
                }
            }
            nodes[i].hub = best.map(|(_, o)| o);
        }

        Graph { nodes, edges }
    }

    /// One step of a spring-electrical force-directed layout in 3D, with role-
    /// weighted repulsion (distinct hub clusters), short leaf links (satellites
    /// orbit their hub) and a hard separation force (guaranteed spacing).
    fn step_layout(&mut self) {
        let n = self.nodes.len();
        // Precompute per-node repulsion weight + collision radius once.
        let w: Vec<f32> = self
            .nodes
            .iter()
            .map(|nd| role_repulsion(&nd.role))
            .collect();
        let r: Vec<f32> = self
            .nodes
            .iter()
            .map(|nd| role_world_radius(&nd.role))
            .collect();

        // Repulsion + hard separation (O(n^2) — fine at prototype scale).
        for i in 0..n {
            for j in (i + 1)..n {
                let d = self.nodes[i].pos.sub(self.nodes[j].pos);
                let mut d2 = d.dot(d);
                if d2 < 0.01 {
                    d2 = 0.01;
                }
                let dist = d2.sqrt();
                let dir = d.scale(1.0 / dist);

                // Same-group leaves don't repel (so they clump); everyone else
                // gets inverse-square repulsion, scaled by both roles' weight.
                let same_group =
                    self.nodes[i].hub.is_some() && self.nodes[i].hub == self.nodes[j].hub;
                if !same_group {
                    let f = CHARGE * w[i] * w[j] / d2;
                    let push = dir.scale(f);
                    self.nodes[i].vel = self.nodes[i].vel.sub(push);
                    self.nodes[j].vel = self.nodes[j].vel.add(push);
                }

                // Hard separation: never let two nodes' glows overlap.
                let min_sep = r[i] + r[j] + NODE_MARGIN;
                if dist < min_sep {
                    let sep = dir.scale((min_sep - dist) * COLLISION_K);
                    self.nodes[i].vel = self.nodes[i].vel.add(sep);
                    self.nodes[j].vel = self.nodes[j].vel.sub(sep);
                }
            }
        }

        // Spring attraction along edges (variable rest length + per-kind strength).
        for e in &self.edges {
            let leaf = is_leaf_role(&self.nodes[e.a].role) || is_leaf_role(&self.nodes[e.b].role);
            let rest = edge_rest_length(&e.kind, leaf);
            let k = edge_spring_k(&e.kind);
            let d = self.nodes[e.b].pos.sub(self.nodes[e.a].pos);
            let dist = d.len().max(0.01);
            let f = (dist - rest) * k;
            let pull = d.scale(1.0 / dist).scale(f);
            self.nodes[e.a].vel = self.nodes[e.a].vel.add(pull);
            self.nodes[e.b].vel = self.nodes[e.b].vel.sub(pull);
        }

        // Group cohesion: pull each leaf toward the centre of its hub-group so
        // the satellites of a hub clump together (one tight group) instead of
        // spreading evenly around it.
        let mut group_sum: HashMap<usize, (V3, u32)> = HashMap::new();
        for node in &self.nodes {
            if let Some(h) = node.hub {
                let entry = group_sum.entry(h).or_insert((V3::default(), 0));
                entry.0 = entry.0.add(node.pos);
                entry.1 += 1;
            }
        }
        for node in &mut self.nodes {
            if let Some(h) = node.hub {
                if let Some(&(sum, count)) = group_sum.get(&h) {
                    if count > 1 {
                        let centroid = sum.scale(1.0 / count as f32);
                        node.vel = node.vel.add(centroid.sub(node.pos).scale(COHESION_K));
                    }
                }
            }
        }

        // Gravity toward centre + integrate (with a velocity clamp).
        for node in &mut self.nodes {
            if node.pinned {
                node.vel = V3::default();
                continue;
            }
            node.vel = node.vel.sub(node.pos.scale(GRAVITY));
            node.vel = node.vel.scale(DAMPING);
            let speed = node.vel.len();
            if speed > MAX_SPEED {
                node.vel = node.vel.scale(MAX_SPEED / speed);
            }
            node.pos = node.pos.add(node.vel);
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
    settle: i32,
    show_labels: bool,
    animate_flow: bool,
    auto_rotate: bool,
    live_sim: bool,
    hidden_roles: HashSet<String>,
    selected: Option<usize>,
    sim_accum: f32,
    rng: u64,
}

impl App {
    fn new(graph: Graph) -> Self {
        Self {
            graph,
            cam: Camera::default(),
            settle: 520,
            show_labels: true,
            animate_flow: true,
            auto_rotate: false,
            live_sim: true,
            hidden_roles: HashSet::new(),
            selected: None,
            sim_accum: 0.0,
            rng: 0x9e3779b97f4a7c15,
        }
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

        // Layout settling + auto-rotate + live demo.
        if self.settle > 0 {
            self.graph.step_layout();
            self.settle -= 1;
        }
        if self.auto_rotate {
            self.cam.yaw += dt * 0.25;
        }
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
                ui.checkbox(&mut self.auto_rotate, "Auto-rotate");
                ui.checkbox(&mut self.live_sim, "Live demo updates");
                ui.add_space(6.0);
                if ui.button("Reset camera").clicked() {
                    self.cam = Camera::default();
                }
                ui.add_space(10.0);
                ui.label(
                    egui::RichText::new(
                        "Drag: orbit · scroll: zoom · right-drag: pan · click a node to inspect.",
                    )
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

                // ----- camera interaction -----
                if response.dragged() {
                    let d = response.drag_delta();
                    if response.dragged_by(egui::PointerButton::Secondary)
                        || response.dragged_by(egui::PointerButton::Middle)
                    {
                        // Pan: move the target in the camera plane.
                        let cam = self.cam.position();
                        let forward = self.cam.target.sub(cam).norm();
                        let right = forward.cross(V3::new(0.0, 1.0, 0.0)).norm();
                        let up = right.cross(forward);
                        let k = self.cam.distance * 0.0015;
                        self.cam.target = self
                            .cam
                            .target
                            .add(right.scale(-d.x * k))
                            .add(up.scale(d.y * k));
                    } else {
                        // Orbit.
                        self.cam.yaw += d.x * 0.01;
                        self.cam.pitch = (self.cam.pitch + d.y * 0.01).clamp(-1.5, 1.5);
                    }
                }
                if response.hovered() {
                    let scroll =
                        ctx.input(|i| i.smooth_scroll_delta.y + (i.zoom_delta() - 1.0) * 200.0);
                    if scroll != 0.0 {
                        self.cam.distance =
                            (self.cam.distance * (1.0 - scroll * 0.0015)).clamp(12.0, 600.0);
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

                // ----- hover/click picking (before drawing, so focus can emphasise) -----
                let mut hover_idx: Option<usize> = None;
                if let Some(mp) = response.hover_pos() {
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
                if response.clicked() {
                    self.selected = hover_idx;
                }
                // Focus = whatever is hovered, else the sticky selection.
                let focus = hover_idx.or(self.selected);
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

                    // ----- pulse: one slow blip per active data path, flowing
                    // downstream (toward the exit) and melting into the receiver -----
                    if edge_has_flow(&e.kind) && live && self.animate_flow {
                        // Orient from the upstream endpoint toward the one nearer
                        // the exit (higher flow rank).
                        let (src, dst) = if role_flow_rank(&a.role) <= role_flow_rank(&b.role) {
                            (pa.screen, pb.screen)
                        } else {
                            (pb.screen, pa.screen)
                        };
                        let cra = core_r_of(role_style(&a.role).size_mult, pa.depth);
                        let crb = core_r_of(role_style(&b.role).size_mult, pb.depth);
                        let pr = ((cra + crb) * 0.5 * 0.40).clamp(1.6, 4.6);
                        // Per-edge phase so pulses don't all march in lock-step.
                        let phase = ((e.a * 13 + e.b * 7) % 97) as f32 / 97.0;
                        let t = (time * PULSE_SPEED + phase).fract();
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
                                with_alpha(Color32::from_rgb(248, 252, 255), PULSE_CORE_A * env),
                            );
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

                    // Brightness: online breathes slow, connecting is nervous + flickers.
                    let pulse_speed = if node.status == "connecting" {
                        5.5
                    } else {
                        1.6
                    };
                    let seed = d.idx as f32 * 12.9898;
                    let mut brightness =
                        st.brightness + (time * pulse_speed + seed).sin() * st.pulse;
                    if st.flicker > 0.0 {
                        brightness += (self_rand_static(time, d.idx) - 0.5) * st.flicker;
                    }
                    brightness = brightness.clamp(0.05, 1.25);

                    // Depth fog/fade.
                    let depth_t = depth_t_of(d.p.depth);
                    let depth_fade = lerp(DEPTH_FADE_MIN, 1.0, depth_t);
                    let mut color = lerp_color(rs.color, GREY_DOWN, st.desat);
                    color = lerp_color(BG, color, lerp(1.0 - DEPTH_FOG_MAX, 1.0, depth_t));
                    let mut glow_op = st.glow * depth_fade;
                    let mut bri = brightness * depth_fade;

                    // Smooth status-change ramp.
                    glow_op *= lerp(0.35, 1.0, node.lit);
                    bri *= lerp(0.5, 1.0, node.lit);

                    // Focus mode: dim everything except the focused node.
                    if focused {
                        if focus == Some(d.idx) {
                            glow_op *= 1.25;
                        } else {
                            glow_op *= 0.42;
                            bri *= 0.6;
                        }
                    }

                    let core_r = core_r_of(rs.size_mult, d.p.depth);

                    // Smooth faint glow: many thin layers, radius + alpha both
                    // falling off from the core outward (blends, no rings).
                    for i in 0..GLOW_LAYERS {
                        // t: 0 at the outermost layer -> 1 at the innermost.
                        let t = i as f32 / (GLOW_LAYERS - 1) as f32;
                        let r = core_r * (GLOW_INNER + (GLOW_OUTER - GLOW_INNER) * (1.0 - t));
                        let a = GLOW_PEAK * t.powf(GLOW_FALLOFF) * bri * glow_op;
                        let col = lerp_color(color, WARM_WHITE, t * GLOW_WARM);
                        painter.circle_filled(d.p.screen, r, with_alpha(col, a));
                    }
                    // Coloured core dot (role colour, lifted just slightly).
                    let core_col = lerp_color(color, WARM_WHITE, 0.12);
                    painter.circle_filled(
                        d.p.screen,
                        core_r * CORE_R_MULT,
                        with_alpha(core_col, CORE_ALPHA * bri),
                    );

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

                // ----- labels (above nodes; near nodes drawn last = on top) -----
                if self.show_labels {
                    for d in &drawn {
                        let node = &self.graph.nodes[d.idx];
                        if node.status == "powered_off" {
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
                        let pos = d.p.screen + Vec2::new(0.0, -core_r - 6.0);
                        // Legibility plate behind the text.
                        let galley =
                            painter.layout_no_wrap(node.label.clone(), font.clone(), TEXT_DIM);
                        let sz = galley.size();
                        let plate = Rect::from_center_size(
                            pos - Vec2::new(0.0, sz.y * 0.5),
                            sz + Vec2::new(8.0, 4.0),
                        );
                        painter.rect_filled(
                            plate,
                            3.0,
                            with_alpha(Color32::from_rgb(4, 6, 12), 0.45 * label_alpha),
                        );
                        let color = if is_focus { TEXT_HI } else { TEXT_DIM };
                        painter.text(
                            pos,
                            Align2::CENTER_BOTTOM,
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
            node("llm-box", "llm", "connecting", "100.64.0.41", "linux"),
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
            edge("llm-box", "anchor-us", "data_path"),
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

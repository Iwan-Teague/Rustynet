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
    size: f32,
}

/// Role registry. Keys must match the `role` field in the data feed. Mirrors the
/// Rustynet role + capability set (client, admin, anchor, exit, blind_exit,
/// relay, + service roles nas/llm). Colours are placeholders.
fn role_style(role: &str) -> RoleStyle {
    match role {
        "client" => RoleStyle {
            color: Color32::from_rgb(61, 220, 132),
            label: "Client",
            desc: "Endpoint device",
            size: 1.0,
        },
        "admin" => RoleStyle {
            color: Color32::from_rgb(95, 208, 255),
            label: "Admin",
            desc: "Control / operator",
            size: 1.15,
        },
        "anchor" => RoleStyle {
            color: Color32::from_rgb(255, 210, 63),
            label: "Anchor",
            desc: "Coordination anchor",
            size: 1.2,
        },
        "relay" => RoleStyle {
            color: Color32::from_rgb(180, 107, 255),
            label: "Relay",
            desc: "Zero-ingress relay",
            size: 1.2,
        },
        "exit" => RoleStyle {
            color: Color32::from_rgb(255, 140, 59),
            label: "Exit",
            desc: "Internet egress",
            size: 1.25,
        },
        "blind_exit" => RoleStyle {
            color: Color32::from_rgb(255, 77, 77),
            label: "Blind exit",
            desc: "Egress, no plaintext",
            size: 1.25,
        },
        "nas" => RoleStyle {
            color: Color32::from_rgb(77, 184, 255),
            label: "NAS",
            desc: "Storage service",
            size: 1.1,
        },
        "llm" => RoleStyle {
            color: Color32::from_rgb(157, 123, 255),
            label: "LLM",
            desc: "Inference service",
            size: 1.1,
        },
        _ => RoleStyle {
            color: Color32::from_rgb(138, 151, 173),
            label: "Unknown",
            desc: "Unrecognised role",
            size: 1.0,
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
            brightness: 1.0,
            glow: 1.0,
            pulse: 0.18,
            desat: 0.0,
            flicker: 0.0,
        },
        "connecting" => StatusStyle {
            brightness: 0.75,
            glow: 0.7,
            pulse: 0.0,
            desat: 0.3,
            flicker: 0.6,
        },
        "powered_off" => StatusStyle {
            brightness: 0.12,
            glow: 0.06,
            pulse: 0.0,
            desat: 1.0,
            flicker: 0.0,
        },
        // "offline" and anything unknown -> dim, mostly grey (fail-visible).
        _ => StatusStyle {
            brightness: 0.28,
            glow: 0.22,
            pulse: 0.0,
            desat: 0.85,
            flicker: 0.0,
        },
    }
}

/// How a connection line is drawn.
struct EdgeKindStyle {
    width: f32,
    flow: bool,
    base_opacity: f32,
}

fn edge_kind_style(kind: &str) -> EdgeKindStyle {
    match kind {
        "control" => EdgeKindStyle {
            width: 1.0,
            flow: false,
            base_opacity: 0.28,
        },
        "potential" => EdgeKindStyle {
            width: 0.8,
            flow: false,
            base_opacity: 0.14,
        },
        // "data_path" and anything unknown -> active traffic path.
        _ => EdgeKindStyle {
            width: 1.6,
            flow: true,
            base_opacity: 0.55,
        },
    }
}

/// Layout + look tunables.
const LINK_DISTANCE: f32 = 14.0;
const CHARGE: f32 = -260.0; // node repulsion
const GRAVITY: f32 = 0.015; // pull toward centre
const DAMPING: f32 = 0.86;

const GREY: Color32 = Color32::from_rgb(90, 96, 114);
const BG: Color32 = Color32::from_rgb(5, 7, 13);

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
    fn lerp(self, o: V3, t: f32) -> V3 {
        self.add(o.sub(self).scale(t))
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
    /// World->screen size multiplier (perspective).
    scale: f32,
    /// Depth in front of the camera (smaller = nearer).
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
            scale: focal / z,
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
            nodes.push(Node {
                label: nd.label.unwrap_or_else(|| nd.id.clone()),
                id: nd.id,
                role: nd.role.unwrap_or_else(|| "client".into()),
                status: nd.status.unwrap_or_else(|| "offline".into()),
                meta: nd.meta,
                pos,
                vel: V3::default(),
                pinned,
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
        Graph { nodes, edges }
    }

    /// One step of a light spring-electrical force-directed layout in 3D.
    fn step_layout(&mut self) {
        let n = self.nodes.len();
        // Repulsion (O(n^2) — fine at prototype scale).
        for i in 0..n {
            for j in (i + 1)..n {
                let d = self.nodes[i].pos.sub(self.nodes[j].pos);
                let mut d2 = d.dot(d);
                if d2 < 0.01 {
                    d2 = 0.01;
                }
                let dist = d2.sqrt();
                let f = CHARGE / d2;
                let dir = d.scale(1.0 / dist);
                let push = dir.scale(f);
                self.nodes[i].vel = self.nodes[i].vel.sub(push);
                self.nodes[j].vel = self.nodes[j].vel.add(push);
            }
        }
        // Spring attraction along edges.
        for e in &self.edges {
            let d = self.nodes[e.b].pos.sub(self.nodes[e.a].pos);
            let dist = d.len().max(0.01);
            let f = (dist - LINK_DISTANCE) * 0.05;
            let pull = d.scale(1.0 / dist).scale(f);
            self.nodes[e.a].vel = self.nodes[e.a].vel.add(pull);
            self.nodes[e.b].vel = self.nodes[e.b].vel.sub(pull);
        }
        // Gravity toward centre + integrate.
        for node in &mut self.nodes {
            if node.pinned {
                node.vel = V3::default();
                continue;
            }
            node.vel = node.vel.sub(node.pos.scale(GRAVITY));
            node.vel = node.vel.scale(DAMPING);
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
            settle: 260,
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

                // ----- starfield -----
                draw_starfield(&painter, rect);

                // ----- project nodes -----
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
                    let col = lerp_color(ca, cb, 0.5);
                    let op = kind.base_opacity * if live { 1.0 } else { 0.25 };
                    painter.line_segment(
                        [pa.screen, pb.screen],
                        Stroke::new(kind.width, with_alpha(col, op)),
                    );

                    // Travelling flow particles in 3D (perspective-correct).
                    if kind.flow && live && self.animate_flow {
                        let count = 3;
                        for k in 0..count {
                            let mut t = (time * 0.18 + k as f32 / count as f32) % 1.0;
                            if t < 0.0 {
                                t += 1.0;
                            }
                            let wp = a.pos.lerp(b.pos, t);
                            if let Some(pp) = self.cam.project(wp, rect) {
                                let r = (2.4 * pp.scale * 0.1).clamp(1.2, 4.0);
                                painter.circle_filled(pp.screen, r * 1.8, with_alpha(col, 0.12));
                                painter.circle_filled(
                                    pp.screen,
                                    r,
                                    with_alpha(lerp_color(col, Color32::WHITE, 0.5), 0.95),
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

                    let mut bright = st.brightness;
                    if st.pulse > 0.0 {
                        bright += (time * 2.5 + node.pos.x).sin() * st.pulse;
                    }
                    if st.flicker > 0.0 {
                        bright *= 0.6 + self_rand_static(time, d.idx) * st.flicker;
                    }
                    let col = lerp_color(rs.color, GREY, st.desat);

                    // Core radius in pixels (perspective-scaled).
                    let core_r = (rs.size * 1.7 * d.p.scale * 0.1).clamp(2.0, 26.0);

                    // Glow halo: stacked translucent circles read as a ball of light.
                    let glow_a = st.glow * bright.max(0.08);
                    for layer in 0..6 {
                        let rr = core_r * (1.4 + layer as f32 * 0.95);
                        let aa = glow_a * (0.16 / (layer as f32 * 0.5 + 1.0));
                        painter.circle_filled(d.p.screen, rr, with_alpha(col, aa));
                    }
                    // Hot core.
                    let hot = lerp_color(col, Color32::WHITE, 0.55 * bright.clamp(0.0, 1.0));
                    painter.circle_filled(
                        d.p.screen,
                        core_r,
                        with_alpha(hot, (0.65 + 0.35 * bright).clamp(0.2, 1.0)),
                    );

                    // Selection ring.
                    if self.selected == Some(d.idx) {
                        painter.circle_stroke(
                            d.p.screen,
                            core_r + 5.0,
                            Stroke::new(1.5, Color32::from_rgb(95, 208, 255)),
                        );
                    }

                    // Label.
                    if self.show_labels && node.status != "powered_off" {
                        painter.text(
                            d.p.screen + Vec2::new(0.0, -core_r - 6.0),
                            Align2::CENTER_BOTTOM,
                            &node.label,
                            FontId::monospace(11.0),
                            with_alpha(Color32::from_rgb(215, 224, 240), 0.92),
                        );
                    }
                }

                // ----- hover + click picking -----
                let mut hover_idx: Option<usize> = None;
                if let Some(mp) = response.hover_pos() {
                    let mut best = f32::MAX;
                    for d in &drawn {
                        let rs = role_style(&self.graph.nodes[d.idx].role);
                        let core_r = (rs.size * 1.7 * d.p.scale * 0.1).clamp(2.0, 26.0);
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
        let c = lerp_color(Color32::WHITE, GREY, st.desat);
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

fn draw_starfield(painter: &egui::Painter, rect: Rect) {
    // Cheap deterministic starfield seeded by position.
    let mut seed: u64 = 0x1234_5678;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed >> 11) as f32 / (1u64 << 53) as f32
    };
    for _ in 0..220 {
        let x = rect.left() + next() * rect.width();
        let y = rect.top() + next() * rect.height();
        let a = 0.15 + next() * 0.35;
        painter.circle_filled(
            Pos2::new(x, y),
            next() * 1.1 + 0.3,
            with_alpha(Color32::from_rgb(159, 179, 217), a),
        );
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
        ],
        edges: vec![
            // Example data path: client -> anchor -> relay -> exit.
            edge("laptop-mac", "anchor-eu", "data_path"),
            edge("anchor-eu", "relay-home", "data_path"),
            edge("relay-home", "exit-nl", "data_path"),
            edge("pc-win", "anchor-us", "data_path"),
            edge("anchor-us", "exit-blind", "data_path"),
            edge("phone", "anchor-eu", "data_path"),
            edge("laptop-mac", "nas-vault", "data_path"),
            edge("pc-win", "llm-box", "data_path"),
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
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::new(graph)))
        }),
    )
}

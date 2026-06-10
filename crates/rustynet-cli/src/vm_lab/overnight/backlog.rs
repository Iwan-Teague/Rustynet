//! Frontier backlog: the typed (platform, role) cell universe the overnight
//! verified-plane march works through.
//!
//! This is the structure that turns blind round-robin into actual forward
//! progress: every cell carries an explicit state (verified / red / flaky /
//! unbuilt / unknown / parked) so the scheduler always knows what is already
//! green and what the highest-value next step is.
//!
//! See `documents/operations/active/OvernightAutonomousBugHuntProposal_2026-06-08.md`
//! §6 for the design.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::role::NodeRole;

/// Role vocabulary for the march, aligned with the product `RolePreset`
/// vocabulary used in the proposal's platform matrix (client / admin / exit /
/// relay / anchor / blind_exit) rather than the narrower orchestrator
/// [`NodeRole`] set. Support is still derived from the real code matrix via
/// [`MarchRole::to_node_role`] — never hardcoded twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarchRole {
    Client,
    Admin,
    Exit,
    Relay,
    Anchor,
    /// Irreversible identity wipe — permanently excluded from the march
    /// (`role_presets.rs:438`, `anything_to_blind_exit_is_irreversible`).
    BlindExit,
}

impl MarchRole {
    pub fn all() -> &'static [MarchRole] {
        &[
            MarchRole::Client,
            MarchRole::Admin,
            MarchRole::Exit,
            MarchRole::Relay,
            MarchRole::Anchor,
            MarchRole::BlindExit,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MarchRole::Client => "client",
            MarchRole::Admin => "admin",
            MarchRole::Exit => "exit",
            MarchRole::Relay => "relay",
            MarchRole::Anchor => "anchor",
            MarchRole::BlindExit => "blind_exit",
        }
    }

    pub fn parse(value: &str) -> Result<MarchRole, String> {
        match value {
            "client" => Ok(MarchRole::Client),
            "admin" => Ok(MarchRole::Admin),
            "exit" => Ok(MarchRole::Exit),
            "relay" => Ok(MarchRole::Relay),
            "anchor" => Ok(MarchRole::Anchor),
            "blind_exit" | "blind-exit" => Ok(MarchRole::BlindExit),
            other => Err(format!("unknown march role: {other}")),
        }
    }

    /// Map to the orchestrator [`NodeRole`] when one exists. `Admin` and
    /// `BlindExit` have no direct orchestrator role (admin is a daemon-role
    /// mapping; blind_exit is the macOS Exit daemon posture) and return
    /// `None`; their support is handled explicitly in [`Self::is_lab_assignable`]
    /// / [`Self::is_product_supported`].
    pub fn to_node_role(self) -> Option<NodeRole> {
        match self {
            MarchRole::Client => Some(NodeRole::Client),
            MarchRole::Exit => Some(NodeRole::Exit),
            MarchRole::Relay => Some(NodeRole::Relay),
            MarchRole::Anchor => Some(NodeRole::Anchor),
            MarchRole::Admin | MarchRole::BlindExit => None,
        }
    }

    /// Can the lab assign this role on this platform at all (to generate
    /// evidence)? `blind_exit` is never assignable for the march — it is
    /// irreversible. Mirrors [`NodeRole::is_lab_assignable_for_platform`] for
    /// the mappable roles.
    pub fn is_lab_assignable(self, platform: VmGuestPlatform) -> bool {
        match self {
            MarchRole::BlindExit => false,
            // Admin is a control-plane client capability with a daemon `admin`
            // role on every desktop OS (role.rs `daemon_node_role_for_platform`).
            MarchRole::Admin => {
                !matches!(platform, VmGuestPlatform::Ios | VmGuestPlatform::Android)
            }
            _ => self
                .to_node_role()
                .map(|nr| nr.is_lab_assignable_for_platform(&platform))
                .unwrap_or(false),
        }
    }

    /// Is this role product-supported (live-evidenced) on this platform today?
    /// `false` for a lab-assignable cell means "frontier — needs net-new
    /// implementation". Mirrors [`NodeRole::is_supported_for_platform`].
    pub fn is_product_supported(self, platform: VmGuestPlatform) -> bool {
        match self {
            MarchRole::BlindExit => false,
            MarchRole::Admin => {
                matches!(
                    platform,
                    VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
                )
            }
            _ => self
                .to_node_role()
                .map(|nr| nr.is_supported_for_platform(&platform))
                .unwrap_or(false),
        }
    }

    /// Best-effort orchestrator stage that exercises this role (informational —
    /// the live-lab oracle is authoritative).
    pub fn stage_hint(self) -> &'static str {
        match self {
            MarchRole::Exit => "active_exit / exit_handoff",
            MarchRole::Anchor => "anchor_validation",
            MarchRole::Relay => "deploy_relay_service / relay_validation",
            MarchRole::Client | MarchRole::Admin => "role_switch_matrix",
            MarchRole::BlindExit => "(excluded)",
        }
    }

    /// The already-working sibling implementation an agent should pattern-match
    /// when implementing an `unbuilt` cell.
    pub fn sibling_reference(self) -> Option<&'static str> {
        match self {
            MarchRole::Relay => Some(
                "crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs \
                 (live Linux + macOS relay deploy)",
            ),
            MarchRole::Anchor => Some(
                "crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/anchor.rs \
                 (live Linux anchor)",
            ),
            MarchRole::Exit => Some(
                "crates/rustynet-cli/src/vm_lab/orchestrator/stage/active_exit.rs \
                 (live Linux/macOS active exit)",
            ),
            MarchRole::Client | MarchRole::Admin | MarchRole::BlindExit => None,
        }
    }
}

/// Lifecycle state of one cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellState {
    /// Live-lab green on the most recent run.
    Verified,
    /// Ran and failed.
    Red,
    /// Passed and failed across runs (timing / nondeterminism).
    Flaky,
    /// No adapter / capability yet — net-new implementation needed.
    Unbuilt,
    /// Lab/product-supported in code but not yet confirmed green this run.
    Unknown,
    /// Deliberately not scheduled (irreversible, unsupported, or budget-exhausted).
    Parked,
}

impl CellState {
    pub fn as_str(self) -> &'static str {
        match self {
            CellState::Verified => "verified",
            CellState::Red => "red",
            CellState::Flaky => "flaky",
            CellState::Unbuilt => "unbuilt",
            CellState::Unknown => "unknown",
            CellState::Parked => "parked",
        }
    }

    pub fn parse(value: &str) -> Result<CellState, String> {
        match value {
            "verified" => Ok(CellState::Verified),
            "red" => Ok(CellState::Red),
            "flaky" => Ok(CellState::Flaky),
            "unbuilt" => Ok(CellState::Unbuilt),
            "unknown" => Ok(CellState::Unknown),
            "parked" => Ok(CellState::Parked),
            other => Err(format!("unknown cell state: {other}")),
        }
    }

    /// A cell the scheduler may still spend a work-unit on.
    pub fn is_actionable(self) -> bool {
        matches!(
            self,
            CellState::Red | CellState::Flaky | CellState::Unbuilt | CellState::Unknown
        )
    }

    /// Base priority before per-cell attempt decay. Higher = more valuable.
    pub fn base_value(self) -> u32 {
        match self {
            // Frontier: clear sibling to copy, net-new but bounded.
            CellState::Unbuilt => 90,
            // Broken: regression or partial — fix it.
            CellState::Red => 70,
            CellState::Flaky => 50,
            // Just needs a confirming run.
            CellState::Unknown => 30,
            CellState::Verified | CellState::Parked => 0,
        }
    }
}

/// A prior live-lab verdict for a cell, used to seed initial state (e.g. from
/// the run matrix or orchestrator skip/fail reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorVerdict {
    Green,
    Failed,
    SkippedNoAdapter,
    Flaky,
}

impl PriorVerdict {
    /// Map an operator/run-matrix status token to a verdict.
    pub fn from_status(status: &str) -> Result<PriorVerdict, String> {
        match status.trim().to_ascii_lowercase().as_str() {
            "pass" | "green" | "verified" => Ok(PriorVerdict::Green),
            "fail" | "red" | "failed" => Ok(PriorVerdict::Failed),
            "skip" | "skipped" | "unbuilt" => Ok(PriorVerdict::SkippedNoAdapter),
            "flaky" => Ok(PriorVerdict::Flaky),
            other => Err(format!(
                "unknown seed status '{other}' (expected pass|fail|skip|flaky)"
            )),
        }
    }
}

/// Parse a `--seed-status os:role=status,...` string into prior verdicts so an
/// operator can tell the march what is already known-green (skip re-testing) or
/// known-broken. Run-matrix auto-seeding (proposal §6.1) is a future refinement
/// that produces the same [`PriorVerdicts`].
pub fn parse_seed_status(raw: &str) -> Result<PriorVerdicts, String> {
    let mut priors = PriorVerdicts::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (lhs, status) = entry
            .split_once('=')
            .ok_or_else(|| format!("seed entry '{entry}' must be os:role=status"))?;
        let (os, role) = lhs
            .split_once(':')
            .ok_or_else(|| format!("seed entry '{entry}' must be os:role=status"))?;
        let platform = platform_from_str(os.trim())?;
        let role = MarchRole::parse(role.trim())?;
        priors.insert(platform, role, PriorVerdict::from_status(status)?);
    }
    Ok(priors)
}

/// Lookup of prior verdicts keyed by (platform, role) string identity.
#[derive(Debug, Default, Clone)]
pub struct PriorVerdicts {
    map: BTreeMap<(String, String), PriorVerdict>,
}

impl PriorVerdicts {
    pub fn new() -> Self {
        PriorVerdicts {
            map: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, platform: VmGuestPlatform, role: MarchRole, verdict: PriorVerdict) {
        self.map.insert(
            (platform.as_str().to_owned(), role.as_str().to_owned()),
            verdict,
        );
    }

    fn get(&self, platform: VmGuestPlatform, role: MarchRole) -> Option<PriorVerdict> {
        self.map
            .get(&(platform.as_str().to_owned(), role.as_str().to_owned()))
            .copied()
    }
}

/// One (platform, role) cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub platform: VmGuestPlatform,
    pub role: MarchRole,
    pub state: CellState,
    /// Base value (state-derived); the scheduler applies attempt decay on top.
    pub value: u32,
    pub attempts: u32,
    pub progress: Option<String>,
    pub stage_hint: String,
    pub sibling_reference: Option<String>,
    pub notes: Option<String>,
    pub parked_reason: Option<String>,
}

impl Cell {
    pub fn id(&self) -> String {
        format!("{}/{}", self.platform.as_str(), self.role.as_str())
    }
}

fn platform_from_str(value: &str) -> Result<VmGuestPlatform, String> {
    match value {
        "linux" => Ok(VmGuestPlatform::Linux),
        "macos" => Ok(VmGuestPlatform::Macos),
        "windows" => Ok(VmGuestPlatform::Windows),
        "ios" => Ok(VmGuestPlatform::Ios),
        "android" => Ok(VmGuestPlatform::Android),
        other => Err(format!("unknown platform in backlog: {other}")),
    }
}

/// The frontier backlog — every cell plus helpers to build, query, mutate, and
/// persist it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrontierBacklog {
    pub cells: Vec<Cell>,
}

impl FrontierBacklog {
    /// Build the cell universe from the lab's platforms × the role vocabulary,
    /// typing each cell from the code support matrix and any prior verdicts.
    pub fn build(platforms: &[VmGuestPlatform], priors: &PriorVerdicts) -> FrontierBacklog {
        let mut cells = Vec::new();
        for &platform in platforms {
            for &role in MarchRole::all() {
                cells.push(classify_initial(platform, role, priors.get(platform, role)));
            }
        }
        FrontierBacklog { cells }
    }

    pub fn counts(&self) -> BacklogCounts {
        let mut c = BacklogCounts::default();
        for cell in &self.cells {
            match cell.state {
                CellState::Verified => c.verified += 1,
                CellState::Red => c.red += 1,
                CellState::Flaky => c.flaky += 1,
                CellState::Unbuilt => c.unbuilt += 1,
                CellState::Unknown => c.unknown += 1,
                CellState::Parked => c.parked += 1,
            }
        }
        c.total = self.cells.len();
        c
    }

    /// One-line-per-cell human summary (for `--dry-run` output and agent prompts).
    pub fn summary(&self) -> String {
        let c = self.counts();
        let mut out = format!(
            "frontier: {} cells — {} verified, {} red, {} flaky, {} unbuilt, {} unknown, {} parked\n",
            c.total, c.verified, c.red, c.flaky, c.unbuilt, c.unknown, c.parked
        );
        for cell in &self.cells {
            out.push_str(&format!(
                "  {:<18} {:<8} value={:<3} attempts={} {}\n",
                cell.id(),
                cell.state.as_str(),
                cell.value,
                cell.attempts,
                cell.parked_reason
                    .as_deref()
                    .or(cell.progress.as_deref())
                    .unwrap_or(""),
            ));
        }
        out
    }

    pub fn mark_verified(&mut self, idx: usize) {
        if let Some(cell) = self.cells.get_mut(idx) {
            cell.state = CellState::Verified;
            cell.value = CellState::Verified.base_value();
        }
    }

    /// Partial credit: the stage advanced. The cell stays actionable and the
    /// failed-attempt counter is forgiven once (real progress earns another
    /// session).
    pub fn record_progress(&mut self, idx: usize, from: &str, to: &str) {
        if let Some(cell) = self.cells.get_mut(idx) {
            cell.progress = Some(format!("{from} -> {to}"));
            cell.attempts = cell.attempts.saturating_sub(1);
        }
    }

    /// A genuine no-progress attempt. Increments the counter; parks the cell if
    /// the per-cell attempt budget is exhausted.
    pub fn attempt_failed(&mut self, idx: usize, max_attempts: u32) {
        if let Some(cell) = self.cells.get_mut(idx) {
            cell.attempts += 1;
            if cell.attempts >= max_attempts {
                cell.state = CellState::Parked;
                cell.value = 0;
                cell.parked_reason = Some(format!(
                    "attempt budget exhausted ({}/{max_attempts})",
                    cell.attempts
                ));
            }
        }
    }

    pub fn park(&mut self, idx: usize, reason: &str) {
        if let Some(cell) = self.cells.get_mut(idx) {
            cell.state = CellState::Parked;
            cell.value = 0;
            cell.parked_reason = Some(reason.to_owned());
        }
    }

    // -- persistence (string-keyed, decoupled from enum derives) --

    pub fn to_json_value(&self) -> Value {
        let cells: Vec<Value> = self.cells.iter().map(cell_to_value).collect();
        let mut root = Map::new();
        root.insert("cells".to_owned(), Value::Array(cells));
        Value::Object(root)
    }

    pub fn to_json_string(&self) -> Result<String, String> {
        serde_json::to_string_pretty(&self.to_json_value())
            .map_err(|e| format!("serialize backlog failed: {e}"))
    }

    pub fn from_json_str(raw: &str) -> Result<FrontierBacklog, String> {
        let value: Value =
            serde_json::from_str(raw).map_err(|e| format!("parse backlog json failed: {e}"))?;
        let arr = value
            .get("cells")
            .and_then(Value::as_array)
            .ok_or_else(|| "backlog json missing `cells` array".to_owned())?;
        let mut cells = Vec::with_capacity(arr.len());
        for item in arr {
            cells.push(cell_from_value(item)?);
        }
        Ok(FrontierBacklog { cells })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BacklogCounts {
    pub total: usize,
    pub verified: usize,
    pub red: usize,
    pub flaky: usize,
    pub unbuilt: usize,
    pub unknown: usize,
    pub parked: usize,
}

/// Type a single cell from the platform/role support matrix + any prior verdict.
/// Fail-closed ordering: irreversible and unsupported cells are parked before
/// any prior verdict is consulted.
pub fn classify_initial(
    platform: VmGuestPlatform,
    role: MarchRole,
    prior: Option<PriorVerdict>,
) -> Cell {
    let base = |state: CellState| Cell {
        platform,
        role,
        state,
        value: state.base_value(),
        attempts: 0,
        progress: None,
        stage_hint: role.stage_hint().to_owned(),
        sibling_reference: role.sibling_reference().map(str::to_owned),
        notes: None,
        parked_reason: None,
    };

    // 1. blind_exit is irreversible — permanently parked, never scheduled.
    if role == MarchRole::BlindExit {
        let mut cell = base(CellState::Parked);
        cell.parked_reason = Some(
            "blind_exit irreversible identity wipe; factory reset required to leave \
             (role_presets.rs:438) — excluded from the march"
                .to_owned(),
        );
        return cell;
    }

    // 2. not lab-assignable on this platform → parked.
    if !role.is_lab_assignable(platform) {
        let mut cell = base(CellState::Parked);
        cell.parked_reason = Some(format!(
            "{} not lab-assignable on {}",
            role.as_str(),
            platform.as_str()
        ));
        return cell;
    }

    // 3. seed from prior verdict if present.
    let state = match prior {
        Some(PriorVerdict::Green) => CellState::Verified,
        Some(PriorVerdict::Failed) => CellState::Red,
        Some(PriorVerdict::SkippedNoAdapter) => CellState::Unbuilt,
        Some(PriorVerdict::Flaky) => CellState::Flaky,
        // 4. no prior: product-supported → just needs a confirming run;
        //    lab-assignable but not yet supported → frontier (unbuilt).
        None => {
            if role.is_product_supported(platform) {
                CellState::Unknown
            } else {
                CellState::Unbuilt
            }
        }
    };

    let mut cell = base(state);
    if state == CellState::Unbuilt && prior.is_none() {
        cell.notes = Some("frontier: lab-assignable but not yet product-supported".to_owned());
    }
    cell
}

fn cell_to_value(cell: &Cell) -> Value {
    let mut m = Map::new();
    m.insert(
        "platform".to_owned(),
        Value::String(cell.platform.as_str().to_owned()),
    );
    m.insert(
        "role".to_owned(),
        Value::String(cell.role.as_str().to_owned()),
    );
    m.insert(
        "state".to_owned(),
        Value::String(cell.state.as_str().to_owned()),
    );
    m.insert("value".to_owned(), Value::from(cell.value));
    m.insert("attempts".to_owned(), Value::from(cell.attempts));
    m.insert(
        "stage_hint".to_owned(),
        Value::String(cell.stage_hint.clone()),
    );
    let opt = |s: &Option<String>| match s {
        Some(v) => Value::String(v.clone()),
        None => Value::Null,
    };
    m.insert("progress".to_owned(), opt(&cell.progress));
    m.insert("sibling_reference".to_owned(), opt(&cell.sibling_reference));
    m.insert("notes".to_owned(), opt(&cell.notes));
    m.insert("parked_reason".to_owned(), opt(&cell.parked_reason));
    Value::Object(m)
}

fn cell_from_value(value: &Value) -> Result<Cell, String> {
    let get_str = |key: &str| -> Result<String, String> {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("backlog cell missing string field `{key}`"))
    };
    let opt_str =
        |key: &str| -> Option<String> { value.get(key).and_then(Value::as_str).map(str::to_owned) };
    let get_u32 = |key: &str| -> Result<u32, String> {
        value
            .get(key)
            .and_then(Value::as_u64)
            .map(|v| v as u32)
            .ok_or_else(|| format!("backlog cell missing integer field `{key}`"))
    };

    Ok(Cell {
        platform: platform_from_str(&get_str("platform")?)?,
        role: MarchRole::parse(&get_str("role")?)?,
        state: CellState::parse(&get_str("state")?)?,
        value: get_u32("value")?,
        attempts: get_u32("attempts")?,
        progress: opt_str("progress"),
        stage_hint: get_str("stage_hint")?,
        sibling_reference: opt_str("sibling_reference"),
        notes: opt_str("notes"),
        parked_reason: opt_str("parked_reason"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAB: &[VmGuestPlatform] = &[
        VmGuestPlatform::Linux,
        VmGuestPlatform::Macos,
        VmGuestPlatform::Windows,
    ];

    fn cell(b: &FrontierBacklog, platform: VmGuestPlatform, role: MarchRole) -> &Cell {
        b.cells
            .iter()
            .find(|c| c.platform == platform && c.role == role)
            .expect("cell present")
    }

    #[test]
    fn blind_exit_is_always_parked_with_irreversible_reason() {
        for &platform in LAB {
            let c = classify_initial(platform, MarchRole::BlindExit, None);
            assert_eq!(c.state, CellState::Parked, "{platform:?} blind_exit");
            assert_eq!(c.value, 0);
            assert!(
                c.parked_reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("irreversible")
            );
        }
    }

    #[test]
    fn blind_exit_parked_even_with_green_prior() {
        // fail-closed: irreversibility is checked before any prior verdict.
        let c = classify_initial(
            VmGuestPlatform::Macos,
            MarchRole::BlindExit,
            Some(PriorVerdict::Green),
        );
        assert_eq!(c.state, CellState::Parked);
    }

    #[test]
    fn linux_relay_supported_is_unknown_without_prior() {
        let c = classify_initial(VmGuestPlatform::Linux, MarchRole::Relay, None);
        assert_eq!(c.state, CellState::Unknown);
    }

    #[test]
    fn windows_relay_is_unbuilt_frontier() {
        // relay is lab-assignable on Windows but not product-supported → frontier.
        let c = classify_initial(VmGuestPlatform::Windows, MarchRole::Relay, None);
        assert_eq!(c.state, CellState::Unbuilt);
        assert_eq!(c.value, 90);
        assert!(c.sibling_reference.is_some());
    }

    #[test]
    fn macos_relay_and_anchor_are_unbuilt() {
        assert_eq!(
            classify_initial(VmGuestPlatform::Macos, MarchRole::Relay, None).state,
            CellState::Unbuilt
        );
        assert_eq!(
            classify_initial(VmGuestPlatform::Macos, MarchRole::Anchor, None).state,
            CellState::Unbuilt
        );
    }

    #[test]
    fn windows_exit_is_unbuilt_not_supported() {
        // Exit is a membership owner → not product-supported on Windows, but
        // lab-assignable for evidence → unbuilt, not parked.
        let c = classify_initial(VmGuestPlatform::Windows, MarchRole::Exit, None);
        assert_eq!(c.state, CellState::Unbuilt);
    }

    #[test]
    fn prior_verdict_seeds_state() {
        assert_eq!(
            classify_initial(
                VmGuestPlatform::Linux,
                MarchRole::Relay,
                Some(PriorVerdict::Green)
            )
            .state,
            CellState::Verified
        );
        assert_eq!(
            classify_initial(
                VmGuestPlatform::Linux,
                MarchRole::Anchor,
                Some(PriorVerdict::Failed)
            )
            .state,
            CellState::Red
        );
        assert_eq!(
            classify_initial(
                VmGuestPlatform::Windows,
                MarchRole::Relay,
                Some(PriorVerdict::SkippedNoAdapter)
            )
            .state,
            CellState::Unbuilt
        );
    }

    #[test]
    fn build_covers_every_platform_role_pair() {
        let b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        assert_eq!(b.cells.len(), LAB.len() * MarchRole::all().len());
        // blind_exit parked on all three.
        assert_eq!(
            b.cells
                .iter()
                .filter(|c| c.role == MarchRole::BlindExit && c.state == CellState::Parked)
                .count(),
            3
        );
    }

    #[test]
    fn attempt_failed_parks_at_budget() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let idx = b
            .cells
            .iter()
            .position(|c| c.platform == VmGuestPlatform::Windows && c.role == MarchRole::Relay)
            .expect("windows relay");
        b.attempt_failed(idx, 3);
        assert_eq!(b.cells[idx].state, CellState::Unbuilt);
        b.attempt_failed(idx, 3);
        b.attempt_failed(idx, 3);
        assert_eq!(b.cells[idx].state, CellState::Parked);
        assert!(
            b.cells[idx]
                .parked_reason
                .as_deref()
                .unwrap_or_default()
                .contains("budget")
        );
    }

    #[test]
    fn record_progress_forgives_one_attempt() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let idx = 0;
        b.attempt_failed(idx, 5);
        b.attempt_failed(idx, 5);
        assert_eq!(b.cells[idx].attempts, 2);
        b.record_progress(idx, "3/7", "5/7");
        assert_eq!(b.cells[idx].attempts, 1);
        assert_eq!(b.cells[idx].progress.as_deref(), Some("3/7 -> 5/7"));
    }

    #[test]
    fn mark_verified_zeroes_value_and_sets_state() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        b.mark_verified(0);
        assert_eq!(b.cells[0].state, CellState::Verified);
        assert_eq!(b.cells[0].value, 0);
    }

    #[test]
    fn json_round_trips() {
        let mut priors = PriorVerdicts::new();
        priors.insert(
            VmGuestPlatform::Linux,
            MarchRole::Relay,
            PriorVerdict::Green,
        );
        let b = FrontierBacklog::build(LAB, &priors);
        let json = b.to_json_string().expect("serialize");
        let back = FrontierBacklog::from_json_str(&json).expect("deserialize");
        assert_eq!(b, back);
    }

    #[test]
    fn counts_sum_to_total() {
        let b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let c = b.counts();
        assert_eq!(
            c.verified + c.red + c.flaky + c.unbuilt + c.unknown + c.parked,
            c.total
        );
        assert_eq!(c.total, b.cells.len());
    }

    #[test]
    fn prior_verdicts_lookup_is_platform_role_specific() {
        let mut priors = PriorVerdicts::new();
        priors.insert(
            VmGuestPlatform::Linux,
            MarchRole::Relay,
            PriorVerdict::Green,
        );
        let b = FrontierBacklog::build(LAB, &priors);
        assert_eq!(
            cell(&b, VmGuestPlatform::Linux, MarchRole::Relay).state,
            CellState::Verified
        );
        // macOS relay must NOT inherit Linux's verdict.
        assert_eq!(
            cell(&b, VmGuestPlatform::Macos, MarchRole::Relay).state,
            CellState::Unbuilt
        );
    }

    #[test]
    fn from_status_maps_all_tokens() {
        assert_eq!(
            PriorVerdict::from_status("PASS").unwrap(),
            PriorVerdict::Green
        );
        assert_eq!(
            PriorVerdict::from_status("fail").unwrap(),
            PriorVerdict::Failed
        );
        assert_eq!(
            PriorVerdict::from_status("skip").unwrap(),
            PriorVerdict::SkippedNoAdapter
        );
        assert_eq!(
            PriorVerdict::from_status("flaky").unwrap(),
            PriorVerdict::Flaky
        );
        assert!(PriorVerdict::from_status("nonsense").is_err());
    }

    #[test]
    fn parse_seed_status_seeds_cells() {
        let priors =
            parse_seed_status("linux:relay=pass, windows:exit=skip, macos:anchor=flaky").unwrap();
        let b = FrontierBacklog::build(LAB, &priors);
        assert_eq!(
            cell(&b, VmGuestPlatform::Linux, MarchRole::Relay).state,
            CellState::Verified
        );
        // windows:exit=skip still types as unbuilt (skip == no adapter).
        assert_eq!(
            cell(&b, VmGuestPlatform::Windows, MarchRole::Exit).state,
            CellState::Unbuilt
        );
        assert_eq!(
            cell(&b, VmGuestPlatform::Macos, MarchRole::Anchor).state,
            CellState::Flaky
        );
    }

    #[test]
    fn parse_seed_status_rejects_malformed() {
        assert!(parse_seed_status("linux-relay=pass").is_err()); // missing ':'
        assert!(parse_seed_status("linux:relay").is_err()); // missing '=status'
        assert!(parse_seed_status("mars:relay=pass").is_err()); // bad platform
        assert!(parse_seed_status("linux:wizard=pass").is_err()); // bad role
    }

    #[test]
    fn parse_seed_status_ignores_empty_entries() {
        let priors = parse_seed_status(" , linux:relay=pass , ").unwrap();
        let b = FrontierBacklog::build(LAB, &priors);
        assert_eq!(
            cell(&b, VmGuestPlatform::Linux, MarchRole::Relay).state,
            CellState::Verified
        );
    }
}

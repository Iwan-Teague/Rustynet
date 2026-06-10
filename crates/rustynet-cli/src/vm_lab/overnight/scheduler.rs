//! Scheduler: picks the next cell to work, applies the per-cell attempt
//! budget, and rotates breadth-first so one hard cell cannot consume the whole
//! night. See proposal §9.

use crate::vm_lab::overnight::backlog::{Cell, FrontierBacklog};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// Spread effort across the frontier: among actionable cells prefer the
    /// highest base value, then the fewest attempts. Default.
    BreadthFirst,
    /// Stay on the single highest-value cell until it greens or its budget is
    /// exhausted, then move on.
    DeepFirst,
}

impl Rotation {
    pub fn parse(value: &str) -> Result<Rotation, String> {
        match value {
            "breadth-first" | "breadth" => Ok(Rotation::BreadthFirst),
            "deep-first" | "deep" => Ok(Rotation::DeepFirst),
            other => Err(format!(
                "unknown rotation '{other}' (expected breadth-first | deep-first)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rotation::BreadthFirst => "breadth-first",
            Rotation::DeepFirst => "deep-first",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub max_attempts_per_cell: u32,
    pub rotation: Rotation,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            max_attempts_per_cell: 3,
            rotation: Rotation::BreadthFirst,
        }
    }
}

/// Effective priority of a cell right now. Returns 0 for any non-actionable or
/// over-budget cell so it is never selected; otherwise the state's base value.
///
/// Anti-tarpit is handled by the attempt-budget cutoff plus the rotation
/// tiebreak (breadth-first prefers fewest attempts, deep-first prefers most) —
/// not by value decay, which would make deep-first abandon a struggling cell
/// for any untouched equal-value one.
pub fn effective_value(cell: &Cell, cfg: &SchedulerConfig) -> u32 {
    if !cell.state.is_actionable() {
        return 0;
    }
    if cell.attempts >= cfg.max_attempts_per_cell {
        return 0;
    }
    cell.state.base_value()
}

/// Index of the next cell to work, or `None` when the frontier is exhausted.
///
/// Tie-break is deterministic (stable index order) so a dry-run plan and a live
/// run schedule the same way.
pub fn next_actionable(backlog: &FrontierBacklog, cfg: &SchedulerConfig) -> Option<usize> {
    let mut best: Option<(usize, u32, u32)> = None; // (idx, effective_value, attempts)
    for (idx, cell) in backlog.cells.iter().enumerate() {
        let value = effective_value(cell, cfg);
        if value == 0 {
            continue;
        }
        let candidate = (idx, value, cell.attempts);
        best = Some(match best {
            None => candidate,
            Some(current) => {
                if is_better(cfg.rotation, candidate, current) {
                    candidate
                } else {
                    current
                }
            }
        });
    }
    best.map(|(idx, _, _)| idx)
}

fn is_better(rotation: Rotation, candidate: (usize, u32, u32), current: (usize, u32, u32)) -> bool {
    let (c_idx, c_val, c_att) = candidate;
    let (cur_idx, cur_val, cur_att) = current;
    match rotation {
        // Breadth-first: highest value, then FEWEST attempts (spread effort),
        // then lowest index.
        Rotation::BreadthFirst => {
            (c_val, std::cmp::Reverse(c_att), std::cmp::Reverse(c_idx))
                > (
                    cur_val,
                    std::cmp::Reverse(cur_att),
                    std::cmp::Reverse(cur_idx),
                )
        }
        // Deep-first: highest value, then MOST attempts (finish what's started),
        // then lowest index.
        Rotation::DeepFirst => {
            (c_val, c_att, std::cmp::Reverse(c_idx))
                > (cur_val, cur_att, std::cmp::Reverse(cur_idx))
        }
    }
}

/// The ordered list of cell indices the scheduler would work, given the current
/// states and assuming each pick fails its full attempt budget (so no cell
/// greens). Used by `--dry-run` to print the plan without running anything.
pub fn dry_run_plan(backlog: &FrontierBacklog, cfg: &SchedulerConfig) -> Vec<usize> {
    let mut work = backlog.clone();
    let mut order = Vec::new();
    // Bound the projection so a misconfiguration can never loop forever.
    let bound = work
        .cells
        .len()
        .saturating_mul(cfg.max_attempts_per_cell as usize)
        + 1;
    for _ in 0..bound {
        match next_actionable(&work, cfg) {
            Some(idx) => {
                order.push(idx);
                // Project the pessimistic path: this attempt made no progress.
                work.attempt_failed(idx, cfg.max_attempts_per_cell);
            }
            None => break,
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::overnight::backlog::{CellState, MarchRole, PriorVerdicts};

    const LAB: &[VmGuestPlatform] = &[
        VmGuestPlatform::Linux,
        VmGuestPlatform::Macos,
        VmGuestPlatform::Windows,
    ];

    #[test]
    fn unbuilt_outranks_unknown() {
        let b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let cfg = SchedulerConfig::default();
        let idx = next_actionable(&b, &cfg).expect("an actionable cell");
        // Highest base value is 90 (unbuilt). First pick must be an unbuilt cell.
        assert_eq!(b.cells[idx].state, CellState::Unbuilt);
    }

    #[test]
    fn parked_and_verified_are_never_selected() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        // Park / verify everything except one unknown linux client.
        for i in 0..b.cells.len() {
            b.park(i, "test");
        }
        // Re-open exactly one cell as Unknown.
        b.cells[0].state = CellState::Unknown;
        b.cells[0].value = CellState::Unknown.base_value();
        let cfg = SchedulerConfig::default();
        assert_eq!(next_actionable(&b, &cfg), Some(0));
    }

    #[test]
    fn returns_none_when_frontier_exhausted() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        for i in 0..b.cells.len() {
            b.mark_verified(i);
        }
        assert_eq!(next_actionable(&b, &SchedulerConfig::default()), None);
    }

    #[test]
    fn over_budget_cell_drops_out() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let cfg = SchedulerConfig {
            max_attempts_per_cell: 2,
            rotation: Rotation::BreadthFirst,
        };
        // Exhaust the natural top pick repeatedly; it must eventually never be chosen.
        for _ in 0..10 {
            if let Some(idx) = next_actionable(&b, &cfg) {
                b.attempt_failed(idx, cfg.max_attempts_per_cell);
            }
        }
        // Every remaining selection must be within budget.
        if let Some(idx) = next_actionable(&b, &cfg) {
            assert!(b.cells[idx].attempts < cfg.max_attempts_per_cell);
        }
    }

    #[test]
    fn breadth_first_spreads_across_cells_of_equal_value() {
        // Two unbuilt cells, equal base value; breadth-first must alternate
        // rather than hammer one.
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let cfg = SchedulerConfig {
            max_attempts_per_cell: 5,
            rotation: Rotation::BreadthFirst,
        };
        let first = next_actionable(&b, &cfg).expect("first");
        b.attempt_failed(first, cfg.max_attempts_per_cell);
        let second = next_actionable(&b, &cfg).expect("second");
        // After one failed attempt on `first`, a fresh equal-value cell (0
        // attempts) should be preferred.
        assert_ne!(first, second);
        assert_eq!(b.cells[second].attempts, 0);
    }

    #[test]
    fn deep_first_stays_on_one_cell() {
        let mut b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let cfg = SchedulerConfig {
            max_attempts_per_cell: 5,
            rotation: Rotation::DeepFirst,
        };
        let first = next_actionable(&b, &cfg).expect("first");
        b.attempt_failed(first, cfg.max_attempts_per_cell);
        let second = next_actionable(&b, &cfg).expect("second");
        // Deep-first prefers the in-progress (more-attempts) cell of equal value.
        assert_eq!(first, second);
    }

    #[test]
    fn dry_run_plan_terminates_and_only_lists_actionable() {
        let b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let cfg = SchedulerConfig::default();
        let plan = dry_run_plan(&b, &cfg);
        assert!(!plan.is_empty());
        // No parked/verified cell index appears.
        for &idx in &plan {
            // base state at plan-build time was actionable
            let role = b.cells[idx].role;
            assert_ne!(
                role,
                MarchRole::BlindExit,
                "blind_exit must never be planned"
            );
        }
        // Bounded length.
        assert!(plan.len() <= b.cells.len() * cfg.max_attempts_per_cell as usize);
    }

    #[test]
    fn blind_exit_never_appears_in_any_plan() {
        let b = FrontierBacklog::build(LAB, &PriorVerdicts::new());
        let plan = dry_run_plan(&b, &SchedulerConfig::default());
        for &idx in &plan {
            assert_ne!(b.cells[idx].role, MarchRole::BlindExit);
        }
    }
}

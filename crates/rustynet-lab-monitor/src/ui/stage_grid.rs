use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

use crate::app::{App, Panel};

/// Braille-dot spinner frames for the box of whichever stage is currently
/// running -- purely a wall-clock animation (no App state needed): the event
/// loop already redraws roughly every 100ms (see run_event_loop's poll
/// timeout), so advancing the frame from elapsed time alone is enough to
/// read as spinning.
pub(crate) const SPINNER_FRAMES: [&str; 8] = [
    "[⠋⠋]", "[⠙⠙]", "[⠹⠹]", "[⠸⠸]", "[⠼⠼]", "[⠴⠴]", "[⠦⠦]", "[⠧⠧]",
];

fn spinner_frame_for_elapsed_ms(elapsed_ms: u128) -> &'static str {
    let idx = (elapsed_ms / 120) as usize % SPINNER_FRAMES.len();
    SPINNER_FRAMES[idx]
}

pub(crate) fn spinner_glyph() -> &'static str {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    spinner_frame_for_elapsed_ms(epoch.elapsed().as_millis())
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::StageGrid;
    let border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled(
            "STAGE GRID [4] ←→ column  ↑↓ select  Space toggle  Enter detail",
            Style::default().fg(border_fg),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app
        .planned_stage_groups()
        .iter()
        .all(|group| group.stages.is_empty())
    {
        let color = if app.data_errors.is_empty() {
            Color::Yellow
        } else {
            Color::Red
        };
        f.render_widget(
            Paragraph::new(format!(
                "{} — no local catalog substituted",
                app.plan_source_label()
            ))
            .style(Style::default().fg(color)),
            inner,
        );
        return;
    }

    let mut status_by_stage = app
        .stage_outcomes
        .iter()
        .map(|outcome| (outcome.stage.as_str(), outcome.status.as_str()))
        .collect::<HashMap<_, _>>();
    // Fold in stages the pipeline has provably passed but which never
    // recorded an outcome (conditional infra like restart_unready_vms) as
    // `skipped`, so their column can clear instead of hanging on a
    // forever-pending cell. A real recorded outcome always wins (or_insert
    // never overwrites), and these stages by construction have none.
    let implicit = app.implicitly_completed_stages();
    for stage in &implicit {
        status_by_stage.entry(stage.as_str()).or_insert("skipped");
    }
    render_planned_with_statuses(f, inner, app, &status_by_stage);
}

fn render_planned_with_statuses(
    f: &mut Frame,
    area: Rect,
    app: &App,
    status_by_stage: &HashMap<&str, &str>,
) {
    let mut chunks: Vec<Rect> = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(36),
        Constraint::Percentage(39),
    ])
    .split(area)
    .to_vec();
    // Nudge BOOTSTRAP 1 char right without touching PRE or LIVE LAB: shrink
    // its width by 1 as its start moves right by 1, so its right edge (and
    // therefore LIVE LAB's unchanged start) lands exactly where it did
    // before.
    if let Some(bootstrap) = chunks.get_mut(1) {
        bootstrap.x = bootstrap.x.saturating_add(1);
        bootstrap.width = bootstrap.width.saturating_sub(1);
    }

    let focused = app.focused_panel == Panel::StageGrid;
    // §3.4 VerifiedPass, run-level half: computed once for the whole grid. No
    // group renders release-green unless the run itself is verified (native
    // dialect, passed+bound candidate verdict, final promotion, current-gen
    // cleanup). A bash/unverified/in-progress run leaves this false.
    let run_verified = app.run_verified();
    for (idx, group) in app.planned_stage_groups().into_iter().enumerate().take(3) {
        let mut lines = Vec::new();
        if group.stages.is_empty() {
            f.render_widget(Paragraph::new(lines), chunks[idx]);
            continue;
        }
        let group_len = group.stages.len();
        let col_focused = focused && idx == app.stage_grid_col;
        let cursor_row = app.stage_grid_row[idx].min(group_len.saturating_sub(1));
        let enabled = group
            .stages
            .iter()
            .filter(|stage| app.stage_enabled(stage))
            .count();
        // completed/failed/skipped count over the same subset the
        // denominator (`enabled`) describes. Historically completed
        // counted ANY recorded outcome in the group while enabled counted
        // the current config's plan — two orthogonal filters over one
        // list, producing displays like "13/9" (finding 7).
        let completed = group
            .stages
            .iter()
            .filter(|stage| {
                app.stage_enabled(stage)
                    && status_by_stage
                        .get(stage.as_str())
                        .is_some_and(|status| is_final(status))
            })
            .count();
        let failed = group
            .stages
            .iter()
            .filter(|stage| {
                app.stage_enabled(stage)
                    && matches!(
                        status_by_stage.get(stage.as_str()),
                        Some(status)
                            if crate::data::stage_reader::StageStatus::parse(status).is_failure()
                    )
            })
            .count();
        let skipped = group
            .stages
            .iter()
            .filter(|stage| {
                app.stage_enabled(stage)
                    && matches!(
                        status_by_stage.get(stage.as_str()),
                        Some(&"skipped") | Some(&"skip")
                    )
            })
            .count();
        // §3.4 VerifiedPass, per-stage half: count only enabled stages that are a
        // CURRENT-GENERATION raw pass. A reused/skipped/not-run cell, or a pass
        // carried over from a prior generation in a reused report dir, does not
        // count — which is what stops an all-reused group rendering green.
        let verified_pass = group
            .stages
            .iter()
            .filter(|stage| app.stage_enabled(stage) && app.stage_is_current_gen_pass(stage))
            .count();
        // Release-green replaces the old `all_enabled_complete` (which counted any
        // terminal outcome, so an all-reused group went green): a group is green
        // ONLY when the run is verified AND every enabled stage is a current-gen
        // raw pass.
        let group_green = group_is_release_green(run_verified, enabled, failed, verified_pass);
        let header_style = stage_group_header_style(
            col_focused,
            failed,
            group_green,
            !status_by_stage.is_empty(),
        );
        lines.push(Line::from(stage_group_header_spans(
            group.name,
            completed,
            enabled,
            skipped,
            group.stages.len(),
            header_style,
        )));
        let visible_stage_rows = (chunks[idx].height as usize).saturating_sub(2).max(1);
        // Center on this group's own cursor row regardless of which column
        // is focused -- each group remembers its own scroll position, not
        // just whichever one happens to be selected right now.
        let scroll_start = cursor_row
            .saturating_sub(visible_stage_rows / 2)
            .min(group_len.saturating_sub(visible_stage_rows));
        for (local_idx, stage) in group
            .stages
            .into_iter()
            .enumerate()
            .skip(scroll_start)
            .take(visible_stage_rows)
        {
            let selected = col_focused && local_idx == cursor_row;
            // `possible` = right platform/role for this stage to ever run
            // (independent of the user's own toggle); `will_run` = possible
            // AND not manually toggled off. Only `!possible` is grayed out --
            // a stage the user toggled off but that is still possible stays
            // white, just with an empty box, so it reads as "possible, not
            // currently planned" rather than "can't happen".
            let possible = app.stage_selected_for_current_target(&stage);
            let will_run = app.stage_enabled(&stage);
            // Gated on a lab genuinely running right now, not just on
            // `active_stage` being populated -- that field is refreshed
            // from log/pipeline-position inference and can go stale (e.g. a
            // run stopped before `active_job` ever observed a state
            // transition to react to), which otherwise leaves a stage
            // spinning forever after the lab has actually gone idle.
            let active = app.lab_is_actively_running()
                && app.active_stage.as_deref() == Some(stage.as_str());
            let status = if active {
                "active"
            } else if let Some(status) = status_by_stage.get(stage.as_str()) {
                status
            } else if !possible {
                "disabled"
            } else if will_run {
                "will_run"
            } else {
                "excluded"
            };
            let (symbol, status_style) = cell_for_status(status);
            let mut style = if active {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(status, "pass" | "fail" | "skipped" | "disabled") {
                status_style
            } else if possible {
                Style::default().fg(Color::White)
            } else {
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::DIM)
            };
            if selected {
                style = style.bg(Color::DarkGray);
            }
            let cursor = " ";
            lines.push(Line::from(vec![
                Span::styled(format!("{cursor} "), style),
                Span::styled(format!("{symbol} "), status_style),
                Span::styled(stage, style),
            ]));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[idx]);
    }
}

/// The box fill means one thing only: "will this run on the next live lab" --
/// it does NOT track cursor position. `will_run` (possible + not manually
/// toggled off) is the only filled-box state; `excluded` (possible, but the
/// user toggled it off) stays white so it still reads as "could run", just
/// not right now; `disabled` (impossible for this config -- wrong
/// platform/role) is the only grayed-out state.
pub(crate) fn cell_for_status(status: &str) -> (&'static str, Style) {
    if status == "active" {
        return (
            spinner_glyph(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        );
    }
    if status == "disabled" {
        return (
            "[  ]",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        );
    }
    if status == "will_run" {
        return ("[██]", Style::default().fg(Color::White));
    }
    if status == "excluded" {
        return ("[  ]", Style::default().fg(Color::White));
    }
    match crate::data::stage_reader::StageStatus::parse(status) {
        crate::data::stage_reader::StageStatus::Pass => ("[██]", Style::default().fg(Color::Green)),
        crate::data::stage_reader::StageStatus::Reused => {
            ("[↺↺]", Style::default().fg(Color::Cyan))
        }
        crate::data::stage_reader::StageStatus::Fail
        | crate::data::stage_reader::StageStatus::Aborted
        | crate::data::stage_reader::StageStatus::TimedOut => {
            ("[✗✗]", Style::default().fg(Color::Red))
        }
        // Unproven: terminal and failure-ranked, but visibly distinct from a
        // hard fail (a claim that could not be PROVEN, not one disproved).
        crate::data::stage_reader::StageStatus::NotProven => {
            ("[‼‼]", Style::default().fg(Color::Red))
        }
        crate::data::stage_reader::StageStatus::Running => (
            spinner_glyph(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        crate::data::stage_reader::StageStatus::Skipped
        | crate::data::stage_reader::StageStatus::NotApplicable => (
            "[  ]",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        ),
        crate::data::stage_reader::StageStatus::NotRun => {
            ("[--]", Style::default().fg(Color::DarkGray))
        }
        crate::data::stage_reader::StageStatus::Pending => {
            ("[░░]", Style::default().fg(Color::DarkGray))
        }
        crate::data::stage_reader::StageStatus::Unknown => {
            ("[??]", Style::default().fg(Color::Magenta))
        }
    }
}

fn is_final(status: &str) -> bool {
    crate::data::stage_reader::StageStatus::parse(status).is_terminal()
}

fn progress_bar_string(done: usize, total: usize, width: usize) -> String {
    if total == 0 {
        return format!("[{:░<width$}]", "", width = width);
    }
    let filled = (done * width) / total;
    format!(
        "[{}{}]",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    )
}

/// Decides the color for a group's header (bar + title). Green is reserved for a
/// RELEASE-VERIFIED column: `group_green` (§3.4 VerifiedPass — the run is
/// verified and every enabled stage is a current-generation raw pass) is the only
/// path to green, replacing the old `all_enabled_complete` that counted any
/// terminal outcome and so greened an all-reused column. A failure still wins
/// over everything, so a failing column stays red; a settled-but-unverified
/// column (e.g. all reused, or a run with no accepted verdict) stays white, not
/// green.
/// The §3.4 VerifiedPass aggregate for a stage group's green: the run itself is
/// release-verified AND every enabled stage is a current-generation raw pass
/// (`verified_pass >= enabled`) with no failure. This REPLACES the old
/// `all_enabled_complete = enabled > 0 && failed == 0 && completed >= enabled`,
/// whose `completed` counted any terminal outcome — so an all-reused,
/// all-skipped, or all-not-run group (zero fresh passes) rendered green. Here a
/// group with zero current-generation passes has `verified_pass == 0` and can
/// never be green, and an unverified run (no accepted verdict / no promotion /
/// bash dialect) leaves `run_verified` false regardless of the cells.
fn group_is_release_green(
    run_verified: bool,
    enabled: usize,
    failed: usize,
    verified_pass: usize,
) -> bool {
    run_verified && enabled > 0 && failed == 0 && verified_pass >= enabled
}

fn stage_group_header_style(
    col_focused: bool,
    failed: usize,
    group_green: bool,
    has_any_status: bool,
) -> Style {
    if col_focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if failed > 0 {
        Style::default().fg(Color::Red)
    } else if group_green {
        Style::default().fg(Color::Green)
    } else if !has_any_status {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::White)
    }
}

/// Builds a group's header line: bar + "x/y" against `enabled` (the subset
/// of stages actually selected to run next), NOT the group's full catalog
/// size -- "2/40" reads as "barely anything passed" when it really means
/// "both of the 2 selected stages passed". The bar's fill is clamped to
/// `enabled` so a stale completed-count from a prior, wider stage selection
/// can't overfill the bar past its own width.
fn stage_group_header_spans(
    group_name: &str,
    completed: usize,
    enabled: usize,
    skipped: usize,
    total: usize,
    header_style: Style,
) -> Vec<Span<'static>> {
    let mut spans = vec![Span::styled(
        format!(
            "{group_name}  {}  {completed}/{enabled}",
            progress_bar_string(completed.min(enabled), enabled, 8),
        ),
        header_style,
    )];
    if skipped > 0 {
        spans.push(Span::styled(format!("  {skipped} skipped"), header_style));
    }
    spans.push(Span::styled(
        format!(" catalog:{total}"),
        Style::default().fg(Color::DarkGray),
    ));
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    use std::path::PathBuf;

    #[test]
    fn no_spinner_renders_when_active_stage_is_stale_and_no_lab_is_running() {
        // Regression: a lab started then immediately stopped left
        // `active_stage` (or a synthetic "running" stage_outcomes entry)
        // pointing at "preflight" with no job actually running -- the grid
        // must never show a spinner in that state, matching the header's
        // own IDLE display.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_stage = Some("preflight".to_owned());
        assert!(
            app.active_job.is_none(),
            "no job started in this test -- confirms the idle precondition"
        );

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, f.area(), &app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        let text: String = buf.content().iter().map(|cell| cell.symbol()).collect();
        for frame in SPINNER_FRAMES {
            assert!(
                !text.contains(frame),
                "spinner glyph {frame:?} must not render while idle"
            );
        }
    }

    #[test]
    fn spinner_starts_on_the_first_frame() {
        assert_eq!(spinner_frame_for_elapsed_ms(0), SPINNER_FRAMES[0]);
        assert_eq!(spinner_frame_for_elapsed_ms(119), SPINNER_FRAMES[0]);
    }

    #[test]
    fn spinner_advances_a_frame_every_120ms() {
        assert_eq!(spinner_frame_for_elapsed_ms(120), SPINNER_FRAMES[1]);
        assert_eq!(spinner_frame_for_elapsed_ms(240), SPINNER_FRAMES[2]);
    }

    #[test]
    fn spinner_wraps_around_after_the_last_frame() {
        let cycle_ms = 120 * SPINNER_FRAMES.len() as u128;
        assert_eq!(spinner_frame_for_elapsed_ms(cycle_ms), SPINNER_FRAMES[0]);
        assert_eq!(
            spinner_frame_for_elapsed_ms(cycle_ms + 120),
            SPINNER_FRAMES[1]
        );
    }

    #[test]
    fn cell_for_status_uses_a_spinner_glyph_for_a_running_stage() {
        let (symbol, _) = cell_for_status("running");
        assert!(SPINNER_FRAMES.contains(&symbol));
        let (symbol, _) = cell_for_status("active");
        assert!(SPINNER_FRAMES.contains(&symbol));
    }

    #[test]
    fn will_run_is_filled_white_excluded_is_empty_white() {
        let (symbol, style) = cell_for_status("will_run");
        assert_eq!(symbol, "[██]");
        assert_eq!(style.fg, Some(Color::White));

        let (symbol, style) = cell_for_status("excluded");
        assert_eq!(symbol, "[  ]");
        assert_eq!(style.fg, Some(Color::White));
    }

    #[test]
    fn recorded_statuses_have_distinct_terminal_visuals() {
        let (symbol, style) = cell_for_status("pass");
        assert_eq!(symbol, "[██]");
        assert_eq!(style.fg, Some(Color::Green));

        let (symbol, style) = cell_for_status("fail");
        assert_eq!(symbol, "[✗✗]");
        assert_eq!(style.fg, Some(Color::Red));

        let (symbol, style) = cell_for_status("skipped");
        assert_eq!(symbol, "[  ]");
        assert_eq!(style.fg, Some(Color::DarkGray));

        let (symbol, style) = cell_for_status("reused");
        assert_eq!(symbol, "[↺↺]");
        assert_eq!(style.fg, Some(Color::Cyan));

        for status in ["aborted", "timed_out"] {
            let (symbol, style) = cell_for_status(status);
            assert_eq!(symbol, "[✗✗]");
            assert_eq!(style.fg, Some(Color::Red));
        }
    }

    #[test]
    fn disabled_is_the_only_grayed_out_empty_box() {
        let (symbol, style) = cell_for_status("disabled");
        assert_eq!(symbol, "[  ]");
        assert_eq!(style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn header_count_and_bar_are_relative_to_enabled_not_total() {
        // Regression: "2/40" (completed against the group's full 40-stage
        // catalog) reads as "almost nothing passed" when only 2 stages were
        // ever selected to run and both did -- the count and the bar must
        // both be measured against `enabled` (2).
        let style = Style::default().fg(Color::White);
        let spans = stage_group_header_spans("LIVE LAB", 2, 2, 0, 40, style);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("2/2"),
            "expected completed/enabled, got {text:?}"
        );
        assert!(
            !text.contains("2/40"),
            "must not show completed/total: {text:?}"
        );
        // The bar itself must be full (both of the 2 enabled stages done),
        // not read as 2-out-of-40 nearly-empty.
        assert!(text.contains("[████████]"));
        // The group's full catalog size is still shown, explicitly labeled
        // suffix, distinct from the enabled-based main fraction.
        assert!(
            text.contains("catalog:40"),
            "expected a catalog total suffix: {text:?}"
        );
    }

    #[test]
    fn header_bar_fill_is_clamped_when_completed_exceeds_a_stale_enabled_count() {
        // A stage selection change between runs can leave `completed` (from
        // the prior, wider selection) larger than the current `enabled`
        // count -- the bar must not overfill past its own width.
        let style = Style::default().fg(Color::White);
        let spans = stage_group_header_spans("PRE", 5, 2, 0, 10, style);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("5/2"), "raw counts stay honest: {text:?}");
        assert!(
            text.contains("[████████]"),
            "bar clamps to full, not overfilled"
        );
    }

    #[test]
    fn header_total_suffix_is_dimmed_separately_from_the_main_count() {
        let style = Style::default().fg(Color::White);
        let spans = stage_group_header_spans("PRE", 1, 3, 0, 5, style);
        let total_span = spans
            .iter()
            .find(|s| s.content.contains("catalog:"))
            .expect("a total span");
        assert_eq!(total_span.content.as_ref(), " catalog:5");
        assert_eq!(total_span.style.fg, Some(Color::DarkGray));
        let main_span = &spans[0];
        assert_eq!(main_span.style.fg, Some(Color::White));
    }

    #[test]
    fn release_green_requires_a_verified_run_and_fresh_passes_on_every_enabled_stage() {
        // The happy path: run verified, all 3 enabled stages current-gen passes.
        assert!(group_is_release_green(true, 3, 0, 3));
        // THE P0 FIX: an all-reused/all-skipped/all-not-run group has zero
        // current-generation passes (verified_pass == 0) — never green, even
        // though the run itself is verified and nothing "failed".
        assert!(!group_is_release_green(true, 3, 0, 0));
        // A partially-fresh group (some reused) is not green either.
        assert!(!group_is_release_green(true, 3, 0, 2));
        // An UNVERIFIED run (no accepted verdict / no promotion / bash dialect)
        // is never green even if every cell shows a fresh pass.
        assert!(!group_is_release_green(false, 3, 0, 3));
        // A failure blocks green.
        assert!(!group_is_release_green(true, 3, 1, 3));
        // Nothing enabled is not "done".
        assert!(!group_is_release_green(true, 0, 0, 0));
    }

    #[test]
    fn header_turns_green_only_when_the_group_is_release_verified() {
        // group_green is the §3.4 VerifiedPass result (the run is verified AND
        // every enabled stage is a current-generation raw pass); it is the ONLY
        // path to green now.
        let style = stage_group_header_style(false, 0, true, true);
        assert_eq!(style.fg, Some(Color::Green));
        // Settled but NOT verified — e.g. an all-reused group, or a run with no
        // accepted verdict — is white, never green (the P0 false-green fix).
        let unverified = stage_group_header_style(false, 0, false, true);
        assert_eq!(unverified.fg, Some(Color::White));
    }

    #[test]
    fn header_stays_red_when_a_column_has_a_failure() {
        // A failure wins over everything else, even a (contradictory) green.
        let style = stage_group_header_style(false, 1, false, true);
        assert_eq!(style.fg, Some(Color::Red));
    }

    #[test]
    fn header_is_not_green_when_the_group_is_not_verified() {
        let style = stage_group_header_style(false, 0, false, true);
        assert_ne!(style.fg, Some(Color::Green));
    }

    #[test]
    fn header_is_not_green_before_any_stage_has_run() {
        let style = stage_group_header_style(false, 0, false, false);
        assert_eq!(style.fg, Some(Color::Cyan));
    }

    #[test]
    fn focused_column_stays_yellow_even_when_verified() {
        let style = stage_group_header_style(true, 0, true, true);
        assert_eq!(style.fg, Some(Color::Yellow));
    }
}

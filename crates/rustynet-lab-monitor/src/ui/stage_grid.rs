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
const SPINNER_FRAMES: [&str; 8] = [
    "[⠋⠋]", "[⠙⠙]", "[⠹⠹]", "[⠸⠸]", "[⠼⠼]", "[⠴⠴]", "[⠦⠦]", "[⠧⠧]",
];

fn spinner_frame_for_elapsed_ms(elapsed_ms: u128) -> &'static str {
    let idx = (elapsed_ms / 120) as usize % SPINNER_FRAMES.len();
    SPINNER_FRAMES[idx]
}

fn spinner_glyph() -> &'static str {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = *EPOCH.get_or_init(Instant::now);
    spinner_frame_for_elapsed_ms(epoch.elapsed().as_millis())
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::StageGrid;
    let border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled(
            "STAGE GRID [3] ←→ column  ↑↓ select  Space toggle  Enter detail",
            Style::default().fg(border_fg),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let status_by_stage = app
        .stage_outcomes
        .iter()
        .map(|outcome| (outcome.stage.as_str(), outcome.status.as_str()))
        .collect::<HashMap<_, _>>();
    render_planned_with_statuses(f, inner, app, &status_by_stage);
}

fn render_planned_with_statuses(
    f: &mut Frame,
    area: Rect,
    app: &App,
    status_by_stage: &HashMap<&str, &str>,
) {
    let chunks = Layout::horizontal([
        Constraint::Percentage(25),
        Constraint::Percentage(36),
        Constraint::Percentage(39),
    ])
    .split(area);

    let focused = app.focused_panel == Panel::StageGrid;
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
        let completed = group
            .stages
            .iter()
            .filter(|stage| {
                status_by_stage
                    .get(stage.as_str())
                    .is_some_and(|status| is_final(status))
            })
            .count();
        let failed = group
            .stages
            .iter()
            .filter(|stage| status_by_stage.get(stage.as_str()) == Some(&"fail"))
            .count();
        let skipped = group
            .stages
            .iter()
            .filter(|stage| status_by_stage.get(stage.as_str()) == Some(&"skipped"))
            .count();
        let header_style = stage_group_header_style(
            col_focused,
            enabled,
            completed,
            failed,
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
            let active = app.active_stage.as_deref() == Some(stage.as_str());
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
fn cell_for_status(status: &str) -> (&'static str, Style) {
    match status {
        "pass" => ("[██]", Style::default().fg(Color::Green)),
        "fail" => ("[✗✗]", Style::default().fg(Color::Red)),
        "running" | "active" => (
            spinner_glyph(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        // "disabled" = genuinely impossible for this config (grayed out).
        "disabled" => (
            "[  ]",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        ),
        "skipped" => (
            "[  ]",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM),
        ),
        "will_run" => ("[██]", Style::default().fg(Color::White)),
        "excluded" => ("[  ]", Style::default().fg(Color::White)),
        _ => ("[░░]", Style::default().fg(Color::DarkGray)),
    }
}

fn is_final(status: &str) -> bool {
    matches!(status, "pass" | "fail" | "skipped")
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

/// Decides the color for a group's header (bar + title): a column that has
/// finished every one of its currently-enabled stages (and none failed)
/// reads as done-and-green, regardless of the group's full catalog size --
/// a failure still wins over "everything ran", so a fully-completed-but-
/// failing column stays red rather than misreporting success as green.
fn stage_group_header_style(
    col_focused: bool,
    enabled: usize,
    completed: usize,
    failed: usize,
    has_any_status: bool,
) -> Style {
    let all_enabled_complete = enabled > 0 && failed == 0 && completed >= enabled;
    if col_focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if failed > 0 {
        Style::default().fg(Color::Red)
    } else if all_enabled_complete {
        Style::default().fg(Color::Green)
    } else if !has_any_status {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::White)
    }
}

/// Builds a group's header line: bar + "x/y" against `enabled` (the subset
/// of stages actually selected to run next), NOT `total` (the group's full
/// catalog size) -- "2/40" reads as "barely anything passed" when it really
/// means "both of the 2 selected stages passed"; "2/2" plus a dim total off
/// to the side says that correctly. The bar's fill is clamped to `enabled`
/// so a stale completed-count from a prior, wider stage selection can't
/// overfill the bar past its own width.
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
        format!("  ({total} total)"),
        Style::default().fg(Color::DarkGray),
    ));
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // both be measured against `enabled` (2), with the 40 relegated to
        // a dim "(40 total)" suffix, not the main fraction.
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
        assert!(text.contains("(40 total)"));
        // The bar itself must be full (both of the 2 enabled stages done),
        // not read as 2-out-of-40 nearly-empty.
        assert!(text.contains("[████████]"));
    }

    #[test]
    fn header_total_suffix_is_dimmed_separately_from_the_main_count() {
        let style = Style::default().fg(Color::White);
        let spans = stage_group_header_spans("PRE", 1, 3, 0, 5, style);
        let total_span = spans
            .iter()
            .find(|s| s.content.contains("total"))
            .expect("a total span");
        assert_eq!(total_span.style.fg, Some(Color::DarkGray));
        let main_span = &spans[0];
        assert_eq!(main_span.style.fg, Some(Color::White));
        assert_ne!(main_span.style.fg, total_span.style.fg);
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
}

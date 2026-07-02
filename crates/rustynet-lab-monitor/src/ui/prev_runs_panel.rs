use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;
use crate::data::run_matrix::RunSummary;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled("PREV RUNS", Style::default().fg(Color::Cyan)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.recent_runs.is_empty() {
        f.render_widget(
            Paragraph::new("No completed runs in matrix")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let cols = Layout::horizontal([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .split(inner);

    let group_sizes: Vec<usize> = app
        .planned_stage_groups()
        .iter()
        .map(|group| group.stages.len())
        .collect();

    for i in 0..3 {
        if let Some(run) = app.recent_runs.get(i) {
            render_run_card(f, cols[i], run, i, &group_sizes);
        } else {
            render_empty_slot(f, cols[i]);
        }
    }
}

fn render_run_card(f: &mut Frame, area: Rect, run: &RunSummary, idx: usize, group_sizes: &[usize]) {
    let label = match idx {
        0 => "Run 1  latest",
        1 => "Run 2",
        _ => "Run 3  oldest",
    };

    let is_pass = run.overall_result.eq_ignore_ascii_case("pass");
    let is_empty = run.overall_result.is_empty();

    let (result_sym, result_color) = if is_pass {
        ("✓ PASS", Color::Green)
    } else if is_empty {
        ("? ----", Color::DarkGray)
    } else {
        ("✗ FAIL", Color::Red)
    };

    // Progress bar: width = column width minus brackets and count text.
    let count_str = format!(" {}/{}", run.passed_stages, run.total_stages);
    let bar_w = (area.width as usize)
        .saturating_sub(2 + count_str.len()) // brackets + count
        .clamp(4, 20);
    let ratio = if run.total_stages > 0 {
        run.passed_stages as f64 / run.total_stages as f64
    } else {
        0.0
    };
    let filled = ((ratio * bar_w as f64).round() as usize).min(bar_w);
    let bar_color = if is_pass { Color::Green } else { Color::Red };

    // Truncate stage names to one line — area.width minus symbol prefix.
    let max_name = (area.width as usize).saturating_sub(3).max(8);

    // Stage line goes BEFORE the bar so it's visible even in short panels.
    let stage_line: Line = if !is_pass && !run.first_failed_stage.is_empty() {
        let name = truncate(&short_stage_name(&run.first_failed_stage), max_name);
        Line::from(vec![
            Span::styled("⊗ ", Style::default().fg(Color::Red)),
            Span::styled(name, Style::default().fg(Color::Red)),
        ])
    } else if is_pass && !run.last_passed_stage.is_empty() {
        let name = truncate(&short_stage_name(&run.last_passed_stage), max_name);
        Line::from(vec![
            Span::styled("✓ ", Style::default().fg(Color::Green)),
            Span::styled(name, Style::default().fg(Color::Green)),
        ])
    } else {
        Line::from(Span::styled("—", Style::default().fg(Color::DarkGray)))
    };

    // For failed runs show which stage number it was; inline with bar.
    let stage_pos = if !is_pass && run.total_stages > 0 {
        format!(" ({}/{})", run.passed_stages + 1, run.total_stages)
    } else {
        String::new()
    };

    let lines: Vec<Line> = vec![
        // 1: run label
        Line::from(Span::styled(label, Style::default().fg(Color::Cyan))),
        // 2: status + commit
        Line::from(vec![
            Span::styled(result_sym, Style::default().fg(result_color)),
            Span::styled("  @ ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                if run.git_commit.is_empty() {
                    "-------".into()
                } else {
                    run.git_commit.clone()
                },
                Style::default().fg(Color::White),
            ),
        ]),
        // 3: stage name — always before the bar
        stage_line,
        // 4: progress bar (with PRE/BOOTSTRAP/LIVE LAB group dividers) +
        // passed/total count + optional fail position
        Line::from(
            [
                vec![Span::raw("[")],
                bar_spans_with_group_ticks(filled, bar_w, bar_color, group_sizes),
                vec![
                    Span::raw("]"),
                    Span::styled(count_str, Style::default().fg(Color::Gray)),
                    Span::styled(stage_pos, Style::default().fg(Color::DarkGray)),
                ],
            ]
            .concat(),
        ),
    ];

    f.render_widget(Paragraph::new(lines), area);
}

/// Build the `[███░░░]`-style bar as individual character spans, with a
/// vertical divider `│` overlaid at the 2 positions that split the bar
/// proportionally to the 3 stage-grid group sizes (PRE/BOOTSTRAP/LIVE LAB)
/// -- so e.g. a run that failed partway through can be read against roughly
/// which phase it was in, not just "X of Y stages". This is a proportional
/// visual guide, not an exact per-column mapping: the bar's own fill ratio
/// is measured in CSV-check-column units (RunSummary::total_stages), while
/// the group sizes are measured in a different unit (pipeline stage
/// names, see planned_stage_groups) -- the two don't share a 1:1 axis, so
/// the dividers mark rough proportions, not "this exact check is here".
fn bar_spans_with_group_ticks(
    filled: usize,
    bar_w: usize,
    fill_color: Color,
    group_sizes: &[usize],
) -> Vec<Span<'static>> {
    let total: usize = group_sizes.iter().sum();
    let tick_positions: Vec<usize> = if total == 0 || bar_w == 0 {
        Vec::new()
    } else {
        let mut running = 0usize;
        // Only the boundaries BETWEEN groups (skip the very last one --
        // there's nothing after LIVE LAB to divide from).
        group_sizes[..group_sizes.len().saturating_sub(1)]
            .iter()
            .map(|len| {
                running += len;
                ((running * bar_w) / total).min(bar_w.saturating_sub(1))
            })
            .collect()
    };

    (0..bar_w)
        .map(|i| {
            if tick_positions.contains(&i) {
                Span::styled("│", Style::default().fg(Color::Cyan))
            } else if i < filled {
                Span::styled("█", Style::default().fg(fill_color))
            } else {
                Span::styled("░", Style::default().fg(Color::DarkGray))
            }
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Strip common OS/type prefixes from a stage column name for compact display.
/// e.g. "linux_stage_baseline_runtime" → "baseline_runtime"
///      "cross_os_dns"                 → "x: dns"
///      "validate_macos_exit_foo"      → "validate_macos_exit_foo" (kept as-is)
fn short_stage_name(name: &str) -> String {
    // Some multi-node stages record their failure as "{node_alias}::{stage}"
    // to disambiguate which node failed (e.g.
    // "debian-headless-1::validate_linux_hello_limiter_flood") -- strip
    // that prefix so the remainder matches the plain stage name shown in
    // the Stage Grid, instead of looking like a name that doesn't exist
    // anywhere.
    let name = name.rsplit("::").next().unwrap_or(name);
    for prefix in &["linux_stage_", "macos_stage_", "windows_stage_"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
    if let Some(rest) = name.strip_prefix("cross_os_") {
        return format!("x:{rest}");
    }
    name.to_owned()
}

fn render_empty_slot(f: &mut Frame, area: Rect) {
    f.render_widget(
        Paragraph::new("—").style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glyphs<'a>(spans: &'a [Span<'static>]) -> Vec<&'a str> {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn short_stage_name_strips_a_node_alias_prefix() {
        assert_eq!(
            short_stage_name("debian-headless-1::validate_linux_hello_limiter_flood"),
            "validate_linux_hello_limiter_flood"
        );
    }

    #[test]
    fn short_stage_name_unaffected_without_a_node_alias() {
        assert_eq!(
            short_stage_name("linux_stage_baseline_runtime"),
            "baseline_runtime"
        );
        assert_eq!(short_stage_name("cross_os_dns"), "x:dns");
        assert_eq!(
            short_stage_name("validate_macos_admin_issue"),
            "validate_macos_admin_issue"
        );
    }

    #[test]
    fn ticks_land_proportionally_to_group_sizes() {
        // 5 + 19 + 40 = 64 total; a 64-wide bar should divide at exactly
        // 5 and 24 (5+19).
        let spans = bar_spans_with_group_ticks(0, 64, Color::Green, &[5, 19, 40]);
        let g = glyphs(&spans);
        assert_eq!(g[5], "│");
        assert_eq!(g[24], "│");
        // Everywhere else in an all-empty bar is the empty glyph.
        assert_eq!(g.iter().filter(|c| **c == "│").count(), 2);
    }

    #[test]
    fn ticks_stay_in_bounds_for_a_narrower_bar() {
        // Same 5/19/40 proportions, but an 8-wide bar -- must produce
        // exactly 8 spans (no panic, no out-of-bounds position).
        let spans = bar_spans_with_group_ticks(0, 8, Color::Green, &[5, 19, 40]);
        assert_eq!(spans.len(), 8);
    }

    #[test]
    fn no_ticks_when_group_sizes_are_all_zero() {
        let spans = bar_spans_with_group_ticks(2, 10, Color::Green, &[0, 0, 0]);
        let g = glyphs(&spans);
        assert!(!g.contains(&"│"));
    }

    #[test]
    fn fill_and_empty_glyphs_still_correct_around_ticks() {
        let spans = bar_spans_with_group_ticks(3, 10, Color::Green, &[2, 3, 5]);
        let g = glyphs(&spans);
        // Boundaries at 2 and 5 (2, then 2+3=5).
        assert_eq!(g[2], "│");
        assert_eq!(g[5], "│");
        // filled=3: positions 0,1 are filled (2 is a tick, overrides).
        assert_eq!(g[0], "█");
        assert_eq!(g[1], "█");
        // 3 and 4 are past the fill boundary and not ticks -- empty.
        assert_eq!(g[3], "░");
        assert_eq!(g[4], "░");
    }
}

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
        0 => "RUN 1  LATEST",
        1 => "RUN 2",
        _ => "RUN 3  OLDEST",
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
    // "{passed}/{in-scope} │ {catalog}" -- all three from the run's OWN
    // manifest (see App::run_plan_summary), so they're always coherent
    // (passed <= in-scope <= catalog). The main fraction is scoped to what
    // this run's topology actually intended to run; the number after the
    // divider is the full planned catalog, for reference. Historically the
    // left came from the manifest plan and the right from CSV columns -- two
    // different universes that could read e.g. "28/165 | 100" (in-scope
    // larger than the "total").
    let count_str = if run.counts_exact {
        format!(
            " {}/{} │ catalog {}",
            run.subset_passed_stages, run.subset_total_stages, run.total_stages
        )
    } else {
        format!(
            " CSV {}/{} (plan unavailable)",
            run.subset_passed_stages, run.subset_total_stages
        )
    };
    let bar_w = (area.width as usize)
        .saturating_sub(2 + count_str.chars().count()) // brackets + count
        .clamp(4, 20);

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
        // 4: progress bar (PRE/BOOTSTRAP/LIVE LAB sections, each independently
        // filled by its own pass ratio -- same style as the Stage Grid's
        // column bars) + passed/total count.
        Line::from(
            [
                vec![Span::raw("[")],
                bar_spans_by_section(run.section_stages, run.failing_section, bar_w, group_sizes),
                vec![
                    Span::raw("]"),
                    Span::styled(count_str, Style::default().fg(Color::Gray)),
                ],
            ]
            .concat(),
        ),
    ];

    f.render_widget(Paragraph::new(lines), area);
}

/// Builds the `[███░░░│███░░]`-style bar as individual character spans: 3
/// sections proportional in WIDTH to the stage-grid group sizes
/// (PRE/BOOTSTRAP/LIVE LAB), each filled independently by its OWN
/// `(passed, total)` ratio from `section_stages` (gray = never reached
/// within that section) -- not the run's single overall ratio, so a run
/// that got all the way through PRE and BOOTSTRAP but died early in LIVE LAB
/// shows exactly that shape. Same layout as the Stage Grid's own per-column
/// bars, just laid out side by side in one line instead of 3 separate
/// panes.
///
/// Fill color is white, EXCEPT the one section named by `failing_section`
/// (see `RunSummary::failing_section`), which fills red instead -- marking
/// exactly where this run's own named failure happened, not just "some
/// section wasn't 100%" (a narrowly-scoped but PASSING run can easily have
/// sections well under 100% simply because most of the catalog was never
/// targeted, which isn't a failure at all).
///
/// The `│` divider is its OWN character INSERTED between sections, not
/// overlaid on top of one -- an earlier version overlaid it on each
/// section's first cell, which silently swallowed that cell's fill: a
/// section computing 2-of-6 filled would render only 1 visible cell (the
/// other one hidden under the divider), making a 33%-passed section look
/// visually identical to an unrelated 17%-passed section a few cells later.
/// Reserving space for the dividers up front keeps every section's full
/// width available for its own fill.
fn bar_spans_by_section(
    section_stages: [(usize, usize); 3],
    failing_section: Option<usize>,
    bar_w: usize,
    group_sizes: &[usize],
) -> Vec<Span<'static>> {
    let grey = || Span::styled("░", Style::default().fg(Color::DarkGray));
    if bar_w == 0 {
        return Vec::new();
    }
    let group_total: usize = group_sizes.iter().sum();
    if group_total == 0 {
        return (0..bar_w).map(|_| grey()).collect();
    }

    let dividers = group_sizes.len().saturating_sub(1);
    // Leave at least 1 cell per section even on a very narrow bar.
    let fill_w = bar_w
        .saturating_sub(dividers)
        .max(group_sizes.len().min(bar_w));

    // Proportional width per section over fill_w (not bar_w), via cumulative
    // rounding so the widths always sum to exactly fill_w.
    let mut widths = Vec::with_capacity(group_sizes.len());
    let mut running = 0usize;
    let mut prev_alloc = 0usize;
    for size in group_sizes {
        running += size;
        let alloc = (running * fill_w) / group_total;
        widths.push(alloc.saturating_sub(prev_alloc));
        prev_alloc = alloc;
    }
    if let (Some(last), true) = (widths.last_mut(), prev_alloc < fill_w) {
        *last += fill_w - prev_alloc;
    }

    let mut spans = Vec::with_capacity(bar_w);
    let section_count = widths.len();
    for (idx, (&width, &(passed, total))) in widths.iter().zip(section_stages.iter()).enumerate() {
        let ratio = if total == 0 {
            0.0
        } else {
            passed as f64 / total as f64
        };
        let filled = ((ratio * width as f64).round() as usize).min(width);
        // The failing section always gets exactly one red marker cell at
        // the point of failure, even if `filled` is 0 (the very first step
        // in this section is what failed) or would otherwise fill the
        // entire width (leave room for the marker by capping `filled` a
        // cell short) -- "some section wasn't 100% white" isn't the signal
        // here, "this exact cell is where it broke" is. White fill runs up
        // to (not including) the marker; everything after is unreached grey.
        let marker = (failing_section == Some(idx)).then(|| filled.min(width.saturating_sub(1)));
        let white_up_to = marker.unwrap_or(filled);
        for i in 0..width {
            if Some(i) == marker {
                spans.push(Span::styled("█", Style::default().fg(Color::Red)));
            } else if i < white_up_to {
                spans.push(Span::styled("█", Style::default().fg(Color::White)));
            } else {
                spans.push(grey());
            }
        }
        if idx + 1 < section_count {
            spans.push(Span::styled("│", Style::default().fg(Color::Cyan)));
        }
    }
    while spans.len() < bar_w {
        spans.push(grey());
    }
    spans.truncate(bar_w);
    spans
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

    const ZERO_SECTIONS: [(usize, usize); 3] = [(0, 0), (0, 0), (0, 0)];

    #[test]
    fn ticks_land_proportionally_to_group_sizes() {
        // 5 + 19 + 40 = 64 total; dividers are reserved cells (2 of them),
        // so the 3 sections split the remaining 62 cells proportionally:
        // 4 / 19 / 39, with dividers at positions 4 and 24 (4, then 4+1+19).
        let spans = bar_spans_by_section(ZERO_SECTIONS, None, 64, &[5, 19, 40]);
        let g = glyphs(&spans);
        assert_eq!(g[4], "│");
        assert_eq!(g[24], "│");
        assert_eq!(g.iter().filter(|c| **c == "│").count(), 2);
    }

    #[test]
    fn ticks_stay_in_bounds_for_a_narrower_bar() {
        // Same 5/19/40 proportions, but an 8-wide bar -- must produce
        // exactly 8 spans (no panic, no out-of-bounds position).
        let spans = bar_spans_by_section(ZERO_SECTIONS, None, 8, &[5, 19, 40]);
        assert_eq!(spans.len(), 8);
    }

    #[test]
    fn no_ticks_when_group_sizes_are_all_zero() {
        let spans = bar_spans_by_section(ZERO_SECTIONS, None, 10, &[0, 0, 0]);
        let g = glyphs(&spans);
        assert!(!g.contains(&"│"));
    }

    #[test]
    fn zero_total_sections_render_as_all_grey() {
        let spans = bar_spans_by_section(ZERO_SECTIONS, None, 10, &[2, 3, 5]);
        let g = glyphs(&spans);
        assert!(g.iter().all(|c| *c == "░" || *c == "│"));
        assert!(!g.contains(&"█"));
    }

    #[test]
    fn zero_width_bar_returns_no_spans() {
        let sections = [(5, 5), (1, 2), (0, 3)];
        assert!(bar_spans_by_section(sections, None, 0, &[2, 3, 5]).is_empty());
    }

    #[test]
    fn each_section_fills_independently_by_its_own_pass_ratio() {
        // Regression for the PREV RUNS redesign: each of the 3 sections must
        // color by ITS OWN (passed, total), not the run's single overall
        // ratio -- e.g. a run that finished BOOTSTRAP cleanly but barely
        // started LIVE LAB must show that shape, not a uniform average bar.
        // group_sizes [2, 4, 6] (sum 12) over a 12-wide bar: 2 dividers
        // reserved leaves 10 fill cells, split 1 / 4 / 5. Layout: section1
        // (1 cell) | divider | section2 (4 cells) | divider | section3
        // (5 cells) = 1+1+4+1+5 = 12.
        let sections = [
            (2, 2), // section 1 (PRE-analogous): fully passed
            (2, 4), // section 2 (BOOTSTRAP-analogous): half passed
            (6, 6), // section 3 (LIVE LAB-analogous): fully passed
        ];

        let spans = bar_spans_by_section(sections, None, 12, &[2, 4, 6]);
        let g = glyphs(&spans);

        assert_eq!(g[0], "█", "section 1's only cell, fully passed");
        assert_eq!(g[1], "│", "tick at the PRE/BOOTSTRAP boundary");
        assert_eq!(g[2], "█", "section 2 at 50%: first of its 2 filled cells");
        assert_eq!(g[3], "█", "section 2 at 50%: second of its 2 filled cells");
        assert_eq!(g[4], "░");
        assert_eq!(g[5], "░");
        assert_eq!(g[6], "│", "tick at the BOOTSTRAP/LIVE LAB boundary");
        for (i, glyph) in g.iter().enumerate().take(12).skip(7) {
            assert_eq!(*glyph, "█", "section 3 is fully passed: index {i}");
        }
    }

    #[test]
    fn bootstrap_section_fills_from_its_own_ratio_not_the_overall_run_ratio() {
        // Direct regression for the reported bug: a run where BOOTSTRAP
        // genuinely passed most of its checks must show BOOTSTRAP mostly
        // filled, even if the overall run's CSV-wide ratio is low because
        // LIVE LAB barely started. group_sizes [5, 19, 40] over a 64-wide
        // bar reserves 2 divider cells (62 fill cells: 4/19/39), putting
        // BOOTSTRAP's 19 cells at positions [5, 24).
        let sections = [
            (5, 5),   // PRE: complete
            (17, 19), // BOOTSTRAP: nearly all passed
            (2, 40),  // LIVE LAB: barely started
        ];
        let spans = bar_spans_by_section(sections, None, 64, &[5, 19, 40]);
        let g = glyphs(&spans);
        let bootstrap_filled = g[5..24].iter().filter(|c| **c == "█").count();
        assert!(
            bootstrap_filled >= 15,
            "BOOTSTRAP (17/19 passed) must render mostly filled, got {bootstrap_filled}/19 filled cells: {g:?}"
        );
    }

    #[test]
    fn the_divider_no_longer_swallows_a_sections_own_fill_cell() {
        // Regression for the reported bug: with the divider overlaid on a
        // section's own first cell, a section computing 2-of-N filled
        // rendered only 1 visible cell (the other one hidden under the
        // divider) -- making a 33%-passed BOOTSTRAP section look visually
        // identical to an unrelated 17%-passed LIVE LAB section a few cells
        // later. The divider must now be a separate cell, so both of a
        // 2-filled section's cells are visible.
        let sections = [(5, 5), (4, 12), (17, 102)];
        let spans = bar_spans_by_section(sections, None, 20, &[5, 19, 40]);
        let g = glyphs(&spans);
        let filled = g.iter().filter(|c| **c == "█").count();
        // Both BOOTSTRAP (4/12 -> 2 of its cells) and LIVE LAB (17/102 -> 2
        // of its cells) should each show 2 visible filled cells, not 1.
        assert!(
            filled >= 4,
            "expected at least 2 filled cells per non-PRE section (plus PRE's own), got {filled}: {g:?}"
        );
    }

    #[test]
    fn fill_is_white_unless_failing_then_red() {
        let sections = [(5, 5), (12, 12), (10, 40)];

        let passing = bar_spans_by_section(sections, None, 64, &[5, 19, 40]);
        assert!(
            passing
                .iter()
                .all(|s| s.style.fg != Some(Color::Green) && s.style.fg != Some(Color::Red)),
            "a passing run's fill must be white, never green or red"
        );
        assert!(
            passing
                .iter()
                .any(|s| s.content.as_ref() == "█" && s.style.fg == Some(Color::White)),
            "expected at least one white-filled cell"
        );

        // failing_section = Some(1) -> BOOTSTRAP (index 1) gets exactly one
        // red marker cell; PRE (index 0) and LIVE LAB (index 2) stay white.
        let failing = bar_spans_by_section(sections, Some(1), 64, &[5, 19, 40]);
        assert!(
            failing[0].style.fg == Some(Color::White),
            "PRE (not the failing section) must stay white"
        );
        let bootstrap_red = failing[5..24]
            .iter()
            .any(|s| s.content.as_ref() == "█" && s.style.fg == Some(Color::Red));
        assert!(
            bootstrap_red,
            "BOOTSTRAP (the failing section) must have a red marker"
        );
        let live_lab_red = failing[25..]
            .iter()
            .any(|s| s.content.as_ref() == "█" && s.style.fg == Some(Color::Red));
        assert!(
            !live_lab_red,
            "LIVE LAB (not the failing section) must not be red"
        );
    }

    #[test]
    fn failing_section_always_shows_a_marker_even_at_zero_or_full_progress() {
        // The marker must be visible in two edge cases the plain fill-ratio
        // math alone would otherwise hide: (a) the failure is the very
        // FIRST step in its section (filled = 0 -- nothing to distinguish
        // "broke immediately" from "not reached" without a marker), and (b)
        // the section's ratio rounds up to 100% width even though not
        // literally every step passed (no room left for a marker unless
        // filled is capped a cell short).
        let group_sizes = [5, 19, 40];

        // (a) PRE fails on its very first step: 0 of 5 passed.
        let zero_progress = [(0, 5), (0, 19), (0, 40)];
        let spans = bar_spans_by_section(zero_progress, Some(0), 64, &group_sizes);
        assert_eq!(
            spans[0].style.fg,
            Some(Color::Red),
            "the failing section's first cell must be the marker when nothing passed yet"
        );

        // (b) BOOTSTRAP "fully" passed by ratio (19/19) but is still the
        // failing section (e.g. a later, ungranular check failed) -- must
        // still show a marker, sacrificing one white cell for it.
        let full_ratio = [(5, 5), (19, 19), (0, 40)];
        let spans = bar_spans_by_section(full_ratio, Some(1), 64, &group_sizes);
        let bootstrap_has_marker = spans[5..24]
            .iter()
            .any(|s| s.content.as_ref() == "█" && s.style.fg == Some(Color::Red));
        assert!(
            bootstrap_has_marker,
            "a 100%-ratio failing section must still show a marker, not just solid white"
        );
    }
}

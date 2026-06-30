use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::app::App;
use crate::data::run_matrix::RunSummary;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title("PREV RUNS")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
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

    for i in 0..3 {
        if let Some(run) = app.recent_runs.get(i) {
            render_run_card(f, cols[i], run, i);
        } else {
            render_empty_slot(f, cols[i]);
        }
    }
}

fn render_run_card(f: &mut Frame, area: Rect, run: &RunSummary, idx: usize) {
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
        .min(20)
        .max(4);
    let ratio = if run.total_stages > 0 {
        run.passed_stages as f64 / run.total_stages as f64
    } else {
        0.0
    };
    let filled = ((ratio * bar_w as f64).round() as usize).min(bar_w);
    let empty = bar_w - filled;
    let bar_color = if is_pass { Color::Green } else { Color::Red };

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(label, Style::default().fg(Color::Cyan))),
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
        // Progress bar + count
        Line::from(vec![
            Span::raw("["),
            Span::styled("█".repeat(filled), Style::default().fg(bar_color)),
            Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
            Span::raw("]"),
            Span::styled(count_str, Style::default().fg(Color::Gray)),
        ]),
    ];

    if !is_pass && !run.first_failed_stage.is_empty() {
        // Show failed stage name and its position in the run.
        let failed_num = run.passed_stages + 1;
        lines.push(Line::from(vec![
            Span::styled("⊗ ", Style::default().fg(Color::Red)),
            Span::styled(
                short_stage_name(&run.first_failed_stage),
                Style::default().fg(Color::Red),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("  stage {}/{}", failed_num, run.total_stages),
            Style::default().fg(Color::DarkGray),
        )));
    } else if is_pass && !run.last_ran_stage.is_empty() {
        // Show last stage that ran so user knows how far the run got.
        lines.push(Line::from(vec![
            Span::styled("✓ ", Style::default().fg(Color::Green)),
            Span::styled(
                short_stage_name(&run.last_ran_stage),
                Style::default().fg(Color::Green),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            "  last stage",
            Style::default().fg(Color::DarkGray),
        )));
    } else if is_pass {
        lines.push(Line::from(Span::styled(
            "all stages passed",
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/// Strip common OS/type prefixes from a stage column name for compact display.
/// e.g. "linux_stage_baseline_runtime" → "baseline_runtime"
///      "cross_os_dns"                 → "x: dns"
///      "validate_macos_exit_foo"      → "validate_macos_exit_foo" (kept as-is)
fn short_stage_name(name: &str) -> String {
    for prefix in &[
        "linux_stage_",
        "macos_stage_",
        "windows_stage_",
    ] {
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

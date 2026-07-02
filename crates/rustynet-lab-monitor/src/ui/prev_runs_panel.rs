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
        .clamp(4, 20);
    let ratio = if run.total_stages > 0 {
        run.passed_stages as f64 / run.total_stages as f64
    } else {
        0.0
    };
    let filled = ((ratio * bar_w as f64).round() as usize).min(bar_w);
    let empty = bar_w - filled;
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
        // 4: progress bar + passed/total count + optional fail position
        Line::from(vec![
            Span::raw("["),
            Span::styled("█".repeat(filled), Style::default().fg(bar_color)),
            Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
            Span::raw("]"),
            Span::styled(count_str, Style::default().fg(Color::Gray)),
            Span::styled(stage_pos, Style::default().fg(Color::DarkGray)),
        ]),
    ];

    f.render_widget(Paragraph::new(lines), area);
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

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::collections::HashMap;

use crate::app::{App, Panel};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::StageGrid;
    let block = Block::default()
        .title("STAGE GRID [3] ←→ column  ↑↓ select  Space toggle  Enter detail")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
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
        let header_style = if col_focused {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if status_by_stage.is_empty() {
            Style::default().fg(Color::Cyan)
        } else if failed > 0 {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::White)
        };
        let header = if status_by_stage.is_empty() {
            format!("{}  {}/{} enabled", group.name, enabled, group.stages.len())
        } else if skipped > 0 {
            format!(
                "{}  {}  {}/{}  {} skipped",
                group.name,
                progress_bar_string(completed, group.stages.len(), 8),
                completed,
                group.stages.len(),
                skipped
            )
        } else {
            format!(
                "{}  {}  {}/{}",
                group.name,
                progress_bar_string(completed, group.stages.len(), 8),
                completed,
                group.stages.len()
            )
        };
        lines.push(Line::from(vec![Span::styled(header, header_style)]));
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
            let enabled = app.stage_enabled(&stage);
            let active = app.active_stage.as_deref() == Some(stage.as_str());
            let status = if active {
                "active"
            } else if let Some(status) = status_by_stage.get(stage.as_str()) {
                status
            } else if enabled {
                "pending"
            } else {
                "disabled"
            };
            let (symbol, status_style) = cell_for_status(status);
            let mut style = if active {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(status, "pass" | "fail" | "skipped" | "disabled") {
                status_style
            } else if enabled {
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

fn cell_for_status(status: &str) -> (&'static str, Style) {
    match status {
        "pass" => ("[██]", Style::default().fg(Color::Green)),
        "fail" => ("[✗✗]", Style::default().fg(Color::Red)),
        "running" | "active" => (
            "[▓▓]",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        // "disabled" = not part of the current plan (grayed out, empty box).
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
        // "pending" = enabled, part of the current plan, hasn't run yet --
        // filled white box so it visually reads as "will run" rather than
        // blending into the empty "disabled" box.
        "pending" => ("[██]", Style::default().fg(Color::White)),
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

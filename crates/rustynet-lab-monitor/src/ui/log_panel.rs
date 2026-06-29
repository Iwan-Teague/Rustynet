use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, Panel};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let active_stage = app.active_stage.as_deref().unwrap_or("none");
    let focused = app.focused_panel == Panel::Log;
    let title = format!("LOG [4/L] — {} summary", active_stage);

    let block = Block::default()
        .title(title.as_str())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.log_lines.is_empty() {
        f.render_widget(
            Paragraph::new("No log output").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let max_lines = inner.height as usize;
    let total_lines = app.log_lines.len();
    let start = total_lines.saturating_sub(max_lines);
    let end = (start + max_lines).min(total_lines);

    let visible: Vec<Line> = app.log_lines[start..end]
        .iter()
        .map(|line| {
            let style = if line.contains("FAIL") {
                Style::default().fg(Color::Red)
            } else if line.contains("PASS") {
                Style::default().fg(Color::Green)
            } else if line.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if line.contains("WARN") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(line.as_str(), style))
        })
        .collect();

    f.render_widget(Paragraph::new(visible).scroll((0, 0)), inner);
}

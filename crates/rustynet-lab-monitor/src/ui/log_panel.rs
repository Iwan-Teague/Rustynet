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

    let pinned = app.log_scroll > 0;
    let new_lines = if pinned {
        app.log_lines.len().saturating_sub(app.log_scroll_anchor)
    } else {
        0
    };
    let has_pill = pinned && new_lines > 0;

    let scroll_hint = if pinned {
        "  G/End=follow"
    } else {
        "  ↑=scroll"
    };
    let title = format!("LOG [4/L] — {active_stage}{scroll_hint}");

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

    // Reserve one line for the "↓ N new" pill when pinned with new content.
    let (content_area, pill_area) = if has_pill && inner.height >= 2 {
        let ca = Rect {
            height: inner.height - 1,
            ..inner
        };
        let pa = Rect {
            y: inner.y + inner.height - 1,
            height: 1,
            ..inner
        };
        (ca, Some(pa))
    } else {
        (inner, None)
    };

    let max_lines = content_area.height as usize;
    let total = app.log_lines.len();

    // log_scroll = lines above the bottom; clamp so we can't scroll past the top.
    let scroll_clamped = app.log_scroll.min(total.saturating_sub(max_lines));
    let start = total.saturating_sub(max_lines + scroll_clamped);
    let end = (start + max_lines).min(total);

    let visible: Vec<Line> = app.log_lines[start..end]
        .iter()
        .map(|line| {
            let style = if line.contains("FAIL") || line.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if line.contains("PASS") {
                Style::default().fg(Color::Green)
            } else if line.contains("WARN") {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(line.as_str(), style))
        })
        .collect();

    f.render_widget(Paragraph::new(visible), content_area);

    if let Some(pill_rect) = pill_area {
        let pill = format!(" ↓ {} new line{}  G/End to follow ", new_lines, if new_lines == 1 { "" } else { "s" });
        f.render_widget(
            Paragraph::new(Span::styled(
                pill,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow),
            )),
            pill_rect,
        );
    }
}

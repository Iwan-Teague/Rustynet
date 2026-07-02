use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(Span::styled(
            "LOOP PIPELINE",
            Style::default().fg(Color::Cyan),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut spans = Vec::new();
    for (idx, (label, active, done)) in app.pipeline_steps().into_iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled(" -> ", Style::default().fg(Color::DarkGray)));
        }
        let style = if active {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else if done {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        spans.push(Span::styled(label, style));
    }

    f.render_widget(Paragraph::new(Line::from(spans)), inner);
}

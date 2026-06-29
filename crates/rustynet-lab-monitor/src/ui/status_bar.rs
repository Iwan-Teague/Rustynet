use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, _app: &App) {
    let hints = [
        ("Tab", "page"),
        ("s", "start"),
        ("x", "stop"),
        ("a", "auto target"),
        ("?", "help"),
        ("q", "quit"),
    ];

    let spans: Vec<Span> = hints
        .iter()
        .map(|(key, desc)| {
            Span::styled(
                format!(" {}:{} ", key, desc),
                Style::default().fg(Color::DarkGray),
            )
        })
        .collect();

    let line = Line::from(spans);
    f.render_widget(
        Paragraph::new(line).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

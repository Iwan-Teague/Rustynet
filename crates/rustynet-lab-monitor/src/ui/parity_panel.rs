use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Style},
    text::Span,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{Os, ParityState, Role};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::Parity;
    let block = Block::default()
        .title("PARITY MATRIX [2/P]")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused {
            Color::Yellow
        } else {
            Color::DarkGray
        }));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.parity_matrix.is_empty() {
        f.render_widget(
            Paragraph::new("No run matrix data").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let header =
        Row::new(vec!["ROLE", "LINUX", "MACOS", "WIN"]).style(Style::default().fg(Color::Cyan));

    let mut rows: Vec<Row> = Vec::new();
    for role in Role::all() {
        let linux = app
            .parity_matrix
            .get(&(role, Os::Linux))
            .map(|s| cell_span(*s))
            .unwrap_or_else(|| Span::styled("[  ]", Style::default().fg(Color::DarkGray)));
        let macos = app
            .parity_matrix
            .get(&(role, Os::Macos))
            .map(|s| cell_span(*s))
            .unwrap_or_else(|| Span::styled("[  ]", Style::default().fg(Color::DarkGray)));
        let win = app
            .parity_matrix
            .get(&(role, Os::Windows))
            .map(|s| cell_span(*s))
            .unwrap_or_else(|| Span::styled("[  ]", Style::default().fg(Color::DarkGray)));

        rows.push(Row::new(vec![
            Span::styled(role.label(), Style::default().fg(Color::White)),
            linux,
            macos,
            win,
        ]));
    }

    let widths = [
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths).header(header).column_spacing(1);

    f.render_widget(table, inner);
}

fn cell_span(state: ParityState) -> Span<'static> {
    let (symbol, color) = match state {
        ParityState::Proven => ("[ ██ ]", Color::Green),
        ParityState::Failed => ("[ ✗✗ ]", Color::Red),
        ParityState::Unproven => ("[ ░░ ]", Color::DarkGray),
    };
    Span::styled(symbol, Style::default().fg(color))
}

use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{CellOutcome, Os, ParityState, Role};

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

    let empty_history: Vec<CellOutcome> = Vec::new();

    let rows: Vec<Row> = Role::all()
        .into_iter()
        .map(|role| {
            let role_cell = Cell::new(Text::from(role.label()))
                .style(Style::default().fg(Color::White));
            let os_cells: Vec<Cell> = Os::all()
                .into_iter()
                .map(|os| {
                    let state = app
                        .parity_matrix
                        .get(&(role, os))
                        .copied()
                        .unwrap_or(ParityState::Unproven);
                    let history = app
                        .parity_sparklines
                        .get(&(role, os))
                        .map(Vec::as_slice)
                        .unwrap_or(empty_history.as_slice());
                    Cell::new(parity_cell_text(state, history))
                })
                .collect();

            let mut cells: Vec<Cell> = vec![role_cell];
            cells.extend(os_cells);
            Row::new(cells).height(2)
        })
        .collect();

    let widths = [
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths).header(header).column_spacing(1);
    f.render_widget(table, inner);
}

fn parity_cell_text(state: ParityState, history: &[CellOutcome]) -> Text<'static> {
    Text::from(vec![state_line(state), sparkline(history)])
}

fn state_line(state: ParityState) -> Line<'static> {
    let (symbol, color) = match state {
        ParityState::Proven => ("[██]", Color::Green),
        ParityState::Failed => ("[✗✗]", Color::Red),
        ParityState::Unproven => ("[░░]", Color::DarkGray),
    };
    Line::from(Span::styled(symbol, Style::default().fg(color)))
}

fn sparkline(history: &[CellOutcome]) -> Line<'static> {
    if history.is_empty() {
        return Line::from(Span::styled("—", Style::default().fg(Color::DarkGray)));
    }
    let spans: Vec<Span<'static>> = history
        .iter()
        .copied()
        .map(|outcome| match outcome {
            CellOutcome::Pass => Span::styled("▇", Style::default().fg(Color::Green)),
            CellOutcome::Fail => Span::styled("▄", Style::default().fg(Color::Red)),
            CellOutcome::NotRun => Span::styled("░", Style::default().fg(Color::DarkGray)),
        })
        .collect();
    Line::from(spans)
}

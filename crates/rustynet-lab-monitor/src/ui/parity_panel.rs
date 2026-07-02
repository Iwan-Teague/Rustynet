use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{CellOutcome, Os, ParityState, Role};

// chars inside the brackets — [██████] = 8 chars total
const BAR_WIDTH: usize = 6;

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
            let role_cell = Cell::new(role.label()).style(Style::default().fg(Color::White));
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
                    Cell::new(progress_bar(state, history))
                })
                .collect();

            let mut cells: Vec<Cell> = vec![role_cell];
            cells.extend(os_cells);
            Row::new(cells)
        })
        .collect();

    // 10 + 8 + 8 + 8 + 3 spacing = 37 — fits in 38-char inner at 34% of 120
    let widths = [
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(8),
    ];

    let table = Table::new(rows, widths).header(header).column_spacing(1);
    f.render_widget(table, inner);
}

/// Single-line `[██████]` progress bar encoding parity state + run history.
///
/// - Proven  → full bright-green block
/// - Failed  → red fill (pass ratio) + red dim remainder — entire bar stays red
/// - Flaky   → yellow fill (pass ratio) + yellow dim remainder — elevated recent
///   failure rate without being consistently broken (see `classify_recent_history`)
/// - Unproven → gray fill (pass ratio) + dark-gray remainder
fn progress_bar(state: ParityState, history: &[CellOutcome]) -> Line<'static> {
    let relevant = history
        .iter()
        .filter(|o| **o != CellOutcome::NotRun)
        .count();
    let passes = history.iter().filter(|o| **o == CellOutcome::Pass).count();

    match state {
        ParityState::Proven => Line::from(Span::styled(
            format!("[{}]", "█".repeat(BAR_WIDTH)),
            Style::default().fg(Color::Green),
        )),
        ParityState::Failed => build_bar(passes, relevant, Color::Red, Color::Red),
        ParityState::Flaky => build_bar(passes, relevant, Color::Yellow, Color::Yellow),
        ParityState::Unproven => build_bar(passes, relevant, Color::Gray, Color::DarkGray),
    }
}

fn build_bar(
    passes: usize,
    relevant: usize,
    fill_color: Color,
    empty_color: Color,
) -> Line<'static> {
    let ratio = if relevant > 0 {
        passes as f64 / relevant as f64
    } else {
        0.0
    };
    let filled = ((ratio * BAR_WIDTH as f64).round() as usize).min(BAR_WIDTH);
    let empty = BAR_WIDTH - filled;

    let mut spans: Vec<Span<'static>> = vec![Span::raw("[")];
    if filled > 0 {
        spans.push(Span::styled(
            "█".repeat(filled),
            Style::default().fg(fill_color),
        ));
    }
    if empty > 0 {
        spans.push(Span::styled(
            "░".repeat(empty),
            Style::default().fg(empty_color),
        ));
    }
    spans.push(Span::raw("]"));
    Line::from(spans)
}

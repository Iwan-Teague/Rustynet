use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::app::{App, Panel};
use crate::data::run_matrix::{ParityState, StageMatrixEntry};

/// Full "everything that needs to pass" stage matrix: every individual
/// live-lab stage/security check, one column per OS, colored by its
/// current state. Bigger and more granular than the 8-role parity matrix
/// (which shows one representative stage per role) — this shows every
/// stage so gaps between OSes are visible at a glance.
pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::StageMatrix;
    let sel = app.stage_matrix_os_col;
    let matrix = &app.full_stage_matrix;
    let total =
        matrix.linux.len() + matrix.macos.len() + matrix.windows.len() + matrix.cross_os.len();
    let passed = count_passed(&matrix.linux)
        + count_passed(&matrix.macos)
        + count_passed(&matrix.windows)
        + count_passed(&matrix.cross_os);

    let outer_border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let outer = Block::default()
        .title(Span::styled(
            format!("FULL STAGE MATRIX [7] — {passed}/{total} checks passed"),
            Style::default().fg(outer_border_fg),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(outer_border_fg));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    if total == 0 {
        f.render_widget(
            Paragraph::new("No run matrix data").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(inner);
    let columns = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(rows[0]);

    // All 3 columns share the same vertical space (only width differs via
    // the horizontal split), so any one of them tells the real visible
    // row count -- stash it so the up/down key handlers (which run before
    // the next render) can clamp scroll to the real max immediately
    // instead of only at render time.
    let visible = render_os_column(
        f,
        columns[0],
        "LINUX",
        &matrix.linux,
        app.stage_matrix_scroll[0],
        focused && sel == 0,
    );
    app.stage_matrix_visible_rows.set(visible);
    render_os_column(
        f,
        columns[1],
        "MACOS",
        &matrix.macos,
        app.stage_matrix_scroll[1],
        focused && sel == 1,
    );
    render_os_column(
        f,
        columns[2],
        "WINDOWS",
        &matrix.windows,
        app.stage_matrix_scroll[2],
        focused && sel == 2,
    );
    render_cross_os_strip(f, rows[1], &matrix.cross_os);
}

fn render_os_column(
    f: &mut Frame,
    area: Rect,
    label: &str,
    stages: &[StageMatrixEntry],
    scroll: usize,
    selected: bool,
) -> usize {
    let passed = count_passed(stages);
    let border_fg = if selected { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled(
            format!("{label} {passed}/{}", stages.len()),
            Style::default().fg(border_fg),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible = inner.height as usize;
    let max_scroll = stages.len().saturating_sub(visible.max(1));
    let offset = scroll.min(max_scroll);

    let lines: Vec<Line> = stages
        .iter()
        .skip(offset)
        .take(visible)
        .map(stage_line)
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
    visible
}

fn render_cross_os_strip(f: &mut Frame, area: Rect, cross_os: &[StageMatrixEntry]) {
    if cross_os.is_empty() {
        return;
    }
    let passed = count_passed(cross_os);
    let mut spans: Vec<Span<'static>> = vec![Span::styled(
        format!("CROSS-OS {passed}/{}: ", cross_os.len()),
        Style::default().fg(Color::Cyan),
    )];
    for (idx, entry) in cross_os.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(glyph(entry.state), color_style(entry.state)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn stage_line(entry: &StageMatrixEntry) -> Line<'static> {
    Line::from(vec![
        Span::styled(glyph(entry.state), color_style(entry.state)),
        Span::styled(format!(" {}", entry.name), color_style(entry.state)),
    ])
}

fn glyph(state: ParityState) -> &'static str {
    match state {
        ParityState::Proven => "■",
        ParityState::Failed => "■",
        ParityState::Flaky => "▲",
        ParityState::Unproven => "□",
    }
}

fn color_style(state: ParityState) -> Style {
    Style::default().fg(match state {
        ParityState::Proven => Color::Green,
        ParityState::Failed => Color::Red,
        ParityState::Flaky => Color::Yellow,
        ParityState::Unproven => Color::DarkGray,
    })
}

fn count_passed(stages: &[StageMatrixEntry]) -> usize {
    stages
        .iter()
        .filter(|e| e.state == ParityState::Proven)
        .count()
}

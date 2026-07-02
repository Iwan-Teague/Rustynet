use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::app::{App, Panel};

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::Jobs;
    let border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled("JOBS [5/J]", Style::default().fg(border_fg)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(job) = &app.active_job {
        let label = Style::default().fg(Color::Blue);
        let value = Style::default().fg(Color::White);
        let muted = Style::default().fg(Color::Gray);
        let mut lines = vec![
            Line::from(Span::styled("Job:", label)),
            Line::from(Span::styled(job.job_id.clone(), value)),
            Line::from(Span::styled("State:", label)),
            Line::from(Span::styled(job.state.clone(), value)),
            Line::from(Span::styled("Area:", label)),
            Line::from(Span::styled(job.area.clone(), value)),
            Line::from(Span::styled("Report:", label)),
            Line::from(Span::styled(job.report_dir.clone(), muted)),
        ];
        if app.stop_after_current {
            lines.push(Line::from(Span::styled("Drain:", label)));
            lines.push(Line::from(Span::styled(
                "stop after current run",
                Style::default().fg(Color::Yellow),
            )));
        }
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
    } else {
        f.render_widget(
            Paragraph::new("No active job").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
    }
}

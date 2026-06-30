use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

use crate::app::App;

pub fn render(f: &mut Frame, full_area: Rect, app: &App) {
    let Some(outcome) = app.selected_stage_outcome() else {
        return;
    };

    let popup_w = 72u16.min(full_area.width.saturating_sub(4));
    let popup_h = 22u16.min(full_area.height.saturating_sub(4));
    let x = (full_area.width.saturating_sub(popup_w)) / 2;
    let y = (full_area.height.saturating_sub(popup_h)) / 2;
    let popup_area = Rect::new(full_area.x + x, full_area.y + y, popup_w, popup_h);

    f.render_widget(Clear, popup_area);

    let border_color = status_color(outcome.status.as_str());
    let block = Block::default()
        .title(format!(" {} ", outcome.stage))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let dim = Style::default().fg(Color::DarkGray);
    let white = Style::default().fg(Color::White);
    let cyan = Style::default().fg(Color::Cyan);

    let badge = format!(
        "{}  {}",
        status_symbol(outcome.status.as_str()),
        outcome.status.to_uppercase()
    );
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(badge, Style::default().fg(border_color))),
        Line::default(),
        Line::from(Span::styled("SUMMARY", cyan)),
    ];

    if outcome.summary.is_empty() {
        lines.push(Line::from(Span::styled("—", dim)));
    } else {
        lines.push(Line::from(Span::styled(outcome.summary.as_str(), white)));
    }

    lines.push(Line::default());

    if outcome.artifacts.is_empty() {
        lines.push(Line::from(Span::styled("ARTIFACTS  none", dim)));
    } else {
        lines.push(Line::from(Span::styled(
            format!("ARTIFACTS  ({})", outcome.artifacts.len()),
            cyan,
        )));
        for artifact in &outcome.artifacts {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(artifact.as_str(), white),
            ]));
        }
    }

    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Esc · Enter  close   ↑↓ scroll",
        dim,
    )));

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((app.stage_detail_scroll as u16, 0)),
        inner,
    );
}

fn status_color(status: &str) -> Color {
    match status {
        "pass" => Color::Green,
        "fail" => Color::Red,
        "running" | "active" => Color::Yellow,
        "skipped" => Color::DarkGray,
        _ => Color::White,
    }
}

fn status_symbol(status: &str) -> &'static str {
    match status {
        "pass" => "[██]",
        "fail" => "[✗✗]",
        "running" | "active" => "[▓▓]",
        "skipped" => "[  ]",
        _ => "[░░]",
    }
}

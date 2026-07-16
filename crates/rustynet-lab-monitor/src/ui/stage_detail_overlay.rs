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

// Both of these used to re-implement their own literal "pass"/"fail"/
// "running"/"skipped" match instead of going through the crate's one
// canonical status parser (`StageStatus::parse`, dispatched via
// `stage_grid::cell_for_status` — the same function the Stage Grid itself
// uses). That meant a real terminal status the orchestrator actually emits
// but this match didn't literally spell out -- `aborted`, `timed_out`,
// `reused`, or any of `StageStatus::parse`'s other recognized aliases --
// fell through to the neutral/pending-looking default here, in the one view
// meant to explain a stage's outcome in detail. Delegating closes that gap
// and keeps color/symbol pinned to a single source of truth.
fn status_color(status: &str) -> Color {
    super::stage_grid::cell_for_status(status)
        .1
        .fg
        .unwrap_or(Color::White)
}

fn status_symbol(status: &str) -> &'static str {
    super::stage_grid::cell_for_status(status).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_and_active_use_the_stage_grid_spinner_not_a_static_glyph() {
        assert!(super::super::stage_grid::SPINNER_FRAMES.contains(&status_symbol("running")));
        assert!(super::super::stage_grid::SPINNER_FRAMES.contains(&status_symbol("active")));
    }

    #[test]
    fn aborted_and_timed_out_render_red_not_the_neutral_default() {
        // Regression: this overlay used to match "pass"/"fail"/"running"/
        // "skipped" literally and fall everything else -- including real
        // terminal statuses the orchestrator actually emits, like
        // "aborted" and "timed_out" -- through to the neutral default
        // (Color::White, "[░░]"), masking a failure as merely pending in
        // the one view meant to explain it. They must render exactly like
        // "fail" now that both route through the canonical StageStatus
        // parser.
        assert_eq!(status_color("aborted"), Color::Red);
        assert_eq!(status_color("timed_out"), Color::Red);
        assert_eq!(status_symbol("aborted"), "[✗✗]");
        assert_eq!(status_symbol("timed_out"), "[✗✗]");
    }

    #[test]
    fn reused_renders_distinctly_not_as_a_plain_pass() {
        assert_eq!(status_color("reused"), Color::Cyan);
        assert_eq!(status_symbol("reused"), "[↺↺]");
    }

    #[test]
    fn unknown_status_never_renders_as_a_pass_like_green() {
        assert_ne!(status_color("totally-not-a-real-status"), Color::Green);
    }
}

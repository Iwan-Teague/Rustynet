use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::app::App;

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let vms = app.vm_statuses.len();
    let (job, area_name, status) = match &app.active_job {
        Some(job) => {
            let status = match job.state.as_str() {
                "running" => "RUNNING",
                "done" => "DONE",
                "crashed" => "CRASHED",
                _ => "IDLE",
            };
            (job.job_id.as_str(), job.area.as_str(), status)
        }
        None => {
            let area = if app.config.area.is_empty() {
                "-"
            } else {
                app.config.area.as_str()
            };
            ("-", area, "IDLE")
        }
    };
    let title = Style::default().fg(Color::Blue);
    let value = Style::default().fg(Color::White);
    let sep = Style::default().fg(Color::DarkGray);
    let timers = app.stage_timer_labels();
    let top = Line::from(vec![
        Span::styled("RUSTYNET", title),
        Span::styled(" │ ", sep),
        Span::styled("STATUS:", title),
        Span::styled(format!("{:<8}", status), value),
        Span::styled(" │ ", sep),
        Span::styled(format!("{}:", timers[0].0), title),
        Span::styled(format!("{:<6}", fixed(timers[0].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[1].0), title),
        Span::styled(format!("{:<6}", fixed(timers[1].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[2].0), title),
        Span::styled(format!("{:<6}", fixed(timers[2].1.as_str(), 6)), value),
        Span::styled(" │ ", sep),
        Span::styled("VMS:", title),
        Span::styled(format!("{:<3}", vms), value),
        Span::styled(" │ ", sep),
        Span::styled("STAGES:", title),
        Span::styled(
            format!("{}/{}", app.stage_progress.passed, app.stage_progress.total),
            value,
        ),
    ]);
    let job_area_line = Line::from(vec![
        Span::styled("JOB:", title),
        Span::styled(format!(" {}", fixed(job, 56)), value),
        Span::styled(" │ ", sep),
        Span::styled("AREA:", title),
        Span::styled(format!(" {}", fixed(area_name, 56)), value),
    ]);

    let p = Paragraph::new(vec![top, Line::from(""), job_area_line, Line::from("")]);
    f.render_widget(p, area);
}

fn fixed(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        let mut out = value
            .chars()
            .take(max.saturating_sub(1))
            .collect::<String>();
        out.push('…');
        out
    }
}

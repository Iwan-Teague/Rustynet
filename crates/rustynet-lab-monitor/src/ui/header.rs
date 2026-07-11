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
            // A dead-PID job whose JSON still claims `running` ended
            // abnormally — say so instead of a clean IDLE.
            let status = if app.last_run_crashed {
                "CRASHED"
            } else {
                "IDLE"
            };
            ("-", area, status)
        }
    };
    let title = Style::default().fg(Color::Blue);
    let value = Style::default().fg(Color::White);
    let sep = Style::default().fg(Color::DarkGray);
    let timers = app.stage_timer_labels();
    let (run_done, run_total) = app.current_run_stage_progress();
    let run_checks = app
        .current_run_check_progress()
        .map(|(done, total)| format!("{done}/{total}"))
        .unwrap_or_else(|| "n/a".to_owned());
    let top = Line::from(vec![
        Span::styled("RUSTYNET", title),
        Span::styled(" │ ", sep),
        Span::styled("STATUS:", title),
        Span::styled(format!("{status:<8}"), value),
        Span::styled(" │ ", sep),
        Span::styled(format!("{}:", timers[0].0), title),
        Span::styled(format!("{:<6}", fixed(timers[0].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[1].0), title),
        Span::styled(format!("{:<6}", fixed(timers[1].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[2].0), title),
        Span::styled(format!("{:<6}", fixed(timers[2].1.as_str(), 6)), value),
        Span::styled(" │ ", sep),
        Span::styled("VMS:", title),
        Span::styled(format!("{vms:<3}"), value),
        Span::styled(" │ ", sep),
        Span::styled("SETTLED:", title),
        Span::styled(format!("{run_done}/{run_total}"), value),
        Span::styled(" TESTS:", title),
        Span::styled(run_checks, value),
        Span::styled(" │ ", sep),
        // History-wide coverage, discovered from matrix schema. Separate
        // from this invocation's stage/test totals above.
        Span::styled("COVERAGE:", title),
        Span::styled(
            format!("{}/{}", app.stage_progress.passed, app.stage_progress.total),
            value,
        ),
        // Green-but-unstable checks (latest pass, flake classifier not yet
        // Proven) — a warning sidecar, deliberately not subtracted from
        // the fraction.
        Span::styled(
            if app.stage_progress.flaky > 0 {
                format!(" ~{} flaky", app.stage_progress.flaky)
            } else {
                String::new()
            },
            Style::default().fg(Color::Yellow),
        ),
    ]);
    let job_area_line = Line::from(vec![
        Span::styled("JOB:", title),
        Span::styled(format!(" {}", fixed(job, 46)), value),
        Span::styled(" │ ", sep),
        Span::styled("AREA:", title),
        Span::styled(format!(" {}", fixed(area_name, 46)), value),
    ]);
    let source_line = Line::from(vec![
        Span::styled("PLAN:", title),
        Span::styled(format!(" {}", app.plan_source_label()), value),
        Span::styled(" │ ", sep),
        Span::styled(format!("{}:", app.stage_source_title()), title),
        Span::styled(format!(" {}", app.stage_source_value()), value),
        Span::styled(" │ ", sep),
        Span::styled("REFRESH:", title),
        Span::styled(" 2s stages / 5s active VMs", value),
    ]);

    let p = Paragraph::new(vec![top, job_area_line, source_line, Line::from("")]);
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

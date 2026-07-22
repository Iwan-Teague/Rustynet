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
    let (job, status) = match &app.active_job {
        Some(job) => {
            let status = match job.state.as_str() {
                "running" => "RUNNING",
                "done" => "DONE",
                "crashed" => "CRASHED",
                _ => "IDLE",
            };
            (job.job_id.as_str(), status)
        }
        None => {
            // A dead-PID job whose JSON still claims `running` ended
            // abnormally — say so instead of a clean IDLE.
            let status = if app.last_run_crashed {
                "CRASHED"
            } else {
                "IDLE"
            };
            ("-", status)
        }
    };
    let title = Style::default().fg(Color::Blue);
    let value = Style::default().fg(Color::White);
    let sep = Style::default().fg(Color::DarkGray);
    let timers = app.stage_finish_labels(chrono::Local::now());
    let (run_done, run_total) = app.current_run_stage_progress();
    let run_checks = app
        .current_run_check_progress()
        .map(|(done, total)| format!("{done}/{total}"))
        .unwrap_or_else(|| "n/a".to_owned());

    // Top line — overall posture: status, history-wide coverage, which run this
    // is, and the plan it came from. (JOB alone identifies the run; the former
    // AREA field was a near-duplicate of the job name, so it was dropped.)
    let mut top_spans = vec![
        Span::styled("STATUS:", title),
        Span::styled(format!("{status:<8}"), value),
        Span::styled(" │ ", sep),
        Span::styled("COVERAGE:", title),
        Span::styled(
            format!("{}/{}", app.stage_progress.passed, app.stage_progress.total),
            value,
        ),
    ];
    // Green-but-unstable checks (latest pass, flake classifier not yet Proven)
    // — a warning sidecar, deliberately not subtracted from the fraction.
    if app.stage_progress.flaky > 0 {
        top_spans.push(Span::styled(
            format!(" ~{} flaky", app.stage_progress.flaky),
            Style::default().fg(Color::Yellow),
        ));
    }
    top_spans.extend([
        Span::styled(" │ ", sep),
        Span::styled("JOB:", title),
        Span::styled(format!(" {}", fixed(job, 46)), value),
        Span::styled(" │ ", sep),
        Span::styled("PLAN:", title),
        Span::styled(format!(" {}", app.plan_source_label()), value),
    ]);
    let top = Line::from(top_spans);

    // Middle line — everything about the run happening right now: how long it
    // has been going, when each phase is estimated to finish, and how many
    // stages/checks have settled so far.
    let mut run_spans = vec![Span::styled("THIS RUN:", title)];
    match app.run_elapsed_label() {
        Some(elapsed) => run_spans.push(Span::styled(format!(" {elapsed}"), value)),
        None => run_spans.push(Span::styled(" —", value)),
    }
    run_spans.extend([
        Span::styled(" │ ", sep),
        Span::styled(format!("{}:", timers[0].0), title),
        Span::styled(format!("{:<6}", fixed(timers[0].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[1].0), title),
        Span::styled(format!("{:<6}", fixed(timers[1].1.as_str(), 6)), value),
        Span::styled(format!("{}:", timers[2].0), title),
        Span::styled(format!("{:<6}", fixed(timers[2].1.as_str(), 6)), value),
        Span::styled(" │ ", sep),
        Span::styled("SETTLED:", title),
        Span::styled(format!("{run_done}/{run_total}"), value),
        Span::styled(" TESTS:", title),
        Span::styled(run_checks, value),
    ]);
    let run_line = Line::from(run_spans);

    // Bottom line — provenance and environment: the data source (live vs
    // previous run, and its age), how many VMs are visible, refresh cadences.
    let bottom_line = Line::from(vec![
        Span::styled(format!("{}:", app.stage_source_title()), title),
        Span::styled(format!(" {}", app.stage_source_value()), value),
        Span::styled(" │ ", sep),
        Span::styled("VMS:", title),
        Span::styled(format!("{vms}"), value),
        Span::styled(" │ ", sep),
        Span::styled("REFRESH:", title),
        Span::styled(" 2s stages / 5s active VMs", value),
    ]);

    let p = Paragraph::new(vec![top, run_line, bottom_line, Line::from("")]);
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

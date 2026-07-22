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

    // Every value between two "│" separators is padded to a FIXED width with
    // `cell()` so a separator holds its column as the value's own width changes
    // frame to frame (e.g. the elapsed timer or the settled count ticking), and
    // the sub-values inside a multi-value field stay evenly spaced.

    // Top line — overall posture: status, which run this is, its plan, and
    // history-wide coverage last. (JOB alone identifies the run; the former AREA
    // field was a near-duplicate of the job name, so it was dropped.)
    let flaky_slot = if app.stage_progress.flaky > 0 {
        // Green-but-unstable checks (latest pass, flake classifier not yet
        // Proven) — a warning sidecar, deliberately not subtracted from the
        // fraction.
        format!(" ~{} flaky", app.stage_progress.flaky)
    } else {
        String::new()
    };
    let top = Line::from(vec![
        Span::styled("STATUS:", title),
        Span::styled(cell(status, 8), value),
        Span::styled(" │ ", sep),
        Span::styled("JOB:", title),
        Span::styled(format!(" {}", cell(job, 24)), value),
        Span::styled(" │ ", sep),
        Span::styled("PLAN:", title),
        Span::styled(format!(" {}", app.plan_source_label()), value),
        Span::styled(" │ ", sep),
        Span::styled("COVERAGE:", title),
        Span::styled(
            cell(
                &format!("{}/{}", app.stage_progress.passed, app.stage_progress.total),
                8,
            ),
            value,
        ),
        Span::styled(cell(&flaky_slot, 9), Style::default().fg(Color::Yellow)),
    ]);

    // Middle line — everything about the run happening right now: how long it
    // has been going, when each phase is estimated to finish, and how many
    // stages/checks have settled so far.
    let elapsed = app.run_elapsed_label().unwrap_or_else(|| "—".to_owned());
    let run_line = Line::from(vec![
        Span::styled("THIS RUN:", title),
        Span::styled(format!(" {}", cell(&elapsed, 8)), value),
        Span::styled(" │ ", sep),
        Span::styled(format!("{}:", timers[0].0), title),
        Span::styled(cell(timers[0].1.as_str(), 6), value),
        Span::styled(format!("{}:", timers[1].0), title),
        Span::styled(cell(timers[1].1.as_str(), 6), value),
        Span::styled(format!("{}:", timers[2].0), title),
        Span::styled(cell(timers[2].1.as_str(), 6), value),
        Span::styled(" │ ", sep),
        Span::styled("SETTLED:", title),
        Span::styled(cell(&format!("{run_done}/{run_total}"), 6), value),
        Span::styled(" TESTS:", title),
        Span::styled(cell(&run_checks, 6), value),
    ]);

    // Bottom line — provenance and environment: the data source (live vs
    // previous run, and its age), how many VMs are visible, refresh cadences.
    let bottom_line = Line::from(vec![
        Span::styled(cell(&format!("{}:", app.stage_source_title()), 13), title),
        Span::styled(format!(" {}", cell(&app.stage_source_value(), 14)), value),
        Span::styled(" │ ", sep),
        Span::styled("VMS:", title),
        Span::styled(cell(&vms.to_string(), 3), value),
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

/// Left-align `value` into EXACTLY `width` columns: space-padded when shorter,
/// truncated with `…` when longer. Fixed-width header fields keep every "│"
/// separator anchored to its column as the values inside change width.
fn cell(value: &str, width: usize) -> String {
    let clipped = fixed(value, width);
    format!("{clipped:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_pads_short_values_and_truncates_long_ones_to_exact_width() {
        // Shorter -> space-padded to the fixed width (keeps the next "│" put).
        assert_eq!(cell("12m34s", 8), "12m34s  ");
        assert_eq!(cell("RUNNING", 8), "RUNNING ");
        // Empty -> a blank slot of exactly the width (e.g. the flaky sidecar).
        assert_eq!(cell("", 9), "         ");
        // Longer -> truncated with an ellipsis to EXACTLY the width.
        let clipped = cell("live-lab-verify-f5h-and-then-some", 10);
        assert_eq!(clipped.chars().count(), 10);
        assert!(clipped.ends_with('…'), "got {clipped:?}");
    }
}

use std::path::{Path, PathBuf};

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde_json::Value;

use crate::app::App;

#[derive(Debug, Clone)]
struct AgentsView {
    harness: String,
    review_model: String,
    review_runs: RunStats,
    patch_model: String,
    patch_variant: String,
    patch_runs: RunStats,
    session: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct RunStats {
    runs: usize,
    tokens_total: u64,
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title("AGENTS")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let view = AgentsView::load(&app.repo_root);
    let lines = vec![
        row(
            "Harness",
            &format!("{} live-lab loop", view.harness),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        row("Review", &view.review_model, value_style()),
        row(
            "Review runs",
            &format_run_stats(view.review_runs),
            muted_style(),
        ),
        spacer(),
        row(
            "Patch",
            &format!("{} ({})", view.patch_model, view.patch_variant),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        row(
            "Patch runs",
            &format_run_stats(view.patch_runs),
            muted_style(),
        ),
        row("Session", &view.session, muted_style()),
    ];

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

impl AgentsView {
    fn load(repo_root: &Path) -> Self {
        let main_status = read_json(&repo_root.join("state/opencode-loop/main-agent-status.json"));
        let review_status = read_latest_review_status(repo_root);
        let review_runs = review_run_stats(repo_root);
        let patch_runs = patch_run_stats(repo_root, &main_status);

        let harness = string_field(&main_status, "harness")
            .or_else(|| string_field(&review_status, "harness"))
            .unwrap_or_else(|| "opencode".to_owned());
        let review_model = string_field(&review_status, "model")
            .or_else(|| env_or_default_from_script(repo_root, "OPENCODE_REVIEW_MODEL"))
            .unwrap_or_else(|| "unknown".to_owned());
        let patch_model = string_field(&main_status, "model")
            .or_else(|| env_or_default_from_script(repo_root, "OPENCODE_MAIN_MODEL"))
            .unwrap_or_else(|| "unknown".to_owned());
        let patch_variant = string_field(&main_status, "variant")
            .or_else(|| env_or_default_from_script(repo_root, "OPENCODE_MAIN_VARIANT"))
            .unwrap_or_else(|| "-".to_owned());
        let session = string_field(&main_status, "session_id")
            .or_else(|| nonempty_env("OPENCODE_SESSION_ID"))
            .unwrap_or_else(|| "-".to_owned());

        Self {
            harness,
            review_model,
            review_runs,
            patch_model,
            patch_variant,
            patch_runs,
            session,
        }
    }
}

fn row(label: &str, value: &str, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {label:<16}"), label_style()),
        Span::styled(value.to_owned(), value_style),
    ])
}

fn spacer() -> Line<'static> {
    Line::from("")
}

fn label_style() -> Style {
    Style::default().fg(Color::Blue)
}

fn value_style() -> Style {
    Style::default().fg(Color::White)
}

fn muted_style() -> Style {
    Style::default().fg(Color::Gray)
}

fn format_run_stats(stats: RunStats) -> String {
    if stats.runs == 0 {
        return "0 / tokens -".to_owned();
    }
    format!(
        "{} / tokens {}",
        stats.runs,
        format_tokens(stats.tokens_total)
    )
}

fn format_tokens(tokens: u64) -> String {
    if tokens >= 1_000_000 {
        format!("{:.1}M", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}K", tokens as f64 / 1_000.0)
    } else {
        tokens.to_string()
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn read_latest_review_status(repo_root: &Path) -> Option<Value> {
    let root = repo_root.join("state/opencode-report-reviews");
    let mut latest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let path = entry.path().join("status.json");
        let modified = path
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        if let Some(modified) = modified
            && latest
                .as_ref()
                .map(|(seen, _)| modified > *seen)
                .unwrap_or(true)
        {
            latest = Some((modified, path));
        }
    }
    read_json(&latest?.1)
}

fn review_run_stats(repo_root: &Path) -> RunStats {
    let root = repo_root.join("state/opencode-report-reviews");
    let mut stats = RunStats::default();
    let Ok(entries) = std::fs::read_dir(root) else {
        return stats;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let status = read_json(&dir.join("status.json"));
        if status
            .as_ref()
            .is_none_or(|json| json.get("started_unix").is_none())
        {
            continue;
        }
        stats.runs += 1;
        stats.tokens_total +=
            tokens_from_status_or_events(&status, &dir.join("opencode-events.jsonl"));
    }
    stats
}

fn patch_run_stats(repo_root: &Path, main_status: &Option<Value>) -> RunStats {
    let mut stats = RunStats::default();
    let runs_path = repo_root.join("state/opencode-loop/main-agent-runs.jsonl");
    let runs = read_jsonl(&runs_path);
    for run in &runs {
        stats.runs += 1;
        stats.tokens_total += u64_field(run, "tokens_total").unwrap_or(0);
    }
    if let Some(json) = main_status
        && json.get("started_unix").is_some()
    {
        let current_started = u64_field(json, "started_unix");
        let already_recorded = current_started.is_some_and(|started| {
            runs.iter()
                .any(|run| u64_field(run, "started_unix") == Some(started))
        });
        if !already_recorded {
            stats.runs += 1;
            stats.tokens_total += tokens_from_status_or_events(
                main_status,
                &repo_root.join("state/opencode-loop/main-agent-events.jsonl"),
            );
        }
    }
    stats
}

fn tokens_from_status_or_events(status: &Option<Value>, events_path: &Path) -> u64 {
    status
        .as_ref()
        .and_then(|json| u64_field(json, "tokens_total"))
        .filter(|tokens| *tokens > 0)
        .unwrap_or_else(|| tokens_from_events(events_path))
}

fn tokens_from_events(path: &Path) -> u64 {
    read_jsonl(path)
        .iter()
        .filter(|event| event.get("type").and_then(Value::as_str) == Some("step_finish"))
        .filter_map(|event| event.get("part")?.get("tokens")?.get("total")?.as_u64())
        .sum()
}

fn string_field(json: &Option<Value>, key: &str) -> Option<String> {
    json.as_ref()?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn u64_field(json: &Value, key: &str) -> Option<u64> {
    json.get(key)?.as_u64()
}

fn env_or_default_from_script(repo_root: &Path, key: &str) -> Option<String> {
    nonempty_env(key)
        .or_else(|| shell_default(repo_root, "scripts/loop/opencode_loop.sh", key))
        .or_else(|| shell_default(repo_root, "scripts/loop/opencode_report_review.sh", key))
}

fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn shell_default(repo_root: &Path, rel_script: &str, key: &str) -> Option<String> {
    let raw = std::fs::read_to_string(repo_root.join(rel_script)).ok()?;
    let needle = format!("{key}=\"${{{key}:-");
    let start = raw.find(&needle)? + needle.len();
    let rest = raw.get(start..)?;
    let end = rest.find("}\"")?;
    rest.get(..end)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

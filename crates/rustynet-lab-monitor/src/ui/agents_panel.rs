use std::collections::HashSet;
use std::path::Path;

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::AgentsRow;
use crate::app::{AgentsCol, App, Panel};

/// Durable running-cost ledger, reconciled from the raw per-run artifacts on
/// every load and persisted to disk. Unlike re-summing the raw files each
/// time, the ledger's totals never go backwards even if `main-agent-runs.jsonl`
/// or the `opencode-report-reviews/*` directories are ever pruned or archived
/// later (state/ has been bulk-archived before) — once a run's cost has been
/// folded in, it stays counted for good.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CostLedger {
    #[serde(default)]
    patch: PatchLedger,
    #[serde(default)]
    review: ReviewLedger,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PatchLedger {
    #[serde(default)]
    total_cost_usd: f64,
    #[serde(default)]
    total_runs_ever: usize,
    /// Count of main-agent-runs.jsonl records already folded into the totals
    /// above. That file is strictly append-only, so tracking how many
    /// leading records have been processed is enough to fold in only the new
    /// ones on each reconcile. If the file is ever shorter than this on a
    /// later reconcile (rotated/cleared out from under us), we do NOT
    /// re-process its current contents — under-counting a monitoring metric
    /// is safer than risking a double count of records already folded in.
    #[serde(default)]
    processed_run_lines: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReviewLedger {
    #[serde(default)]
    total_cost_usd: f64,
    /// Directory names under opencode-report-reviews/ already folded into
    /// total_cost_usd. Directories aren't created/iterated in a guaranteed
    /// order, unlike the Patch agent's append-only log, so dedup is by name
    /// instead of a position watermark.
    #[serde(default)]
    processed_run_ids: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AgentsView {
    patch_model: String,
    patch_variant: String,
    session: String,
    /// Number of model API calls in the current/latest loop iteration
    /// (step_finish events in the live, per-iteration events file).
    api_calls: usize,
    /// Number of tool invocations in the current/latest loop iteration.
    tool_calls: usize,
    /// Fresh input tokens in the current/latest loop iteration.
    input_tokens: u64,
    /// Output tokens in the current/latest loop iteration.
    output_tokens: u64,
    /// Cache-read tokens in the current/latest loop iteration.
    cache_read_tokens: u64,
    /// Cost in USD of the current/latest loop iteration only — this file is
    /// truncated at the start of every iteration, so it is NOT a total.
    total_cost_usd: f64,
    /// All-time loop iteration count, from the persisted cost ledger.
    patch_run_count: usize,
    /// All-time cost in USD, from the persisted cost ledger — see
    /// `CostLedger` — including the in-progress iteration's live cost if one
    /// is currently running.
    patch_total_cost_usd: f64,
    /// Review agent model.
    review_model: String,
    /// API calls in the single most-recently-run review invocation.
    review_api_calls: usize,
    /// Tool invocations in the single most-recently-run review invocation.
    review_tool_calls: usize,
    /// Fresh input tokens in the single most-recently-run review invocation.
    review_input_tokens: u64,
    /// Output tokens in the single most-recently-run review invocation.
    review_output_tokens: u64,
    /// Cache-read tokens in the single most-recently-run review invocation.
    review_cache_read_tokens: u64,
    /// Cost in USD of the single most-recently-run review invocation only.
    review_cost_usd: f64,
    /// All-time review run count, from the persisted cost ledger.
    review_run_count: usize,
    /// All-time cost in USD, from the persisted cost ledger — see
    /// `CostLedger`.
    review_total_cost_usd: f64,
}

pub fn render(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused_panel == Panel::Agents;
    let border_fg = if focused { Color::Yellow } else { Color::Cyan };
    let block = Block::default()
        .title(Span::styled("AGENTS [3]", Style::default().fg(border_fg)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_fg));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let view = &app.agents_view;

    // Override model/variant with the user's current selection from App state
    // (what will be used on next launch, not what the last run used).
    let selected_patch_model = app
        .available_models
        .get(app.patch_model_idx)
        .cloned()
        .unwrap_or_default();
    let selected_patch_variant = app
        .available_variants
        .get(app.patch_variant_idx)
        .cloned()
        .unwrap_or_default();
    let selected_review_model = app
        .available_models
        .get(app.review_model_idx)
        .cloned()
        .unwrap_or_default();

    let patch_row_active =
        focused && app.agents_sel_col == Some(AgentsCol::Patch) && app.agents_active;
    let review_row_active =
        focused && app.agents_sel_col == Some(AgentsCol::Review) && app.agents_active;

    let patch_model_ui = if patch_row_active && app.agents_sel_row == Some(AgentsRow::Model) {
        format_model_cycle(&selected_patch_model, &selected_patch_variant, true)
    } else {
        format_model(&selected_patch_model, &selected_patch_variant)
    };
    let review_model_ui = if review_row_active && app.agents_sel_row == Some(AgentsRow::Model) {
        format_model_cycle(&selected_review_model, "", true)
    } else {
        format_model(&selected_review_model, "")
    };

    render_table(
        f,
        inner,
        view,
        &patch_model_ui,
        &review_model_ui,
        focused,
        app,
    );
}

/// Renders one column per agent (Patch, Review) with metrics as rows, so the
/// two agents can be compared at a glance instead of scanning a stacked list.
fn render_table(
    f: &mut Frame,
    area: Rect,
    v: &AgentsView,
    patch_model_ui: &str,
    review_model_ui: &str,
    focused: bool,
    app: &App,
) {
    let no_select = focused && app.agents_sel_col.is_none();
    let patch_row_active =
        focused && app.agents_sel_col == Some(AgentsCol::Patch) && app.agents_active;
    let review_row_active =
        focused && app.agents_sel_col == Some(AgentsCol::Review) && app.agents_active;

    let patch_iter_ui = if patch_row_active && app.agents_sel_row == Some(AgentsRow::Iterations) {
        format!("◀ {} ▶", app.patch_iterations)
    } else {
        app.patch_iterations.to_string()
    };
    let review_iter_ui = if review_row_active && app.agents_sel_row == Some(AgentsRow::Iterations) {
        format!("◀ {} ▶", app.review_iterations)
    } else {
        app.review_iterations.to_string()
    };
    let bold_green = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD);
    let bold_cyan = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let bold_white = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let dim = Style::default().fg(Color::DarkGray);
    let white = Style::default().fg(Color::White);
    let gray = Style::default().fg(Color::Gray);
    let label_style = Style::default().fg(Color::Blue);

    let patch_header_style = bold_green;
    let review_header_style = bold_cyan;
    let patch_style = bold_green;
    let review_style = bold_cyan;

    let patch_model = patch_model_ui.to_owned();
    let review_model = review_model_ui.to_owned();

    let patch_session = if v.session.is_empty() || v.session == "-" {
        "—".to_owned()
    } else {
        truncate_session(&v.session)
    };
    let patch_runs = format!("{} run{}", v.patch_run_count, plural(v.patch_run_count));
    let review_runs = format!("{} run{}", v.review_run_count, plural(v.review_run_count));

    let cache_pct = |cache: u64, input: u64, output: u64| -> f64 {
        let total = input + output + cache;
        if total > 0 {
            cache as f64 / total as f64 * 100.0
        } else {
            0.0
        }
    };
    let patch_cache_pct = cache_pct(v.cache_read_tokens, v.input_tokens, v.output_tokens);
    let review_cache_pct = cache_pct(
        v.review_cache_read_tokens,
        v.review_input_tokens,
        v.review_output_tokens,
    );

    let header = Row::new(vec![
        Cell::new("METRIC").style(label_style.add_modifier(Modifier::BOLD)),
        Cell::new(if no_select { "PATCH  ←" } else { "PATCH" }).style(patch_header_style),
        Cell::new(if no_select { "REVIEW  →" } else { "REVIEW" }).style(review_header_style),
    ]);

    let row_sel = Style::default().fg(Color::Yellow);

    let patch_rowselected = |col_row: Option<(AgentsCol, AgentsRow)>| -> bool {
        focused
            && app.agents_sel_col == Some(AgentsCol::Patch)
            && col_row
                == Some((
                    AgentsCol::Patch,
                    app.agents_sel_row.unwrap_or(AgentsRow::Model),
                ))
            && app.agents_sel_row.is_some()
    };
    let review_rowselected = |col_row: Option<(AgentsCol, AgentsRow)>| -> bool {
        focused
            && app.agents_sel_col == Some(AgentsCol::Review)
            && col_row
                == Some((
                    AgentsCol::Review,
                    app.agents_sel_row.unwrap_or(AgentsRow::Model),
                ))
            && app.agents_sel_row.is_some()
    };

    let rows = vec![
        table_row_with_sel(
            "MODEL",
            row_sel,
            SelCell {
                value: patch_model,
                style: patch_style,
                selected: patch_rowselected(Some((AgentsCol::Patch, AgentsRow::Model))),
            },
            SelCell {
                value: review_model,
                style: review_style,
                selected: review_rowselected(Some((AgentsCol::Review, AgentsRow::Model))),
            },
        ),
        table_row_with_sel(
            "ITER",
            row_sel,
            SelCell {
                value: patch_iter_ui,
                style: patch_style,
                selected: patch_rowselected(Some((AgentsCol::Patch, AgentsRow::Iterations))),
            },
            SelCell {
                value: review_iter_ui,
                style: review_style,
                selected: review_rowselected(Some((AgentsCol::Review, AgentsRow::Iterations))),
            },
        ),
        table_row("SESSION", patch_session, gray, "—".to_owned(), dim),
        table_row("RUNS", patch_runs, dim, review_runs, gray),
        Row::new(vec!["", "", ""]),
        table_row(
            "API CALLS",
            v.api_calls.to_string(),
            white,
            v.review_api_calls.to_string(),
            gray,
        ),
        table_row(
            "TOOL CALLS",
            v.tool_calls.to_string(),
            white,
            v.review_tool_calls.to_string(),
            gray,
        ),
        Row::new(vec!["", "", ""]),
        table_row(
            "COST (TOTAL)",
            format!("${:.4}", v.patch_total_cost_usd),
            bold_white,
            format!("${:.4}", v.review_total_cost_usd),
            bold_white,
        ),
        Row::new(vec!["", "", ""]),
        table_row(
            "TOKENS FRESH",
            fmt_tokens(v.input_tokens + v.output_tokens),
            gray,
            fmt_tokens(v.review_input_tokens + v.review_output_tokens),
            dim,
        ),
        table_row(
            "CACHE READ",
            format!(
                "{} ({:.0}%)",
                fmt_tokens(v.cache_read_tokens),
                patch_cache_pct
            ),
            gray,
            format!(
                "{} ({:.0}%)",
                fmt_tokens(v.review_cache_read_tokens),
                review_cache_pct
            ),
            dim,
        ),
    ];

    let has_caption_room = area.height > rows.len() as u16 + 2;
    let chunks = if has_caption_room {
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(area)
    } else {
        Layout::vertical([Constraint::Min(0)]).split(area)
    };

    let hint = if no_select {
        "← → select column  |  ↑↓ select row  |  Enter activate  |  Esc"
    } else if app.agents_active {
        "← → cycle value  |  ↑↓ other row  |  Esc deactivate"
    } else if app.agents_sel_row.is_some() {
        "Enter activate  |  ↑↓ other row  |  ← → other col  |  Esc"
    } else if focused {
        "↑↓ select row  |  ← → other col  |  Esc"
    } else {
        ""
    };

    let widths = [
        Constraint::Length(13),
        Constraint::Fill(1),
        Constraint::Fill(1),
    ];
    let table = Table::new(rows, widths).header(header).column_spacing(2);
    f.render_widget(table, chunks[0]);

    if has_caption_room {
        let caption = if !hint.is_empty() {
            hint.to_owned()
        } else if !v.session.is_empty() && v.session != "-" {
            format!(" SESSION: {}", v.session)
        } else {
            String::new()
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(caption, dim))),
            chunks[1],
        );
    }
}

fn table_row(
    label: &'static str,
    patch_value: String,
    patch_style: Style,
    review_value: String,
    review_style: Style,
) -> Row<'static> {
    Row::new(vec![
        Cell::new(label).style(Style::default().fg(Color::Blue)),
        Cell::new(patch_value).style(patch_style),
        Cell::new(review_value).style(review_style),
    ])
}

struct SelCell {
    value: String,
    style: Style,
    selected: bool,
}

fn table_row_with_sel(
    label: &'static str,
    row_sel: Style,
    patch: SelCell,
    review: SelCell,
) -> Row<'static> {
    Row::new(vec![
        Cell::new(label).style(Style::default().fg(Color::Blue)),
        Cell::new(patch.value).style(if patch.selected { row_sel } else { patch.style }),
        Cell::new(review.value).style(if review.selected {
            row_sel
        } else {
            review.style
        }),
    ])
}

fn format_model(model: &str, variant: &str) -> String {
    if model.is_empty() {
        return "unknown".to_owned();
    }
    // Strip the "<provider>/" prefix — every provider here is DeepSeek, and
    // dropping it keeps the model name compact in a narrow table column.
    let short = model.rsplit('/').next().unwrap_or(model);
    if variant.is_empty() || variant == "-" {
        short.to_owned()
    } else {
        format!("{short} ({variant})")
    }
}

fn format_model_cycle(model: &str, variant: &str, _show_arrows: bool) -> String {
    let short = model.rsplit('/').next().unwrap_or(model);
    let base = if variant.is_empty() || variant == "-" {
        short.to_owned()
    } else {
        format!("{short} ({variant})")
    };
    format!("◀ {base} ▶")
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn truncate_session(s: &str) -> String {
    // Show the unique suffix (last 12 chars) — session IDs are long.
    if s.len() > 14 {
        format!("…{}", &s[s.len() - 12..])
    } else {
        s.to_owned()
    }
}

fn fmt_tokens(t: u64) -> String {
    if t >= 1_000_000 {
        format!("{:.1}M", t as f64 / 1_000_000.0)
    } else if t >= 1_000 {
        format!("{:.1}K", t as f64 / 1_000.0)
    } else {
        t.to_string()
    }
}

// ── Data loading ─────────────────────────────────────────────────────────────

impl AgentsView {
    pub(crate) fn load(repo_root: &Path) -> Self {
        let mut view = AgentsView::default();

        // Model + variant + session from status file or opencode config.
        let main_status = read_json(&repo_root.join("state/opencode-loop/main-agent-status.json"));
        view.patch_model = string_field(&main_status, "model")
            .or_else(|| agent_model_from_config(repo_root, "rustynet-loop-main"))
            .unwrap_or_default();
        view.patch_variant = string_field(&main_status, "variant")
            .or_else(|| agent_variant_from_config(repo_root, "rustynet-loop-main"))
            .unwrap_or_default();
        view.session = string_field(&main_status, "session_id")
            .or_else(|| nonempty_env("OPENCODE_SESSION_ID"))
            .unwrap_or_default();

        // Live stats from the current/latest iteration's events JSONL. This
        // file is truncated at the start of every loop iteration (see
        // scripts/loop/opencode_loop.sh, `: > "$MAIN_EVENTS"`), so it always
        // holds exactly one run's data — never a running total.
        let events_path = repo_root.join("state/opencode-loop/main-agent-events.jsonl");
        aggregate_events(
            &events_path,
            &mut view.api_calls,
            &mut view.tool_calls,
            &mut view.input_tokens,
            &mut view.output_tokens,
            &mut view.cache_read_tokens,
            &mut view.total_cost_usd,
        );

        // Review agent — the per-column stats above reflect only the single
        // most-recently-run review invocation, not a running total.
        view.review_model =
            agent_model_from_config(repo_root, "rustynet-report-review").unwrap_or_default();
        let reviews_root = repo_root.join("state/opencode-report-reviews");
        if let Some(latest_events) = find_latest_review_events(&reviews_root) {
            aggregate_events(
                &latest_events,
                &mut view.review_api_calls,
                &mut view.review_tool_calls,
                &mut view.review_input_tokens,
                &mut view.review_output_tokens,
                &mut view.review_cache_read_tokens,
                &mut view.review_cost_usd,
            );
        }

        // All-time totals: reconcile the persisted cost ledger against the
        // raw per-run artifacts (folding in anything new since the last
        // reconcile) and write it straight back — see CostLedger's doc
        // comment for why this is a durable ledger rather than a live re-sum.
        let ledger_path = repo_root.join("state/lab-monitor-cost-ledger.json");
        let mut ledger = load_ledger(&ledger_path);
        let runs_path = repo_root.join("state/opencode-loop/main-agent-runs.jsonl");
        reconcile_patch_ledger(&mut ledger.patch, &runs_path);
        reconcile_review_ledger(&mut ledger.review, &reviews_root);
        save_ledger(&ledger_path, &ledger);

        view.patch_run_count = ledger.patch.total_runs_ever;
        view.patch_total_cost_usd = ledger.patch.total_cost_usd;
        // The in-progress iteration's cost isn't archived into
        // main-agent-runs.jsonl until it finishes, so add its live cost on
        // top of the ledger — but only while it's actually running, else the
        // just-finished run would be double counted (once via the ledger,
        // once via the not-yet-truncated live events file).
        if string_field(&main_status, "state").as_deref() == Some("running") {
            view.patch_total_cost_usd += view.total_cost_usd;
        }
        view.review_run_count = ledger.review.processed_run_ids.len();
        view.review_total_cost_usd = ledger.review.total_cost_usd;

        view
    }
}

fn aggregate_events(
    path: &Path,
    api_calls: &mut usize,
    tool_calls: &mut usize,
    input_tokens: &mut u64,
    output_tokens: &mut u64,
    cache_read_tokens: &mut u64,
    total_cost: &mut f64,
) {
    for event in read_jsonl(path) {
        match event.get("type").and_then(Value::as_str) {
            Some("step_finish") => {
                *api_calls += 1;
                if let Some(part) = event.get("part") {
                    if let Some(tok) = part.get("tokens") {
                        *input_tokens += tok.get("input").and_then(Value::as_u64).unwrap_or(0);
                        *output_tokens += tok.get("output").and_then(Value::as_u64).unwrap_or(0);
                        *cache_read_tokens += tok
                            .get("cache")
                            .and_then(|c| c.get("read"))
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                    }
                    *total_cost += part.get("cost").and_then(Value::as_f64).unwrap_or(0.0);
                }
            }
            Some("tool_use") => *tool_calls += 1,
            _ => {}
        }
    }
}

fn load_ledger(path: &Path) -> CostLedger {
    read_json(path)
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

fn save_ledger(path: &Path, ledger: &CostLedger) {
    if let Ok(json) = serde_json::to_string_pretty(ledger) {
        let _ = std::fs::write(path, json);
    }
}

/// Fold any main-agent-runs.jsonl records not yet reflected in `ledger` into
/// its running totals. That file is a flat `{"cost": ..., ...}` shape (one
/// JSON object per finished loop iteration, appended by `mark_main_status()`
/// in scripts/loop/opencode_loop.sh) — not the nested
/// `{"type": "step_finish", "part": {...}}` shape `aggregate_events` reads.
fn reconcile_patch_ledger(ledger: &mut PatchLedger, runs_path: &Path) {
    let runs = read_jsonl(runs_path);
    if runs.len() <= ledger.processed_run_lines {
        // Shrunk or unchanged since last reconcile — see PatchLedger's doc
        // comment on processed_run_lines for why we don't re-process here.
        ledger.processed_run_lines = runs.len();
        return;
    }
    for run in &runs[ledger.processed_run_lines..] {
        ledger.total_cost_usd += run.get("cost").and_then(Value::as_f64).unwrap_or(0.0);
        ledger.total_runs_ever += 1;
    }
    ledger.processed_run_lines = runs.len();
}

/// Fold any not-yet-processed review run directories under `root` into
/// `ledger`'s running totals, keyed by directory name so ordering/pruning of
/// other directories can't cause a double count or a lost contribution.
fn reconcile_review_ledger(ledger: &mut ReviewLedger, root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if ledger.processed_run_ids.contains(&name) {
            continue;
        }
        let events_path = entry.path().join("opencode-events.jsonl");
        if !events_path.is_file() {
            continue; // not finished yet — leave unprocessed, retry next reconcile
        }
        let (mut api, mut tool, mut inp, mut out, mut cache, mut cost) =
            (0usize, 0usize, 0u64, 0u64, 0u64, 0.0f64);
        aggregate_events(
            &events_path,
            &mut api,
            &mut tool,
            &mut inp,
            &mut out,
            &mut cache,
            &mut cost,
        );
        ledger.total_cost_usd += cost;
        ledger.processed_run_ids.insert(name);
    }
}

/// Path to the events file of the most-recently-modified review run under
/// `root`, or `None` if there are no review runs yet.
fn find_latest_review_events(root: &Path) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(root).ok()?;
    let mut latest: Option<(std::time::SystemTime, std::path::PathBuf)> = None;
    for entry in entries.flatten() {
        let events_path = entry.path().join("opencode-events.jsonl");
        let Ok(meta) = std::fs::metadata(&events_path) else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let is_newer = latest.as_ref().is_none_or(|(t, _)| modified > *t);
        if is_newer {
            latest = Some((modified, events_path));
        }
    }
    latest.map(|(_, p)| p)
}

fn agent_model_from_config(repo_root: &Path, agent: &str) -> Option<String> {
    let json = read_json(&repo_root.join(".opencode/opencode.json"))?;
    json.get("agent")?
        .get(agent)?
        .get("model")?
        .as_str()
        .map(str::to_owned)
}

fn agent_variant_from_config(repo_root: &Path, agent: &str) -> Option<String> {
    let json = read_json(&repo_root.join(".opencode/opencode.json"))?;
    json.get("agent")?
        .get(agent)?
        .get("variant")?
        .as_str()
        .map(str::to_owned)
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

fn string_field(json: &Option<Value>, key: &str) -> Option<String> {
    json.as_ref()?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_run_line(path: &Path, cost: f64) {
        let mut existing = std::fs::read_to_string(path).unwrap_or_default();
        existing.push_str(&format!("{{\"cost\":{cost}}}\n"));
        std::fs::write(path, existing).unwrap();
    }

    fn write_review_events(dir: &Path, name: &str, cost: f64) {
        let review_dir = dir.join(name);
        std::fs::create_dir_all(&review_dir).unwrap();
        std::fs::write(
            review_dir.join("opencode-events.jsonl"),
            format!(
                "{{\"type\":\"step_finish\",\"part\":{{\"tokens\":{{\"input\":10,\"output\":5,\"cache\":{{\"read\":1}}}},\"cost\":{cost}}}}}\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn reconcile_patch_ledger_folds_in_all_lines_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let runs_path = dir.path().join("runs.jsonl");
        write_run_line(&runs_path, 0.01);
        write_run_line(&runs_path, 0.02);

        let mut ledger = PatchLedger::default();
        reconcile_patch_ledger(&mut ledger, &runs_path);

        assert_eq!(ledger.total_runs_ever, 2);
        assert!((ledger.total_cost_usd - 0.03).abs() < 1e-9);
        assert_eq!(ledger.processed_run_lines, 2);
    }

    #[test]
    fn reconcile_patch_ledger_is_idempotent_when_nothing_new() {
        let dir = tempfile::tempdir().unwrap();
        let runs_path = dir.path().join("runs.jsonl");
        write_run_line(&runs_path, 0.01);

        let mut ledger = PatchLedger::default();
        reconcile_patch_ledger(&mut ledger, &runs_path);
        reconcile_patch_ledger(&mut ledger, &runs_path);
        reconcile_patch_ledger(&mut ledger, &runs_path);

        assert_eq!(ledger.total_runs_ever, 1);
        assert!((ledger.total_cost_usd - 0.01).abs() < 1e-9);
    }

    #[test]
    fn reconcile_patch_ledger_only_folds_in_newly_appended_lines() {
        let dir = tempfile::tempdir().unwrap();
        let runs_path = dir.path().join("runs.jsonl");
        write_run_line(&runs_path, 0.01);
        write_run_line(&runs_path, 0.02);

        let mut ledger = PatchLedger::default();
        reconcile_patch_ledger(&mut ledger, &runs_path);

        write_run_line(&runs_path, 0.05);
        reconcile_patch_ledger(&mut ledger, &runs_path);

        assert_eq!(ledger.total_runs_ever, 3);
        assert!((ledger.total_cost_usd - 0.08).abs() < 1e-9);
    }

    #[test]
    fn reconcile_patch_ledger_does_not_reprocess_when_file_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let runs_path = dir.path().join("runs.jsonl");
        write_run_line(&runs_path, 0.01);
        write_run_line(&runs_path, 0.02);
        write_run_line(&runs_path, 0.03);

        let mut ledger = PatchLedger::default();
        reconcile_patch_ledger(&mut ledger, &runs_path);
        assert_eq!(ledger.total_runs_ever, 3);

        // Simulate external rotation/cleanup shrinking the file.
        std::fs::write(&runs_path, "{\"cost\":0.99}\n").unwrap();
        reconcile_patch_ledger(&mut ledger, &runs_path);

        // Already-folded-in totals must not be lost or re-added.
        assert_eq!(ledger.total_runs_ever, 3);
        assert!((ledger.total_cost_usd - 0.06).abs() < 1e-9);
        assert_eq!(ledger.processed_run_lines, 1);
    }

    #[test]
    fn reconcile_review_ledger_folds_in_new_dirs_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        write_review_events(dir.path(), "labrun-1", 0.10);
        write_review_events(dir.path(), "labrun-2", 0.20);

        let mut ledger = ReviewLedger::default();
        reconcile_review_ledger(&mut ledger, dir.path());
        reconcile_review_ledger(&mut ledger, dir.path());

        assert_eq!(ledger.processed_run_ids.len(), 2);
        assert!((ledger.total_cost_usd - 0.30).abs() < 1e-9);
    }

    #[test]
    fn reconcile_review_ledger_picks_up_a_dir_once_its_events_file_appears() {
        let dir = tempfile::tempdir().unwrap();
        let review_dir = dir.path().join("labrun-pending");
        std::fs::create_dir_all(&review_dir).unwrap();

        let mut ledger = ReviewLedger::default();
        reconcile_review_ledger(&mut ledger, dir.path());
        assert_eq!(ledger.processed_run_ids.len(), 0);

        write_review_events(dir.path(), "labrun-pending", 0.5);
        reconcile_review_ledger(&mut ledger, dir.path());

        assert_eq!(ledger.processed_run_ids.len(), 1);
        assert!((ledger.total_cost_usd - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ledger_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.json");
        let mut ledger = CostLedger::default();
        ledger.patch.total_cost_usd = 1.23;
        ledger.patch.total_runs_ever = 4;
        ledger
            .review
            .processed_run_ids
            .insert("labrun-1".to_owned());
        ledger.review.total_cost_usd = 4.56;

        save_ledger(&path, &ledger);
        let loaded = load_ledger(&path);

        assert!((loaded.patch.total_cost_usd - 1.23).abs() < 1e-9);
        assert_eq!(loaded.patch.total_runs_ever, 4);
        assert!((loaded.review.total_cost_usd - 4.56).abs() < 1e-9);
        assert!(loaded.review.processed_run_ids.contains("labrun-1"));
    }

    #[test]
    fn load_ledger_defaults_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = load_ledger(&dir.path().join("does-not-exist.json"));
        assert_eq!(ledger.patch.total_runs_ever, 0);
        assert_eq!(ledger.review.processed_run_ids.len(), 0);
    }
}

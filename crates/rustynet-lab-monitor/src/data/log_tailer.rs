use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Tail the last N lines of a log file.
pub fn tail_lines(path: &Path, n: usize) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = if lines.len() > n { lines.len() - n } else { 0 };
    Ok(lines[start..].iter().map(|s| s.to_string()).collect())
}

/// Read the full contents of a log file into a Vec of lines.
#[allow(dead_code)]
pub fn read_all_lines(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(raw.lines().map(|s| s.to_string()).collect())
}

pub fn summarize_stage_lines(
    repo_root: &Path,
    report_dir: &Path,
    stage: &str,
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    lines.push(format!("Summary for {stage}"));

    let parallel = summarize_parallel_stage(repo_root, report_dir, stage)?;
    if !parallel.is_empty() {
        lines.extend(parallel);
        return Ok(lines);
    }

    // bootstrap_hosts is a per-node SERIES stage: `logs/bootstrap_hosts.log`
    // holds only a one-line end-of-stage marker (written when the whole stage
    // finishes), and the --node engine writes no `state/parallel-bootstrap_hosts/`
    // dir, so the generic path below shows "No log output" for the entire
    // ~10-minute bootstrap. Surface the live per-node build instead.
    if stage == "bootstrap_hosts"
        && let Some(node_lines) = summarize_bootstrap_active_node(report_dir)
    {
        return Ok(node_lines);
    }

    let log_path = report_dir.join("logs").join(format!("{stage}.log"));
    let raw = tail_lines(&log_path, 250)?;
    let summarized = summarize_raw_lines(&raw);
    if summarized.is_empty() {
        Ok(raw.into_iter().take(80).collect())
    } else {
        lines.extend(summarized);
        Ok(lines)
    }
}

/// Live build output for the node `bootstrap_hosts` is currently working on.
/// The per-node `logs/bootstrap_node_<alias>.log` files stream a real
/// `cargo build`; the newest by mtime is the node being built right now (the
/// stage is serial). Returns its tail with a header naming the node, or `None`
/// when no per-node log exists yet or is unreadable (caller falls back to the
/// generic path). Best-effort and read-only: any I/O error yields `None`.
fn summarize_bootstrap_active_node(report_dir: &Path) -> Option<Vec<String>> {
    let logs_dir = report_dir.join("logs");
    let (_, newest) = std::fs::read_dir(&logs_dir)
        .ok()?
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("bootstrap_node_") && name.ends_with(".log")
        })
        .filter_map(|entry| Some((entry.metadata().ok()?.modified().ok()?, entry.path())))
        .max_by_key(|(modified, _)| *modified)?;

    let alias = newest
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix("bootstrap_node_"))
        .unwrap_or("node")
        .to_owned();
    let raw = tail_lines(&newest, 200).ok()?;
    if raw.is_empty() {
        return None;
    }
    let mut lines = vec![format!("bootstrap_hosts — building {alias} (live):")];
    lines.extend(raw);
    Some(lines)
}

fn summarize_parallel_stage(
    repo_root: &Path,
    report_dir: &Path,
    stage: &str,
) -> Result<Vec<String>> {
    let parallel_dir = report_dir.join("state").join(format!("parallel-{stage}"));
    if !parallel_dir.exists() {
        return Ok(Vec::new());
    }

    let aliases = load_inventory_aliases(repo_root).unwrap_or_default();
    let mut lines = Vec::new();
    let results_path = parallel_dir.join("results.tsv");
    if results_path.exists() {
        let raw = std::fs::read_to_string(&results_path)
            .with_context(|| format!("reading {}", results_path.display()))?;
        for row in raw.lines().filter(|line| !line.trim().is_empty()) {
            if let Some(summary) = summarize_parallel_result_row(row, stage, &aliases) {
                lines.push(summary);
            }
        }
    }

    if lines.is_empty() {
        for entry in std::fs::read_dir(&parallel_dir)
            .with_context(|| format!("reading {}", parallel_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("log") {
                continue;
            }
            let label = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("node");
            let raw = std::fs::read_to_string(&path).unwrap_or_default();
            lines.push(summarize_worker_log(stage, label, raw.as_str()));
        }
    }

    Ok(lines)
}

fn summarize_parallel_result_row(
    row: &str,
    active_stage: &str,
    aliases: &HashMap<String, String>,
) -> Option<String> {
    let fields = row.split('\t').collect::<Vec<_>>();
    if fields.len() < 9 {
        return None;
    }
    let stage = fields[0];
    let label = fields[1];
    let target = fields[2];
    let node_id = fields[3];
    let role = fields[4];
    let rc = fields[5].parse::<i32>().unwrap_or(1);
    let log_path = Path::new(fields[8]);
    let host = alias_for_target(target, aliases).unwrap_or_else(|| label.to_owned());

    if rc == 0 {
        return Some(success_summary_for_stage(stage, &host, node_id, role));
    }

    let error = last_error_line(log_path).unwrap_or_else(|| "see worker log".to_owned());
    Some(format!(
        "{} failed on {} (rc {}): {}",
        human_stage(active_stage),
        host,
        rc,
        error
    ))
}

fn summarize_worker_log(stage: &str, label: &str, raw: &str) -> String {
    if let Some(error) = raw
        .lines()
        .rev()
        .find(|line| is_error_line(line))
        .map(str::trim)
    {
        return format!("{} failed on {}: {}", human_stage(stage), label, error);
    }
    if raw.contains("Finished `release` profile") || raw.contains("e2e bootstrap host complete") {
        return format!("compiled successfully on {label}");
    }
    if raw
        .lines()
        .any(|line| line.trim_start().starts_with("Compiling "))
    {
        return format!("compiling on {label}");
    }
    format!("{} running on {}", human_stage(stage), label)
}

fn summarize_raw_lines(raw: &[String]) -> Vec<String> {
    let mut summaries = Vec::new();
    let compile_count = raw
        .iter()
        .filter(|line| line.trim_start().starts_with("Compiling "))
        .count();
    if compile_count > 0 {
        if raw
            .iter()
            .any(|line| line.contains("Finished `release` profile"))
        {
            summaries.push("compiled successfully".to_owned());
        } else {
            summaries.push(format!("compiling ({compile_count} crates seen)"));
        }
    }

    for line in raw {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Compiling ") {
            continue;
        }
        if is_error_line(trimmed)
            || trimmed.contains("[stage:")
            || trimmed.contains("PASS")
            || trimmed.contains("FAIL")
            || trimmed.contains("skipped:")
            || trimmed.contains("launched ")
            || trimmed.contains("report:")
            || trimmed.contains("OpenCode")
        {
            summaries.push(trimmed.to_owned());
        }
    }

    // Deliberately no "stage is running" fallback here: a stage's log file
    // is only ever written once its remote command returns (there is no
    // partial/live write path), so non-empty content always means the
    // stage is DONE -- even when its own output format (a raw JSON result
    // blob from the tier 1-4 audit stages, or a single plain-text
    // completion sentence like "macOS host bootstrapped") doesn't contain
    // any of the keywords matched above. Claiming "is running" here was
    // always wrong for this case, and could sit on screen long after a run
    // had actually finished (nothing re-summarizes it once idle). Leaving
    // `summaries` empty here falls through to `summarize_stage_lines`'s own
    // raw-content fallback, which shows the real completion message instead
    // of a misleading placeholder.
    summaries.sort();
    summaries.dedup();
    summaries
}

fn success_summary_for_stage(stage: &str, host: &str, node_id: &str, role: &str) -> String {
    match stage {
        "bootstrap_hosts" => format!("compiled successfully on {host} ({node_id}, {role})"),
        "cleanup_hosts" => format!("cleaned previous Rustynet state on {host}"),
        "verify_ssh_reachability" => format!("ssh reachable on {host}"),
        "prime_remote_access" => format!("remote access primed on {host}"),
        _ => format!(
            "{} passed on {} ({node_id}, {role})",
            human_stage(stage),
            host
        ),
    }
}

fn human_stage(stage: &str) -> String {
    stage.replace('_', " ")
}

fn alias_for_target(target: &str, aliases: &HashMap<String, String>) -> Option<String> {
    let ip = target.rsplit('@').next().unwrap_or(target);
    aliases.get(ip).cloned()
}

fn last_error_line(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok().and_then(|raw| {
        raw.lines()
            .rev()
            .find(|line| is_error_line(line))
            .map(|line| line.trim().to_owned())
    })
}

fn is_error_line(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.contains("error:")
        || lowered.contains("failed")
        || lowered.contains("timed out")
        || lowered.contains("no such file")
        || lowered.contains("permission denied")
}

fn load_inventory_aliases(repo_root: &Path) -> Result<HashMap<String, String>> {
    let path = repo_root
        .join("documents")
        .join("operations")
        .join("active")
        .join("vm_lab_inventory.json");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let mut aliases = HashMap::new();
    for entry in value
        .get("entries")
        .and_then(|entries| entries.as_array())
        .into_iter()
        .flatten()
    {
        let Some(alias) = entry.get("alias").and_then(|value| value.as_str()) else {
            continue;
        };
        for key in ["ssh_target", "last_known_ip", "mesh_ip"] {
            if let Some(ip) = entry.get(key).and_then(|value| value.as_str()) {
                aliases.insert(ip.to_owned(), alias.to_owned());
            }
        }
        if let Some(ips) = entry.get("live_ips").and_then(|value| value.as_array()) {
            for ip in ips.iter().filter_map(|value| value.as_str()) {
                aliases.insert(ip.to_owned(), alias.to_owned());
            }
        }
    }
    Ok(aliases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_hosts_surfaces_the_live_per_node_build_log() {
        // Regression: bootstrap_hosts' own logs/bootstrap_hosts.log holds only a
        // one-line end-of-stage marker and the --node engine writes no parallel
        // dir, so the LOG panel showed "No log output" for the whole ~10-minute
        // bootstrap. The live per-node build log must be surfaced instead.
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        // The end-of-stage marker the generic path would (unhelpfully) show.
        std::fs::write(
            logs.join("bootstrap_hosts.log"),
            "[stage:bootstrap_hosts] pass (rust --node engine)\n",
        )
        .unwrap();
        // The live per-node build output that should be surfaced.
        std::fs::write(
            logs.join("bootstrap_node_ubuntu-utm-1.log"),
            "Compiling rustynet-relay v0.1.0\n    Finished `release` profile in 7.07s\n",
        )
        .unwrap();

        let out =
            summarize_stage_lines(dir.path(), dir.path(), "bootstrap_hosts").expect("summarize");
        let joined = out.join("\n");
        assert!(
            joined.contains("building ubuntu-utm-1"),
            "names the node being built: {joined}"
        );
        assert!(
            joined.contains("Compiling rustynet-relay"),
            "shows the live build output, not the one-line end marker: {joined}"
        );
    }

    #[test]
    fn summarize_parallel_bootstrap_hides_compile_spam() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let inventory = repo.join("documents/operations/active");
        std::fs::create_dir_all(&inventory).unwrap();
        std::fs::write(
            inventory.join("vm_lab_inventory.json"),
            r#"{"entries":[{"alias":"debian-headless-1","ssh_target":"192.168.0.200","live_ips":["192.168.0.200"]}]}"#,
        )
        .unwrap();
        let report = repo.join("state/report");
        let parallel = report.join("state/parallel-bootstrap_hosts");
        std::fs::create_dir_all(&parallel).unwrap();
        let log_path = parallel.join("exit.log");
        std::fs::write(
            &log_path,
            "Compiling libc\nCompiling rustynet-cli\nFinished `release` profile [optimized]\n",
        )
        .unwrap();
        std::fs::write(
            parallel.join("results.tsv"),
            format!(
                "bootstrap_hosts\texit\tdebian@192.168.0.200\texit-1\tadmin\t0\tstart\tfinish\t{}\t\t\t\t\n",
                log_path.display()
            ),
        )
        .unwrap();

        let lines = summarize_stage_lines(repo, &report, "bootstrap_hosts").unwrap();

        assert!(
            lines
                .iter()
                .any(|line| line == "compiled successfully on debian-headless-1 (exit-1, admin)")
        );
        assert!(!lines.iter().any(|line| line.contains("Compiling")));
    }

    #[test]
    fn a_completed_stage_with_no_recognized_keyword_shows_its_real_content_not_is_running() {
        // Regression, verified against a real report dir: the tier 1-4
        // audit stages (membership-revoke, hello-limiter-flood,
        // blind-exit-reversal-denied, etc.) write a raw JSON result blob
        // with no PASS/FAIL/etc. text marker at all -- a log file is only
        // ever written once its stage's remote command returns (there is
        // no partial/live write path), so this content is always a
        // completed result, never an in-progress one. It used to always
        // render as "<stage> is running" regardless, which could sit on
        // screen long after the run had actually finished.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let report = repo.join("state/report");
        let logs = report.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("validate_macos_blind_exit_reversal_denied.log"),
            "{\n  \"schema_version\": 1,\n  \"overall_ok\": true,\n  \"total_cases\": 8\n}\n",
        )
        .unwrap();

        let lines =
            summarize_stage_lines(repo, &report, "validate_macos_blind_exit_reversal_denied")
                .unwrap();

        assert!(
            !lines.iter().any(|line| line.contains("is running")),
            "a completed stage's log must never be summarized as still running: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("overall_ok")),
            "the real JSON result must be shown instead: {lines:?}"
        );
    }

    #[test]
    fn a_plain_text_completion_sentence_with_no_keyword_also_shows_its_real_content() {
        // Same bug, different real log format: bootstrap_macos_host.log's
        // completion message is a single plain sentence with no PASS/FAIL
        // keyword either ("macOS host bootstrapped; node_id=...").
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let report = repo.join("state/report");
        let logs = report.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        std::fs::write(
            logs.join("bootstrap_macos_host.log"),
            "macOS host macos-utm-1 bootstrapped; node_id=macos-client-1\n",
        )
        .unwrap();

        let lines = summarize_stage_lines(repo, &report, "bootstrap_macos_host").unwrap();

        assert!(!lines.iter().any(|line| line.contains("is running")));
        assert!(lines.iter().any(|line| line.contains("bootstrapped")));
    }

    #[test]
    fn a_short_parallel_result_row_is_skipped_not_panicked() {
        // A concurrently-appended results.tsv row caught mid-write has
        // fewer than the 9 required tab fields. Indexing it would panic;
        // the length guard must skip it and return None instead.
        let aliases = HashMap::new();
        assert!(summarize_parallel_result_row("stage\tlabel\ttarget", "stage", &aliases).is_none());
        assert!(summarize_parallel_result_row("", "stage", &aliases).is_none());
    }

    #[test]
    fn a_non_numeric_return_code_is_treated_as_failure_never_a_false_success() {
        // rc lives in field 5; a torn/garbage value there must default to
        // "failed" (rc != 0), never be silently read as the success (rc==0)
        // path -- a false green on a stage that may actually have failed.
        let aliases = HashMap::new();
        let row = "bootstrap_hosts\texit\tdebian@10.0.0.1\texit-1\tadmin\tNOT_A_NUMBER\ts\tf\t/tmp/x.log\t\t\t\t";
        let summary = summarize_parallel_result_row(row, "bootstrap_hosts", &aliases)
            .expect("a 9+-field row still summarizes");
        assert!(
            summary.contains("failed"),
            "unparseable rc must read as failure, got: {summary}"
        );
    }

    #[test]
    fn a_well_formed_success_row_reads_as_success() {
        let aliases = HashMap::new();
        let row =
            "bootstrap_hosts\texit\tdebian@10.0.0.1\texit-1\tadmin\t0\ts\tf\t/tmp/x.log\t\t\t\t";
        let summary = summarize_parallel_result_row(row, "bootstrap_hosts", &aliases)
            .expect("well-formed row summarizes");
        assert!(
            !summary.contains("failed"),
            "rc 0 must not read as failure: {summary}"
        );
    }

    #[test]
    fn summarize_stage_lines_on_a_missing_log_returns_empty_not_an_error() {
        // No parallel dir and no per-stage log at all (queried before the
        // stage wrote anything) -- must degrade to an empty summary, never
        // error or panic.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let report = repo.join("state/report");
        std::fs::create_dir_all(&report).unwrap();

        let lines = summarize_stage_lines(repo, &report, "a_stage_with_no_log_yet")
            .expect("missing log degrades cleanly");
        // No parallel dir and no per-stage log content at all -> an empty
        // summary (the log panel renders "No log output"), never an error
        // or a panic.
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn corrupt_inventory_does_not_break_parallel_summarization() {
        // load_inventory_aliases is best-effort here (.unwrap_or_default at
        // the call site): a corrupt inventory JSON must simply mean "no
        // alias enrichment", falling back to the raw node label -- never a
        // failed or panicking stage summary.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let inventory = repo.join("documents/operations/active");
        std::fs::create_dir_all(&inventory).unwrap();
        std::fs::write(inventory.join("vm_lab_inventory.json"), "{ not json").unwrap();
        let report = repo.join("state/report");
        let parallel = report.join("state/parallel-bootstrap_hosts");
        std::fs::create_dir_all(&parallel).unwrap();
        std::fs::write(
            parallel.join("results.tsv"),
            "bootstrap_hosts\texit\tdebian@10.0.0.1\texit-1\tadmin\t0\ts\tf\t/tmp/x.log\t\t\t\t\n",
        )
        .unwrap();

        let lines = summarize_stage_lines(repo, &report, "bootstrap_hosts")
            .expect("corrupt inventory must not fail the summary");
        // Falls back to the raw node label ("exit") since alias lookup found
        // nothing -- and still produced a real summary line.
        assert!(lines.iter().any(|line| line.contains("exit")), "{lines:?}");
    }
}

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

    let log_path = report_dir.join("logs").join(format!("{stage}.log"));
    let raw = tail_lines(&log_path, 250)?;
    let summarized = summarize_raw_lines(stage, &raw);
    if summarized.is_empty() {
        Ok(raw.into_iter().take(80).collect())
    } else {
        lines.extend(summarized);
        Ok(lines)
    }
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

fn summarize_raw_lines(stage: &str, raw: &[String]) -> Vec<String> {
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

    if summaries.is_empty() && !raw.is_empty() {
        summaries.push(format!("{} is running", human_stage(stage)));
    }

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
}

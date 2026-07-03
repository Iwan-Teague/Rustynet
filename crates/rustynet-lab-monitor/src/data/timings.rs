use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Load `documents/operations/live_lab_stage_timings.csv` and compute
/// P90 duration_secs per stage name over ALL terminal outcomes.
///
/// Finding 6: the old pass-only P50 starved exactly the stages an
/// operator iterates on (a stage failing at 20 minutes forever kept its
/// 300s cold-start estimate), and half of healthy runs exceed a P50 by
/// definition — the wrong statistic for an "overdue" signal. Failed and
/// timed-out attempts are real evidence of how long the stage occupies
/// the pipeline; skipped rows (near-zero durations) are excluded so they
/// cannot drag the estimate down.
pub fn load_stage_timings(repo_root: &Path) -> Result<HashMap<String, u64>> {
    let path = repo_root.join("documents/operations/live_lab_stage_timings.csv");
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&path)
        .with_context(|| format!("opening {}", path.display()))?;

    let mut durations: HashMap<String, Vec<u64>> = HashMap::new();

    for result in reader.deserialize() {
        let record: TimingRecord = match result {
            Ok(r) => r,
            Err(_) => continue,
        };
        if matches!(
            record.outcome.as_str(),
            "skip" | "skipped" | "not_run" | "na"
        ) {
            continue;
        }
        let secs = record.duration_secs.unwrap_or(0);
        if secs > 0 {
            durations.entry(record.stage).or_default().push(secs);
        }
    }

    let mut p90: HashMap<String, u64> = HashMap::new();
    for (stage, mut durs) in durations {
        durs.sort_unstable();
        if durs.is_empty() {
            continue;
        }
        // P90 = smallest value covering >= 90% of observations.
        let index = (durs.len() * 9).div_ceil(10).saturating_sub(1);
        p90.insert(stage, durs[index.min(durs.len() - 1)]);
    }

    Ok(p90)
}

#[derive(Debug, serde::Deserialize)]
struct TimingRecord {
    #[allow(dead_code)]
    timestamp_utc: String,
    #[allow(dead_code)]
    git_commit: String,
    #[allow(dead_code)]
    git_dirty: String,
    stage: String,
    #[allow(dead_code)]
    scope: String,
    duration_secs: Option<u64>,
    outcome: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_timing_csv(dir: &std::path::Path, content: &str) {
        let docs = dir.join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("live_lab_stage_timings.csv"), content).unwrap();
    }

    #[test]
    fn p90_empty() {
        let dir = tempfile::tempdir().unwrap();
        write_timing_csv(
            dir.path(),
            "timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome\n",
        );
        let map = load_stage_timings(dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn p90_single_stage() {
        let dir = tempfile::tempdir().unwrap();
        let content = "\
timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome
2024-01-01T00:00:00Z,abc,no,bootstrap,,120,pass
2024-01-01T00:01:00Z,abc,no,bootstrap,,180,pass
2024-01-01T00:02:00Z,abc,no,bootstrap,,160,pass
";
        write_timing_csv(dir.path(), content);

        let map = load_stage_timings(dir.path()).unwrap();
        // sorted [120, 160, 180]; ceil(3*0.9)=3rd value.
        assert_eq!(map.get("bootstrap"), Some(&180));
    }

    #[test]
    fn p90_uses_all_terminal_outcomes_and_excludes_skips() {
        let dir = tempfile::tempdir().unwrap();
        // A stage that keeps FAILING at ~1200s must not sit at a
        // cold-start estimate forever (the old pass-only filter), and a
        // skipped row's ~0s must not drag the estimate down.
        let content = "\
timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome
2024-01-01T00:00:00Z,abc,no,anchor,,100,pass
2024-01-01T00:00:00Z,abc,no,anchor,,200,pass
2024-01-01T00:00:00Z,abc,no,anchor,,300,pass
2024-01-01T00:00:00Z,abc,no,anchor,,400,fail
2024-01-01T00:00:00Z,abc,no,anchor,,1,skipped
2024-01-01T00:00:00Z,abc,no,flaky,,1200,fail
2024-01-01T00:00:00Z,abc,no,flaky,,1180,fail
";
        write_timing_csv(dir.path(), content);

        let map = load_stage_timings(dir.path()).unwrap();
        // anchor: sorted [100,200,300,400], ceil(4*0.9)=4th value = 400 —
        // the fail row counts, the skipped row does not.
        assert_eq!(map.get("anchor"), Some(&400));
        // flaky (never passed): now has a real estimate instead of none.
        assert_eq!(map.get("flaky"), Some(&1200));
    }
}

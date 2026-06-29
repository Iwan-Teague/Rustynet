use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Load `documents/operations/live_lab_stage_timings.csv` and compute
/// P50 (median) duration_secs per stage name (pass rows only).
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
        if record.outcome != "pass" {
            continue;
        }
        let secs = record.duration_secs.unwrap_or(0);
        if secs > 0 {
            durations.entry(record.stage).or_default().push(secs);
        }
    }

    let mut p50: HashMap<String, u64> = HashMap::new();
    for (stage, mut durs) in durations {
        durs.sort_unstable();
        let median = if durs.is_empty() {
            60
        } else if durs.len() % 2 == 0 {
            (durs[durs.len() / 2 - 1] + durs[durs.len() / 2]) / 2
        } else {
            durs[durs.len() / 2]
        };
        p50.insert(stage, median);
    }

    Ok(p50)
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
    fn p50_empty() {
        let dir = tempfile::tempdir().unwrap();
        write_timing_csv(
            dir.path(),
            "timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome\n",
        );
        let map = load_stage_timings(dir.path()).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn p50_single_stage() {
        let dir = tempfile::tempdir().unwrap();
        let content = "\
timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome
2024-01-01T00:00:00Z,abc,no,bootstrap,,120,pass
2024-01-01T00:01:00Z,abc,no,bootstrap,,180,pass
2024-01-01T00:02:00Z,abc,no,bootstrap,,160,pass
";
        write_timing_csv(dir.path(), content);

        let map = load_stage_timings(dir.path()).unwrap();
        assert_eq!(map.get("bootstrap"), Some(&160));
    }

    #[test]
    fn p50_median_calc() {
        let dir = tempfile::tempdir().unwrap();
        let content = "\
timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome
2024-01-01T00:00:00Z,abc,no,anchor,,100,pass
2024-01-01T00:00:00Z,abc,no,anchor,,200,pass
2024-01-01T00:00:00Z,abc,no,anchor,,300,pass
2024-01-01T00:00:00Z,abc,no,anchor,,400,pass
";
        write_timing_csv(dir.path(), content);

        let map = load_stage_timings(dir.path()).unwrap();
        assert_eq!(map.get("anchor"), Some(&250));
    }
}

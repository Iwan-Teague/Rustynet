#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveLabWorkerResult {
    pub stage_name: String,
    pub label: String,
    pub target: String,
    pub node_id: String,
    pub role: String,
    pub rc: i64,
    pub started_at: String,
    pub finished_at: String,
    pub log_path: String,
    pub snapshot_path: String,
    pub route_policy_path: String,
    pub dns_state_path: String,
    pub primary_failure_reason: String,
}

fn read_tsv(path: &Path) -> Vec<Vec<String>> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split('\t')
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|row| !row.is_empty())
        .collect()
}

fn parse_worker_result_row(stage_name: &str, row: &[String]) -> Option<LiveLabWorkerResult> {
    if row.len() >= 13 {
        return Some(LiveLabWorkerResult {
            stage_name: row[0].clone(),
            label: row[1].clone(),
            target: row[2].clone(),
            node_id: row[3].clone(),
            role: row[4].clone(),
            rc: row[5].parse::<i64>().unwrap_or(1),
            started_at: row[6].clone(),
            finished_at: row[7].clone(),
            log_path: row[8].clone(),
            snapshot_path: row[9].clone(),
            route_policy_path: row[10].clone(),
            dns_state_path: row[11].clone(),
            primary_failure_reason: row[12].clone(),
        });
    }
    if row.len() == 6 {
        return Some(LiveLabWorkerResult {
            stage_name: stage_name.to_string(),
            label: row[0].clone(),
            target: row[1].clone(),
            node_id: row[2].clone(),
            role: row[3].clone(),
            rc: row[4].parse::<i64>().unwrap_or(1),
            started_at: String::new(),
            finished_at: String::new(),
            log_path: row[5].clone(),
            snapshot_path: String::new(),
            route_policy_path: String::new(),
            dns_state_path: String::new(),
            primary_failure_reason: String::new(),
        });
    }
    None
}

pub fn read_parallel_stage_results(
    report_dir: &Path,
    stage_name: &str,
) -> Vec<LiveLabWorkerResult> {
    let results_path = report_dir
        .join("state")
        .join(format!("parallel-{stage_name}"))
        .join("results.tsv");
    read_tsv(results_path.as_path())
        .into_iter()
        .filter_map(|row| parse_worker_result_row(stage_name, row.as_slice()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{LiveLabWorkerResult, read_parallel_stage_results};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("rustynet-live-lab-results-{name}-{stamp}"))
    }

    #[test]
    fn reads_new_worker_result_schema() {
        let report_dir = temp_path("new-schema");
        let state_dir = report_dir.join("state/parallel-validate_baseline_runtime");
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::write(
            state_dir.join("results.tsv"),
            "validate_baseline_runtime\tclient\tdebian@client\tclient-1\tclient\t1\t2026-04-08T10:00:00Z\t2026-04-08T10:00:10Z\t/tmp/client.log\t/tmp/snapshot.txt\t/tmp/route.txt\t/tmp/dns.txt\troute missing\n",
        )
        .expect("results write");

        let results =
            read_parallel_stage_results(report_dir.as_path(), "validate_baseline_runtime");
        assert_eq!(
            results,
            vec![LiveLabWorkerResult {
                stage_name: "validate_baseline_runtime".to_string(),
                label: "client".to_string(),
                target: "debian@client".to_string(),
                node_id: "client-1".to_string(),
                role: "client".to_string(),
                rc: 1,
                started_at: "2026-04-08T10:00:00Z".to_string(),
                finished_at: "2026-04-08T10:00:10Z".to_string(),
                log_path: "/tmp/client.log".to_string(),
                snapshot_path: "/tmp/snapshot.txt".to_string(),
                route_policy_path: "/tmp/route.txt".to_string(),
                dns_state_path: "/tmp/dns.txt".to_string(),
                primary_failure_reason: "route missing".to_string(),
            }]
        );

        let _ = fs::remove_dir_all(report_dir);
    }

    #[test]
    fn reads_legacy_worker_result_schema() {
        let report_dir = temp_path("legacy-schema");
        let state_dir = report_dir.join("state/parallel-bootstrap_hosts");
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::write(
            state_dir.join("results.tsv"),
            "client\tdebian@client\tclient-1\tclient\t0\t/tmp/client.log\n",
        )
        .expect("results write");

        let results = read_parallel_stage_results(report_dir.as_path(), "bootstrap_hosts");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].stage_name, "bootstrap_hosts");
        assert_eq!(results[0].label, "client");
        assert_eq!(results[0].rc, 0);
        assert!(results[0].started_at.is_empty());
        assert!(results[0].snapshot_path.is_empty());

        let _ = fs::remove_dir_all(report_dir);
    }
}

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

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
    if let [
        row_stage_name,
        label,
        target,
        node_id,
        role,
        rc,
        started_at,
        finished_at,
        log_path,
        snapshot_path,
        route_policy_path,
        dns_state_path,
        primary_failure_reason,
        ..,
    ] = row
    {
        return Some(LiveLabWorkerResult {
            stage_name: (*row_stage_name).to_owned(),
            label: (*label).to_owned(),
            target: (*target).to_owned(),
            node_id: (*node_id).to_owned(),
            role: (*role).to_owned(),
            rc: rc.parse::<i64>().unwrap_or(1),
            started_at: (*started_at).to_owned(),
            finished_at: (*finished_at).to_owned(),
            log_path: (*log_path).to_owned(),
            snapshot_path: (*snapshot_path).to_owned(),
            route_policy_path: (*route_policy_path).to_owned(),
            dns_state_path: (*dns_state_path).to_owned(),
            primary_failure_reason: (*primary_failure_reason).to_owned(),
        });
    }
    if let [label, target, node_id, role, rc, log_path] = row {
        return Some(LiveLabWorkerResult {
            stage_name: stage_name.to_owned(),
            label: (*label).to_owned(),
            target: (*target).to_owned(),
            node_id: (*node_id).to_owned(),
            role: (*role).to_owned(),
            rc: rc.parse::<i64>().unwrap_or(1),
            started_at: String::new(),
            finished_at: String::new(),
            log_path: (*log_path).to_owned(),
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
                stage_name: "validate_baseline_runtime".to_owned(),
                label: "client".to_owned(),
                target: "debian@client".to_owned(),
                node_id: "client-1".to_owned(),
                role: "client".to_owned(),
                rc: 1,
                started_at: "2026-04-08T10:00:00Z".to_owned(),
                finished_at: "2026-04-08T10:00:10Z".to_owned(),
                log_path: "/tmp/client.log".to_owned(),
                snapshot_path: "/tmp/snapshot.txt".to_owned(),
                route_policy_path: "/tmp/route.txt".to_owned(),
                dns_state_path: "/tmp/dns.txt".to_owned(),
                primary_failure_reason: "route missing".to_owned(),
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

#[cfg(test)]
mod aq08_6b_differential {
    //! AQ-08 bucket 6b part 1 (rustynet-cli/live_lab_results.rs): seeded-mutation
    //! differential harness. `old_parse_worker_result_row` is a verbatim copy of
    //! the parser body from the pre-patch tree (HEAD 53ba50956), renamed only.
    //! For a golden fixture plus 2000 deterministic mutations per base row
    //! (truncation, field deletion, field duplication, adjacent-field swap,
    //! junk/unicode injection, oversize padding, non-numeric rc), the old and
    //! new parsers must produce identical results. Any divergence fails the
    //! test and names the seed and the offending row.

    use super::*;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn old_parse_worker_result_row(
        stage_name: &str,
        row: &[String],
    ) -> Option<LiveLabWorkerResult> {
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
                stage_name: stage_name.to_owned(),
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

    fn golden_rows() -> Vec<Vec<String>> {
        let wide: Vec<&str> = vec![
            "validate_baseline_runtime",
            "client",
            "debian@client",
            "client-1",
            "client",
            "1",
            "2026-04-08T10:00:00Z",
            "2026-04-08T10:00:10Z",
            "/tmp/client.log",
            "/tmp/snapshot.txt",
            "/tmp/route.txt",
            "/tmp/dns.txt",
            "route missing",
        ];
        let wide_extra: Vec<&str> = wide.iter().copied().chain(["extra-a", "extra-b"]).collect();
        let legacy: Vec<&str> = vec![
            "client",
            "debian@client",
            "client-1",
            "client",
            "0",
            "/tmp/client.log",
        ];
        let empty_fields: Vec<&str> = vec!["", "", "", "", "", "", "", "", "", "", "", "", ""];
        [wide, wide_extra, legacy, empty_fields, vec!["solo"], vec![]]
            .into_iter()
            .map(|row| row.into_iter().map(ToOwned::to_owned).collect())
            .collect()
    }

    fn mutated(row: &[String], rng: &mut Rng) -> Vec<String> {
        let mut row = row.to_vec();
        match rng.below(7) {
            0 => {
                // truncate to a random width
                let keep = rng.below(row.len() + 3);
                row.truncate(keep);
            }
            1 => {
                // delete a random field
                if !row.is_empty() {
                    let at = rng.below(row.len());
                    row.remove(at);
                }
            }
            2 => {
                // duplicate a random field
                if !row.is_empty() {
                    let at = rng.below(row.len());
                    row.insert(at, row[at].clone());
                }
            }
            3 => {
                // swap two adjacent fields
                if row.len() >= 2 {
                    let at = rng.below(row.len() - 1);
                    row.swap(at, at + 1);
                }
            }
            4 => {
                // inject junk / unicode / non-numeric rc
                let junk = [
                    "\tmiddle-tab",
                    "значение",
                    "not-a-number",
                    "-7",
                    "99999999999999999999",
                    "  spaced  ",
                    "\"quoted\"",
                ];
                if !row.is_empty() {
                    let slot = rng.below(row.len());
                    let at = rng.below(junk.len());
                    row[slot] = junk[at].to_owned();
                }
            }
            5 => {
                // oversize padding on a random field
                if !row.is_empty() {
                    let slot = rng.below(row.len());
                    let pad = "p".repeat(64 + rng.below(64));
                    row[slot].insert_str(0, &pad);
                }
            }
            _ => {
                // empty a random field
                if !row.is_empty() {
                    let slot = rng.below(row.len());
                    row[slot] = String::new();
                }
            }
        }
        row
    }

    #[test]
    fn parse_worker_result_row_old_equals_new_over_mutations() {
        let stage_names = ["validate_baseline_runtime", "bootstrap_hosts", ""];
        let bases = golden_rows();
        let mut rng = Rng(0x6B00_0000_0000_0001);
        let mut checked = 0usize;
        for base in &bases {
            for _ in 0..2000 {
                let candidate = mutated(base, &mut rng);
                for stage_name in stage_names {
                    let old = old_parse_worker_result_row(stage_name, candidate.as_slice());
                    let new = parse_worker_result_row(stage_name, candidate.as_slice());
                    assert_eq!(
                        old, new,
                        "DIVERGENCE in parse_worker_result_row on stage {stage_name:?} row {candidate:?}"
                    );
                    checked += 1;
                }
            }
        }
        for stage_name in stage_names {
            for row in &bases {
                let old = old_parse_worker_result_row(stage_name, row.as_slice());
                let new = parse_worker_result_row(stage_name, row.as_slice());
                assert_eq!(
                    old, new,
                    "DIVERGENCE in parse_worker_result_row on GOLDEN stage {stage_name:?} row {row:?}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 20_000, "mutation floor: only {checked} checked");
    }
}

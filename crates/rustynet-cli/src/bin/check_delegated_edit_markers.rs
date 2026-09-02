//! check_delegated_edit_markers — QH-26 item 4 gate.
//!
//! Fails when a commit inside the scan window carries the delegated-edit
//! tier's automatic checkpoint marker pair ("Committed by the delegated-edit
//! tier" and "Review before merging.") without being on the reviewed
//! allowlist. Allowlist-primary: the window depth only bounds how far back
//! new markers are detected; it never absolves history. A marker that
//! predates the window is caught by the day-one census, not by this scan.
//!
//! Exit codes: 0 = clean (all marked commits allowlisted), 1 = offending
//! marker found (SHA + subject listed), 2 = git invocation failed (fail
//! closed). `--self-test` exercises the classifier against a scratch repo.
#![forbid(unsafe_code)]

use std::process::Command;

/// First half of the marker pair the delegated-edit tier writes.
const MARKER_A: &str = "Committed by the delegated-edit tier";
/// Second half of the marker pair. Both halves are required so a quoted or
/// partially quoted marker never trips the gate.
const MARKER_B: &str = "Review before merging.";

const DEFAULT_DEPTH: usize = 200;
const FIELD_SEP: char = '\u{0}';
const RECORD_SEP: char = '\u{1e}';

/// One reviewed automatic-checkpoint commit. Every entry here was resolved
/// against main and human-reviewed before being allowlisted; see
/// documents/operations/active/QualityHardeningTodo_2026-07-25.md QH-26.
struct AllowedMarker {
    sha: &'static str,
    date: &'static str,
    rationale: &'static str,
}

const ALLOWLIST: &[AllowedMarker] = &[
    AllowedMarker {
        sha: "f1ef83b191d3839460883a8745ad3f33810c91e4",
        date: "2026-07-20",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "f54edda5176c986b0f910ac28c7869602336eb93",
        date: "2026-07-20",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "15cf9f1113410ab75d62ff3fb2f5ef4d45151492",
        date: "2026-07-20",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "726be807e05d895ceac8aaa6c61ef7076b8e5b90",
        date: "2026-08-29",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "5757e55c60a9e802b4b83f4d837ae462da3ab67b",
        date: "2026-08-30",
        rationale: "ACCEPT-WITH-FIXES per AnchorTlsUnreviewedCheckpointsSecurityReview_2026-09-02.md (no P0/P1; AT-1 P2 handshake deadline, AT-2 P2 client pinning gap; verdict §9)",
    },
    AllowedMarker {
        sha: "2befe39e01146902e74f72a23addc731e7cfa631",
        date: "2026-08-30",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "1a5bcb21be5793617d9edd6b409feeb6f5d793d6",
        date: "2026-08-30",
        rationale: "ACCEPT-WITH-FIXES per AnchorTlsUnreviewedCheckpointsSecurityReview_2026-09-02.md (no P0/P1; AT-1 P2 handshake deadline, AT-2 P2 client pinning gap; verdict §9)",
    },
    AllowedMarker {
        sha: "4eeee1dd86f7c1a093f44820a4ac0e9157b7584c",
        date: "2026-08-30",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "9a723960233cdd8b073b87110bfb3ded58dba589",
        date: "2026-08-30",
        rationale: "ACCEPT-WITH-FIXES per AnchorTlsUnreviewedCheckpointsSecurityReview_2026-09-02.md (no P0/P1; AT-1 P2 handshake deadline, AT-2 P2 client pinning gap; verdict §9)",
    },
    AllowedMarker {
        sha: "4c2c17da69e170cde3a3843e3875b244223c5600",
        date: "2026-08-30",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
    AllowedMarker {
        sha: "d1890dae0d9ee475b434eaacaf1be2fb74886115",
        date: "2026-08-30",
        rationale: "lab tooling / ledger; allowlist-safe (review table row)",
    },
];

/// A commit as parsed out of `git log`.
pub struct CommitRecord {
    pub sha: String,
    pub subject: String,
    pub body: String,
}

/// The classifier proper: a commit is MARKED only when BOTH marker halves
/// appear in the full body. One half alone is not a marker.
pub fn is_marked(commit: &CommitRecord) -> bool {
    commit.body.contains(MARKER_A) && commit.body.contains(MARKER_B)
}

/// Allowlist match: full 40-hex SHA, or a unique prefix of at least 8 hex
/// chars (mirrors how humans cite SHAs; anything shorter is ambiguous).
pub fn is_allowlisted(commit_sha: &str, allowlist: &[String]) -> bool {
    let sha = commit_sha.to_ascii_lowercase();
    ALLOWLIST
        .iter()
        .any(|a| match_allowlist_entry(&sha, &a.sha.to_ascii_lowercase()))
        || allowlist
            .iter()
            .any(|e| match_allowlist_entry(&sha, &e.to_ascii_lowercase()))
}

fn match_allowlist_entry(sha: &str, entry: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() || !entry.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    // A match is an unambiguous citation: the shorter side must be at least
    // 8 hex chars, and one side must be a prefix of the other (so a cited
    // short SHA matches its full allowlist entry and vice versa).
    let shorter = sha.len().min(entry.len());
    shorter >= 8 && (sha.starts_with(entry) || entry.starts_with(sha))
}

/// Parse `git log --format=%H%x00%s%x00%B%x1e` output into records.
pub fn parse_log(output: &str) -> Vec<CommitRecord> {
    output
        .split(RECORD_SEP)
        .filter(|r| !r.trim().is_empty())
        .filter_map(|record| {
            let mut fields = record.split(FIELD_SEP);
            let sha = fields.next()?.trim().to_string();
            let subject = fields.next()?.to_string();
            let body = fields.next()?.to_string();
            if sha.is_empty() {
                return None;
            }
            Some(CommitRecord { sha, subject, body })
        })
        .collect()
}

fn read_depth() -> usize {
    match std::env::var("MARKER_SCAN_DEPTH") {
        Ok(v) => v.trim().parse().unwrap_or(DEFAULT_DEPTH),
        Err(_) => DEFAULT_DEPTH,
    }
}

fn run_git(dir: &std::path::Path, args: &[&str]) -> Result<String, i32> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| {
            eprintln!("error [2]: failed to spawn git {args:?}: {e}");
            2
        })?;
    if !out.status.success() {
        eprintln!(
            "error [2]: git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return Err(2);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Enumerate the scan window and classify every commit. Returns the marked
/// commits and whether any allowlisted SHA appeared inside the window.
fn scan(
    dir: &std::path::Path,
    depth: usize,
    tip: &str,
    extra_allowlist: &[String],
) -> Result<(Vec<CommitRecord>, bool), i32> {
    let depth_arg = format!("-n{depth}");
    let fmt_arg = "--format=%H%x00%s%x00%B%x1e";
    let output = run_git(dir, &["log", fmt_arg, &depth_arg, tip])?;
    let commits = parse_log(&output);
    let allowlisted_seen = commits
        .iter()
        .any(|c| is_allowlisted(&c.sha, extra_allowlist));
    let marked: Vec<CommitRecord> = commits.into_iter().filter(is_marked).collect();
    Ok((marked, allowlisted_seen))
}

fn extra_allowlist() -> Vec<String> {
    match std::env::var("MARKER_ALLOWLIST") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Prints the reviewed allowlist table (operator surface; `--show-allowlist`).
fn print_allowlist() {
    println!(
        "delegated-edit marker allowlist ({} entries):",
        ALLOWLIST.len()
    );
    for entry in ALLOWLIST.iter() {
        println!("{}  {}  {}", entry.sha, entry.date, entry.rationale);
    }
}

fn report_offenders(marked: &[&CommitRecord]) {
    eprintln!(
        "error [1]: {} marked delegated-edit commit(s) inside the scan window are not on the allowlist:",
        marked.len()
    );
    for c in marked {
        eprintln!("  {}  {}", c.sha, c.subject);
    }
    eprintln!(
        "Review each commit, then either revert it or extend the reviewed allowlist (MARKER_ALLOWLIST is for deliberate post-hoc rescue only)."
    );
}

fn run() -> Result<(), i32> {
    let args: Vec<String> = std::env::args().collect();
    let extra = extra_allowlist();
    if args.iter().any(|a| a == "--self-test") {
        return self_test();
    }
    if args.iter().any(|a| a == "--show-allowlist") {
        print_allowlist();
        return Ok(());
    }
    let depth = read_depth();
    let tip = std::env::var("MARKER_SCAN_TIP").unwrap_or_else(|_| "HEAD".to_string());
    let (marked, allowlisted_seen) = scan(std::path::Path::new("."), depth, &tip, &extra)?;
    if marked.is_empty() {
        if !allowlisted_seen {
            // Loud silence (adversarial review §7.1): the marker has not
            // been observed in this window at all. That is either genuinely
            // clean history or a broken scan (shallow clone, wrong tip,
            // marker text drift) — warn loudly, do not silently pass.
            println!(
                "WARNING: no delegated-edit marker observed in the last {depth} commit(s) at {tip} and no allowlisted SHA inside the window. If this is unexpected, check fetch depth / MARKER_SCAN_TIP / marker text."
            );
        }
        println!(
            "check_delegated_edit_markers: PASS (no unallowlisted markers in the last {depth} commit(s) at {tip})"
        );
        return Ok(());
    }
    let allowed: Vec<&CommitRecord> = marked
        .iter()
        .filter(|c| is_allowlisted(&c.sha, &extra))
        .collect();
    let offenders: Vec<&CommitRecord> = marked
        .iter()
        .filter(|c| !is_allowlisted(&c.sha, &extra))
        .collect();
    for c in &allowed {
        println!("allowlisted marker: {}  {}", c.sha, c.subject);
    }
    if offenders.is_empty() {
        println!(
            "check_delegated_edit_markers: PASS ({} marked commit(s), all allowlisted)",
            allowed.len()
        );
        return Ok(());
    }
    report_offenders(&offenders);
    Err(1)
}

fn run_git_in(dir: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Test Author")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test Committer")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .output()
        .map_err(|e| format!("git {args:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Build a scratch repo with one clean and one marked commit; return the
/// two SHAs (clean first).
fn seed_scratch_repo(dir: &std::path::Path) -> Result<(String, String), String> {
    run_git_in(dir, &["init", "-q"])?;
    run_git_in(dir, &["config", "user.name", "Test Author"])?;
    run_git_in(dir, &["config", "user.email", "test@example.com"])?;
    std::fs::write(dir.join("clean.txt"), "clean commit\n").map_err(|e| e.to_string())?;
    run_git_in(dir, &["add", "clean.txt"])?;
    run_git_in(dir, &["commit", "-q", "-m", "clean commit"])?;
    let clean = run_git_in(dir, &["rev-parse", "HEAD"])?.trim().to_string();
    std::fs::write(dir.join("marked.txt"), "marked commit\n").map_err(|e| e.to_string())?;
    run_git_in(dir, &["add", "marked.txt"])?;
    let msg = format!("wip\n\n{} {}\n{}\n", MARKER_A, "checkpoint", MARKER_B);
    run_git_in(dir, &["commit", "-q", "-m", &msg])?;
    let marked = run_git_in(dir, &["rev-parse", "HEAD"])?.trim().to_string();
    Ok((clean, marked))
}

/// End-to-end self-test against a real scratch git repo: the gate must fail
/// on the marked commit, pass with its SHA allowlisted via
/// MARKER_ALLOWLIST, and pass when pointed only at the clean commit.
fn self_test() -> Result<(), i32> {
    let base = std::env::temp_dir().join(format!("marker-gate-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| {
        eprintln!("error [2]: tempdir: {e}");
        2
    })?;
    let result = self_test_inner(&base);
    let _ = std::fs::remove_dir_all(&base);
    result
}

fn self_test_inner(base: &std::path::Path) -> Result<(), i32> {
    let (clean, marked) = seed_scratch_repo(base).map_err(|e| {
        eprintln!("error [2]: scratch repo seed failed: {e}");
        2
    })?;

    // 1. Unallowlisted marker → exit 1.
    match scan(base, 200, "HEAD", &[]) {
        Ok((m, _)) if m.len() == 1 && m[0].sha == marked => {}
        other => {
            eprintln!(
                "error [1]: self-test: expected exactly the marked commit, got {:?}",
                other.map(|(m, _)| m.len())
            );
            return Err(1);
        }
    }

    // 2. Same window with the SHA allowlisted (unique 8-char prefix) → pass.
    // scan() returns every marked commit; run() partitions them against the
    // allowlist, so here we assert the marked commit classifies as allowed.
    let prefix = marked[..8].to_string();
    match scan(base, 200, "HEAD", std::slice::from_ref(&prefix)) {
        Ok((found, saw_allowed))
            if saw_allowed && found.len() == 1 && is_allowlisted(&found[0].sha, &[prefix]) => {}
        other => {
            eprintln!(
                "error [1]: self-test: allowlisted run should pass cleanly, got {:?}",
                other.map(|(m, a)| (m.len(), a))
            );
            return Err(1);
        }
    }

    // 3. Clean tip only (the clean commit has no parent chain to the marker)
    //    → zero marked, loud-silence warning path.
    match scan(base, 200, &clean, &[]) {
        Ok((m, _)) if m.is_empty() => {}
        other => {
            eprintln!(
                "error [1]: self-test: clean window should have zero marked commits, got {:?}",
                other.map(|(m, _)| m.len())
            );
            return Err(1);
        }
    }
    println!("self-test: PASS (fail-on-marker / pass-with-allowlist / clean-pass)");
    Ok(())
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(sha: &str, subject: &str, body: &str) -> CommitRecord {
        CommitRecord {
            sha: sha.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn marked_requires_both_marker_halves() {
        let full = rec(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "wip",
            &format!("{MARKER_A}\n{MARKER_B}\n"),
        );
        assert!(is_marked(&full));
        let only_a = rec(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "wip",
            &format!("{MARKER_A}\n"),
        );
        assert!(!is_marked(&only_a));
        let only_b = rec(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "wip",
            &format!("{MARKER_B}\n"),
        );
        assert!(!is_marked(&only_b));
        assert!(!is_marked(&rec(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "clean",
            "plain message"
        )));
    }

    #[test]
    fn allowlist_matches_full_sha_and_unique_prefix() {
        assert!(is_allowlisted(
            "5757e55c60a9e802b4b83f4d837ae462da3ab67b",
            &[]
        ));
        assert!(is_allowlisted(
            "5757E55C60A9E802B4B83F4D837AE462DA3AB67B",
            &[]
        ));
        assert!(is_allowlisted("5757e55c", &[]));
        assert!(!is_allowlisted("5757e55", &[])); // < 8 chars: ambiguous
        assert!(!is_allowlisted(
            "5757e55c60a9e802b4b83f4d837ae462da3ab67c",
            &[]
        ));
        let extra = vec!["1234567890abcdef".to_string()];
        assert!(is_allowlisted(
            "1234567890abcdef000000000000000000000000",
            &extra
        ));
        assert!(!is_allowlisted("1234567", &extra));
    }

    #[test]
    fn parse_log_splits_records() {
        let fmt_out = format!(
            "1111{FIELD_SEP}subj one{FIELD_SEP}body one{RECORD_SEP}2222{FIELD_SEP}subj two{FIELD_SEP}body two{RECORD_SEP}"
        );
        let parsed = parse_log(&fmt_out);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sha, "1111");
        assert_eq!(parsed[1].subject, "subj two");
        assert_eq!(parsed[1].body, "body two");
    }

    #[test]
    fn all_const_allowlist_entries_are_full_hex() {
        for a in ALLOWLIST {
            assert_eq!(a.sha.len(), 40, "entry {} not full SHA", a.sha);
            assert!(a.sha.chars().all(|c| c.is_ascii_hexdigit()));
            // The const table must self-match (guards against typos).
            assert!(is_allowlisted(a.sha, &[]));
        }
    }
}

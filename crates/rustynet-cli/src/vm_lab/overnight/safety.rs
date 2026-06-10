//! Safety envelope for unattended operation: branch isolation, the
//! security-sensitive crate denylist, and the clean-tree revert command. See
//! proposal §10.
//!
//! Everything here is pure (no process execution) so it is fully unit-tested;
//! the executor (`executor.rs`) is the only place these argv vectors are
//! actually run.

/// Crates whose code is security-sensitive enough that an agent's diff must not
/// be auto-committed without an independent adversarial review (proposal
/// §10.2). Matched as a path segment `crates/<name>/`.
pub const DENYLISTED_CRATES: &[&str] = &[
    "rustynet-policy",         // policy / default-deny evaluation
    "rustynet-control",        // trust state, membership, signed bundles, role presets
    "rustynet-crypto",         // cryptographic primitives
    "rustynet-local-security", // key custody / OS-secure storage
    "rustynet-dns-zone",       // DNS fail-closed trust surface
];

/// Path fragments that are security-sensitive wherever they appear (defence in
/// depth on top of the crate denylist).
pub const DENYLISTED_PATH_FRAGMENTS: &[&str] = &[
    "key_custody",
    "keychain",
    "signing",
    "signature",
    "secret",
    "killswitch",
];

/// Result of classifying an agent's touched paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffSafety {
    /// No security-sensitive path touched — may auto-commit on green.
    Safe,
    /// Touched a denylisted crate/path — requires adversarial review before commit.
    NeedsAdversarialReview { reasons: Vec<String> },
}

impl DiffSafety {
    pub fn is_safe(&self) -> bool {
        matches!(self, DiffSafety::Safe)
    }
}

/// Is a single repo-relative path security-sensitive?
pub fn is_denylisted_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    for crate_name in DENYLISTED_CRATES {
        if normalized.contains(&format!("crates/{crate_name}/")) {
            return true;
        }
    }
    let lower = normalized.to_ascii_lowercase();
    DENYLISTED_PATH_FRAGMENTS
        .iter()
        .any(|frag| lower.contains(frag))
}

/// Classify the set of paths an agent touched. Fail-closed: an empty/unknown
/// path set is treated as needing review, because "we could not determine what
/// changed" must not silently auto-commit (proposal §10, CLAUDE.md §10.1).
pub fn classify_touched_paths(paths: &[String]) -> DiffSafety {
    if paths.is_empty() {
        return DiffSafety::NeedsAdversarialReview {
            reasons: vec![
                "no touched-path information available — failing closed to review".to_owned(),
            ],
        };
    }
    let mut reasons = Vec::new();
    for path in paths {
        if is_denylisted_path(path) {
            reasons.push(format!("security-sensitive path: {path}"));
        }
    }
    if reasons.is_empty() {
        DiffSafety::Safe
    } else {
        DiffSafety::NeedsAdversarialReview { reasons }
    }
}

/// Reject running on a branch that must never receive unattended commits.
/// Fail-closed: anything that looks like the trunk is refused.
pub fn assert_safe_target_branch(branch: &str) -> Result<(), String> {
    let trimmed = branch.trim();
    if trimmed.is_empty() {
        return Err("refusing to run on an empty branch name".to_owned());
    }
    const FORBIDDEN: &[&str] = &["main", "master", "release", "production", "prod"];
    if FORBIDDEN.iter().any(|b| trimmed.eq_ignore_ascii_case(b)) {
        return Err(format!(
            "refusing to run unattended on protected branch '{trimmed}'; \
             use an isolated overnight branch"
        ));
    }
    Ok(())
}

/// Deterministic isolated branch name for a run.
pub fn overnight_branch_name(prefix: &str, date: &str, run_id: &str) -> String {
    let prefix = if prefix.is_empty() {
        "overnight"
    } else {
        prefix
    };
    format!("{prefix}/{date}_{run_id}")
}

/// The revert sequence that guarantees a clean tree before the next work-unit.
/// Stronger than `git checkout -- .`: `git clean -fd` also removes any
/// untracked files a bad attempt created (proposal §10.3). Returned as argv
/// vectors (argv-only exec — no shell string construction).
pub fn revert_to_clean_argv(unit_base_rev: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "git".to_owned(),
            "reset".to_owned(),
            "--hard".to_owned(),
            unit_base_rev.to_owned(),
        ],
        vec!["git".to_owned(), "clean".to_owned(), "-fd".to_owned()],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_protected_branches() {
        for b in [
            "main",
            "master",
            "MAIN",
            "release",
            "production",
            "prod",
            " main ",
        ] {
            assert!(
                assert_safe_target_branch(b).is_err(),
                "branch {b:?} must be refused"
            );
        }
    }

    #[test]
    fn refuses_empty_branch() {
        assert!(assert_safe_target_branch("").is_err());
        assert!(assert_safe_target_branch("   ").is_err());
    }

    #[test]
    fn accepts_overnight_branch() {
        assert!(assert_safe_target_branch("overnight/2026-06-09_a1b2c3").is_ok());
    }

    #[test]
    fn branch_name_is_deterministic() {
        assert_eq!(
            overnight_branch_name("overnight", "2026-06-09", "a1b2"),
            "overnight/2026-06-09_a1b2"
        );
        assert_eq!(
            overnight_branch_name("", "2026-06-09", "a1b2"),
            "overnight/2026-06-09_a1b2"
        );
    }

    #[test]
    fn denylisted_crate_paths_flagged() {
        for p in [
            "crates/rustynet-policy/src/lib.rs",
            "crates/rustynet-control/src/membership.rs",
            "crates/rustynet-crypto/src/sign.rs",
            "crates/rustynet-local-security/src/keystore.rs",
            "crates/rustynet-dns-zone/src/lib.rs",
        ] {
            assert!(is_denylisted_path(p), "{p} should be denylisted");
        }
    }

    #[test]
    fn denylisted_fragments_flagged_anywhere() {
        assert!(is_denylisted_path(
            "crates/rustynet-cli/src/key_custody_helper.rs"
        ));
        assert!(is_denylisted_path("crates/rustynet-cli/src/foo/signing.rs"));
        assert!(is_denylisted_path(
            "crates/rustynet-backend-wireguard/src/killswitch.rs"
        ));
    }

    #[test]
    fn non_security_paths_are_safe() {
        assert!(!is_denylisted_path(
            "crates/rustynet-cli/src/vm_lab/overnight/backlog.rs"
        ));
        assert!(!is_denylisted_path("crates/rustynet-relay/src/health.rs"));
    }

    #[test]
    fn classify_safe_when_only_non_security_paths() {
        let paths = vec![
            "crates/rustynet-cli/src/vm_lab/overnight/mod.rs".to_owned(),
            "crates/rustynet-relay/src/lib.rs".to_owned(),
        ];
        assert_eq!(classify_touched_paths(&paths), DiffSafety::Safe);
    }

    #[test]
    fn classify_needs_review_when_any_security_path() {
        let paths = vec![
            "crates/rustynet-cli/src/main.rs".to_owned(),
            "crates/rustynet-policy/src/eval.rs".to_owned(),
        ];
        let safety = classify_touched_paths(&paths);
        assert!(!safety.is_safe());
        match safety {
            DiffSafety::NeedsAdversarialReview { reasons } => {
                assert!(reasons.iter().any(|r| r.contains("rustynet-policy")));
            }
            DiffSafety::Safe => panic!("expected review"),
        }
    }

    #[test]
    fn classify_fails_closed_on_empty_paths() {
        // No information about what changed must NOT auto-commit.
        assert!(!classify_touched_paths(&[]).is_safe());
    }

    #[test]
    fn revert_argv_uses_reset_hard_and_clean() {
        let argv = revert_to_clean_argv("abc123");
        assert_eq!(argv.len(), 2);
        assert_eq!(argv[0], vec!["git", "reset", "--hard", "abc123"]);
        assert_eq!(argv[1], vec!["git", "clean", "-fd"]);
    }
}

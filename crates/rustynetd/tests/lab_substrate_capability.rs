// AQ-08 step 3 finish: test-only code is exempt from the crate-wide
// panic-family deny table (crates/rustynetd/Cargo.toml [lints.clippy]),
// the steps 1-2 pattern.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
//! AQ-256: `rustynetd lab-substrate-capability`, the lab tool's probe for a
//! guest daemon built with the LAB-ONLY `lab-substrate` feature.
//!
//! Contract with the rustynet-cli lane: a `lab-substrate` build prints exactly
//! `lab-substrate=yes` and exits 0, without reading the attestation, touching
//! nft or needing root; any other build does not know the subcommand, which
//! the lab tool reads as "capability missing". This runs the real binary in
//! both feature modes (`cargo test -p rustynetd` and `--all-features`).

use std::process::Command;

#[test]
fn lab_substrate_capability_subcommand_matches_the_build() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustynetd"))
        .arg("lab-substrate-capability")
        .output()
        .expect("rustynetd binary should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if cfg!(all(target_os = "linux", feature = "lab-substrate")) {
        assert!(
            output.status.success(),
            "a lab-substrate build must answer the probe: {output:?}"
        );
        assert_eq!(stdout, "lab-substrate=yes\n");
    } else {
        assert!(
            !output.status.success(),
            "a default build must not know the subcommand: {output:?}"
        );
        assert!(
            !stdout.contains("lab-substrate=yes"),
            "a default build must never claim the capability: {stdout}"
        );
    }
}

#[test]
fn lab_substrate_capability_takes_no_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustynetd"))
        .args(["lab-substrate-capability", "--verbose"])
        .output()
        .expect("rustynetd binary should run");
    assert!(!output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("lab-substrate=yes"));
}

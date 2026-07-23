#![forbid(unsafe_code)]
#![cfg(feature = "vm-lab")]
//! CLI shell for the §4.8 independent evidence verifier (increment A2).
//!
//! Recomputes a `--node` live-lab run's §4.1/§4.2/§4.5/§4.6 evidence
//! properties from the RAW report_dir artifacts and cross-checks the run's
//! ledger row — never trusting the orchestrator's self-reported verdict. All
//! logic lives in `rustynet_cli::live_lab_evidence_verifier`; this binary
//! only parses arguments, prints the report, and maps it to the exit-code
//! contract. Gated behind the default-off `vm-lab` feature both here
//! (whole-file `cfg`) and in `Cargo.toml` (`required-features = ["vm-lab"]`
//! on its `[[bin]]` entry — the mechanism that actually keeps
//! `cargo check -p rustynet-cli` (no features) from building this target;
//! a cfg'd-out binary crate still needs a `fn main`).
//!
//! Exit codes: 0 = valid pass; 2 = valid evidence, verdict not pass;
//! 1 = INVALID (a §4 property is violated); 3 = usage / verifier error.

use std::path::PathBuf;
use std::process::ExitCode;

use rustynet_cli::live_lab_evidence_verifier::{
    VerifierConfig, exit_code, render_human, render_json, verify,
};

const USAGE: &str =
    "usage: live_lab_evidence_verifier --report-dir <path> [--matrix <path>] [--json]

Independent §4.8 evidence verifier for --node live-lab runs. Recomputes
§4.1 (manifest completeness), §4.2 (terminal-state taxonomy / verdict),
§4.5 (digest-bound manifest <-> CSV row <-> report_dir cross-check) and
§4.6 (marker-last finalizer) from the raw report artifacts.

  --report-dir <path>  the run's report directory (required)
  --matrix <path>      node run-matrix ledger to cross-check
                       (default: documents/operations/live_lab_node_run_matrix.csv)
  --json               print the structured JSON verdict instead of the
                       human summary

exit codes: 0 valid pass; 2 valid but not a pass; 1 INVALID; 3 error";

fn parse_args() -> Result<(VerifierConfig, bool), String> {
    let mut report_dir: Option<PathBuf> = None;
    let mut matrix_path: Option<PathBuf> = None;
    let mut json = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--report-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--report-dir requires a path".to_owned())?;
                report_dir = Some(PathBuf::from(value));
            }
            "--matrix" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--matrix requires a path".to_owned())?;
                matrix_path = Some(PathBuf::from(value));
            }
            "--json" => json = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let report_dir = report_dir.ok_or_else(|| "--report-dir is required".to_owned())?;
    Ok((
        VerifierConfig {
            report_dir,
            matrix_path,
        },
        json,
    ))
}

fn main() -> ExitCode {
    let (config, json) = match parse_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("live_lab_evidence_verifier: {err}\n\n{USAGE}");
            return ExitCode::from(3);
        }
    };
    match verify(&config) {
        Ok(report) => {
            if json {
                println!("{}", render_json(&report));
            } else {
                print!("{}", render_human(&report));
            }
            ExitCode::from(u8::try_from(exit_code(&report)).unwrap_or(1))
        }
        Err(err) => {
            eprintln!("live_lab_evidence_verifier: {err}");
            ExitCode::from(3)
        }
    }
}

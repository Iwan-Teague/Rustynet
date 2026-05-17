#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::process::{Command, ExitStatus};

const PHASE6_PLATFORM_READINESS_ARGS: &[&str] = &[
    "run",
    "--quiet",
    "-p",
    "rustynet-cli",
    "--",
    "ops",
    "verify-phase6-platform-readiness",
];

const PHASE6_PARITY_EVIDENCE_ARGS: &[&str] = &[
    "run",
    "--quiet",
    "-p",
    "rustynet-cli",
    "--",
    "ops",
    "verify-phase6-parity-evidence",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<_> = env::args_os().skip(1).collect();

    run_cargo(PHASE6_PLATFORM_READINESS_ARGS)?;
    run_cargo(PHASE6_PARITY_EVIDENCE_ARGS)?;

    Ok(())
}

fn run_cargo(args: &[&str]) -> Result<(), i32> {
    let status = Command::new("cargo").args(args).status().map_err(|err| {
        eprintln!(
            "error [{}]: failed to run cargo: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })?;

    if status.success() {
        return Ok(());
    }

    // Pass through subprocess exit code; inner rustynet-cli already
    // classifies parity / readiness failures via the X6 taxonomy.
    Err(exit_code(status))
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(ExitCode::GenericFailure.as_i32())
}

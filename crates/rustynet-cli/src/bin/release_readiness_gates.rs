#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/ReleaseReadinessGuardrails.md",
    "documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md",
    "documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md",
];

const REQUIRED_ARTIFACTS: &[&str] = &["artifacts/release/phase5_readiness_bundle.json"];

const REQUIRED_SCRIPTS: &[&str] = &["scripts/ci/phase5_gates.sh", "scripts/ci/phase10_gates.sh"];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    for script in REQUIRED_SCRIPTS {
        require_file(&root_dir.join(script), "required gate script")?;
    }

    run_script(&root_dir, "scripts/ci/phase5_gates.sh", &[])?;
    run_script(&root_dir, "scripts/ci/phase10_gates.sh", &[])?;

    for required_doc in REQUIRED_DOCS {
        require_file(&root_dir.join(required_doc), "required readiness document")?;
    }
    for required_artifact in REQUIRED_ARTIFACTS {
        require_file(
            &root_dir.join(required_artifact),
            "required readiness bundle artifact",
        )?;
    }

    println!("Release readiness gates: PASS");
    Ok(())
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), i32> {
    let status = Command::new(root_dir.join(script))
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!(
                "failed to execute script {}: {err}",
                root_dir.join(script).display()
            );
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn require_file(path: &Path, label: &str) -> Result<(), i32> {
    if path.is_file() {
        Ok(())
    } else {
        eprintln!("missing {label}: {}", path.display());
        Err(1)
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_ARTIFACTS, REQUIRED_DOCS, REQUIRED_SCRIPTS};

    #[test]
    fn required_readiness_docs_are_non_empty() {
        assert!(!REQUIRED_DOCS.is_empty());
        assert!(REQUIRED_DOCS.iter().all(|path| !path.is_empty()));
    }

    #[test]
    fn required_readiness_artifacts_are_non_empty() {
        assert!(!REQUIRED_ARTIFACTS.is_empty());
        assert!(REQUIRED_ARTIFACTS.iter().all(|path| !path.is_empty()));
    }

    #[test]
    fn required_gate_scripts_are_non_empty() {
        assert!(!REQUIRED_SCRIPTS.is_empty());
        assert!(REQUIRED_SCRIPTS.iter().all(|path| !path.is_empty()));
    }
}

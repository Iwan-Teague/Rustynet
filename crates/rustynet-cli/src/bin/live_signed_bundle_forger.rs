#![forbid(unsafe_code)]

mod live_chaos_support;
mod live_signed_state_chaos;

use std::path::PathBuf;

use live_chaos_support::{repo_root, unix_now};
use live_signed_state_chaos::{generate_manifest, scenario_names, write_manifest};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = repo_root()?;
    let mut output_dir = root.join("artifacts/phase10/chaos_forger");
    let mut scenario = "all".to_owned();
    let mut idx = 1usize;
    let args = std::env::args().collect::<Vec<_>>();
    while idx < args.len() {
        match args[idx].as_str() {
            "--output-dir" => {
                idx += 1;
                output_dir = PathBuf::from(required_value(&args, idx, "--output-dir")?);
            }
            "--scenario" => {
                idx += 1;
                scenario = required_value(&args, idx, "--scenario")?;
            }
            "--list-scenarios" => {
                for name in scenario_names() {
                    println!("{name}");
                }
                return Ok(());
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                print_usage();
                return Err(format!("unknown argument: {other}"));
            }
        }
        idx += 1;
    }

    let manifest = generate_manifest(&output_dir, &scenario, unix_now())?;
    let manifest_path = write_manifest(&output_dir, &manifest)?;
    println!("{}", manifest_path.display());
    Ok(())
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: live_signed_bundle_forger --output-dir <path> [--scenario all|{}]",
        scenario_names().join("|")
    );
}

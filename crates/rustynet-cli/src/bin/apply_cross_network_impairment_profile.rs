#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, ExitStatus, Stdio};

const DEFAULT_PROFILE: &str = "none";
const DEFAULT_INTERFACE: &str = "rustynet0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Apply,
    Clear,
    Status,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let mut mode: Option<Mode> = None;
    let mut profile = DEFAULT_PROFILE.to_string();
    let mut interface = DEFAULT_INTERFACE.to_string();

    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--mode" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| print_usage_error("--mode requires a value"))?;
                mode = Some(parse_mode(value)?);
                index += 2;
            }
            "--profile" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| print_usage_error("--profile requires a value"))?;
                if !profile_supported(value) {
                    eprintln!("unsupported impairment profile: {value}");
                    return Err(2);
                }
                profile = value.clone();
                index += 2;
            }
            "--interface" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| print_usage_error("--interface requires a value"))?;
                if !valid_interface(value) {
                    eprintln!("invalid interface: {value}");
                    return Err(2);
                }
                interface = value.clone();
                index += 2;
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            unknown => {
                eprintln!("unknown argument: {unknown}");
                print_usage();
                return Err(2);
            }
        }
    }

    let mode = mode.ok_or_else(|| {
        eprintln!("--mode is required");
        2
    })?;

    require_command("ip")?;
    require_command("tc")?;
    ensure_interface_exists(&interface)?;

    match mode {
        Mode::Apply => apply_profile(&interface, &profile),
        Mode::Clear => clear_profile(&interface),
        Mode::Status => show_status(&interface),
    }
}

fn parse_mode(value: &str) -> Result<Mode, i32> {
    match value {
        "apply" => Ok(Mode::Apply),
        "clear" => Ok(Mode::Clear),
        "status" => Ok(Mode::Status),
        other => {
            eprintln!("unsupported mode: {other}");
            Err(2)
        }
    }
}

fn print_usage_error(message: &str) -> i32 {
    eprintln!("{message}");
    print_usage();
    2
}

fn print_usage() {
    println!(
        "usage: apply_cross_network_impairment_profile.sh --mode <apply|clear|status> [options]"
    );
    println!();
    println!("options:");
    println!("  --mode <mode>           apply | clear | status");
    println!(
        "  --profile <profile>     none | latency_50ms_loss_1pct | latency_120ms_loss_3pct | loss_5pct (default: none)"
    );
    println!("  --interface <iface>     network interface (default: rustynet0)");
    println!("  -h, --help              show help");
}

fn profile_supported(profile: &str) -> bool {
    matches!(
        profile,
        "none" | "latency_50ms_loss_1pct" | "latency_120ms_loss_3pct" | "loss_5pct"
    )
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn require_command(command: &str) -> Result<(), i32> {
    let status = Command::new("sh")
        .args(["-c", &format!("command -v {command} >/dev/null 2>&1")])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to verify required command {command}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        eprintln!("missing required command: {command}");
        Err(1)
    }
}

fn ensure_interface_exists(interface: &str) -> Result<(), i32> {
    let status = Command::new("ip")
        .args(["link", "show", interface])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to inspect interface {interface}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        eprintln!("interface does not exist: {interface}");
        Err(1)
    }
}

fn clear_profile(interface: &str) -> Result<(), i32> {
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "root"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

fn show_status(interface: &str) -> Result<(), i32> {
    let status = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to query qdisc status: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn apply_profile(interface: &str, profile: &str) -> Result<(), i32> {
    if profile == "none" {
        return clear_profile(interface);
    }
    let root_qdisc = current_root_qdisc(interface)?;
    if let Some(existing) = root_qdisc
        && existing != "noqueue"
        && existing != "netem"
    {
        eprintln!("refusing to overwrite existing root qdisc on {interface}: {existing}");
        return Err(1);
    }

    let args: Vec<&str> = match profile {
        "latency_50ms_loss_1pct" => vec![
            "qdisc", "replace", "dev", interface, "root", "netem", "delay", "50ms", "5ms", "loss",
            "1%",
        ],
        "latency_120ms_loss_3pct" => vec![
            "qdisc", "replace", "dev", interface, "root", "netem", "delay", "120ms", "15ms",
            "loss", "3%",
        ],
        "loss_5pct" => vec![
            "qdisc", "replace", "dev", interface, "root", "netem", "loss", "5%",
        ],
        _ => {
            eprintln!("unsupported impairment profile: {profile}");
            return Err(2);
        }
    };

    let status = Command::new("tc")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to apply impairment profile: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn current_root_qdisc(interface: &str) -> Result<Option<String>, i32> {
    let output = Command::new("tc")
        .args(["qdisc", "show", "dev", interface])
        .output()
        .map_err(|err| {
            eprintln!("failed to query qdisc state for {interface}: {err}");
            1
        })?;
    if !output.status.success() {
        return Err(status_code(output.status));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first_line = text.lines().next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let _ = parts.next();
    let qdisc = parts.next().map(str::to_string);
    Ok(qdisc)
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

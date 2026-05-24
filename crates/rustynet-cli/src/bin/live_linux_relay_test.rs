#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

//! Track B Phase 3 — relay-role live-lab stage scaffold.
//!
//! Today the orchestrator has live coverage for client (implicit),
//! exit_handoff, lan_toggle, two_hop, role_switch_matrix, managed_dns,
//! and anchor. The relay role has no live-lab stage at all — only
//! unit-level coverage in `crates/rustynetd/src/relay_client.rs`
//! (51 tests) and `crates/rustynetd/src/daemon.rs::daemon_runtime_relay_*`
//! (9 tests).
//!
//! This bin lands the dispatcher + scaffold so a follow-up commit can
//! drop in the real Linux validator (install via the existing
//! `ops_install_systemd_relay` path, assert the service is active,
//! run a client-side relay-session probe, uninstall + verify cleanup
//! without leaking the systemd unit / killswitch table). macOS +
//! Windows follow in subsequent Track B phases.
//!
//! The wire surface and CLI flag set match the established
//! live-lab bin contract (see `live_linux_anchor_test`,
//! `live_linux_exit_handoff_test`).

mod live_lab_bin_support;

use std::env;
use std::path::PathBuf;

use live_lab_bin_support::{
    LiveLabPlatform, enforce_linux_only_until_validator_lands, ensure_safe_token, repo_root,
    write_file,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;

    // Track B Phase 3: non-Linux fails closed honestly until the
    // per-platform validator lands. The orchestrator dispatcher
    // routes here based on the relay host's platform. The stage
    // name + phase note are pinned via the `STAGE_NAME` /
    // `PHASE_NOTE` constants below so a per-bin unit test can
    // independently exercise the same gate and assert that
    // run()'s wiring is intact.
    enforce_linux_only_until_validator_lands(config.platform, STAGE_NAME, PHASE_NOTE)?;

    let root = repo_root()?;
    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        root.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        root.join(&config.report_path)
    };

    // Scaffold: write a structured report + log that the orchestrator
    // can consume so the stage's success criterion is reachable now.
    // The real Linux validator (install via ops_install_systemd_relay,
    // health probe via the daemon's `rustynet status` relay fields,
    // datapath probe via WireGuard handshake against the relay
    // candidate, uninstall + cleanup verification) ships in Phase 3b.
    let log_body = format!(
        "[relay-live] Track B Phase 3 scaffold — relay_host={} relay_node_id={} peer_host={} peer_node_id={}\n\
         [relay-live] real Linux validator + datapath probe pending (Phase 3b)\n\
         [relay-live] non-Linux platforms fail closed at the dispatcher gate (Phase 6/7)\n",
        config.relay_host, config.relay_node_id, config.peer_host, config.peer_node_id,
    );
    write_file(&log_path, log_body.as_str())?;

    let report_body = format!(
        "{{\
\"schema_version\":1,\
\"status\":\"scaffold\",\
\"platform\":\"{}\",\
\"relay_host\":\"{}\",\
\"relay_node_id\":\"{}\",\
\"peer_host\":\"{}\",\
\"peer_node_id\":\"{}\",\
\"phase\":\"track-b-phase-3-scaffold\",\
\"next_step\":\"phase-3b-linux-validator\"\
}}\n",
        config.platform.as_str(),
        config.relay_host,
        config.relay_node_id,
        config.peer_host,
        config.peer_node_id,
    );
    write_file(&report_path, report_body.as_str())?;

    // Surface the scaffold state to stdout so an interactive operator
    // sees the honest "Phase 3 scaffold, datapath probe pending"
    // message rather than mistaking the empty success for a real
    // validator pass.
    println!(
        "[relay-live] Track B Phase 3 scaffold complete — log={} report={}",
        log_path.display(),
        report_path.display()
    );
    println!(
        "[relay-live] real Linux datapath probe lands in Phase 3b; macOS + Windows in Phases 6 + 7"
    );

    Ok(())
}

#[derive(Debug)]
struct Config {
    platform: LiveLabPlatform,
    ssh_identity_file: PathBuf,
    relay_host: String,
    relay_node_id: String,
    peer_host: String,
    peer_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    log_path: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: LiveLabPlatform::Linux,
            ssh_identity_file: PathBuf::new(),
            relay_host: "debian@192.168.18.49".to_owned(),
            relay_node_id: "relay-49".to_owned(),
            peer_host: "debian@192.168.18.65".to_owned(),
            peer_node_id: "client-65".to_owned(),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            report_path: PathBuf::from("artifacts/phase10/live_linux_relay_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_relay.log"),
            pinned_known_hosts_file: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform =
                        LiveLabPlatform::parse(next_value(&mut iter, &arg)?.as_str())?;
                }
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--relay-host" => config.relay_host = next_value(&mut iter, &arg)?,
                "--relay-node-id" => config.relay_node_id = next_value(&mut iter, &arg)?,
                "--peer-host" => config.peer_host = next_value(&mut iter, &arg)?,
                "--peer-node-id" => config.peer_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?));
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_relay_test --ssh-identity-file <path> [options]".to_owned(),
            );
        }
        for (label, value) in [
            ("relay-host", config.relay_host.as_str()),
            ("relay-node-id", config.relay_node_id.as_str()),
            ("peer-host", config.peer_host.as_str()),
            ("peer-node-id", config.peer_node_id.as_str()),
            ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ] {
            ensure_safe_token(label, value)?;
        }
        Ok(config)
    }
}

/// Canonical stage name passed to the platform gate. Lifted to a
/// constant so the run()-side call and the test-side wiring
/// assertion both reference the same string — a future refactor
/// that drops the gate from run() (or renames the stage) would
/// surface as a compilation or test failure here.
const STAGE_NAME: &str = "relay-service-lifecycle";

/// Canonical phase note passed to the platform gate. Same
/// rationale as `STAGE_NAME` — single source of truth so the
/// run() call site and the wiring tests agree.
const PHASE_NOTE: &str =
    "the Linux validator + per-platform validators land in Track B Phase 3b/6/7";

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    println!(
        "usage: live_linux_relay_test --ssh-identity-file <path> [options]\n\
         \n\
         Track B Phase 3 scaffold for the relay-role live-lab stage.\n\
         The Linux validator (service-lifecycle + datapath probe)\n\
         lands in Phase 3b; macOS + Windows in Phases 6 + 7.\n\
         \n\
         options:\n\
         \x20\x20--platform <linux|macos|windows>      default linux; non-linux fails closed\n\
         \x20\x20--relay-host <user@host>              SSH target hosting the relay service\n\
         \x20\x20--relay-node-id <id>                  node id of the relay host in signed membership\n\
         \x20\x20--peer-host <user@host>               SSH target acting as the relay client\n\
         \x20\x20--peer-node-id <id>                   node id of the relay client\n\
         \x20\x20--ssh-allow-cidrs <cidr>              management CIDR\n\
         \x20\x20--report-path <path>                  JSON report output\n\
         \x20\x20--log-path <path>                     human-readable log output\n\
         \x20\x20--known-hosts <path>                  pinned SSH known_hosts (else $HOME default)"
    );
}

#[cfg(test)]
mod tests {
    use super::Config;
    use super::live_lab_bin_support::LiveLabPlatform;

    fn base_args() -> Vec<String> {
        vec!["--ssh-identity-file".to_owned(), "/tmp/id".to_owned()]
    }

    #[test]
    fn config_parse_defaults_to_linux_for_backward_compat() {
        let config = Config::parse(base_args()).expect("default parse");
        assert_eq!(config.platform, LiveLabPlatform::Linux);
        assert_eq!(config.relay_host, "debian@192.168.18.49");
    }

    #[test]
    fn config_parse_accepts_explicit_platform() {
        let mut args = base_args();
        args.push("--platform".to_owned());
        args.push("macos".to_owned());
        let config = Config::parse(args).expect("macos parse");
        assert_eq!(config.platform, LiveLabPlatform::MacOs);
    }

    #[test]
    fn config_parse_rejects_unknown_argument_fail_closed() {
        let mut args = base_args();
        args.push("--bogus-flag".to_owned());
        let err = Config::parse(args).expect_err("unknown flag must fail");
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn config_parse_requires_ssh_identity_file() {
        let err = Config::parse(Vec::new()).expect_err("missing identity must fail");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn config_parse_rejects_unsafe_token_in_relay_host() {
        let mut args = base_args();
        args.push("--relay-host".to_owned());
        args.push("debian@host;rm -rf /".to_owned());
        let err = Config::parse(args).expect_err("shell metacharacters must fail closed");
        assert!(err.contains("unsupported characters"));
    }

    // Phase 2 reviewer finding #5 — defense-in-depth. The platform
    // gate inside `run()` references shared constants (`STAGE_NAME`
    // and `PHASE_NOTE`). The tests below exercise the same helper
    // with the same constants so a future refactor that silently
    // drops the gate from `run()` would still leave the stage name
    // unused (`STAGE_NAME` would become dead code) — surfacing as a
    // compile or clippy failure.

    #[test]
    fn platform_gate_passes_for_linux() {
        super::enforce_linux_only_until_validator_lands(
            LiveLabPlatform::Linux,
            super::STAGE_NAME,
            super::PHASE_NOTE,
        )
        .expect("Linux must always pass the gate");
    }

    #[test]
    fn platform_gate_fails_closed_for_macos_and_windows_with_relay_stage_name() {
        for (platform, name) in [
            (LiveLabPlatform::MacOs, "macOS"),
            (LiveLabPlatform::Windows, "Windows"),
        ] {
            let err = super::enforce_linux_only_until_validator_lands(
                platform,
                super::STAGE_NAME,
                super::PHASE_NOTE,
            )
            .expect_err("non-linux must fail closed");
            assert!(err.contains(name), "error must name the platform: {err}");
            assert!(
                err.contains(super::STAGE_NAME),
                "error must include the relay stage name so audit logs are unambiguous: {err}"
            );
            assert!(
                err.contains("Phase 3b/6/7"),
                "error must include the phase note: {err}"
            );
        }
    }
}

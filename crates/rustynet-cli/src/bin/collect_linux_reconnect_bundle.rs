#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_WG_INTERFACE: &str = "rustynet0";
const DEFAULT_JOURNAL_LINES: usize = 120;
const DEFAULT_ROUTE_TABLE: &str = "51820";
const DEFAULT_OUTPUT_PREFIX: &str = "rustynet-linux-reconnect-bundle";

const RUSTYNETD_ENV_PATH: &str = "/etc/default/rustynetd";
const ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";

const STATE_PATHS: &[&str] = &[
    "/var/lib/rustynet/rustynetd.assignment",
    "/var/lib/rustynet/rustynetd.assignment.watermark",
    "/var/lib/rustynet/rustynetd.traversal",
    "/var/lib/rustynet/rustynetd.traversal.watermark",
    "/var/lib/rustynet/rustynetd.trust",
    "/var/lib/rustynet/rustynetd.trust.watermark",
    "/var/lib/rustynet/rustynetd.dns-zone",
    "/var/lib/rustynet/rustynetd.dns-zone.watermark",
];

const RUSTYNETD_ALLOWED_KEYS: &[&str] = &[
    "RUSTYNET_NODE_ID",
    "RUSTYNET_NODE_ROLE",
    "RUSTYNET_WG_INTERFACE",
    "RUSTYNET_WG_LISTEN_PORT",
    "RUSTYNET_EGRESS_INTERFACE",
    "RUSTYNET_AUTO_TUNNEL_ENFORCE",
    "RUSTYNET_FAIL_CLOSED_SSH_ALLOW",
    "RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS",
];

const RUSTYNETD_ALLOWED_PREFIXES: &[&str] =
    &["RUSTYNET_TRAVERSAL_", "RUSTYNET_RELAY_", "RUSTYNET_DNS_"];

const ASSIGNMENT_REFRESH_ALLOWED_KEYS: &[&str] = &[
    "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID",
    "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID",
    "RUSTYNET_ASSIGNMENT_NODES",
    "RUSTYNET_ASSIGNMENT_ALLOW",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    output_path: Option<PathBuf>,
    probe_targets: Vec<String>,
    wg_interface: String,
    daemon_socket: PathBuf,
    journal_lines: usize,
    sudo_mode: SudoMode,
    quiet: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_path: None,
            probe_targets: Vec::new(),
            wg_interface: DEFAULT_WG_INTERFACE.to_string(),
            daemon_socket: PathBuf::from(DEFAULT_DAEMON_SOCKET),
            journal_lines: DEFAULT_JOURNAL_LINES,
            sudo_mode: SudoMode::Auto,
            quiet: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SudoMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseResult {
    Help,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Privilege {
    PreferRoot,
    PlainOnly,
}

#[derive(Debug)]
struct SudoContext {
    enabled: bool,
    summary: String,
}

#[derive(Debug)]
struct CommandRecord {
    command_display: String,
    exit_code: Option<i32>,
    output: String,
    ran_with_sudo: bool,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let mut config = Config::default();
    let parse_result = parse_args_from(env::args_os(), &mut config).map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        eprintln!("{}", usage());
        1
    })?;
    if parse_result == ParseResult::Help {
        print!("{}", usage());
        return Ok(());
    }

    ensure_linux().map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        1
    })?;

    let repo_root = repo_root().map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        1
    })?;

    let collected_at_utc = collect_utc_timestamp().map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        1
    })?;
    let collected_at_unix = collect_unix_timestamp().map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        1
    })?;

    let output_path = config
        .output_path
        .clone()
        .unwrap_or_else(|| default_output_path(&collected_at_utc));
    let sudo = SudoContext::prepare(config.sudo_mode).map_err(|err| {
        eprintln!("[collect-reconnect] ERROR: {err}");
        1
    })?;

    log(config.quiet, "Collecting Linux reconnect bundle...");
    let report = build_report(
        &config,
        &repo_root,
        &sudo,
        &collected_at_utc,
        collected_at_unix,
    );

    write_private_file(&output_path, report.as_bytes()).map_err(|err| {
        eprintln!(
            "[collect-reconnect] ERROR: failed to write {}: {err}",
            output_path.display()
        );
        1
    })?;

    println!("{}", output_path.display());
    Ok(())
}

fn ensure_linux() -> Result<(), String> {
    if env::consts::OS == "linux" {
        Ok(())
    } else {
        Err("this collector only supports Linux hosts".to_string())
    }
}

fn parse_args_from<I, T>(args: I, config: &mut Config) -> Result<ParseResult, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    while let Some(arg) = iter.next() {
        let arg = arg.to_string_lossy();
        match arg.as_ref() {
            "--help" | "-h" => return Ok(ParseResult::Help),
            "--output" => {
                let value = next_value(&mut iter, "--output")?;
                config.output_path = Some(PathBuf::from(value));
            }
            "--probe-target" => {
                config
                    .probe_targets
                    .push(next_value(&mut iter, "--probe-target")?);
            }
            "--wg-interface" => {
                config.wg_interface = next_value(&mut iter, "--wg-interface")?;
            }
            "--daemon-socket" => {
                config.daemon_socket = PathBuf::from(next_value(&mut iter, "--daemon-socket")?);
            }
            "--journal-lines" => {
                let value = next_value(&mut iter, "--journal-lines")?;
                config.journal_lines = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --journal-lines value: {value}"))?;
                if config.journal_lines == 0 {
                    return Err("--journal-lines must be greater than zero".to_string());
                }
            }
            "--sudo" => {
                config.sudo_mode = parse_sudo_mode(&next_value(&mut iter, "--sudo")?)?;
            }
            "--quiet" => config.quiet = true,
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    Ok(ParseResult::Config)
}

fn next_value<I>(iter: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    iter.next()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_sudo_mode(value: &str) -> Result<SudoMode, String> {
    match value {
        "auto" => Ok(SudoMode::Auto),
        "always" => Ok(SudoMode::Always),
        "never" => Ok(SudoMode::Never),
        _ => Err(format!(
            "invalid --sudo value: {value} (expected auto|always|never)"
        )),
    }
}

impl SudoContext {
    fn prepare(mode: SudoMode) -> Result<Self, String> {
        match mode {
            SudoMode::Never => Ok(Self {
                enabled: false,
                summary: "sudo disabled by operator request".to_string(),
            }),
            SudoMode::Auto | SudoMode::Always => {
                if !command_exists("sudo") {
                    if mode == SudoMode::Always {
                        return Err(
                            "sudo is not available but --sudo=always was requested".to_string()
                        );
                    }
                    return Ok(Self {
                        enabled: false,
                        summary: "sudo not available; privileged probes will run unprivileged"
                            .to_string(),
                    });
                }

                let validation = if io::stdin().is_terminal() {
                    Command::new("sudo").arg("-v").status()
                } else {
                    Command::new("sudo").args(["-n", "true"]).status()
                };

                match validation {
                    Ok(status) if status.success() => Ok(Self {
                        enabled: true,
                        summary: "sudo available; privileged probes enabled".to_string(),
                    }),
                    Ok(status) => {
                        if mode == SudoMode::Always {
                            Err(format!(
                                "sudo validation failed with exit code {}",
                                status_code(status)
                            ))
                        } else {
                            Ok(Self {
                                enabled: false,
                                summary: format!(
                                    "sudo validation failed with exit code {}; privileged probes will run unprivileged",
                                    status_code(status)
                                ),
                            })
                        }
                    }
                    Err(err) => {
                        if mode == SudoMode::Always {
                            Err(format!("failed to validate sudo access: {err}"))
                        } else {
                            Ok(Self {
                                enabled: false,
                                summary: format!(
                                    "failed to validate sudo access ({err}); privileged probes will run unprivileged"
                                ),
                            })
                        }
                    }
                }
            }
        }
    }
}

fn build_report(
    config: &Config,
    repo_root: &Path,
    sudo: &SudoContext,
    collected_at_utc: &str,
    collected_at_unix: u64,
) -> String {
    let mut report = String::new();
    writeln!(report, "# RustyNet Linux Reconnect Bundle").unwrap();
    writeln!(report).unwrap();
    writeln!(report, "- captured_at_utc: {collected_at_utc}").unwrap();
    writeln!(report, "- captured_at_unix: {collected_at_unix}").unwrap();
    writeln!(
        report,
        "- daemon_socket: {}",
        config.daemon_socket.display()
    )
    .unwrap();
    writeln!(report, "- wireguard_interface: {}", config.wg_interface).unwrap();
    writeln!(report, "- route_table: {DEFAULT_ROUTE_TABLE}").unwrap();
    writeln!(report, "- privileged_coverage: {}", sudo.summary).unwrap();
    writeln!(report).unwrap();
    writeln!(
        report,
        "This bundle intentionally excludes private keys, passphrase files, and signing secrets."
    )
    .unwrap();

    let host_identity = run_first_success(
        &[
            CommandSpec::plain("hostnamectl status", "hostnamectl", &["status"]),
            CommandSpec::plain("hostname", "hostname", &[]),
        ],
        sudo,
    );
    append_command_section(&mut report, "Host Identity", &host_identity);

    append_command_section(
        &mut report,
        "IPv4 Addressing",
        &run_command(
            CommandSpec::plain("ip -4 addr show", "ip", &["-4", "addr", "show"]),
            sudo,
        ),
    );
    let routes = run_command(CommandSpec::plain("ip route", "ip", &["route"]), sudo);
    append_command_section(&mut report, "Routes", &routes);
    append_command_section(
        &mut report,
        "Routing Rules",
        &run_command(
            CommandSpec::plain("ip rule show", "ip", &["rule", "show"]),
            sudo,
        ),
    );
    let route_table = run_command(
        CommandSpec::plain(
            "ip route show table 51820",
            "ip",
            &["route", "show", "table", DEFAULT_ROUTE_TABLE],
        ),
        sudo,
    );
    append_command_section(&mut report, "RustyNet Route Table", &route_table);

    let listeners = run_command(
        CommandSpec::prefer_root("ss -ltnup", "ss", &["-ltnup"]),
        sudo,
    );
    append_filtered_command_section(
        &mut report,
        "Relevant Listeners",
        &listeners,
        filter_listener_lines,
    );

    let systemctl_status = run_command(
        CommandSpec::prefer_root(
            "systemctl status rustynetd --no-pager -l",
            "systemctl",
            &["status", "rustynetd", "--no-pager", "-l"],
        ),
        sudo,
    );
    append_command_section(&mut report, "rustynetd Service Status", &systemctl_status);

    let rustynet_status = run_rustynet_command(
        repo_root,
        &config.daemon_socket,
        "status",
        &[],
        "cargo run --quiet -p rustynet-cli --bin rustynet-cli -- status",
    );
    append_command_section(&mut report, "RustyNet Status", &rustynet_status);

    let rustynet_netcheck = run_rustynet_command(
        repo_root,
        &config.daemon_socket,
        "netcheck",
        &[],
        "cargo run --quiet -p rustynet-cli --bin rustynet-cli -- netcheck",
    );
    append_command_section(&mut report, "RustyNet Netcheck", &rustynet_netcheck);

    let wg_endpoints = run_command(
        CommandSpec::prefer_root(
            &format!("wg show {} endpoints", config.wg_interface),
            "wg",
            &["show", &config.wg_interface, "endpoints"],
        ),
        sudo,
    );
    append_command_section(&mut report, "WireGuard Endpoints", &wg_endpoints);
    let wg_allowed_ips = run_command(
        CommandSpec::prefer_root(
            &format!("wg show {} allowed-ips", config.wg_interface),
            "wg",
            &["show", &config.wg_interface, "allowed-ips"],
        ),
        sudo,
    );
    append_command_section(&mut report, "WireGuard Allowed IPs", &wg_allowed_ips);
    append_command_section(
        &mut report,
        "WireGuard Latest Handshakes",
        &run_command(
            CommandSpec::prefer_root(
                &format!("wg show {} latest-handshakes", config.wg_interface),
                "wg",
                &["show", &config.wg_interface, "latest-handshakes"],
            ),
            sudo,
        ),
    );

    let rustynetd_env = run_command(
        CommandSpec::prefer_root(
            &format!("cat {RUSTYNETD_ENV_PATH}"),
            "cat",
            &[RUSTYNETD_ENV_PATH],
        ),
        sudo,
    );
    append_filtered_env_section(
        &mut report,
        "rustynetd Environment Subset",
        &rustynetd_env,
        RUSTYNETD_ALLOWED_KEYS,
        RUSTYNETD_ALLOWED_PREFIXES,
    );

    let assignment_env = run_command(
        CommandSpec::prefer_root(
            &format!("cat {ASSIGNMENT_REFRESH_ENV_PATH}"),
            "cat",
            &[ASSIGNMENT_REFRESH_ENV_PATH],
        ),
        sudo,
    );
    append_filtered_env_section(
        &mut report,
        "Assignment Refresh Environment Subset",
        &assignment_env,
        ASSIGNMENT_REFRESH_ALLOWED_KEYS,
        &[],
    );

    append_command_section(
        &mut report,
        "State File mtimes",
        &run_command(
            CommandSpec {
                display: "stat -c %n size=%s mtime=%y <state_paths>".to_string(),
                program: "stat".to_string(),
                args: build_stat_args(),
                current_dir: None,
                env: Vec::new(),
                privilege: Privilege::PreferRoot,
            },
            sudo,
        ),
    );

    let nft_rules = run_command(
        CommandSpec::prefer_root("nft list ruleset", "nft", &["list", "ruleset"]),
        sudo,
    );
    append_filtered_command_section(
        &mut report,
        "Relevant nftables Rules",
        &nft_rules,
        filter_nft_lines,
    );

    let resolved_probe_targets = resolve_probe_targets(
        config,
        &routes,
        &route_table,
        &wg_endpoints,
        &wg_allowed_ips,
    );
    writeln!(
        report,
        "- probe_targets: {}",
        if resolved_probe_targets.is_empty() {
            "none".to_string()
        } else {
            resolved_probe_targets.join(", ")
        }
    )
    .unwrap();
    writeln!(report).unwrap();

    for target in &resolved_probe_targets {
        append_command_section(
            &mut report,
            &format!("Route Probe {target}"),
            &run_command(
                CommandSpec::plain(
                    &format!("ip route get {target}"),
                    "ip",
                    &["route", "get", target],
                ),
                sudo,
            ),
        );
        append_command_section(
            &mut report,
            &format!("Ping Probe {target}"),
            &run_command(
                CommandSpec::plain(
                    &format!("ping -c 2 -W 3 {target}"),
                    "ping",
                    &["-c", "2", "-W", "3", target],
                ),
                sudo,
            ),
        );
    }

    append_command_section(
        &mut report,
        "Recent rustynetd Journal",
        &run_command(
            CommandSpec::prefer_root(
                &format!(
                    "journalctl -u rustynetd -n {} --no-pager",
                    config.journal_lines
                ),
                "journalctl",
                &[
                    "-u",
                    "rustynetd",
                    "-n",
                    &config.journal_lines.to_string(),
                    "--no-pager",
                ],
            ),
            sudo,
        ),
    );

    report
}

fn build_stat_args() -> Vec<String> {
    let mut args = vec!["-c".to_string(), "%n size=%s mtime=%y".to_string()];
    args.extend(STATE_PATHS.iter().map(|path| (*path).to_string()));
    args
}

fn resolve_probe_targets(
    config: &Config,
    routes: &CommandRecord,
    route_table: &CommandRecord,
    wg_endpoints: &CommandRecord,
    wg_allowed_ips: &CommandRecord,
) -> Vec<String> {
    let mut targets = BTreeSet::new();
    for target in &config.probe_targets {
        let trimmed = target.trim();
        if !trimmed.is_empty() {
            targets.insert(trimmed.to_string());
        }
    }

    for target in auto_probe_targets(routes, route_table, wg_endpoints, wg_allowed_ips) {
        targets.insert(target);
    }

    targets.into_iter().collect()
}

fn auto_probe_targets(
    routes: &CommandRecord,
    route_table: &CommandRecord,
    wg_endpoints: &CommandRecord,
    wg_allowed_ips: &CommandRecord,
) -> Vec<String> {
    let mut targets = BTreeSet::new();

    if routes.exit_code == Some(0) {
        for target in parse_default_gateway_targets(&routes.output) {
            targets.insert(target);
        }
    }
    if route_table.exit_code == Some(0) {
        for target in parse_host_route_targets(&route_table.output) {
            targets.insert(target);
        }
    }
    if wg_endpoints.exit_code == Some(0) {
        for target in parse_wg_endpoint_targets(&wg_endpoints.output) {
            targets.insert(target);
        }
    }
    if wg_allowed_ips.exit_code == Some(0) {
        for target in parse_wg_allowed_ip_targets(&wg_allowed_ips.output) {
            targets.insert(target);
        }
    }

    targets.into_iter().collect()
}

fn parse_default_gateway_targets(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "default" || parts.next()? != "via" {
                return None;
            }
            parse_private_probe_ipv4(parts.next()?)
        })
        .collect()
}

fn parse_host_route_targets(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let destination = line.split_whitespace().next()?;
            parse_private_probe_cidr_or_ip(destination)
        })
        .collect()
}

fn parse_wg_endpoint_targets(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _peer = parts.next()?;
            let endpoint = parts.next()?;
            if endpoint == "(none)" || endpoint == "off" {
                return None;
            }
            let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
            parse_private_probe_ipv4(host.trim_matches(['[', ']']))
        })
        .collect()
}

fn parse_wg_allowed_ip_targets(output: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(_peer) = parts.next() else {
            continue;
        };
        let rest = parts.collect::<Vec<_>>().join(" ");
        for entry in rest.split(',') {
            if let Some(target) = parse_private_probe_cidr_or_ip(entry.trim()) {
                targets.push(target);
            }
        }
    }
    targets
}

fn parse_private_probe_cidr_or_ip(value: &str) -> Option<String> {
    let token = value.trim();
    if token.is_empty() || token == "default" {
        return None;
    }
    let candidate = token
        .split_once('/')
        .map_or(token, |(ip, prefix)| if prefix == "32" { ip } else { "" });
    parse_private_probe_ipv4(candidate)
}

fn parse_private_probe_ipv4(value: &str) -> Option<String> {
    let octets = parse_ipv4_octets(value)?;
    if is_private_or_mesh_ipv4(&octets) {
        Some(value.to_string())
    } else {
        None
    }
}

fn parse_ipv4_octets(value: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = value.split('.');
    for slot in &mut octets {
        *slot = parts.next()?.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

fn is_private_or_mesh_ipv4(octets: &[u8; 4]) -> bool {
    match octets {
        [10, _, _, _] => true,
        [172, second, _, _] if (16..=31).contains(second) => true,
        [192, 168, _, _] => true,
        [100, second, _, _] if (64..=127).contains(second) => true,
        [127, _, _, _] => true,
        _ => false,
    }
}

#[derive(Clone)]
struct CommandSpec {
    display: String,
    program: String,
    args: Vec<String>,
    current_dir: Option<PathBuf>,
    env: Vec<(String, String)>,
    privilege: Privilege,
}

impl CommandSpec {
    fn plain(display: &str, program: &str, args: &[&str]) -> Self {
        Self {
            display: display.to_string(),
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            current_dir: None,
            env: Vec::new(),
            privilege: Privilege::PlainOnly,
        }
    }

    fn prefer_root(display: &str, program: &str, args: &[&str]) -> Self {
        Self {
            display: display.to_string(),
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            current_dir: None,
            env: Vec::new(),
            privilege: Privilege::PreferRoot,
        }
    }
}

fn run_first_success(specs: &[CommandSpec], sudo: &SudoContext) -> CommandRecord {
    let mut last = None;
    for spec in specs {
        let record = run_command(spec.clone(), sudo);
        if record.exit_code == Some(0) {
            return record;
        }
        last = Some(record);
    }
    last.unwrap_or_else(|| CommandRecord {
        command_display: "(no command)".to_string(),
        exit_code: None,
        output: "no commands were attempted".to_string(),
        ran_with_sudo: false,
    })
}

fn run_rustynet_command(
    repo_root: &Path,
    daemon_socket: &Path,
    subcommand: &str,
    extra_args: &[&str],
    display: &str,
) -> CommandRecord {
    let mut args = vec![
        "run".to_string(),
        "--quiet".to_string(),
        "-p".to_string(),
        "rustynet-cli".to_string(),
        "--bin".to_string(),
        "rustynet-cli".to_string(),
        "--".to_string(),
        subcommand.to_string(),
    ];
    args.extend(extra_args.iter().map(|arg| (*arg).to_string()));

    run_command(
        CommandSpec {
            display: display.to_string(),
            program: "cargo".to_string(),
            args,
            current_dir: Some(repo_root.to_path_buf()),
            env: vec![(
                "RUSTYNET_DAEMON_SOCKET".to_string(),
                daemon_socket.display().to_string(),
            )],
            privilege: Privilege::PlainOnly,
        },
        &SudoContext {
            enabled: false,
            summary: String::new(),
        },
    )
}

fn run_command(spec: CommandSpec, sudo: &SudoContext) -> CommandRecord {
    let use_sudo = spec.privilege == Privilege::PreferRoot && sudo.enabled;
    let mut command = if use_sudo {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(&spec.program);
        command
    } else {
        Command::new(&spec.program)
    };

    if let Some(current_dir) = &spec.current_dir {
        command.current_dir(current_dir);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    command.args(&spec.args);

    let command_display = if use_sudo {
        format!("sudo -n {}", spec.display)
    } else {
        spec.display
    };

    match command.output() {
        Ok(output) => CommandRecord {
            command_display,
            exit_code: Some(status_code(output.status)),
            output: combine_output(&output.stdout, &output.stderr),
            ran_with_sudo: use_sudo,
        },
        Err(err) => CommandRecord {
            command_display,
            exit_code: None,
            output: format!("failed to execute command: {err}"),
            ran_with_sudo: use_sudo,
        },
    }
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.signal().map_or(1, |signal| 128 + signal)
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

fn combine_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "(no output)".to_string(),
        (false, true) => stdout,
        (true, false) => format!("[stderr]\n{stderr}"),
        (false, false) => format!("{stdout}\n\n[stderr]\n{stderr}"),
    }
}

fn append_command_section(report: &mut String, title: &str, record: &CommandRecord) {
    writeln!(report).unwrap();
    writeln!(report, "## {title}").unwrap();
    writeln!(report).unwrap();
    writeln!(report, "- command: `{}`", record.command_display).unwrap();
    writeln!(
        report,
        "- exit_code: {}",
        record
            .exit_code
            .map(|value| value.to_string())
            .unwrap_or_else(|| "launch_error".to_string())
    )
    .unwrap();
    writeln!(
        report,
        "- ran_with_sudo: {}",
        if record.ran_with_sudo { "yes" } else { "no" }
    )
    .unwrap();
    writeln!(report).unwrap();
    writeln!(report, "```text").unwrap();
    writeln!(report, "{}", record.output).unwrap();
    writeln!(report, "```").unwrap();
}

fn append_filtered_command_section(
    report: &mut String,
    title: &str,
    record: &CommandRecord,
    filter: fn(&str) -> String,
) {
    if record.exit_code == Some(0) {
        let filtered = filter(&record.output);
        let filtered_record = CommandRecord {
            command_display: record.command_display.clone(),
            exit_code: record.exit_code,
            output: if filtered.trim().is_empty() {
                "(no matching lines)".to_string()
            } else {
                filtered
            },
            ran_with_sudo: record.ran_with_sudo,
        };
        append_command_section(report, title, &filtered_record);
    } else {
        append_command_section(report, title, record);
    }
}

fn append_filtered_env_section(
    report: &mut String,
    title: &str,
    record: &CommandRecord,
    allowed_keys: &[&str],
    allowed_prefixes: &[&str],
) {
    if record.exit_code == Some(0) {
        let filtered = filter_env_lines(&record.output, allowed_keys, allowed_prefixes);
        let filtered_record = CommandRecord {
            command_display: record.command_display.clone(),
            exit_code: record.exit_code,
            output: if filtered.trim().is_empty() {
                "(no allowed keys present)".to_string()
            } else {
                filtered
            },
            ran_with_sudo: record.ran_with_sudo,
        };
        append_command_section(report, title, &filtered_record);
    } else {
        append_command_section(report, title, record);
    }
}

fn filter_listener_lines(output: &str) -> String {
    filter_lines(output, |line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        trimmed.starts_with("Netid")
            || trimmed.contains("rustynet")
            || trimmed.contains(":22")
            || trimmed.contains(":51820")
    })
}

fn filter_nft_lines(output: &str) -> String {
    filter_lines(output, |line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        trimmed.contains("rustynet")
            || trimmed.contains("51820")
            || trimmed.contains("dport 22")
            || trimmed.contains("sport 22")
    })
}

fn filter_lines<F>(output: &str, keep: F) -> String
where
    F: Fn(&str) -> bool,
{
    output
        .lines()
        .filter(|line| keep(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn filter_env_lines(output: &str, allowed_keys: &[&str], allowed_prefixes: &[&str]) -> String {
    let mut retained = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(key) = parse_env_key(trimmed) {
            if allowed_keys.contains(&key)
                || allowed_prefixes
                    .iter()
                    .any(|prefix| key.starts_with(prefix))
            {
                retained.push(trimmed.to_string());
            }
        }
    }
    retained.join("\n")
}

fn parse_env_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let candidate = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let equals = candidate.find('=')?;
    let key = candidate[..equals].trim();
    if key.is_empty() { None } else { Some(key) }
}

fn command_exists(program: &str) -> bool {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .map(|dir| dir.join(program))
        .any(|path| path.is_file())
}

fn collect_utc_timestamp() -> Result<String, String> {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .map_err(|err| format!("failed to execute date: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "date returned exit code {}",
            status_code(output.status)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn collect_unix_timestamp() -> Result<u64, String> {
    let output = Command::new("date")
        .args(["-u", "+%s"])
        .output()
        .map_err(|err| format!("failed to execute date: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "date returned exit code {}",
            status_code(output.status)
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .map_err(|err| format!("invalid unix timestamp from date: {err}"))
}

fn default_output_path(collected_at_utc: &str) -> PathBuf {
    let safe_timestamp = collected_at_utc
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    let filename = format!("{DEFAULT_OUTPUT_PREFIX}-{safe_timestamp}.md");
    match env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(filename),
        None => PathBuf::from(filename),
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

fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| DEFAULT_OUTPUT_PREFIX.to_string());
    path.with_file_name(format!("{file_name}.tmp-{}", std::process::id()))
}

fn usage() -> &'static str {
    "collect_linux_reconnect_bundle

Usage:
  ./scripts/operations/collect_linux_reconnect_bundle.sh [OPTIONS]

Options:
  --output <path>            Write the markdown bundle to this path.
  --probe-target <host|ip>   Add a route+ping probe target. Repeat as needed.
  --wg-interface <name>      WireGuard interface to inspect (default: rustynet0).
  --daemon-socket <path>     rustynetd socket path (default: /run/rustynet/rustynetd.sock).
  --journal-lines <n>        Number of rustynetd journal lines to capture (default: 120).
  --sudo <auto|always|never> Control privileged probing behavior (default: auto).
  --quiet                    Suppress progress logs.
  --help                     Show this help.

Notes:
  - Output is markdown and is written with 0600 permissions.
  - The collector excludes private keys, passphrases, and signing secrets.
  - rustynet status/netcheck are run from the pulled repository via cargo for commit-bound evidence.
  - With no --probe-target flags, the collector auto-discovers private/mesh probe targets from current routes and WireGuard state.
"
}

fn log(quiet: bool, message: &str) {
    if !quiet {
        eprintln!("[collect-reconnect] {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_repeated_probe_targets() {
        let mut config = Config::default();
        let result = parse_args_from(
            [
                "collect_linux_reconnect_bundle",
                "--probe-target",
                "100.109.33.213",
                "--probe-target",
                "192.168.64.22",
                "--wg-interface",
                "wg-test0",
                "--daemon-socket",
                "/tmp/rustynetd.sock",
                "--journal-lines",
                "240",
                "--sudo",
                "never",
                "--quiet",
            ],
            &mut config,
        )
        .unwrap();

        assert_eq!(result, ParseResult::Config);
        assert_eq!(
            config.probe_targets,
            vec!["100.109.33.213".to_string(), "192.168.64.22".to_string()]
        );
        assert_eq!(config.wg_interface, "wg-test0");
        assert_eq!(config.daemon_socket, PathBuf::from("/tmp/rustynetd.sock"));
        assert_eq!(config.journal_lines, 240);
        assert_eq!(config.sudo_mode, SudoMode::Never);
        assert!(config.quiet);
    }

    #[test]
    fn filter_env_lines_only_keeps_allowlisted_keys() {
        let raw = r#"
# comment
RUSTYNET_NODE_ID=node-1
RUSTYNET_ASSIGNMENT_SIGNING_SECRET=/etc/rustynet/assignment.signing.secret
RUSTYNET_TRAVERSAL_PROBE_MAX_PAIRS=4
export RUSTYNET_DNS_ZONE_NAME=rustynet
IGNORED_KEY=value
"#;

        let filtered = filter_env_lines(raw, RUSTYNETD_ALLOWED_KEYS, RUSTYNETD_ALLOWED_PREFIXES);

        assert!(filtered.contains("RUSTYNET_NODE_ID=node-1"));
        assert!(filtered.contains("RUSTYNET_TRAVERSAL_PROBE_MAX_PAIRS=4"));
        assert!(filtered.contains("export RUSTYNET_DNS_ZONE_NAME=rustynet"));
        assert!(!filtered.contains("RUSTYNET_ASSIGNMENT_SIGNING_SECRET"));
        assert!(!filtered.contains("IGNORED_KEY"));
    }

    #[test]
    fn listener_filter_keeps_expected_rows() {
        let raw = "\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*     users:((\"sshd\",pid=1))
udp   UNCONN 0      0      0.0.0.0:51820   0.0.0.0:*     users:((\"rustynetd\",pid=2))
tcp   LISTEN 0      128    127.0.0.1:8080  0.0.0.0:*     users:((\"python\",pid=3))
";

        let filtered = filter_listener_lines(raw);

        assert!(filtered.contains("Netid State"));
        assert!(filtered.contains("0.0.0.0:22"));
        assert!(filtered.contains("0.0.0.0:51820"));
        assert!(!filtered.contains("127.0.0.1:8080"));
    }

    #[test]
    fn auto_probe_targets_are_discovered_from_private_state() {
        let routes = CommandRecord {
            command_display: "ip route".to_string(),
            exit_code: Some(0),
            output: "default via 192.168.64.1 dev eth0\n10.0.0.0/24 dev rustynet0".to_string(),
            ran_with_sudo: false,
        };
        let route_table = CommandRecord {
            command_display: "ip route show table 51820".to_string(),
            exit_code: Some(0),
            output: "100.109.33.213 dev rustynet0 scope link\n1.1.1.1 dev rustynet0".to_string(),
            ran_with_sudo: false,
        };
        let wg_endpoints = CommandRecord {
            command_display: "wg show rustynet0 endpoints".to_string(),
            exit_code: Some(0),
            output: "peer-a\t192.168.64.22:51820\npeer-b\t203.0.113.10:51820".to_string(),
            ran_with_sudo: false,
        };
        let wg_allowed_ips = CommandRecord {
            command_display: "wg show rustynet0 allowed-ips".to_string(),
            exit_code: Some(0),
            output: "peer-a\t100.109.33.213/32, 0.0.0.0/0\npeer-b\t192.168.128.30/32".to_string(),
            ran_with_sudo: false,
        };

        let targets = auto_probe_targets(&routes, &route_table, &wg_endpoints, &wg_allowed_ips);

        assert_eq!(
            targets,
            vec![
                "100.109.33.213".to_string(),
                "192.168.128.30".to_string(),
                "192.168.64.1".to_string(),
                "192.168.64.22".to_string()
            ]
        );
    }
}

#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static CLEANUP_RUNNING: AtomicBool = AtomicBool::new(false);

const NFT_RULES: &str = r#"table inet rustynet_e2e {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "veth_ei_e" accept
  }
}

table ip rustynet_e2e_nat {
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "veth_ei_e" ip saddr 100.64.0.0/10 masquerade
  }
}
"#;

struct Cleanup {
    ns_client: String,
    ns_exit: String,
    ns_inet: String,
    ns_lan: String,
    key_dir: PathBuf,
}

impl Cleanup {
    fn run(&self) {
        if CLEANUP_RUNNING.swap(true, Ordering::SeqCst) {
            return;
        }
        for namespace in [&self.ns_client, &self.ns_exit, &self.ns_inet, &self.ns_lan] {
            let _ = run_status(cmd("ip", &["netns", "del", namespace]));
        }
        let _ = fs::remove_dir_all(&self.key_dir);
        CLEANUP_RUNNING.store(false, Ordering::SeqCst);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.run();
    }
}

fn main() {
    if let Err(err) = run() {
        let code = classify_local_error(err.as_str());
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("error [{code}]: {err}");
        } else {
            eprintln!("error [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

/// Classify error-message text into the X6 taxonomy.
///
/// `real_wireguard_exitnode_e2e` runs the netns-based exit-node leak
/// gate as root on Linux. Detected leaks (kill-switch fail, DNS leak,
/// LAN reach when policy says block) are real fail-closed verdicts
/// surfaced via the `report writer returned ...` path — those must map
/// to `PolicyReject` so a retry-only-on-70 CI loop cannot mask a real
/// security finding by retrying. Missing tools / non-root / non-Linux
/// preconditions also map to `PolicyReject` since the gate's claim
/// cannot be evaluated and the orchestration must change before retry.
fn classify_local_error(message: &str) -> ExitCode {
    let lower = message.to_ascii_lowercase();
    if lower.contains("must run as root") {
        ExitCode::PolicyReject
    } else if lower.contains("missing required command") {
        ExitCode::ConfigError
    } else if lower.contains("report writer returned") {
        // Fail-closed verdict from the report writer: a leak / kill-
        // switch failure / DNS escape was detected. Operator review
        // required; do NOT retry.
        ExitCode::PolicyReject
    } else if lower.contains("report path has no parent")
        || lower.contains("unable to resolve repository root")
        || lower.contains("create report dir")
        || lower.contains("runtime dir")
        || lower.contains("key dir")
        || lower.contains("path is not valid utf-8")
    {
        ExitCode::ConfigError
    } else if lower.contains("spawn ")
        || lower.contains("run command")
        || lower.contains("wait ")
        || lower.contains("write ")
        || lower.contains("read ")
        || lower.contains("not utf8")
        || lower.contains("not utf-8")
        || lower.contains("parse ")
        || lower.contains("system clock")
        || lower.contains("command failed with status")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let report_path = env::var("RUSTYNET_E2E_REPORT_PATH")
        .unwrap_or_else(|_| "artifacts/phase10/netns_e2e_report.json".to_owned());
    let report_path = PathBuf::from(report_path);
    let report_parent = report_path
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", report_path.display()))?;
    fs::create_dir_all(report_parent).map_err(|e| format!("create report dir: {e}"))?;

    if current_uid()? != 0 {
        return Err("real_wireguard_exitnode_e2e.sh must run as root".to_owned());
    }

    for command in [
        "ip", "wg", "nft", "ping", "timeout", "cargo", "tcpdump", "bash",
    ] {
        require_command(command)?;
    }

    let pid = process::id();
    let ns_client = format!("ryn-client-{pid}");
    let ns_exit = format!("ryn-exit-{pid}");
    let ns_inet = format!("ryn-inet-{pid}");
    let ns_lan = format!("ryn-lan-{pid}");
    let dns_server_ip = "198.18.0.1";
    let dns_server_port = "53";

    let runtime_dir = prepare_secure_runtime_dir("rustynet-e2e", "RUSTYNET_E2E_RUNTIME_DIR")?;
    let key_dir = runtime_dir.join(format!("keys-{pid}"));
    fs::create_dir_all(&key_dir).map_err(|e| format!("create key dir: {e}"))?;

    let cleanup = Cleanup {
        ns_client: ns_client.clone(),
        ns_exit: ns_exit.clone(),
        ns_inet: ns_inet.clone(),
        ns_lan: ns_lan.clone(),
        key_dir: key_dir.clone(),
    };

    for namespace in [&ns_client, &ns_exit, &ns_inet, &ns_lan] {
        run_ok(cmd("ip", &["netns", "add", namespace]))?;
    }
    for namespace in [&ns_client, &ns_exit, &ns_inet, &ns_lan] {
        run_ns_ok(namespace, ["ip", "link", "set", "lo", "up"])?;
    }

    run_ok(cmd(
        "ip",
        &[
            "link",
            "add",
            "veth_ce_c",
            "type",
            "veth",
            "peer",
            "name",
            "veth_ce_e",
        ],
    ))?;
    run_ok(cmd(
        "ip",
        &["link", "set", "veth_ce_c", "netns", &ns_client],
    ))?;
    run_ok(cmd("ip", &["link", "set", "veth_ce_e", "netns", &ns_exit]))?;
    run_ns_ok(
        &ns_client,
        ["ip", "addr", "add", "172.16.10.2/24", "dev", "veth_ce_c"],
    )?;
    run_ns_ok(
        &ns_exit,
        ["ip", "addr", "add", "172.16.10.1/24", "dev", "veth_ce_e"],
    )?;
    run_ns_ok(&ns_client, ["ip", "link", "set", "veth_ce_c", "up"])?;
    run_ns_ok(&ns_exit, ["ip", "link", "set", "veth_ce_e", "up"])?;

    run_ok(cmd(
        "ip",
        &[
            "link",
            "add",
            "veth_ei_e",
            "type",
            "veth",
            "peer",
            "name",
            "veth_ei_i",
        ],
    ))?;
    run_ok(cmd("ip", &["link", "set", "veth_ei_e", "netns", &ns_exit]))?;
    run_ok(cmd("ip", &["link", "set", "veth_ei_i", "netns", &ns_inet]))?;
    run_ns_ok(
        &ns_exit,
        ["ip", "addr", "add", "198.18.0.2/24", "dev", "veth_ei_e"],
    )?;
    run_ns_ok(
        &ns_inet,
        ["ip", "addr", "add", "198.18.0.1/24", "dev", "veth_ei_i"],
    )?;
    run_ns_ok(&ns_exit, ["ip", "link", "set", "veth_ei_e", "up"])?;
    run_ns_ok(&ns_inet, ["ip", "link", "set", "veth_ei_i", "up"])?;

    run_ok(cmd(
        "ip",
        &[
            "link",
            "add",
            "veth_el_e",
            "type",
            "veth",
            "peer",
            "name",
            "veth_el_l",
        ],
    ))?;
    run_ok(cmd("ip", &["link", "set", "veth_el_e", "netns", &ns_exit]))?;
    run_ok(cmd("ip", &["link", "set", "veth_el_l", "netns", &ns_lan]))?;
    run_ns_ok(
        &ns_exit,
        ["ip", "addr", "add", "192.168.50.1/24", "dev", "veth_el_e"],
    )?;
    run_ns_ok(
        &ns_lan,
        ["ip", "addr", "add", "192.168.50.2/24", "dev", "veth_el_l"],
    )?;
    run_ns_ok(&ns_exit, ["ip", "link", "set", "veth_el_e", "up"])?;
    run_ns_ok(&ns_lan, ["ip", "link", "set", "veth_el_l", "up"])?;

    run_ns_ok(
        &ns_lan,
        ["ip", "route", "add", "100.64.0.0/10", "via", "192.168.50.1"],
    )?;

    let client_key = key_dir.join("client.key");
    let exit_key = key_dir.join("exit.key");
    let client_pub = key_dir.join("client.pub");
    let exit_pub = key_dir.join("exit.pub");

    generate_wg_key(&ns_client, &client_key)?;
    generate_wg_key(&ns_exit, &exit_key)?;
    generate_wg_pubkey(&ns_client, &client_key, &client_pub)?;
    generate_wg_pubkey(&ns_exit, &exit_key, &exit_pub)?;
    let client_pub_text = read_trimmed(&client_pub)?;
    let exit_pub_text = read_trimmed(&exit_pub)?;

    run_ns_ok(&ns_exit, ["ip", "link", "add", "wg0", "type", "wireguard"])?;
    run_ns_ok(
        &ns_exit,
        ["ip", "addr", "add", "100.64.0.1/24", "dev", "wg0"],
    )?;
    run_ns_ok(
        &ns_exit,
        [
            "wg",
            "set",
            "wg0",
            "private-key",
            path_str(&exit_key)?,
            "listen-port",
            "51820",
            "peer",
            &client_pub_text,
            "allowed-ips",
            "100.64.0.2/32",
        ],
    )?;
    run_ns_ok(&ns_exit, ["ip", "link", "set", "wg0", "up"])?;

    run_ns_ok(
        &ns_client,
        ["ip", "link", "add", "wg0", "type", "wireguard"],
    )?;
    run_ns_ok(
        &ns_client,
        ["ip", "addr", "add", "100.64.0.2/32", "dev", "wg0"],
    )?;
    run_ns_ok(
        &ns_client,
        [
            "wg",
            "set",
            "wg0",
            "private-key",
            path_str(&client_key)?,
            "peer",
            &exit_pub_text,
            "endpoint",
            "172.16.10.1:51820",
            "allowed-ips",
            "0.0.0.0/0",
            "persistent-keepalive",
            "5",
        ],
    )?;
    run_ns_ok(&ns_client, ["ip", "link", "set", "wg0", "up"])?;
    run_ns_ok(
        &ns_client,
        ["ip", "route", "replace", "default", "dev", "wg0"],
    )?;

    run_ns_quiet_ok(&ns_exit, ["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
    run_ns_stdin_ok(&ns_exit, ["nft", "-f", "-"], NFT_RULES)?;

    let mut exit_status = "fail";
    let mut lan_off_status = "fail";
    let mut lan_on_status = "fail";
    let mut dns_up_status = "fail";
    let mut kill_switch_status = "fail";
    let mut dns_down_status = "fail";

    if run_expect_success_ns(&ns_client, ["ping", "-c", "1", "-W", "1", dns_server_ip]) {
        exit_status = "pass";
    }

    if run_expect_failure_ns(&ns_client, ["ping", "-c", "1", "-W", "1", "192.168.50.2"]) {
        lan_off_status = "pass";
    }

    run_ns_ok(
        &ns_exit,
        [
            "nft",
            "add",
            "rule",
            "inet",
            "rustynet_e2e",
            "forward",
            "iifname",
            "wg0",
            "oifname",
            "veth_el_e",
            "ip",
            "daddr",
            "192.168.50.0/24",
            "accept",
        ],
    )?;
    if run_expect_success_ns(&ns_client, ["ping", "-c", "1", "-W", "1", "192.168.50.2"]) {
        lan_on_status = "pass";
    }

    let mut dns_up_capture = spawn_ns_quiet(
        &ns_inet,
        [
            "timeout",
            "4",
            "tcpdump",
            "-ni",
            "veth_ei_i",
            "-c",
            "1",
            "udp and dst host 198.18.0.1 and dst port 53",
        ],
    )?;
    thread::sleep(Duration::from_millis(200));
    if send_udp_probe(&ns_client, dns_server_ip, dns_server_port, "dns-probe-up").is_ok() {
        let status = dns_up_capture
            .wait()
            .map_err(|e| format!("wait tcpdump dns-up: {e}"))?;
        if status.success() {
            dns_up_status = "pass";
        }
    } else {
        let _ = dns_up_capture.wait();
    }

    run_ns_ok(&ns_client, ["ip", "link", "set", "wg0", "down"])?;
    let _ = run_status(ns_command(
        &ns_client,
        ["ip", "route", "del", "default", "dev", "wg0"],
    ));

    if run_expect_failure_ns(&ns_client, ["ping", "-c", "1", "-W", "1", dns_server_ip]) {
        kill_switch_status = "pass";
    }

    let mut dns_down_capture = spawn_ns_quiet(
        &ns_inet,
        [
            "timeout",
            "3",
            "tcpdump",
            "-ni",
            "veth_ei_i",
            "-c",
            "1",
            "udp and dst host 198.18.0.1 and dst port 53",
        ],
    )?;
    thread::sleep(Duration::from_millis(200));
    let dns_down_send_failed =
        send_udp_probe(&ns_client, dns_server_ip, dns_server_port, "dns-probe-down").is_err();
    let dns_down_status_code = dns_down_capture
        .wait()
        .map_err(|e| format!("wait tcpdump dns-down: {e}"))?
        .code();
    if matches!(dns_down_status_code, Some(124)) && dns_down_send_failed {
        dns_down_status = "pass";
    }

    write_json_report(
        &report_path,
        exit_status,
        lan_off_status,
        lan_on_status,
        dns_up_status,
        kill_switch_status,
        dns_down_status,
    )?;
    println!("E2E report written to {}", report_path.display());

    drop(cleanup);
    Ok(())
}

fn current_uid() -> Result<u32, String> {
    let output = command_output(cmd("id", &["-u"]))?;
    let text = String::from_utf8(output).map_err(|e| format!("id -u output not utf8: {e}"))?;
    text.trim()
        .parse::<u32>()
        .map_err(|e| format!("parse id -u: {e}"))
}

fn require_command(command: &str) -> Result<(), String> {
    let status = run_status(cmd("command", &["-v", command]));
    match status {
        Ok(0) => Ok(()),
        Ok(_) => Err(format!("missing required command: {command}")),
        Err(_) => {
            let status = run_status(cmd("which", &[command]));
            match status {
                Ok(0) => Ok(()),
                _ => Err(format!("missing required command: {command}")),
            }
        }
    }
}

fn run_expect_success_ns<const N: usize>(namespace: &str, args: [&str; N]) -> bool {
    run_status(ns_command(namespace, args)).is_ok_and(|code| code == 0)
}

fn run_expect_failure_ns<const N: usize>(namespace: &str, args: [&str; N]) -> bool {
    run_status(ns_command(namespace, args)).is_ok_and(|code| code != 0)
}

fn run_ns_ok<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    run_ok(ns_command(namespace, args))
}

fn run_ns_quiet_ok<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    let mut command = ns_command(namespace, args);
    command.stdout(Stdio::null());
    run_ok(command)
}

fn run_ns_stdin_ok<const N: usize>(
    namespace: &str,
    args: [&str; N],
    stdin_data: &str,
) -> Result<(), String> {
    let mut command = ns_command(namespace, args);
    command.stdin(Stdio::piped()).stdout(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn command with stdin: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(stdin_data.as_bytes())
            .map_err(|e| format!("write stdin: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("wait command: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}"))
    }
}

fn spawn_ns_quiet<const N: usize>(
    namespace: &str,
    args: [&str; N],
) -> Result<process::Child, String> {
    let mut command = ns_command(namespace, args);
    command.stdout(Stdio::null()).stderr(Stdio::null());
    command.spawn().map_err(|e| format!("spawn command: {e}"))
}

fn ns_command<const N: usize>(namespace: &str, args: [&str; N]) -> Command {
    let mut command = cmd("ip", &[]);
    command.arg("netns").arg("exec").arg(namespace);
    command.args(args);
    command
}

fn cmd(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command.env("PATH", secure_path());
    command
}

fn secure_path() -> OsString {
    let current = env::var_os("PATH").unwrap_or_default();
    let mut value = OsString::from("/usr/local/sbin:/usr/sbin:/sbin:");
    value.push(current);
    value
}

fn run_ok(mut command: Command) -> Result<(), String> {
    let status = command.status().map_err(|e| format!("run command: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}"))
    }
}

fn run_status(mut command: Command) -> Result<i32, String> {
    let status = command.status().map_err(|e| format!("run command: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn command_output(mut command: Command) -> Result<Vec<u8>, String> {
    let output = command.output().map_err(|e| format!("run command: {e}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!("command failed with status {}", output.status))
    }
}

fn generate_wg_key(namespace: &str, output_path: &Path) -> Result<(), String> {
    let output = command_output(ns_command(namespace, ["wg", "genkey"]))?;
    write_private_key_file(output_path, output)
}

/// Create the per-run runtime directory fail-closed.
///
/// The harness runs as root on a shared CI runner and stores freshly
/// generated WireGuard private keys here, so the directory must never be
/// taken over by another local user: an existing path (including a
/// symlink) is refused outright, a fresh default location is derived from
/// a randomly seeded hash instead of a fixed shared name, and the created
/// directory is verified to be mode `0700` and not a symlink before any
/// key material is written into it.
fn prepare_secure_runtime_dir(default_prefix: &str, env_var: &str) -> Result<PathBuf, String> {
    let candidate = match env::var_os(env_var) {
        Some(value) => PathBuf::from(value),
        None => env::temp_dir().join(format!("{default_prefix}-{}", unique_suffix()?)),
    };
    secure_runtime_dir(&candidate)?;
    Ok(candidate)
}

fn unique_suffix() -> Result<String, String> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before unix epoch: {e}"))?
        .as_nanos();
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(nanos);
    hasher.write_u32(process::id());
    Ok(format!("{:016x}", hasher.finish()))
}

fn secure_runtime_dir(path: &Path) -> Result<(), String> {
    create_secure_runtime_dir(path, verify_secure_runtime_dir)
}

/// Single hardened creation path. The post-create verification step is a
/// parameter so tests can observe that it always runs; production wires the
/// real [`verify_secure_runtime_dir`].
fn create_secure_runtime_dir<F>(path: &Path, post_create_verify: F) -> Result<(), String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    if fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "runtime dir already exists; refusing to reuse pre-existing path: {}",
            path.display()
        ));
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| format!("create runtime dir {}: {e}", path.display()))?;
    post_create_verify(path)
}

fn verify_secure_runtime_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("stat runtime dir {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "runtime dir must not be a symlink: {}",
                path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(format!(
                "runtime dir must be mode 0700, got {mode:04o}: {}",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write WireGuard private key material with owner-only permissions.
fn write_private_key_file(output_path: &Path, key_bytes: Vec<u8>) -> Result<(), String> {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(output_path)
            .and_then(|mut file| file.write_all(&key_bytes))
            .map_err(|e| format!("write wg key {}: {e}", output_path.display()))
    }
    #[cfg(not(unix))]
    {
        fs::write(output_path, key_bytes)
            .map_err(|e| format!("write wg key {}: {e}", output_path.display()))
    }
}

fn generate_wg_pubkey(namespace: &str, key_path: &Path, output_path: &Path) -> Result<(), String> {
    let key_text =
        fs::read(key_path).map_err(|e| format!("read key {}: {e}", key_path.display()))?;
    let mut command = ns_command(namespace, ["wg", "pubkey"]);
    command.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn wg pubkey: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&key_text)
            .map_err(|e| format!("write wg pubkey stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("wait wg pubkey: {e}"))?;
    if !output.status.success() {
        return Err(format!("wg pubkey failed with status {}", output.status));
    }
    fs::write(output_path, output.stdout)
        .map_err(|e| format!("write pubkey {}: {e}", output_path.display()))
}

fn read_trimmed(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(text.trim().to_owned())
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid utf-8: {}", path.display()))
}

fn send_udp_probe(namespace: &str, ip: &str, port: &str, payload: &str) -> Result<(), String> {
    let mut command = Command::new("ip");
    command
        .arg("netns")
        .arg("exec")
        .arg(namespace)
        .arg("env")
        .arg(format!("RUSTYNET_UDP_PAYLOAD={payload}"))
        .arg("timeout")
        .arg("2")
        .arg("bash")
        .arg("-lc")
        .arg(format!(
            "printf '%s' \"$RUSTYNET_UDP_PAYLOAD\" >/dev/udp/{ip}/{port}"
        ));
    run_ok(command)
}

fn write_json_report(
    report_path: &Path,
    exit_status: &str,
    lan_off_status: &str,
    lan_on_status: &str,
    dns_up_status: &str,
    kill_switch_status: &str,
    dns_down_status: &str,
) -> Result<(), String> {
    let environment =
        env::var("RUSTYNET_PHASE10_E2E_ENVIRONMENT").unwrap_or_else(|_| "lab-netns".to_owned());
    let (captured_at_utc, captured_at_unix) = utc_now()?;
    let root = repo_root()?;
    let mut command = cmd(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
            "--",
            "ops",
            "write-real-wireguard-exitnode-e2e-report",
            "--report-path",
            path_str(report_path)?,
            "--exit-status",
            exit_status,
            "--lan-off-status",
            lan_off_status,
            "--lan-on-status",
            lan_on_status,
            "--dns-up-status",
            dns_up_status,
            "--kill-switch-status",
            kill_switch_status,
            "--dns-down-status",
            dns_down_status,
            "--environment",
            &environment,
            "--captured-at-utc",
            &captured_at_utc,
            "--captured-at-unix",
            &captured_at_unix,
        ],
    );
    command.current_dir(root);
    let output = command_output(command)?;
    let text =
        String::from_utf8(output).map_err(|e| format!("report writer output not utf8: {e}"))?;
    if text.trim() == "pass" {
        Ok(())
    } else {
        Err(format!("report writer returned {}", text.trim()))
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "unable to resolve repository root".to_owned())
}

fn utc_now() -> Result<(String, String), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock before unix epoch: {e}"))?;
    let unix = now.as_secs();
    let timestamp = command_output(cmd("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]))?;
    let text = String::from_utf8(timestamp).map_err(|e| format!("date output not utf8: {e}"))?;
    Ok((text.trim().to_owned(), unix.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("ryn-e2e-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn secure_runtime_dir_refuses_pre_existing_path() {
        let base = scratch_dir("refuse-existing");
        let target = base.join("planted");
        #[cfg(unix)]
        {
            // Attacker-realistic plant: already 0700 and not a symlink, so
            // every post-create verification would accept it. Only the
            // explicit pre-existing-path refusal may reject it.
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&target)
                .expect("plant attacker-owned dir");
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&target).expect("plant");
        assert!(secure_runtime_dir(&target).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_runtime_dir_refuses_symlinked_path_even_dangling() {
        use std::os::unix::fs::symlink;
        let base = scratch_dir("refuse-symlink");
        let link = base.join("link");
        symlink(base.join("does-not-exist"), &link).expect("symlink");
        // symlink_metadata succeeds for dangling links, so the refusal
        // must fire before any create attempt follows the link.
        assert!(secure_runtime_dir(&link).is_err());
        assert!(
            fs::symlink_metadata(&link)
                .expect("link survives")
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn verify_rejects_wrong_mode_dir() {
        use std::os::unix::fs::DirBuilderExt;
        let base = scratch_dir("wrong-mode");
        let target = base.join("loose");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&target)
            .expect("create loose");
        assert!(verify_secure_runtime_dir(&target).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_runtime_dir_fresh_create_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("fresh-mode");
        let target = base.join("fresh");
        secure_runtime_dir(&target).expect("fresh create must succeed");
        let mode = fs::symlink_metadata(&target)
            .expect("dir meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn secure_runtime_dir_always_runs_post_create_verification() {
        use std::cell::Cell;
        use std::rc::Rc;
        let base = scratch_dir("verify-wired");
        let target = base.join("wired");
        let calls = Rc::new(Cell::new(0usize));
        let counter = Rc::clone(&calls);
        // The spy delegates to the real verifier, so this pins the wiring
        // (create is always followed by verification) without weakening what
        // is checked: the created dir must still pass the real mode check.
        let result = create_secure_runtime_dir(&target, move |p| {
            counter.set(counter.get() + 1);
            verify_secure_runtime_dir(p)
        });
        assert!(
            result.is_ok(),
            "wired create+verify must succeed: {result:?}"
        );
        assert_eq!(
            calls.get(),
            1,
            "post-create verification must run exactly once"
        );
    }

    #[test]
    fn secure_runtime_dir_wrapper_delegates_to_the_seam_with_the_real_verifier() {
        // The counting-spy pin drives the seam directly, so it cannot see what
        // the production wrapper passes: a wrapper reverted to inline creation
        // or swapped to a no-op verifier stayed green under every prior test
        // (proven by mutation). Audit the source like the rustynetd seam audits
        // do — the census forces conscious review of any NEW internal caller,
        // and the delegation must sit inside the wrapper window with the real
        // verifier named. Needles are fragment-assembled so this audit never
        // matches its own source.
        let source = include_str!("real_wireguard_exitnode_e2e.rs");
        let callsite_census = ["create_secure_runtime_dir", "("].concat();
        assert_eq!(
            source.matches(callsite_census.as_str()).count(),
            2,
            "unexpected create_secure_runtime_dir caller — review it and update \
             this census deliberately; the wrapper must stay the only production \
             caller so the post-create verifier cannot be swapped or skipped"
        );
        let delegation = [
            "create_secure_runtime_dir",
            "(path, ",
            "verify_secure_runtime_dir)",
        ]
        .concat();
        assert_eq!(
            source.matches(delegation.as_str()).count(),
            1,
            "the wrapper must delegate to the seam exactly once, passing the REAL \
             owner-only verifier; a no-op or dropped verifier silently disables \
             post-create permission verification"
        );
        let wrapper_start = source
            .find("fn secure_runtime_dir(path: &Path)")
            .expect("the secure_runtime_dir wrapper must exist");
        let seam_start = source
            .find("fn create_secure_runtime_dir")
            .expect("the creation seam must exist");
        let delegation_at = source
            .find(delegation.as_str())
            .expect("count 1 implies a match");
        assert!(
            delegation_at > wrapper_start && delegation_at < seam_start,
            "the delegation must sit inside the secure_runtime_dir wrapper, so \
             production cannot reach the seam through any other wiring"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = scratch_dir("key-mode");
        let key_path = base.join("client.key");
        write_private_key_file(&key_path, b"test-private-key".to_vec()).expect("write key");
        let mode = fs::metadata(&key_path)
            .expect("key meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn unique_suffix_differs_across_calls() {
        let a = unique_suffix().expect("suffix a");
        let b = unique_suffix().expect("suffix b");
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
    }
}

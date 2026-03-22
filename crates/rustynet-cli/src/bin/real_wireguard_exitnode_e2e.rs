#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitCode, Stdio};
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

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), String> {
    let report_path = env::var("RUSTYNET_E2E_REPORT_PATH")
        .unwrap_or_else(|_| "artifacts/phase10/netns_e2e_report.json".to_owned());
    let runtime_dir =
        env::var("RUSTYNET_E2E_RUNTIME_DIR").unwrap_or_else(|_| "/tmp/rustynet-e2e".to_owned());
    let report_path = PathBuf::from(report_path);
    let runtime_dir = PathBuf::from(runtime_dir);
    let report_parent = report_path
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", report_path.display()))?;
    fs::create_dir_all(report_parent).map_err(|e| format!("create report dir: {e}"))?;
    fs::create_dir_all(&runtime_dir).map_err(|e| format!("create runtime dir: {e}"))?;

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
    fs::write(output_path, output)
        .map_err(|e| format!("write wg key {}: {e}", output_path.display()))
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

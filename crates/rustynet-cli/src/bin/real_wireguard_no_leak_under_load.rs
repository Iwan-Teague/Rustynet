#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NFT_RULES: &str = r#"table inet rustynet_noleak {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "veth_ei_e" accept
  }
}

table ip rustynet_noleak_nat {
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
    key_dir: PathBuf,
    load_pcap: PathBuf,
    down_pcap: PathBuf,
    tcpdump_load_pid: Option<u32>,
    tcpdump_down_pid: Option<u32>,
}

impl Cleanup {
    fn stop_pid(pid: Option<u32>) {
        if let Some(pid) = pid {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        Self::stop_pid(self.tcpdump_load_pid.take());
        Self::stop_pid(self.tcpdump_down_pid.take());
        for namespace in [&self.ns_client, &self.ns_exit, &self.ns_inet] {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
        let _ = fs::remove_dir_all(&self.key_dir);
        let _ = fs::remove_file(&self.load_pcap);
        let _ = fs::remove_file(&self.down_pcap);
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let report_path = env::var("RUSTYNET_NO_LEAK_REPORT_PATH")
        .unwrap_or_else(|_| "artifacts/phase10/no_leak_dataplane_report.json".to_owned());
    let runtime_dir = env::var("RUSTYNET_NO_LEAK_RUNTIME_DIR")
        .unwrap_or_else(|_| "/tmp/rustynet-no-leak-gate".to_owned());
    let report_path = PathBuf::from(report_path);
    let runtime_dir = PathBuf::from(runtime_dir);
    let report_parent = report_path
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", report_path.display()))?;
    fs::create_dir_all(report_parent).map_err(|e| format!("create report dir: {e}"))?;
    fs::create_dir_all(&runtime_dir).map_err(|e| format!("create runtime dir: {e}"))?;

    if current_uid()? != 0 {
        return Err("real_wireguard_no_leak_under_load.sh must run as root".to_owned());
    }

    for command in [
        "ip", "wg", "nft", "ping", "timeout", "tcpdump", "cargo", "bash",
    ] {
        require_command(command)?;
    }

    let pid = process::id();
    let ns_client = format!("rnleak-client-{pid}");
    let ns_exit = format!("rnleak-exit-{pid}");
    let ns_inet = format!("rnleak-inet-{pid}");
    let key_dir = runtime_dir.join(format!("keys-{pid}"));
    let load_pcap = runtime_dir.join(format!("underlay-load-{pid}.pcap"));
    let down_pcap = runtime_dir.join(format!("underlay-down-{pid}.pcap"));
    fs::create_dir_all(&key_dir).map_err(|e| format!("create key dir: {e}"))?;

    let mut cleanup = Cleanup {
        ns_client: ns_client.clone(),
        ns_exit: ns_exit.clone(),
        ns_inet: ns_inet.clone(),
        key_dir: key_dir.clone(),
        load_pcap: load_pcap.clone(),
        down_pcap: down_pcap.clone(),
        tcpdump_load_pid: None,
        tcpdump_down_pid: None,
    };

    for namespace in [&ns_client, &ns_exit, &ns_inet] {
        run_ok(cmd("ip", &["netns", "add", namespace]))?;
    }
    for namespace in [&ns_client, &ns_exit, &ns_inet] {
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

    let mut tunnel_up_status = "fail";
    let mut load_ping_status = "fail";
    let mut tunnel_down_block_status = "fail";

    if run_expect_success_ns(&ns_client, ["ping", "-c", "2", "-W", "1", "198.18.0.1"]) {
        tunnel_up_status = "pass";
    }

    let load_child = spawn_ns_tcpdump(&ns_client, &load_pcap)?;
    cleanup.tcpdump_load_pid = Some(load_child.id());
    thread::sleep(Duration::from_secs(1));

    if run_expect_success_ns(
        &ns_client,
        [
            "timeout",
            "6",
            "ping",
            "-i",
            "0.05",
            "-W",
            "1",
            "198.18.0.1",
        ],
    ) {
        load_ping_status = "pass";
    }
    let probe_end = Instant::now() + Duration::from_secs(4);
    while Instant::now() < probe_end {
        let _ = send_udp_probe(&ns_client, "198.18.0.1", "53", "rustynet-load");
        thread::sleep(Duration::from_millis(20));
    }

    thread::sleep(Duration::from_secs(1));
    if let Some(pid) = cleanup.tcpdump_load_pid.take() {
        stop_pid(pid);
    }

    run_ns_ok(&ns_client, ["ip", "link", "set", "wg0", "down"])?;

    let down_child = spawn_ns_tcpdump(&ns_client, &down_pcap)?;
    cleanup.tcpdump_down_pid = Some(down_child.id());
    thread::sleep(Duration::from_secs(1));

    if run_expect_failure_ns(
        &ns_client,
        ["timeout", "4", "ping", "-i", "0.2", "-W", "1", "198.18.0.1"],
    ) {
        tunnel_down_block_status = "pass";
    }

    for _ in 0..8 {
        let _ = send_udp_probe(&ns_client, "198.18.0.1", "53", "rustynet-down");
    }

    thread::sleep(Duration::from_secs(1));
    if let Some(pid) = cleanup.tcpdump_down_pid.take() {
        stop_pid(pid);
    }

    write_json_report(
        &report_path,
        &load_pcap,
        &down_pcap,
        tunnel_up_status,
        load_ping_status,
        tunnel_down_block_status,
    )?;
    println!(
        "No-leak dataplane report written to {}",
        report_path.display()
    );
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
    if run_status(cmd("which", &[command])).is_ok_and(|code| code == 0) {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
    }
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

fn secure_path() -> std::ffi::OsString {
    let current = env::var_os("PATH").unwrap_or_default();
    let mut value = std::ffi::OsString::from("/usr/local/sbin:/usr/sbin:/sbin:");
    value.push(current);
    value
}

fn run_ns_ok<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    run_ok(ns_command(namespace, args))
}

fn run_ns_quiet_ok<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    let mut command = ns_command(namespace, args);
    command.stdout(Stdio::null());
    run_ok(command)
}

fn run_expect_success_ns<const N: usize>(namespace: &str, args: [&str; N]) -> bool {
    run_status(ns_command(namespace, args)).is_ok_and(|code| code == 0)
}

fn run_expect_failure_ns<const N: usize>(namespace: &str, args: [&str; N]) -> bool {
    run_status(ns_command(namespace, args)).is_ok_and(|code| code != 0)
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

fn spawn_ns_tcpdump(namespace: &str, output_path: &Path) -> Result<process::Child, String> {
    let mut command = ns_command(
        namespace,
        [
            "tcpdump",
            "-i",
            "veth_ce_c",
            "-nn",
            "-U",
            "-w",
            path_str(output_path)?,
            "ip and src host 172.16.10.2",
        ],
    );
    command.stdout(Stdio::null()).stderr(Stdio::null());
    command.spawn().map_err(|e| format!("spawn tcpdump: {e}"))
}

fn stop_pid(pid: u32) {
    let _ = Command::new("kill").arg(pid.to_string()).status();
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
    load_pcap: &Path,
    down_pcap: &Path,
    tunnel_up_status: &str,
    load_ping_status: &str,
    tunnel_down_block_status: &str,
) -> Result<(), String> {
    let environment =
        env::var("RUSTYNET_NO_LEAK_ENVIRONMENT").unwrap_or_else(|_| "lab-netns".to_owned());
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
            "write-real-wireguard-no-leak-under-load-report",
            "--report-path",
            path_str(report_path)?,
            "--load-pcap",
            path_str(load_pcap)?,
            "--down-pcap",
            path_str(down_pcap)?,
            "--tunnel-up-status",
            tunnel_up_status,
            "--load-ping-status",
            load_ping_status,
            "--tunnel-down-block-status",
            tunnel_down_block_status,
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

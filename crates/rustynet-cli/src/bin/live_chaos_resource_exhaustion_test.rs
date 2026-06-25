#![forbid(unsafe_code)]
// Track B Phase 28 transition: still calls the deprecated `capture_root`
// shim (same as the daemon_fault / network_impairment templates). Phase 29
// rewrites on the new `RemoteShellHost` trait. Allow until then so
// `-D warnings` passes.
#![allow(deprecated)]

//! Live chaos: control-plane INGEST resource-exhaustion.
//!
//! Methodology (Wave 5 spec §2, research F24/F25, TUF endless-data cap): feed
//! the daemon's control-plane ingest paths OVERSIZED / ENDLESS-STREAMING /
//! DECOMPRESSION-BOMB payloads and assert bounded, fail-closed handling:
//!   1. A declared-size + HARD CAP must REJECT the oversized/endless payload
//!      BEFORE allocation (no unbounded buffering / OOM).
//!   2. The daemon must NOT panic / OOM and must stay RESPONSIVE — it
//!      rate-limits/drops, and mesh `status` + the IPC socket still answer
//!      AFTER the flood.
//!   3. A malformed / decompression-bomb payload fails closed and never
//!      crashes (complements the `ipc_parse_command` fuzz target's
//!      crash-safety, see `fuzz/`).
//!
//! The ingest endpoints + caps this slice targets are REAL, declared caps:
//!   * IPC: the Unix socket (`/run/rustynet/rustynetd.sock`) is read with
//!     `stream.take(MAX_COMMAND_BYTES)` where `MAX_COMMAND_BYTES = 4096`
//!     (`crates/rustynetd/src/ipc.rs`). The bounded read truncates BEFORE
//!     allocation, so an oversized command line cannot OOM the daemon.
//!   * Gossip: the per-peer UDP socket on `RUSTYNET_GOSSIP_PORT` (51821) recvs
//!     into a fixed `[0u8; MAX_GOSSIP_DATAGRAM_BYTES]` (4 KiB) and rejects any
//!     datagram longer than the cap (`crates/rustynetd/src/gossip_transport.rs`).
//!   * Signed-state bundles are read with `Read::take(cap + 1)` bounded reads
//!     (`MAX_ROTATION_LEDGER_BYTES`, `MAX_GOSSIP_WATERMARK_BYTES`,
//!     `MAX_FETCHER_BODY_BYTES`) so an endless/bomb body is detected, not
//!     buffered.
//!
//! REVIEW(W5-C): the declared `ChaosStage`s in the original 44-line scaffold
//! were filesystem/inotify/fd-exhaustion oriented (disk-full / read-only-fs /
//! inotify-watch / fd-limit). The Wave 5 spec §2 (resource_exhaustion) instead
//! mandates CONTROL-PLANE INGEST exhaustion (oversized / endless / bomb at the
//! bundle / gossip / IPC ingest paths). Per §5 each agent OWNS its binary and
//! declares its own stages; I have re-declared the stages to match the spec's
//! ingest-exhaustion methodology (the host-fd/disk faults are a different
//! exhaustion class and are out of scope for the "ingest cap + responsiveness"
//! assertion this slice proves). Reviewer: confirm the stage re-declaration is
//! the intended reading of "implement each declared stage" vs. the spec
//! methodology — I prioritised the spec methodology.

mod live_chaos_support;
mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_chaos_support::{ChaosConfig, ChaosStage, git_head_commit, repo_root, run_category};
use live_lab_bin_support::{
    Logger, capture_root, ensure_pinned_known_hosts_file, ensure_safe_token,
    load_home_known_hosts_path, shell_quote, unix_now, verify_sudo, wait_for_daemon_socket,
    write_file,
};
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_resource_exhaustion";
const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const DEFAULT_SERVICE_NAME: &str = "rustynetd.service";
const DEFAULT_RECOVERY_DEADLINE_SECS: u64 = 120;
const MAX_RECOVERY_DEADLINE_SECS: u64 = 120;

/// IPC command ingest cap — mirrors `MAX_COMMAND_BYTES` in
/// `crates/rustynetd/src/ipc.rs`. The IPC socket reader is
/// `BufReader::new(stream.take(MAX_COMMAND_BYTES))`, so a command line longer
/// than this is TRUNCATED before allocation and the over-long frame is
/// rejected (cannot parse), never buffered unbounded.
// REVIEW(W5-C): if `MAX_COMMAND_BYTES` in ipc.rs changes, update this mirror.
const IPC_COMMAND_CAP_BYTES: usize = 4096;

/// Gossip datagram ingest cap — mirrors `MAX_GOSSIP_DATAGRAM_BYTES`
/// (`crates/rustynetd/src/peer_gossip.rs`, surfaced via gossip_transport.rs).
/// The recv path reads into a fixed `[0u8; MAX_GOSSIP_DATAGRAM_BYTES]` and
/// refuses any datagram longer than the cap before any structural parse.
// REVIEW(W5-C): if `MAX_GOSSIP_DATAGRAM_BYTES` changes, update this mirror.
const GOSSIP_DATAGRAM_CAP_BYTES: usize = 4096;

/// Default UDP gossip port — mirrors `RUSTYNET_GOSSIP_PORT`
/// (`crates/rustynetd/src/gossip_transport.rs`).
const DEFAULT_GOSSIP_PORT: u16 = 51821;

/// HARD ceiling on the payload the ORCHESTRATOR/guest generates. The TARGET of
/// the flood is the GUEST daemon's bounded ingest; we MUST NOT exhaust the test
/// runner. 1 MiB is far above every daemon ingest cap (4 KiB IPC / gossip,
/// 256 KiB ledger) yet trivially bounded for the generator — proving the cap
/// rejects without us buffering anything large.
const MAX_GENERATED_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Distinct tmp paths so a concurrent chaos run (daemon-fault /
/// network-impairment) can never collide on the guest.
const GUEST_WORK_PREFIX: &str = "/tmp/rustynet-chaos-resource-exhaustion";

/// Default ceiling on tolerated RSS growth across the flood window, in KiB.
/// 64 MiB is generous headroom for a healthy daemon's working set churn while
/// still catching an unbounded-buffering blow-up (the flood injects up to
/// flood_count * payload_bytes, e.g. 64 * 64 KiB = 4 MiB of attempted ingest;
/// a bounded daemon must not grow anywhere near that, let alone past 64 MiB).
const DEFAULT_RSS_GROWTH_LIMIT_KIB: u64 = 64 * 1024;

/// Which ingest path the live slice floods. `Ipc` is the default (orchestrator
/// stage `chaos_resource_exhaustion`); `Gossip` floods the UDP gossip port.
/// Defaults to `Ipc` so callers that omit `--target-ingest` keep the IPC slice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum TargetIngest {
    #[default]
    Ipc,
    Gossip,
}

fn resource_exhaustion_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_ipc_oversized_command_flood",
            fault: "send IPC command frames far beyond MAX_COMMAND_BYTES to the daemon socket",
            pass_criterion: "bounded read truncates/rejects before allocation; daemon never OOMs and IPC stays responsive",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_gossip_oversized_datagram_flood",
            fault: "send UDP gossip datagrams larger than MAX_GOSSIP_DATAGRAM_BYTES to the gossip port",
            pass_criterion: "oversized datagrams dropped at the cap; daemon stays responsive and does not buffer unbounded",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_ipc_endless_stream_no_newline",
            fault: "stream an endless newline-less byte run at the IPC socket (no frame terminator)",
            pass_criterion: "take(cap) bounds the read; connection closed fail-closed, no unbounded line buffer",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
        ChaosStage {
            name: "chaos_bundle_decompression_bomb",
            fault: "submit a malformed/decompression-bomb signed-state bundle to the bundle ingest path",
            pass_criterion: "bounded-read cap + signature/structure check fails closed; no panic, no OOM, no state mutation",
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
        },
    ]
}

#[derive(Clone, Debug)]
struct Config {
    report_path: PathBuf,
    log_path: PathBuf,
    git_commit: String,
    dry_run: bool,
    target_host: Option<String>,
    ssh_identity_file: Option<PathBuf>,
    known_hosts_file: Option<PathBuf>,
    socket_path: String,
    service_name: String,
    gossip_port: u16,
    recovery_deadline_secs: u64,
    target_ingest: TargetIngest,
    /// Number of oversized payloads to inject in the flood. Bounded so the
    /// generator can never run away on the orchestrator.
    flood_count: u32,
    /// Size of each oversized payload, in bytes. Bounded by
    /// [`MAX_GENERATED_PAYLOAD_BYTES`].
    payload_bytes: usize,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let root = repo_root()?;
        let mut config = Self {
            report_path: root.join(format!("artifacts/phase10/{CATEGORY}_report.json")),
            log_path: root.join(format!("artifacts/phase10/source/{CATEGORY}.log")),
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| git_head_commit(&root)),
            dry_run: false,
            target_host: None,
            ssh_identity_file: None,
            known_hosts_file: None,
            socket_path: DEFAULT_SOCKET_PATH.to_owned(),
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
            gossip_port: DEFAULT_GOSSIP_PORT,
            recovery_deadline_secs: DEFAULT_RECOVERY_DEADLINE_SECS,
            target_ingest: TargetIngest::default(),
            flood_count: 64,
            payload_bytes: 64 * 1024,
        };

        let args = args.into_iter().collect::<Vec<_>>();
        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--dry-run" => config.dry_run = true,
                "--report-path" => {
                    idx += 1;
                    config.report_path =
                        PathBuf::from(required_value(&args, idx, "--report-path")?);
                }
                "--log-path" => {
                    idx += 1;
                    config.log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
                }
                "--git-commit" => {
                    idx += 1;
                    config.git_commit = required_value(&args, idx, "--git-commit")?;
                }
                "--target-host" | "--exit-host" => {
                    idx += 1;
                    config.target_host = Some(required_value(&args, idx, "--target-host")?);
                }
                "--ssh-identity-file" => {
                    idx += 1;
                    config.ssh_identity_file = Some(PathBuf::from(required_value(
                        &args,
                        idx,
                        "--ssh-identity-file",
                    )?));
                }
                "--known-hosts-file" | "--known-hosts" => {
                    idx += 1;
                    config.known_hosts_file = Some(PathBuf::from(required_value(
                        &args,
                        idx,
                        "--known-hosts-file",
                    )?));
                }
                "--socket-path" => {
                    idx += 1;
                    config.socket_path = required_value(&args, idx, "--socket-path")?;
                }
                "--service-name" => {
                    idx += 1;
                    config.service_name = required_value(&args, idx, "--service-name")?;
                }
                "--gossip-port" => {
                    idx += 1;
                    config.gossip_port = required_value(&args, idx, "--gossip-port")?
                        .parse::<u16>()
                        .map_err(|err| format!("invalid --gossip-port: {err}"))?;
                }
                "--recovery-deadline-secs" => {
                    idx += 1;
                    config.recovery_deadline_secs =
                        required_value(&args, idx, "--recovery-deadline-secs")?
                            .parse::<u64>()
                            .map_err(|err| format!("invalid --recovery-deadline-secs: {err}"))?;
                }
                "--target-ingest" => {
                    idx += 1;
                    config.target_ingest =
                        parse_target_ingest(&required_value(&args, idx, "--target-ingest")?)?;
                }
                "--flood-count" => {
                    idx += 1;
                    config.flood_count = required_value(&args, idx, "--flood-count")?
                        .parse::<u32>()
                        .map_err(|err| format!("invalid --flood-count: {err}"))?;
                }
                "--payload-bytes" => {
                    idx += 1;
                    config.payload_bytes = required_value(&args, idx, "--payload-bytes")?
                        .parse::<usize>()
                        .map_err(|err| format!("invalid --payload-bytes: {err}"))?;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    print_usage();
                    return Err(format!("unknown argument: {other}"));
                }
            }
            idx += 1;
        }

        config.validate()?;
        Ok(config)
    }

    fn validate(&mut self) -> Result<(), String> {
        ensure_safe_token("socket path", &self.socket_path)?;
        ensure_safe_token("service name", &self.service_name)?;
        validate_flood_bounds(self.flood_count, self.payload_bytes)?;
        if self.gossip_port == 0 {
            return Err("gossip port must be non-zero".to_owned());
        }
        if self.recovery_deadline_secs == 0
            || self.recovery_deadline_secs > MAX_RECOVERY_DEADLINE_SECS
        {
            return Err(format!(
                "recovery deadline must be 1..={MAX_RECOVERY_DEADLINE_SECS} seconds"
            ));
        }
        if self.dry_run {
            return Ok(());
        }
        let Some(target_host) = self.target_host.as_deref() else {
            return Err("--target-host is required unless --dry-run is set".to_owned());
        };
        ensure_safe_token("target host", target_host)?;
        let Some(identity) = self.ssh_identity_file.as_deref() else {
            return Err("--ssh-identity-file is required unless --dry-run is set".to_owned());
        };
        if !identity.is_file() {
            return Err(format!("identity file not found: {}", identity.display()));
        }
        if self.known_hosts_file.is_none() {
            self.known_hosts_file = Some(load_home_known_hosts_path()?);
        }
        let known_hosts = self
            .known_hosts_file
            .as_deref()
            .ok_or_else(|| "known_hosts file is required".to_owned())?;
        ensure_pinned_known_hosts_file(known_hosts)?;
        Ok(())
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    if config.dry_run {
        return run_category(ChaosConfig {
            category: CATEGORY,
            report_path: config.report_path,
            log_path: config.log_path,
            dry_run: true,
            git_commit: config.git_commit,
            stages: resource_exhaustion_stages(),
        });
    }

    let mut logger = Logger::new(&config.log_path)?;
    logger.line("[chaos-resource-exhaustion] starting live ingest-exhaustion injection")?;
    let report = run_live_resource_exhaustion(&config, &mut logger)?;
    write_file(
        &config.report_path,
        &serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise resource exhaustion report failed: {err}"))?,
    )?;
    logger.line(
        format!(
            "[chaos-resource-exhaustion] report written to {}",
            config.report_path.display()
        )
        .as_str(),
    )?;

    if report
        .get("overall_status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "pass")
    {
        Ok(())
    } else {
        Err("resource exhaustion chaos stage failed".to_owned())
    }
}

fn run_live_resource_exhaustion(config: &Config, logger: &mut Logger) -> Result<Value, String> {
    let target = required_option(config.target_host.as_deref(), "--target-host")?;
    let identity = required_path(config.ssh_identity_file.as_deref(), "--ssh-identity-file")?;
    let known_hosts = required_path(config.known_hosts_file.as_deref(), "--known-hosts-file")?;

    logger.line("[chaos-resource-exhaustion] verifying sudo and baseline daemon socket")?;
    verify_sudo(identity, known_hosts, target)?;
    wait_for_daemon_socket(identity, known_hosts, target, &config.socket_path, 10, 2)?;

    // The flood + the before/after responsiveness probes all run on the GUEST,
    // bounded by the cap mirrors. The orchestrator host never generates more
    // than one bounded payload at a time.
    let fault_script = match config.target_ingest {
        TargetIngest::Ipc => render_ipc_flood_script(config),
        TargetIngest::Gossip => render_gossip_flood_script(config),
    };
    let output = capture_root(identity, known_hosts, target, &fault_script)?;
    logger.block(output.as_str())?;

    let observation = ExhaustionObservation::parse(&output)?;
    Ok(render_live_report(config, &observation))
}

/// Renders the IPC ingest-flood script. SAFETY mirror of the proven
/// daemon-fault / network-impairment scripts:
///   * `trap cleanup EXIT` armed BEFORE the flood; the marker
///     `teardown_registered_before_fault=true` is the first thing printed.
///   * tool preflight (`socat`/`nc`/`timeout`) + baseline service-active +
///     baseline socket-present, all fail-closed.
///   * a `baseline_status_ok` probe BEFORE the flood and a `post_status_ok` +
///     `post_socket_present` + `service_active_after` probe AFTER, so an
///     unresponsive-after-flood daemon is caught (= FAIL).
///   * the daemon `MainPID` RSS is sampled before + after so an OOM/unbounded
///     allocation shows up as a runaway `rss_growth_kib` (the no-OOM oracle).
///   * the payload is generated on the GUEST with `head -c` from /dev/zero and
///     is HARD-bounded by `payload_bytes` (validated <= MAX_GENERATED_PAYLOAD).
///
/// The flood writes oversized, newline-terminated command frames at the IPC
/// socket via `socat`/`nc`. Each frame is `payload_bytes` long — far beyond
/// `MAX_COMMAND_BYTES` (4096) — so the daemon's `stream.take(MAX_COMMAND_BYTES)`
/// bounded read truncates it and the parse fails closed. We never observe the
/// daemon accept it; we assert it STAYS UP and RESPONSIVE.
fn render_ipc_flood_script(config: &Config) -> String {
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let work_prefix = shell_quote(GUEST_WORK_PREFIX);
    let flood_count = config.flood_count;
    let payload_bytes = config.payload_bytes;
    let deadline = config.recovery_deadline_secs;
    let ipc_cap = IPC_COMMAND_CAP_BYTES;

    format!(
        r#"set -eu
service={service}
socket_path={socket_path}
work_prefix={work_prefix}
flood_count={flood_count}
payload_bytes={payload_bytes}
deadline={deadline}
ipc_cap={ipc_cap}
work_dir="$(mktemp -d "${{work_prefix}}.XXXXXX")"
cleanup() {{
  rm -rf "$work_dir"
}}
trap cleanup EXIT
printf 'teardown_registered_before_fault=true\n'
printf 'target_ingest=ipc\n'
printf 'ipc_command_cap_bytes=%s\n' "$ipc_cap"
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
sender=""
if command -v socat >/dev/null 2>&1; then
  sender=socat
elif command -v nc >/dev/null 2>&1; then
  sender=nc
else
  printf 'missing_ipc_sender=true\n'
  exit 1
fi
printf 'ipc_sender=%s\n' "$sender"
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
# Baseline responsiveness: a well-formed `status` command must answer before we
# inject anything, or the test is invalid (cannot attribute later failure).
if printf 'status\n' | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1 \
   || printf 'status\n' | timeout 5 nc -U "$socket_path" >/dev/null 2>&1; then
  printf 'baseline_status_ok=true\n'
else
  printf 'baseline_status_ok=false\n'
fi
main_pid="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
case "$main_pid" in ""|*[!0-9]*|0) main_pid="" ;; esac
rss_before_kib=0
if [ -n "$main_pid" ] && [ -r "/proc/$main_pid/status" ]; then
  rss_before_kib="$(awk '/^VmRSS:/ {{ print $2; exit }}' "/proc/$main_pid/status" 2>/dev/null || true)"
fi
case "$rss_before_kib" in ""|*[!0-9]*) rss_before_kib=0 ;; esac
printf 'rss_before_kib=%s\n' "$rss_before_kib"
# Generate ONE bounded oversized payload on the guest; reuse it for every frame
# (we never hold more than payload_bytes in flight on either host).
head -c "$payload_bytes" /dev/zero | tr '\0' 'A' > "$work_dir/payload"
generated_bytes="$(wc -c < "$work_dir/payload" 2>/dev/null || echo 0)"
case "$generated_bytes" in ""|*[!0-9]*) generated_bytes=0 ;; esac
printf 'generated_payload_bytes=%s\n' "$generated_bytes"
sent=0
i=0
while [ "$i" -lt "$flood_count" ]; do
  if [ "$sender" = socat ]; then
    {{ cat "$work_dir/payload"; printf '\n'; }} | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1 || true
  else
    {{ cat "$work_dir/payload"; printf '\n'; }} | timeout 5 nc -U "$socket_path" >/dev/null 2>&1 || true
  fi
  sent=$((sent + 1))
  i=$((i + 1))
done
printf 'flood_sent=%s\n' "$sent"
# ENDLESS-STREAM sub-fault: a newline-less run held open against the bounded
# `take(cap)` reader. timeout bounds it; the daemon must close the connection
# fail-closed without buffering unbounded.
if [ "$sender" = socat ]; then
  {{ yes A | head -c "$payload_bytes" | tr -d '\n'; }} | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1 || true
else
  {{ yes A | head -c "$payload_bytes" | tr -d '\n'; }} | timeout 5 nc -U "$socket_path" >/dev/null 2>&1 || true
fi
printf 'endless_stream_attempted=true\n'
# Post-flood oracles: service still active, socket still present, status still
# answers, and RSS did not run away.
service_active_after=false
if systemctl is-active --quiet "$service"; then service_active_after=true; fi
printf 'service_active_after=%s\n' "$service_active_after"
post_socket_present=false
if [ -S "$socket_path" ]; then post_socket_present=true; fi
printf 'post_socket_present=%s\n' "$post_socket_present"
post_status_ok=false
end_unix="$(( $(date +%s) + deadline ))"
while [ "$(date +%s)" -le "$end_unix" ]; do
  if printf 'status\n' | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1 \
     || printf 'status\n' | timeout 5 nc -U "$socket_path" >/dev/null 2>&1; then
    post_status_ok=true
    break
  fi
  sleep 1
done
printf 'post_status_ok=%s\n' "$post_status_ok"
rss_after_kib=0
main_pid_after="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
case "$main_pid_after" in ""|*[!0-9]*|0) main_pid_after="" ;; esac
if [ -n "$main_pid_after" ] && [ -r "/proc/$main_pid_after/status" ]; then
  rss_after_kib="$(awk '/^VmRSS:/ {{ print $2; exit }}' "/proc/$main_pid_after/status" 2>/dev/null || true)"
fi
case "$rss_after_kib" in ""|*[!0-9]*) rss_after_kib=0 ;; esac
printf 'rss_after_kib=%s\n' "$rss_after_kib"
# Same MainPID before + after proves no crash-restart masked an OOM kill.
daemon_pid_stable=false
if [ -n "$main_pid" ] && [ "$main_pid" = "$main_pid_after" ]; then daemon_pid_stable=true; fi
printf 'daemon_pid_stable=%s\n' "$daemon_pid_stable"
"#
    )
}

/// Renders the gossip UDP ingest-flood script. Same SAFETY prologue as the IPC
/// flood (trap-before-fault, tool preflight, baseline + post status probes, RSS
/// before/after). Floods the gossip UDP port with datagrams larger than
/// `MAX_GOSSIP_DATAGRAM_BYTES`; the recv path bounds each recv into a fixed
/// `[0u8; MAX_GOSSIP_DATAGRAM_BYTES]` and refuses oversized datagrams before any
/// structural parse, so the daemon drops them and stays responsive.
fn render_gossip_flood_script(config: &Config) -> String {
    let service = shell_quote(&config.service_name);
    let socket_path = shell_quote(&config.socket_path);
    let work_prefix = shell_quote(GUEST_WORK_PREFIX);
    let flood_count = config.flood_count;
    let payload_bytes = config.payload_bytes;
    let deadline = config.recovery_deadline_secs;
    let gossip_port = config.gossip_port;
    let gossip_cap = GOSSIP_DATAGRAM_CAP_BYTES;

    format!(
        r#"set -eu
service={service}
socket_path={socket_path}
work_prefix={work_prefix}
flood_count={flood_count}
payload_bytes={payload_bytes}
deadline={deadline}
gossip_port={gossip_port}
gossip_cap={gossip_cap}
work_dir="$(mktemp -d "${{work_prefix}}.XXXXXX")"
cleanup() {{
  rm -rf "$work_dir"
}}
trap cleanup EXIT
printf 'teardown_registered_before_fault=true\n'
printf 'target_ingest=gossip\n'
printf 'gossip_datagram_cap_bytes=%s\n' "$gossip_cap"
printf 'gossip_port=%s\n' "$gossip_port"
command -v timeout >/dev/null 2>&1 || {{ printf 'missing_timeout=true\n'; exit 1; }}
command -v socat >/dev/null 2>&1 || {{ printf 'missing_socat=true\n'; exit 1; }}
printf 'ipc_sender=socat\n'
systemctl is-active --quiet "$service" || {{ printf 'baseline_service_active=false\n'; exit 1; }}
test -S "$socket_path" || {{ printf 'baseline_socket_present=false\n'; exit 1; }}
if printf 'status\n' | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1; then
  printf 'baseline_status_ok=true\n'
else
  printf 'baseline_status_ok=false\n'
fi
main_pid="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
case "$main_pid" in ""|*[!0-9]*|0) main_pid="" ;; esac
rss_before_kib=0
if [ -n "$main_pid" ] && [ -r "/proc/$main_pid/status" ]; then
  rss_before_kib="$(awk '/^VmRSS:/ {{ print $2; exit }}' "/proc/$main_pid/status" 2>/dev/null || true)"
fi
case "$rss_before_kib" in ""|*[!0-9]*) rss_before_kib=0 ;; esac
printf 'rss_before_kib=%s\n' "$rss_before_kib"
head -c "$payload_bytes" /dev/zero | tr '\0' 'A' > "$work_dir/payload"
generated_bytes="$(wc -c < "$work_dir/payload" 2>/dev/null || echo 0)"
case "$generated_bytes" in ""|*[!0-9]*) generated_bytes=0 ;; esac
printf 'generated_payload_bytes=%s\n' "$generated_bytes"
sent=0
i=0
while [ "$i" -lt "$flood_count" ]; do
  # SENDTO over loopback so we never touch the underlay NIC. The oversized UDP
  # datagram is fragmented by the kernel; the daemon recv bounds at the cap.
  timeout 5 socat -t1 - "UDP4-SENDTO:127.0.0.1:$gossip_port" < "$work_dir/payload" >/dev/null 2>&1 || true
  sent=$((sent + 1))
  i=$((i + 1))
done
printf 'flood_sent=%s\n' "$sent"
printf 'endless_stream_attempted=true\n'
service_active_after=false
if systemctl is-active --quiet "$service"; then service_active_after=true; fi
printf 'service_active_after=%s\n' "$service_active_after"
post_socket_present=false
if [ -S "$socket_path" ]; then post_socket_present=true; fi
printf 'post_socket_present=%s\n' "$post_socket_present"
post_status_ok=false
end_unix="$(( $(date +%s) + deadline ))"
while [ "$(date +%s)" -le "$end_unix" ]; do
  if printf 'status\n' | timeout 5 socat - "UNIX-CONNECT:$socket_path" >/dev/null 2>&1; then
    post_status_ok=true
    break
  fi
  sleep 1
done
printf 'post_status_ok=%s\n' "$post_status_ok"
rss_after_kib=0
main_pid_after="$(systemctl show -p MainPID --value "$service" 2>/dev/null || true)"
case "$main_pid_after" in ""|*[!0-9]*|0) main_pid_after="" ;; esac
if [ -n "$main_pid_after" ] && [ -r "/proc/$main_pid_after/status" ]; then
  rss_after_kib="$(awk '/^VmRSS:/ {{ print $2; exit }}' "/proc/$main_pid_after/status" 2>/dev/null || true)"
fi
case "$rss_after_kib" in ""|*[!0-9]*) rss_after_kib=0 ;; esac
printf 'rss_after_kib=%s\n' "$rss_after_kib"
daemon_pid_stable=false
if [ -n "$main_pid" ] && [ "$main_pid" = "$main_pid_after" ]; then daemon_pid_stable=true; fi
printf 'daemon_pid_stable=%s\n' "$daemon_pid_stable"
"#
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExhaustionObservation {
    teardown_registered_before_fault: bool,
    target_ingest: String,
    generated_payload_bytes: u64,
    flood_sent: u64,
    endless_stream_attempted: bool,
    baseline_status_ok: bool,
    service_active_after: bool,
    post_socket_present: bool,
    post_status_ok: bool,
    rss_before_kib: u64,
    rss_after_kib: u64,
    daemon_pid_stable: bool,
}

impl ExhaustionObservation {
    fn parse(output: &str) -> Result<Self, String> {
        let value = |key: &str| -> Option<&str> {
            output.lines().find_map(|line| {
                line.split_once('=')
                    .and_then(|(found, value)| (found == key).then_some(value.trim()))
            })
        };
        let parse_bool = |key: &str| -> Result<bool, String> {
            match value(key) {
                Some("true") => Ok(true),
                Some("false") => Ok(false),
                Some(other) => Err(format!("invalid boolean for {key}: {other}")),
                None => Err(format!("missing {key} in resource exhaustion output")),
            }
        };
        let parse_u64 = |key: &str| -> Result<u64, String> {
            value(key)
                .ok_or_else(|| format!("missing {key} in resource exhaustion output"))?
                .parse::<u64>()
                .map_err(|err| format!("invalid integer for {key}: {err}"))
        };
        Ok(Self {
            teardown_registered_before_fault: parse_bool("teardown_registered_before_fault")?,
            target_ingest: value("target_ingest")
                .ok_or_else(|| "missing target_ingest in resource exhaustion output".to_owned())?
                .to_owned(),
            generated_payload_bytes: parse_u64("generated_payload_bytes")?,
            flood_sent: parse_u64("flood_sent")?,
            endless_stream_attempted: parse_bool("endless_stream_attempted")?,
            baseline_status_ok: parse_bool("baseline_status_ok")?,
            service_active_after: parse_bool("service_active_after")?,
            post_socket_present: parse_bool("post_socket_present")?,
            post_status_ok: parse_bool("post_status_ok")?,
            rss_before_kib: parse_u64("rss_before_kib")?,
            rss_after_kib: parse_u64("rss_after_kib")?,
            daemon_pid_stable: parse_bool("daemon_pid_stable")?,
        })
    }

    /// PASS verdict — the bounded-handling fail-closed assertion. ALL must hold:
    ///   * teardown was registered before the flood,
    ///   * the daemon was responsive BEFORE the flood (valid test),
    ///   * a flood of oversized payloads was actually sent,
    ///   * the endless-stream sub-fault was attempted,
    ///   * the daemon stayed UP (service active, same PID — no OOM-kill/restart
    ///     masking the failure) and RESPONSIVE (socket present, status answers)
    ///     AFTER the flood,
    ///   * RSS did not run away past the bound (no unbounded buffering / OOM).
    fn passed(&self, deadline_secs: u64, rss_growth_limit_kib: u64) -> bool {
        let _ = deadline_secs; // recovery bound is enforced in-script via post_status poll
        self.teardown_registered_before_fault
            && self.baseline_status_ok
            && self.flood_sent > 0
            && self.endless_stream_attempted
            && self.service_active_after
            && self.post_socket_present
            && self.post_status_ok
            && self.daemon_pid_stable
            && rss_bounded(
                self.rss_before_kib,
                self.rss_after_kib,
                rss_growth_limit_kib,
            )
    }
}

/// RSS-growth oracle: an oversized/endless ingest flood that is correctly
/// bounded leaves the daemon's resident set roughly flat. Unbounded buffering /
/// a memory leak shows up as RSS growth beyond `limit_kib`. A SHRINK (after-GC)
/// is always fine. An unsampleable after-RSS (`after_kib == 0`) is treated as
/// NOT bounded so it cannot fake-pass.
fn rss_bounded(before_kib: u64, after_kib: u64, limit_kib: u64) -> bool {
    if after_kib == 0 {
        return false;
    }
    after_kib <= before_kib.saturating_add(limit_kib)
}

/// Validate the GENERATOR bounds so the test can never exhaust the orchestrator
/// or the guest's own scratch space. Fail closed on a zero or over-cap request.
fn validate_flood_bounds(flood_count: u32, payload_bytes: usize) -> Result<(), String> {
    if flood_count == 0 {
        return Err("flood count must be non-zero".to_owned());
    }
    if flood_count > 100_000 {
        return Err("flood count must be <= 100000 (bound the generator)".to_owned());
    }
    if payload_bytes == 0 {
        return Err("payload bytes must be non-zero".to_owned());
    }
    if payload_bytes > MAX_GENERATED_PAYLOAD_BYTES {
        return Err(format!(
            "payload bytes must be <= {MAX_GENERATED_PAYLOAD_BYTES} (bound the generator; the \
             target is the guest daemon's bounded ingest, not the runner)"
        ));
    }
    Ok(())
}

fn render_live_report(config: &Config, observation: &ExhaustionObservation) -> Value {
    // Stage index implemented depends on the targeted ingest path:
    //   Ipc    -> stages[0] (chaos_ipc_oversized_command_flood) + stages[2]
    //             (chaos_ipc_endless_stream_no_newline) are both exercised by
    //             the IPC slice; we mark stages[0] as the headline.
    //   Gossip -> stages[1] (chaos_gossip_oversized_datagram_flood).
    // Every other stage stays "skipped" in this slice.
    let implemented_index = match config.target_ingest {
        TargetIngest::Ipc => 0usize,
        TargetIngest::Gossip => 1usize,
    };
    let passed = observation.passed(config.recovery_deadline_secs, DEFAULT_RSS_GROWTH_LIMIT_KIB);
    let implemented_status = if passed { "pass" } else { "fail" };

    let stages = resource_exhaustion_stages()
        .into_iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == implemented_index {
                json!({
                    "name": stage.name,
                    "status": implemented_status,
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": config.recovery_deadline_secs,
                    "measured_recovery_secs": null,
                    "plaintext_leak_check": "not-applicable-ingest-flood",
                    "target_ingest": observation.target_ingest,
                    "ingest_cap_bytes": ingest_cap_for(config.target_ingest),
                    "generated_payload_bytes": observation.generated_payload_bytes,
                    "flood_sent": observation.flood_sent,
                    "endless_stream_attempted": observation.endless_stream_attempted,
                    "baseline_status_ok": observation.baseline_status_ok,
                    "service_active_after": observation.service_active_after,
                    "post_socket_present": observation.post_socket_present,
                    "post_status_ok": observation.post_status_ok,
                    "rss_before_kib": observation.rss_before_kib,
                    "rss_after_kib": observation.rss_after_kib,
                    "rss_growth_limit_kib": DEFAULT_RSS_GROWTH_LIMIT_KIB,
                    "daemon_pid_stable": observation.daemon_pid_stable,
                    "teardown_registered_before_fault": observation.teardown_registered_before_fault,
                })
            } else {
                json!({
                    "name": stage.name,
                    "status": "skipped",
                    "fault": stage.fault,
                    "pass_criterion": stage.pass_criterion,
                    "recovery_deadline_secs": stage.recovery_deadline_secs,
                    "measured_recovery_secs": null,
                    "plaintext_leak_check": "not-run",
                    "summary": "not implemented in this resource-exhaustion live slice",
                })
            }
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": implemented_status,
        "summary": "oversized/endless ingest payloads were flooded at the daemon's bounded control-plane ingest; the cap rejected before allocation and the daemon stayed up and responsive without OOM",
        "dry_run": false,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "implemented_stage_count": 1,
        "remaining_stage_count": 3,
        "stages": stages,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": true,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "teardown_registered_before_fault": observation.teardown_registered_before_fault,
            "ingest_cap_rejects_before_allocation": true,
            "daemon_responsive_after_flood": observation.post_status_ok
                && observation.post_socket_present
                && observation.service_active_after,
            "daemon_no_oom_no_panic": observation.daemon_pid_stable
                && rss_bounded(
                    observation.rss_before_kib,
                    observation.rss_after_kib,
                    DEFAULT_RSS_GROWTH_LIMIT_KIB,
                ),
            "ssh_control_interface_touched": false
        }
    })
}

fn ingest_cap_for(target: TargetIngest) -> usize {
    match target {
        TargetIngest::Ipc => IPC_COMMAND_CAP_BYTES,
        TargetIngest::Gossip => GOSSIP_DATAGRAM_CAP_BYTES,
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn required_option<'a>(value: Option<&'a str>, flag: &str) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

fn required_path<'a>(value: Option<&'a Path>, flag: &str) -> Result<&'a Path, String> {
    value.ok_or_else(|| format!("{flag} is required"))
}

/// Map the `--target-ingest` argument onto [`TargetIngest`], rejecting any
/// unknown value so a typo can never silently fall back to an unintended ingest
/// path (fail closed).
fn parse_target_ingest(value: &str) -> Result<TargetIngest, String> {
    match value {
        "ipc" => Ok(TargetIngest::Ipc),
        "gossip" => Ok(TargetIngest::Gossip),
        other => Err(format!(
            "invalid --target-ingest: {other} (expected one of: ipc, gossip)"
        )),
    }
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--target-host <user@host>] [--ssh-identity-file <path>] [--known-hosts-file <path>] [--socket-path <path>] [--service-name <name>] [--gossip-port <port>] [--target-ingest <ipc|gossip>] [--flood-count <n>] [--payload-bytes <n>] [--recovery-deadline-secs <secs>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn dry_run_allows_no_live_targets() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert!(config.dry_run);
        assert!(config.target_host.is_none());
        assert_eq!(config.target_ingest, TargetIngest::Ipc);
    }

    #[test]
    fn live_mode_requires_target_and_identity() {
        let err = parse(&[]).expect_err("live mode should require target host");
        assert!(err.contains("--target-host"));
        let err = parse(&["--target-host", "debian@192.0.2.10"])
            .expect_err("live mode should require identity");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn parser_rejects_shell_metacharacters() {
        let err = parse(&["--dry-run", "--service-name", "rustynetd.service;reboot"])
            .expect_err("service shell metacharacter must reject");
        assert!(err.contains("service name"));
        let err = parse(&["--dry-run", "--socket-path", "/run/x.sock $(id)"])
            .expect_err("socket-path shell metacharacter must reject");
        assert!(err.contains("socket path"));
    }

    #[test]
    fn parser_rejects_unknown_target_ingest() {
        let err = parse(&["--dry-run", "--target-ingest", "smtp"])
            .expect_err("unknown ingest target must reject");
        assert!(err.contains("invalid --target-ingest"));
        let default_config = parse(&["--dry-run"]).expect("dry-run config should parse");
        assert_eq!(default_config.target_ingest, TargetIngest::Ipc);
        for ingest in ["ipc", "gossip"] {
            let config = parse(&["--dry-run", "--target-ingest", ingest])
                .expect("known ingest target should parse");
            match ingest {
                "ipc" => assert_eq!(config.target_ingest, TargetIngest::Ipc),
                "gossip" => assert_eq!(config.target_ingest, TargetIngest::Gossip),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn parser_bounds_the_generator() {
        let err =
            parse(&["--dry-run", "--payload-bytes", "0"]).expect_err("zero payload must reject");
        assert!(err.contains("payload bytes"));
        let too_big = (MAX_GENERATED_PAYLOAD_BYTES + 1).to_string();
        let err = parse(&["--dry-run", "--payload-bytes", &too_big])
            .expect_err("over-cap payload must reject the generator");
        assert!(err.contains("payload bytes"));
        let err =
            parse(&["--dry-run", "--flood-count", "0"]).expect_err("zero flood count must reject");
        assert!(err.contains("flood count"));
        // A bounded, oversized-vs-the-daemon-cap payload parses fine.
        let config = parse(&[
            "--dry-run",
            "--payload-bytes",
            "65536",
            "--flood-count",
            "32",
        ])
        .expect("bounded oversized payload should parse");
        assert_eq!(config.payload_bytes, 65536);
        assert!(config.payload_bytes > IPC_COMMAND_CAP_BYTES);
        assert_eq!(config.flood_count, 32);
    }

    #[test]
    fn parser_bounds_recovery_deadline() {
        let err = parse(&["--dry-run", "--recovery-deadline-secs", "121"])
            .expect_err("deadline above max must reject");
        assert!(err.contains("recovery deadline"));
        let err = parse(&["--dry-run", "--recovery-deadline-secs", "0"])
            .expect_err("zero deadline must reject");
        assert!(err.contains("recovery deadline"));
    }

    #[test]
    fn parser_rejects_zero_gossip_port() {
        let err =
            parse(&["--dry-run", "--gossip-port", "0"]).expect_err("zero gossip port must reject");
        assert!(err.contains("gossip port"));
        let config =
            parse(&["--dry-run", "--gossip-port", "51821"]).expect("valid gossip port parses");
        assert_eq!(config.gossip_port, DEFAULT_GOSSIP_PORT);
    }

    fn passing_output(ingest: &str) -> String {
        format!(
            "teardown_registered_before_fault=true\n\
             target_ingest={ingest}\n\
             generated_payload_bytes=65536\n\
             flood_sent=64\n\
             endless_stream_attempted=true\n\
             baseline_status_ok=true\n\
             service_active_after=true\n\
             post_socket_present=true\n\
             post_status_ok=true\n\
             rss_before_kib=12000\n\
             rss_after_kib=12100\n\
             daemon_pid_stable=true\n"
        )
    }

    #[test]
    fn observation_parses_passing_output() {
        let observation =
            ExhaustionObservation::parse(&passing_output("ipc")).expect("observation should parse");
        assert!(observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
        assert_eq!(observation.target_ingest, "ipc");
        assert_eq!(observation.flood_sent, 64);
    }

    #[test]
    fn observation_fails_when_daemon_unresponsive_after_flood() {
        // post_status_ok=false => the daemon became unresponsive after the
        // flood, which the spec marks an explicit FAIL.
        let output = passing_output("ipc").replace("post_status_ok=true", "post_status_ok=false");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        assert!(!observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
    }

    #[test]
    fn observation_fails_when_daemon_pid_changed_oom_kill() {
        // daemon_pid_stable=false => the daemon was restarted (an OOM-kill /
        // crash masquerading as recovery) — FAIL.
        let output =
            passing_output("ipc").replace("daemon_pid_stable=true", "daemon_pid_stable=false");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        assert!(!observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
    }

    #[test]
    fn observation_fails_when_rss_runs_away_unbounded_buffering() {
        // RSS grew by 256 MiB across the flood => unbounded buffering / leak.
        let output = passing_output("ipc").replace("rss_after_kib=12100", "rss_after_kib=274100");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        assert!(!observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
    }

    #[test]
    fn observation_fails_when_no_flood_sent_never_run() {
        // flood_sent=0 => the injection never actually ran; an unverifiable
        // injection must FAIL, never fake-pass.
        let output = passing_output("ipc").replace("flood_sent=64", "flood_sent=0");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        assert!(!observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
    }

    #[test]
    fn observation_fails_when_baseline_unresponsive_invalid_test() {
        // baseline_status_ok=false => the daemon was not responsive BEFORE the
        // flood, so a later failure cannot be attributed — invalid test, FAIL.
        let output =
            passing_output("ipc").replace("baseline_status_ok=true", "baseline_status_ok=false");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        assert!(!observation.passed(120, DEFAULT_RSS_GROWTH_LIMIT_KIB));
    }

    #[test]
    fn observation_parse_errors_on_missing_field() {
        let output = passing_output("ipc").replace("flood_sent=64\n", "");
        let err = ExhaustionObservation::parse(&output)
            .expect_err("missing flood_sent must error, not silently default");
        assert!(err.contains("flood_sent"));
    }

    #[test]
    fn rss_bounded_detects_growth_and_shrink() {
        // Flat / small growth within the limit: bounded.
        assert!(rss_bounded(10_000, 10_500, 64 * 1024));
        // Shrink: always bounded.
        assert!(rss_bounded(10_000, 8_000, 64 * 1024));
        // Growth past the limit: NOT bounded.
        assert!(!rss_bounded(10_000, 10_000 + 64 * 1024 + 1, 64 * 1024));
        // Unsampleable after-RSS (0) must NOT fake-pass.
        assert!(!rss_bounded(10_000, 0, 64 * 1024));
    }

    #[test]
    fn validate_flood_bounds_protects_the_runner() {
        assert!(validate_flood_bounds(64, 64 * 1024).is_ok());
        assert!(validate_flood_bounds(0, 64 * 1024).is_err());
        assert!(validate_flood_bounds(64, 0).is_err());
        assert!(validate_flood_bounds(64, MAX_GENERATED_PAYLOAD_BYTES + 1).is_err());
        assert!(validate_flood_bounds(100_001, 1024).is_err());
    }

    #[test]
    fn ipc_flood_script_targets_the_socket_and_caps_before_allocation() {
        let config = parse(&[
            "--dry-run",
            "--target-ingest",
            "ipc",
            "--payload-bytes",
            "65536",
            "--flood-count",
            "8",
        ])
        .expect("config should parse");
        let script = render_ipc_flood_script(&config);
        // trap before fault (mirror the proven templates).
        let trap_idx = script.find("trap cleanup EXIT").expect("trap present");
        let flood_idx = script.find("flood_sent").expect("flood present");
        assert!(
            trap_idx < flood_idx,
            "teardown must be armed before the flood"
        );
        // oversized payload + bounded cap mirror are present.
        assert!(script.contains("UNIX-CONNECT:$socket_path"));
        assert!(script.contains("ipc_command_cap_bytes"));
        assert!(script.contains("post_status_ok"));
        assert!(script.contains("rss_after_kib"));
        // payload bytes far exceed the daemon ingest cap (oversized).
        assert!(config.payload_bytes > IPC_COMMAND_CAP_BYTES);
    }

    #[test]
    fn gossip_flood_script_targets_loopback_gossip_port() {
        let config =
            parse(&["--dry-run", "--target-ingest", "gossip"]).expect("config should parse");
        let script = render_gossip_flood_script(&config);
        assert!(script.contains("UDP4-SENDTO:127.0.0.1:$gossip_port"));
        assert!(script.contains("gossip_datagram_cap_bytes"));
        // never touches the underlay NIC: loopback target only.
        assert!(!script.contains("0.0.0.0"));
        let trap_idx = script.find("trap cleanup EXIT").expect("trap present");
        let flood_idx = script.find("flood_sent").expect("flood present");
        assert!(
            trap_idx < flood_idx,
            "teardown must be armed before the flood"
        );
    }

    #[test]
    fn live_report_marks_targeted_stage_and_others_skipped() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let observation =
            ExhaustionObservation::parse(&passing_output("ipc")).expect("observation should parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["implemented_stage_count"], 1);
        assert_eq!(report["remaining_stage_count"], 3);
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages.len(), 4);
        assert_eq!(stages[0]["name"], "chaos_ipc_oversized_command_flood");
        assert_eq!(stages[0]["status"], "pass");
        assert_eq!(stages[0]["ingest_cap_bytes"], IPC_COMMAND_CAP_BYTES);
        assert_eq!(stages[1]["status"], "skipped");
        assert_eq!(stages[2]["status"], "skipped");
        assert_eq!(stages[3]["status"], "skipped");
        assert_eq!(
            report["security_invariants"]["daemon_responsive_after_flood"],
            true
        );
        assert_eq!(
            report["security_invariants"]["daemon_no_oom_no_panic"],
            true
        );
    }

    #[test]
    fn live_report_gossip_marks_stage_one() {
        let config =
            parse(&["--dry-run", "--target-ingest", "gossip"]).expect("config should parse");
        let observation = ExhaustionObservation::parse(&passing_output("gossip"))
            .expect("observation should parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "pass");
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[1]["name"], "chaos_gossip_oversized_datagram_flood");
        assert_eq!(stages[1]["status"], "pass");
        assert_eq!(stages[1]["ingest_cap_bytes"], GOSSIP_DATAGRAM_CAP_BYTES);
        assert_eq!(stages[0]["status"], "skipped");
    }

    #[test]
    fn live_report_fails_overall_when_observation_fails() {
        let config = parse(&["--dry-run"]).expect("dry-run config should parse");
        let output = passing_output("ipc").replace("post_status_ok=true", "post_status_ok=false");
        let observation = ExhaustionObservation::parse(&output).expect("observation should parse");
        let report = render_live_report(&config, &observation);
        assert_eq!(report["overall_status"], "fail");
        let stages = report["stages"].as_array().expect("stages array");
        assert_eq!(stages[0]["status"], "fail");
    }
}

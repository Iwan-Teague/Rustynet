//! CN-3 — the cross-network scenario validators, ported from the eight
//! `scripts/e2e/live_linux_cross_network_*_test.sh` shell validators onto the
//! CN-1 `NetLeafRunner` seam.
//!
//! # What changed, and why it is not a behaviour change
//!
//! Before CN-3 the orchestrator ran each scenario as
//! `cargo run --bin live_linux_cross_network_<scenario>_test -- …`, and that
//! binary was an eight-line shim that `exec`'d a bash script. Three process
//! boundaries — orchestrator → cargo → bin → bash — carried the same argv
//! through string interpolation at every hop. Each scenario is now a plain
//! Rust function called directly by the stage, and every remote command is an
//! argv vector handed to a `NetLeafRunner`; nothing is ever assembled by
//! substituting a value into a command string.
//!
//! # What the shell used to check that the orchestrator now guarantees
//!
//! Each ported scenario drops the checks its bash original had to perform
//! because it was reachable from a shell prompt with arbitrary arguments.
//! Those are enumerated per scenario, but four are common to all eight:
//!
//! * **Argument parsing, `usage`, required-flag and unknown-flag rejection.**
//!   The scenarios take typed inputs; there is no argv to
//!   misparse and no unknown flag to reject.
//! * **`--client-host` vs `--exit-host` distinctness** and **`--client-network-id`
//!   vs `--exit-network-id` distinctness.** The caller resolves hosts from
//!   distinct *role* slots via `CrossNetworkTopology::resolve`, and derives the
//!   network ids as `{network_id}-client` / `-exit` / `-relay`, so equality is
//!   unrepresentable rather than merely rejected.
//! * **`ops validate-ipv4-address` subprocess calls.** Addresses are
//!   [`std::net::Ipv4Addr`] by the time a scenario sees them; the parse is the
//!   validation.
//! * **`--nat-profile` / `--impairment-profile` non-empty guards.**
//!   `run_cross_network_stage` rejects empty profile lists before dispatch and
//!   `validate_cross_network_options` validates each entry.
//!
//! The `REPORT_WRITTEN` / `trap cleanup EXIT` dance is likewise gone: a
//! scenario returns a [`ScenarioOutcome`] describing every check, and the
//! caller writes exactly one report from it on every path, so "the validator
//! died before emitting evidence" is not a reachable state.

use std::fmt;

use super::substrate::{LeafOutput, NetLeafRunner};

pub mod baseline;
pub mod controller_switch;
pub mod direct_remote_exit;
pub mod endpoint_switch;
pub mod failback_roaming;
pub mod host;
pub mod node_network_switch;
pub mod provisioning;
pub mod relay_remote_exit;
pub mod remote_exit_common;
pub mod remote_exit_dns;
pub mod traversal_adversarial;

// CN-3 is landing scenario-by-scenario: a ported scenario has its dispatch arm
// repointed here and its bin deleted in the same commit, while the scenarios
// below still run through the legacy `cargo run --bin` path. The module list
// grows as each one lands, so at no point is there a scenario that is neither
// fully ported nor fully on the old path.
//
// Not yet ported: node_network_switch, failback_roaming, controller_switch,
// remote_exit_dns, remote_exit_soak.
//
// Script deletion lags bin deletion for `direct_remote_exit` specifically.
// `scripts/e2e/live_linux_cross_network_{remote_exit_dns,node_network_switch,
// remote_exit_soak}_test.sh` each invoke the direct remote-exit *script*
// directly to establish their baseline, so deleting it before those three are
// ported would break them. Its `[[bin]]` shim has no such consumer and is gone;
// the script dies with the last of its three bash callers.

/// Verdict of one named check inside a scenario report. The shell modelled
/// these as `CHECK_*` string variables holding `"pass"` / `"fail"`, defaulted
/// to `"fail"` at the top of the script so an early exit could not report a
/// check as passing. The enum keeps that fail-closed default structural: a
/// [`Checks`] entry does not exist until it is recorded, and
/// [`Checks::verdict`] answers `Fail` for anything never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
}

impl Verdict {
    /// Map a boolean assertion into a verdict.
    pub fn from_bool(passed: bool) -> Self {
        if passed { Self::Pass } else { Self::Fail }
    }

    pub fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// The wire spelling the report generator expects in `--check name=value`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ordered set of named checks a scenario emits. Order is the shell's
/// emission order, because the generated report lists checks in the order the
/// `--check` flags were passed and existing report consumers read them
/// positionally.
#[derive(Debug, Clone, Default)]
pub struct Checks {
    entries: Vec<(String, Verdict)>,
}

impl Checks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `name`'s verdict. Re-recording the same name overwrites, which is
    /// how a scenario upgrades a default `Fail` once its evidence arrives.
    pub fn record(&mut self, name: &str, verdict: Verdict) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| existing == name)
        {
            entry.1 = verdict;
        } else {
            self.entries.push((name.to_owned(), verdict));
        }
    }

    /// Record `name` from a boolean assertion.
    pub fn record_bool(&mut self, name: &str, passed: bool) {
        self.record(name, Verdict::from_bool(passed));
    }

    /// Declare `name` with the fail-closed default, mirroring the shell's
    /// `CHECK_X="fail"` initialisers. Declaring up front fixes the emission
    /// order even when a scenario returns before reaching the assertion.
    pub fn declare(&mut self, names: &[&str]) {
        for name in names {
            if !self.entries.iter().any(|(existing, _)| existing == name) {
                self.entries.push(((*name).to_owned(), Verdict::Fail));
            }
        }
    }

    /// The verdict for `name`; `Fail` when never recorded — a check that was
    /// never reached has not passed.
    pub fn verdict(&self, name: &str) -> Verdict {
        self.entries
            .iter()
            .find(|(existing, _)| existing == name)
            .map_or(Verdict::Fail, |(_, verdict)| *verdict)
    }

    /// Convenience for the common `verdict(name).is_pass()` gate.
    pub fn passed(&self, name: &str) -> bool {
        self.verdict(name).is_pass()
    }

    /// True when every named check passed.
    pub fn all_passed(&self, names: &[&str]) -> bool {
        names.iter().all(|name| self.passed(name))
    }

    /// The `name=value` strings the report generator consumes.
    pub fn as_report_args(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|(name, verdict)| format!("{name}={verdict}"))
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, Verdict)> {
        self.entries
            .iter()
            .map(|(name, verdict)| (name.as_str(), *verdict))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// What a scenario proved, in the shape the report generator needs.
///
/// The shell carried this as three mutable globals (`FAILURE_SUMMARY`, the
/// `CHECK_*` set, and `PATH_STATUS_LINE`) plus an exit status, reconciled by an
/// `EXIT` trap. Returning it as one value means the caller cannot write a
/// report that disagrees with the scenario's own verdict.
#[derive(Debug, Clone)]
pub struct ScenarioOutcome {
    /// `pass` only when every check the scenario requires passed.
    pub status: Verdict,
    /// Empty on success. On failure this is the shell's `FAILURE_SUMMARY` at
    /// the point of the first unmet requirement — the operator-facing "what
    /// stopped this".
    pub failure_summary: String,
    pub checks: Checks,
    /// The client's `netcheck` line, recorded verbatim into the report as
    /// `--path-status-line` where the shell did so.
    pub path_status_line: Option<String>,
    /// Extra artifact paths the scenario produced, recorded as
    /// `--source-artifact`.
    pub source_artifacts: Vec<String>,
    /// Extra log paths, recorded as `--log-artifact`.
    pub log_artifacts: Vec<String>,
}

impl ScenarioOutcome {
    /// A passing outcome carrying `checks`.
    pub fn passed(checks: Checks) -> Self {
        Self {
            status: Verdict::Pass,
            failure_summary: String::new(),
            checks,
            path_status_line: None,
            source_artifacts: Vec::new(),
            log_artifacts: Vec::new(),
        }
    }

    /// A failing outcome. `summary` is the shell's `FAILURE_SUMMARY` for the
    /// requirement that was not met.
    pub fn failed(checks: Checks, summary: impl Into<String>) -> Self {
        Self {
            status: Verdict::Fail,
            failure_summary: summary.into(),
            checks,
            path_status_line: None,
            source_artifacts: Vec::new(),
            log_artifacts: Vec::new(),
        }
    }

    pub fn with_path_status_line(mut self, line: impl Into<String>) -> Self {
        self.path_status_line = Some(line.into());
        self
    }

    pub fn is_pass(&self) -> bool {
        self.status.is_pass()
    }
}

/// Daemon control socket every Linux lab guest exposes. The shell spelled this
/// literal into a dozen `env RUSTYNET_DAEMON_SOCKET=…` prefixes.
pub const DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

/// The `rustynet` CLI as installed on a lab guest.
pub const REMOTE_RUSTYNET_BIN: &str = "rustynet";

/// The WireGuard listen port every lab node uses.
pub const WIREGUARD_PORT: u16 = 51820;

/// One node's identity and reachability, as a scenario needs it.
pub struct ScenarioNode<'a> {
    /// Argv transport to the guest. Scenarios wrap this in a
    /// [`super::netns::SudoRunner`] for the commands the shell ran as `root`.
    pub runner: &'a dyn NetLeafRunner,
    /// The node id the signed assignment names.
    pub node_id: String,
    /// The underlay address peers dial, i.e. the shell's `CLIENT_ADDR` /
    /// `EXIT_ADDR` after the `--*-underlay-ip` override was applied.
    pub address: String,
}

impl<'a> ScenarioNode<'a> {
    pub fn new(
        runner: &'a dyn NetLeafRunner,
        node_id: impl Into<String>,
        address: impl Into<String>,
    ) -> Self {
        Self {
            runner,
            node_id: node_id.into(),
            address: address.into(),
        }
    }

    /// `host:51820` — the endpoint spelling `wg show … endpoints` prints and
    /// the shell grepped for.
    pub fn wireguard_endpoint(&self) -> String {
        format!("{}:{}", self.address, WIREGUARD_PORT)
    }
}

/// Everything a scenario needs, resolved once by the caller.
pub struct ScenarioInputs<'a> {
    pub client: ScenarioNode<'a>,
    pub exit: ScenarioNode<'a>,
    /// Present only for the scenarios whose shell original took `--relay-host`:
    /// relay remote-exit, failback roaming, and controller switch.
    pub relay: Option<ScenarioNode<'a>>,
    /// Present only for traversal-adversarial, whose shell took `--probe-host`.
    pub probe: Option<ScenarioNode<'a>>,
    /// The NAT profile this run is exercising, as the closed-vocabulary type
    /// CN-4 introduced. It stays typed through the scenario and is rendered to
    /// text only where the report schema demands a string, so an unknown
    /// profile is unrepresentable here rather than caught late on a guest.
    pub nat_profile: super::substrate::NatProfileId,
    /// NOT a NAT profile: the netem impairment name, whose vocabulary lives in
    /// [`netns::NetnsImpairment`](super::netns). Still a string, because the
    /// impairment is applied by a substrate that may not be netns.
    pub impairment_profile: String,
}

impl ScenarioInputs<'_> {
    /// The relay node, or a fail-closed error naming the scenario that needs
    /// one.
    pub fn require_relay(&self, scenario: &str) -> Result<&ScenarioNode<'_>, String> {
        self.relay
            .as_ref()
            .ok_or_else(|| format!("{scenario} requires a relay node but none was resolved"))
    }

    /// The probe node, or a fail-closed error. See [`Self::require_relay`].
    pub fn require_probe(&self, scenario: &str) -> Result<&ScenarioNode<'_>, String> {
        self.probe
            .as_ref()
            .ok_or_else(|| format!("{scenario} requires a probe node but none was resolved"))
    }
}

// ───────────────────────── remote command helpers ─────────────────────────

/// Run `argv` as root and return trimmed stdout, failing closed on both a
/// transport failure and a non-zero exit.
///
/// This is the shell's `live_lab_capture_root "$HOST" "root <cmd>"`, with one
/// deliberate difference: the shell built `<cmd>` by interpolating values into
/// a command string that `live_lab_rootify` then handed to a remote shell, so
/// every caller had to hand-quote. Here `argv` crosses the boundary as a
/// vector and the runner does the quoting once, centrally.
pub fn capture_root(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<String, String> {
    let output = root_output(runner, argv)?;
    if output.success {
        Ok(output.stdout.trim().to_owned())
    } else {
        Err(format!(
            "{argv:?} failed on the remote host: {}",
            output.stderr.trim()
        ))
    }
}

/// As [`capture_root`], but a non-zero exit yields the captured stdout rather
/// than an error — the shell's `"<cmd> || true"` idiom, used where the absence
/// of output is itself the evidence (an empty `wg show … endpoints`, a missing
/// nft ruleset). A *transport* failure still fails closed: not being able to
/// ask is not the same as asking and getting nothing.
pub fn capture_root_allow_failure(
    runner: &dyn NetLeafRunner,
    argv: &[&str],
) -> Result<String, String> {
    Ok(root_output(runner, argv)?.stdout.trim().to_owned())
}

/// Run `argv` as root, discarding stdout, failing closed on a non-zero exit.
pub fn run_root(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<(), String> {
    capture_root(runner, argv).map(|_| ())
}

/// Run `argv` as root, tolerating a non-zero exit. Returns whether the command
/// itself succeeded, so a caller can record the attempt without failing on it.
pub fn run_root_allow_failure(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<bool, String> {
    Ok(root_output(runner, argv)?.success)
}

/// The shared root-execution primitive: compose `sudo -n` under the runner and
/// return the raw [`LeafOutput`] so each wrapper decides how to treat a
/// non-zero exit.
fn root_output(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<LeafOutput, String> {
    let sudo = super::netns::SudoRunner::new(runner);
    sudo.run(argv)
        .map_err(|err| format!("{argv:?}: transport failure: {err}"))
}

/// Run an `env VAR=… rustynet …` invocation as root against the daemon socket.
/// The shell wrote this as a literal
/// `root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet …`
/// prefix in fourteen places.
pub fn rustynet_capture(runner: &dyn NetLeafRunner, args: &[&str]) -> Result<String, String> {
    let socket_assignment = format!("RUSTYNET_DAEMON_SOCKET={DAEMON_SOCKET}");
    let mut argv: Vec<&str> = vec!["env", socket_assignment.as_str(), REMOTE_RUSTYNET_BIN];
    argv.extend_from_slice(args);
    capture_root(runner, &argv)
}

/// As [`rustynet_capture`], tolerating a non-zero exit from the CLI itself.
pub fn rustynet_capture_allow_failure(
    runner: &dyn NetLeafRunner,
    args: &[&str],
) -> Result<String, String> {
    let socket_assignment = format!("RUSTYNET_DAEMON_SOCKET={DAEMON_SOCKET}");
    let mut argv: Vec<&str> = vec!["env", socket_assignment.as_str(), REMOTE_RUSTYNET_BIN];
    argv.extend_from_slice(args);
    capture_root_allow_failure(runner, &argv)
}

/// `rustynet status` on a node — the shell's `live_lab_status`.
pub fn status(runner: &dyn NetLeafRunner) -> Result<String, String> {
    rustynet_capture(runner, &["status"])
}

/// `rustynet netcheck` on a node.
pub fn netcheck(runner: &dyn NetLeafRunner) -> Result<String, String> {
    rustynet_capture(runner, &["netcheck"])
}

/// Retry `argv` as root until it succeeds, up to `attempts` times, sleeping
/// `sleep` between tries. Mirrors `live_lab_retry_root`, including its final
/// behaviour: the last attempt's failure is the returned error, so the caller
/// sees the guest's own stderr rather than a generic "gave up".
pub fn retry_root(
    runner: &dyn NetLeafRunner,
    argv: &[&str],
    attempts: u32,
    sleep: std::time::Duration,
) -> Result<(), String> {
    let attempts = attempts.max(1);
    let mut last_error = String::new();
    for attempt in 1..=attempts {
        match root_output(runner, argv) {
            Ok(output) if output.success => return Ok(()),
            Ok(output) => last_error = output.stderr.trim().to_owned(),
            Err(err) => last_error = err,
        }
        if attempt < attempts {
            std::thread::sleep(sleep);
        }
    }
    Err(format!(
        "{argv:?} did not succeed after {attempts} attempts: {last_error}"
    ))
}

/// `live_lab_wait_for_daemon_socket`'s default attempt count.
pub const DAEMON_SOCKET_ATTEMPTS: u32 = 20;
/// `live_lab_wait_for_daemon_socket`'s default inter-attempt sleep.
pub const DAEMON_SOCKET_SLEEP_SECS: u64 = 2;

/// Wait for the daemon control socket to exist — `live_lab_wait_for_daemon_socket`
/// with its shell defaults of 20 attempts, 2 seconds apart.
///
/// The shell branched here on a Windows named-pipe spelling of the socket path.
/// That branch is dropped: every cross-network scenario host is a Linux guest
/// (`run_script_stage` resolves them from the Linux cross-network topology),
/// so the named-pipe arm was unreachable from these eight validators.
pub fn wait_for_daemon_socket(runner: &dyn NetLeafRunner) -> Result<(), String> {
    retry_root(
        runner,
        &["test", "-S", DAEMON_SOCKET],
        DAEMON_SOCKET_ATTEMPTS,
        std::time::Duration::from_secs(DAEMON_SOCKET_SLEEP_SECS),
    )
    .map_err(|err| format!("daemon control socket did not appear: {err}"))
}

/// The marker `rustynet ops check-no-plaintext-passphrase-files` prints when a
/// node holds no plaintext passphrase material.
pub const NO_PLAINTEXT_MARKER: &str = "no-plaintext-passphrase-files";

/// Assert a node stores no plaintext passphrase files — the shell's
/// `live_lab_no_plaintext_passphrase_check`, which compared the command's
/// output against this exact marker string.
pub fn no_plaintext_passphrase_check(runner: &dyn NetLeafRunner) -> Result<bool, String> {
    let output = capture_root_allow_failure(
        runner,
        &[
            REMOTE_RUSTYNET_BIN,
            "ops",
            "check-no-plaintext-passphrase-files",
        ],
    )?;
    Ok(output.trim() == NO_PLAINTEXT_MARKER)
}

// ───────────────────────── netcheck predicates ─────────────────────────

/// The client proved a live, direct path: `netcheck` reports both
/// `path_mode=direct_active` and `path_live_proven=true`.
///
/// Both halves are required. `path_mode` alone is the daemon's *intent*; only
/// `path_live_proven=true` says traffic actually crossed it, which is the
/// distinction the cross-network suite exists to make.
pub fn path_proven_direct(netcheck_output: &str) -> bool {
    netcheck_output.contains("path_mode=direct_active")
        && netcheck_output.contains("path_live_proven=true")
}

/// The client proved a live path through the relay: `path_mode=relay_active`
/// and `path_live_proven=true`.
pub fn path_proven_relay(netcheck_output: &str) -> bool {
    netcheck_output.contains("path_mode=relay_active")
        && netcheck_output.contains("path_live_proven=true")
}

/// Alarm states that mean the signed traversal/DNS state is not healthy. The
/// shell enumerated these as a chain of negated glob matches; naming the set
/// once keeps the two call sites from drifting apart.
const UNHEALTHY_ALARM_STATES: &[&str] = &["critical", "error", "missing"];

/// Signed traversal and DNS state are healthy.
///
/// Mirrors the shell's compound condition exactly: no `traversal_alarm_state`
/// or `dns_alarm_state` in {critical, error, missing}, **and** a positive
/// `traversal_error=none`. The positive requirement matters — a `netcheck`
/// that omitted the field entirely would satisfy every negative clause while
/// proving nothing, so absence must not read as health.
pub fn signed_state_healthy(netcheck_output: &str) -> bool {
    for state in UNHEALTHY_ALARM_STATES {
        if netcheck_output.contains(&format!("traversal_alarm_state={state}"))
            || netcheck_output.contains(&format!("dns_alarm_state={state}"))
        {
            return false;
        }
    }
    netcheck_output.contains("traversal_error=none")
}

/// The client selected `exit_node_id` as its exit and is in `ExitActive`.
/// Both clauses come from the shell's `grep -Fq` pair against `rustynet status`.
pub fn client_exit_selected(status_output: &str, exit_node_id: &str) -> bool {
    status_output.contains(&format!("exit_node={exit_node_id}"))
        && status_output.contains("state=ExitActive")
}

/// The client's relay session is actually carrying traffic.
///
/// Kept separate from [`path_proven_relay`] because it is a third, independent
/// clause the relay scenario requires: `path_mode=relay_active` says the daemon
/// chose the relay and `path_live_proven=true` says a path was proven, but only
/// `relay_session_state=live` says the relay session itself is up. A session
/// that is negotiating or stale satisfies neither of the first two's absence.
pub fn relay_session_live(netcheck_output: &str) -> bool {
    netcheck_output.contains("relay_session_state=live")
}

/// The exit node reports it is serving the default route.
pub fn exit_serving_route(status_output: &str) -> bool {
    status_output.contains("serving_exit_node=true")
}

/// The tunnel interface every lab node brings up.
pub const TUNNEL_INTERFACE: &str = "rustynet0";

/// The client's route to the internet names the tunnel interface.
///
/// Note this asks whether the tunnel is named, NOT whether it is the only
/// device named — see
/// [`endpoint_switch::route_leaves_non_tunnel_dev`](endpoint_switch::route_leaves_non_tunnel_dev)
/// for the stricter reading the failback scenario samples with, and why the two
/// coexist.
pub fn route_via_rustynet(route_output: &str) -> bool {
    route_output.contains(&format!("dev {TUNNEL_INTERFACE}"))
}

/// The exit's nftables ruleset carries a masquerade rule, i.e. NAT is actually
/// installed rather than merely advertised.
pub fn exit_masquerade_present(nft_output: &str) -> bool {
    nft_output.contains("masquerade")
}

// ───────────────────────── route advertisement ─────────────────────────

/// `live_lab_retry_root … 10 2` around `route advertise`.
pub const ROUTE_ADVERTISE_ATTEMPTS: u32 = 10;
/// The nominal inter-attempt sleep of that retry. Callers pass it through
/// [`provisioning::LabContext::pace`] so tests keep the attempt count while
/// collapsing the wait.
pub const ROUTE_ADVERTISE_SLEEP: std::time::Duration = std::time::Duration::from_secs(2);

/// `rustynet route advertise 0.0.0.0/0` on a node, retried as the shell did.
///
/// Shared because both remote-exit scenarios advertise a default route and the
/// relay one does it twice; a second copy of the retry bound would be a second
/// place for the lab's convergence budget to drift.
pub fn advertise_default_route(
    runner: &dyn NetLeafRunner,
    sleep: std::time::Duration,
) -> Result<(), String> {
    let socket_assignment = format!("RUSTYNET_DAEMON_SOCKET={DAEMON_SOCKET}");
    retry_root(
        runner,
        &[
            "env",
            socket_assignment.as_str(),
            REMOTE_RUSTYNET_BIN,
            "route",
            "advertise",
            "0.0.0.0/0",
        ],
        ROUTE_ADVERTISE_ATTEMPTS,
        sleep,
    )
}

#[cfg(test)]
mod tests;

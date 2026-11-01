//! Semantic witnesses for the exit-demotion-residue restore.
//!
//! WHY THIS FILE EXISTS (katana-xnet-146). The scripted `MockShellHost` replays
//! whatever its author predicted the guest would say. A restore that issued
//! `role set admin` against a node whose env file still said `client` therefore
//! PASSED every scripted test and two independent reviews, and then failed live:
//! the fake never modelled what `rustynet role set` actually does.
//!
//! [`SemanticExitGuest`] models it. The guest holds {the daemon's LIVE primary
//! role and exit-serving capability, the PERSISTED env-file lines}, and
//! `rustynet role set <X>` is implemented by calling the REAL pure planner
//! (`role_cli::plan_concrete_actions`, through [`plan_role_set`]) with the LIVE
//! preset and applying ONLY the actions the planner returns:
//!
//! * `WriteNodeRoleEnv` rewrites the persisted env line and NEVER the live role
//!   (`execute_role_action` in main.rs documents that it does not restart the
//!   daemon; katana-xnet-146 measured it: the daemon was started once);
//! * `Advertise` / `Retract` / `Deploy` / `UndeployExitService` change the live
//!   capability only;
//! * `NoOp` changes nothing, which is exactly what a restore `role set admin`
//!   planned on a daemon that still reported `admin` (the env file mtime did not
//!   move at the restore).
//!
//! On top of that the guest answers the argv the restore uses against the env
//! file (`grep`, `sed -i`, `cat`) and `rustynet status` (the LIVE role), so a
//! restart simulation (`live := persisted`) shows what the NEXT daemon start
//! would read.
//!
//! Tests labelled "control" validate the model itself and hold on any version of
//! the stage; every other test is a restore witness that fails when the
//! persisted line is not restored and verified.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use rustynet_control::role_presets::PrimaryRole;

use super::{INJECT_EVALUATION_PANIC, demote_to_client, validate_linux_exit_demotion_residue};
use crate::role_cli::{self, ConcreteAction, DEFAULT_DAEMON_ENV_PATH, RoleSetPlan};
use crate::vm_lab::orchestrator::remote_shell::{
    RemoteExitStatus, RemoteShellError, RemoteShellHost, RemoteStat, validate_argv, validate_env,
};

const ALIAS: &str = "katana-exit-1";
const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";
const MESH_CIDR: &str = "100.64.0.0/10";
const SOCKET_ENV: &str = "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock";
const CLI: &str = "/usr/local/bin/rustynet";
const GREP_PATTERN: &str = "^(RUSTYNET_)?NODE_ROLE=";

// ── The semantic guest ──────────────────────────────────────────────────────

/// Whether an env-file role write also restarts the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartPolicy {
    /// MEASURED on katana-xnet-146: `role set` never restarts the daemon.
    Never,
    /// Counterfactual: a role write also restarts the daemon (live :=
    /// persisted). The stage must stay correct in that world too.
    OnEnvWrite,
}

/// Injectable guest misbehaviour.
#[derive(Debug, Clone, Default)]
struct Faults {
    /// `role set client` writes the env line, then exits 1 (a failure after the
    /// side effect already landed).
    role_set_client_fails_after_env_write: bool,
    /// `sed -i` exits with this code WITHOUT touching the file.
    sed_fails_untouched: Option<i32>,
    /// `sed -i` applies the rewrite, then exits with this code.
    sed_fails_after_apply: Option<i32>,
    /// `sed -i` exits 0 and writes nothing.
    sed_silent_noop: bool,
    /// `sed -i` exits 0 but writes this (possibly multi-line) text instead of
    /// the requested `KEY=value` line.
    sed_writes_text: Option<String>,
    /// Retraction leaves the NAT table behind (a residual open relay).
    retract_leaves_nat: bool,
    /// The daemon restarts (live := persisted) at the daemon-running check,
    /// i.e. between the demotion and the restore.
    restart_during_evaluation: bool,
    /// `grep` exits with this code and stderr instead of reading the file.
    grep_fails: Option<(i32, String)>,
}

#[derive(Debug)]
struct GuestState {
    /// The daemon's LIVE primary role (`node_role=` in `rustynet status`).
    live_primary: PrimaryRole,
    /// Live exit-serving capability (`serving_exit_node=`).
    serving_exit: bool,
    /// The exit preflight / forwarding service (sysctl forwarding on).
    exit_service_deployed: bool,
    /// The generation-rotated NAT table is loaded.
    nat_table_present: bool,
    /// The PERSISTED `/etc/default/rustynetd`, one entry per line.
    env_lines: Vec<String>,
    /// How many times the env file was rewritten (its mtime moved).
    env_writes: usize,
    restarts: usize,
    restart_policy: RestartPolicy,
    faults: Faults,
    /// Every argv the stage issued, in order.
    log: Vec<Vec<String>>,
}

struct SemanticExitGuest {
    state: Mutex<GuestState>,
}

fn exit_status(code: i32, stdout: &str, stderr: &str) -> RemoteExitStatus {
    RemoteExitStatus {
        code,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// A representative daemon env file: the role line sits among unrelated keys.
fn standard_env_lines() -> Vec<String> {
    vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "RUSTYNET_NODE_ROLE=admin".to_owned(),
        "RUSTYNET_BACKEND=linux-wireguard".to_owned(),
        "RUSTYNET_WG_INTERFACE=rustynet0".to_owned(),
    ]
}

fn env_without_role_line() -> Vec<String> {
    standard_env_lines()
        .into_iter()
        .filter(|line| !line.starts_with("RUSTYNET_NODE_ROLE="))
        .collect()
}

impl SemanticExitGuest {
    /// An exit node that has been serving exit since its single daemon start:
    /// live `admin` + exit-serving, NAT loaded, forwarding on, `env_lines` on disk.
    fn serving_exit(env_lines: Vec<String>) -> Self {
        Self {
            state: Mutex::new(GuestState {
                live_primary: PrimaryRole::Admin,
                serving_exit: true,
                exit_service_deployed: true,
                nat_table_present: true,
                env_lines,
                env_writes: 0,
                restarts: 0,
                restart_policy: RestartPolicy::Never,
                faults: Faults::default(),
                log: Vec::new(),
            }),
        }
    }

    fn standard() -> Self {
        Self::serving_exit(standard_env_lines())
    }

    fn with_faults(self, faults: Faults) -> Self {
        self.lock().faults = faults;
        self
    }

    fn with_restart_policy(self, policy: RestartPolicy) -> Self {
        self.lock().restart_policy = policy;
        self
    }

    fn lock(&self) -> MutexGuard<'_, GuestState> {
        self.state.lock().expect("semantic guest mutex poisoned")
    }

    fn persisted_lines(&self) -> Vec<String> {
        self.lock().env_lines.clone()
    }

    fn live_primary(&self) -> PrimaryRole {
        self.lock().live_primary
    }

    fn is_serving_exit(&self) -> bool {
        self.lock().serving_exit
    }

    fn env_writes(&self) -> usize {
        self.lock().env_writes
    }

    fn commands(&self) -> Vec<Vec<String>> {
        self.lock().log.clone()
    }

    /// Every `role set <X>` target, in dispatch order.
    fn role_set_targets(&self) -> Vec<String> {
        self.commands()
            .iter()
            .filter_map(|argv| role_set_target(argv))
            .collect()
    }

    /// What the NEXT daemon start would read (systemd re-reads the env file).
    fn restart_daemon(&self) {
        self.lock().restart();
    }
}

fn role_set_target(argv: &[String]) -> Option<String> {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["sudo", "-n", "env", SOCKET_ENV, CLI, "role", "set", target] => Some((*target).to_owned()),
        _ => None,
    }
}

impl GuestState {
    fn status_line(&self) -> String {
        format!(
            "node_id=katana-exit-1 node_role={} state=Ready generation=7 exit_node=none \
             serving_exit_node={} lan_access=off",
            self.live_primary.as_str(),
            self.serving_exit
        )
    }

    /// systemd re-reads `EnvironmentFile=` on every start, so the next
    /// daemon's `--node-role` is the LAST role assignment in the file (the
    /// guest honours both key spellings, as the role CLI's rewrite does; the
    /// real unit only substitutes `RUSTYNET_NODE_ROLE`); a file with no role
    /// assignment falls back to the unit's `client` default. A restart also
    /// drops any live exit-serving advertisement.
    fn restart(&mut self) {
        let persisted = self.env_lines.iter().rev().find_map(|line| {
            line.strip_prefix("RUSTYNET_NODE_ROLE=")
                .or_else(|| line.strip_prefix("NODE_ROLE="))
        });
        self.live_primary = persisted
            .and_then(|value| PrimaryRole::from_str(value).ok())
            .unwrap_or(PrimaryRole::Client);
        self.serving_exit = false;
        self.restarts += 1;
    }

    fn snapshot_json(&self, nat_table: &str) -> String {
        let forwarding = if self.exit_service_deployed {
            "Enabled"
        } else {
            "Disabled"
        };
        serde_json::json!({
            "schema_version": 1,
            "captured_at_unix": 1_700_000_000_u64,
            "mesh_cidr": MESH_CIDR,
            "nat_table": nat_table,
            "nat_table_present": self.nat_table_present,
            "internal_prefix": if self.nat_table_present { MESH_CIDR } else { "" },
            "tunnel_forwarding": forwarding,
            "egress_forwarding": forwarding,
            "ipv6_tunnel_forwarding": "Disabled",
            "ipv6_egress_forwarding": "Disabled",
        })
        .to_string()
    }

    fn dispatch(&mut self, argv: &[&str]) -> Result<RemoteExitStatus, RemoteShellError> {
        let out = match argv {
            ["sudo", "-n", "nft", "list", "tables"] => {
                let mut tables = String::from("table inet rustynet_g7\n");
                if self.nat_table_present {
                    tables.push_str("table ip rustynet_nat_g7\n");
                }
                exit_status(0, &tables, "")
            }
            [
                _daemon,
                "linux-exit-nat-lifecycle-snapshot",
                "--mesh-cidr",
                MESH_CIDR,
                "--nat-table",
                nat_table,
            ] => exit_status(0, &self.snapshot_json(nat_table), ""),
            ["sudo", "-n", "env", socket, cli, rest @ ..] => {
                if *socket != SOCKET_ENV || *cli != CLI {
                    exit_status(127, "", "semantic fake: unexpected daemon CLI seam")
                } else {
                    match rest {
                        ["status"] => exit_status(0, &format!("{}\n", self.status_line()), ""),
                        ["role", "set", target] => self.role_set(target),
                        _ => exit_status(2, "", "semantic fake: unsupported rustynet subcommand"),
                    }
                }
            }
            ["systemctl", "is-active", "--quiet", "rustynetd.service"] => {
                if self.faults.restart_during_evaluation {
                    self.restart();
                }
                exit_status(0, "", "")
            }
            ["sleep", _secs] => exit_status(0, "", ""),
            ["sudo", "-n", "grep", "-E", pattern, path] => self.grep(pattern, path),
            ["sudo", "-n", "sed", "-i", "-E", program, path] => self.sed_in_place(program, path),
            ["sudo", "-n", "cat", path] => {
                if *path == DEFAULT_DAEMON_ENV_PATH {
                    exit_status(0, &format!("{}\n", self.env_lines.join("\n")), "")
                } else {
                    exit_status(1, "", "cat: no such file")
                }
            }
            other => {
                return Err(RemoteShellError::Transport {
                    message: format!("semantic guest has no model for argv {other:?}"),
                });
            }
        };
        Ok(out)
    }

    /// `rustynet role set <target>`: the REAL planner on the LIVE preset, then
    /// only the actions it returned (see the module docs).
    fn role_set(&mut self, target: &str) -> RemoteExitStatus {
        let actions = match plan_role_set(&self.status_line(), target) {
            Ok(actions) => actions,
            Err(message) => {
                return exit_status(1, &format!("error [generic_failure (1)]: {message}\n"), "");
            }
        };
        let mut wrote_env = false;
        for action in &actions {
            match self.apply(action) {
                Ok(wrote) => wrote_env |= wrote,
                Err(message) => {
                    return exit_status(
                        1,
                        &format!("error [generic_failure (1)]: {message}\n"),
                        "",
                    );
                }
            }
        }
        if wrote_env && target == "client" && self.faults.role_set_client_fails_after_env_write {
            return exit_status(
                1,
                "error [generic_failure (1)]: role-transition audit log append failed\n",
                "",
            );
        }
        exit_status(
            0,
            &format!("transition planned: {} action(s)\n", actions.len()),
            "",
        )
    }

    /// Apply one planner action. Returns whether it wrote the env file.
    fn apply(&mut self, action: &ConcreteAction) -> Result<bool, String> {
        match action {
            ConcreteAction::NoOp => Ok(false),
            ConcreteAction::WriteNodeRoleEnv {
                new_primary,
                env_path,
                ..
            } => {
                if env_path != &PathBuf::from(DEFAULT_DAEMON_ENV_PATH) {
                    return Err(format!("unexpected env path {}", env_path.display()));
                }
                rewrite_env_like_role_cli(&mut self.env_lines, new_primary.as_str());
                self.env_writes += 1;
                if self.restart_policy == RestartPolicy::OnEnvWrite {
                    self.restart();
                }
                Ok(true)
            }
            ConcreteAction::AdvertiseDefaultRoute => {
                if self.live_primary != PrimaryRole::Admin {
                    return Err(
                        "route advertise failed: command denied: current node role does not \
                         permit this operation"
                            .to_owned(),
                    );
                }
                self.serving_exit = true;
                self.nat_table_present = true;
                Ok(false)
            }
            ConcreteAction::RetractDefaultRoute => {
                self.serving_exit = false;
                if !self.faults.retract_leaves_nat {
                    self.nat_table_present = false;
                }
                Ok(false)
            }
            ConcreteAction::DeployExitService => {
                self.exit_service_deployed = true;
                Ok(false)
            }
            ConcreteAction::UndeployExitService => {
                self.exit_service_deployed = false;
                Ok(false)
            }
            other => Err(format!("semantic guest does not model {other:?}")),
        }
    }

    fn grep(&self, pattern: &str, path: &str) -> RemoteExitStatus {
        if let Some((code, stderr)) = &self.faults.grep_fails {
            return exit_status(*code, "", stderr);
        }
        if path != DEFAULT_DAEMON_ENV_PATH {
            return exit_status(2, "", &format!("grep: {path}: No such file or directory"));
        }
        if pattern != GREP_PATTERN {
            return exit_status(2, "", "semantic fake: only the role-line grep is modelled");
        }
        let matched: Vec<&str> = self
            .env_lines
            .iter()
            .map(String::as_str)
            .filter(|line| {
                line.starts_with("RUSTYNET_NODE_ROLE=") || line.starts_with("NODE_ROLE=")
            })
            .collect();
        if matched.is_empty() {
            return exit_status(1, "", "");
        }
        exit_status(0, &format!("{}\n", matched.join("\n")), "")
    }

    fn sed_in_place(&mut self, program: &str, path: &str) -> RemoteExitStatus {
        if path != DEFAULT_DAEMON_ENV_PATH {
            return exit_status(4, "", &format!("sed: can't read {path}: No such file"));
        }
        if let Some(code) = self.faults.sed_fails_untouched {
            return exit_status(
                code,
                "",
                "sed: couldn't open temporary file /etc/default/sedAbCdEf: Permission denied",
            );
        }
        let Some((key, value)) = parse_role_sed_program(program) else {
            return exit_status(
                1,
                "",
                "sed: -e expression #1: not a role-line rewrite the semantic guest models",
            );
        };
        if self.faults.sed_silent_noop {
            return exit_status(0, "", "");
        }
        let replacement = self
            .faults
            .sed_writes_text
            .clone()
            .unwrap_or_else(|| format!("{key}={value}"));
        let prefix = format!("{key}=");
        for line in &mut self.env_lines {
            if line.starts_with(&prefix) {
                line.clone_from(&replacement);
            }
        }
        self.env_writes += 1;
        if let Some(code) = self.faults.sed_fails_after_apply {
            return exit_status(code, "", "sed: couldn't preserve ownership of the new file");
        }
        exit_status(0, "", "")
    }
}

/// `rustynet role set` as `execute_role` + `execute_role_plan` run it: resolve
/// the LIVE preset from the status line, plan with the REAL pure planner, and
/// refuse a blocked transition. Returns the planner's ordered actions.
fn plan_role_set(status_line: &str, target: &str) -> Result<Vec<ConcreteAction>, String> {
    let current =
        role_cli::resolve_preset_from_status(status_line).map_err(|err| err.user_message())?;
    let target_preset = role_cli::parse_preset_arg(target).map_err(|err| err.user_message())?;
    match role_cli::plan_concrete_actions(
        current,
        target_preset,
        false,
        PathBuf::from(DEFAULT_DAEMON_ENV_PATH),
    ) {
        RoleSetPlan::Allowed { actions, .. } => Ok(actions),
        RoleSetPlan::Blocked { from, to, error } => Err(format!(
            "transition {from} → {to} blocked: {}",
            error.user_message()
        )),
    }
}

/// Mirror of `update_node_role_env_file` (main.rs): every `NODE_ROLE=` /
/// `RUSTYNET_NODE_ROLE=` line is rewritten with the key it already uses; with
/// no such line, `NODE_ROLE=<role>` is appended.
fn rewrite_env_like_role_cli(lines: &mut Vec<String>, new_role: &str) {
    let mut found = false;
    for line in lines.iter_mut() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("NODE_ROLE=") || trimmed.starts_with("RUSTYNET_NODE_ROLE=") {
            let key = if trimmed.starts_with("RUSTYNET_NODE_ROLE=") {
                "RUSTYNET_NODE_ROLE"
            } else {
                "NODE_ROLE"
            };
            *line = format!("{key}={new_role}");
            found = true;
        }
    }
    if !found {
        lines.push(format!("NODE_ROLE={new_role}"));
    }
}

/// The only sed program the guest models: `s/^KEY=.*$/KEY=value/` with a
/// closed key set and a `[a-z_]+` value. Anything else is refused the way a
/// malformed expression would be, so the guest doubles as an oracle that the
/// stage never builds a program from unvalidated data.
fn parse_role_sed_program(program: &str) -> Option<(String, String)> {
    let rest = program.strip_prefix("s/^")?;
    let (key, replacement) = rest.split_once("=.*$/")?;
    let replacement = replacement.strip_suffix('/')?;
    let (replacement_key, value) = replacement.split_once('=')?;
    let key_ok = key == "RUSTYNET_NODE_ROLE" || key == "NODE_ROLE";
    let value_ok = !value.is_empty() && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    (key_ok && replacement_key == key && value_ok).then(|| (key.to_owned(), value.to_owned()))
}

impl RemoteShellHost for SemanticExitGuest {
    fn read_file(&self, remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
        Err(RemoteShellError::Unsupported {
            message: format!("the restore is argv-only; read_file({remote_path}) is not modelled"),
        })
    }

    fn write_file(
        &self,
        remote_path: &str,
        _bytes: &[u8],
        _mode_octal: u16,
    ) -> Result<(), RemoteShellError> {
        Err(RemoteShellError::Unsupported {
            message: format!("the restore is argv-only; write_file({remote_path}) is not modelled"),
        })
    }

    fn stat(&self, remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
        Err(RemoteShellError::Unsupported {
            message: format!("stat({remote_path}) is not modelled"),
        })
    }

    fn run_argv(
        &self,
        argv: &[&str],
        env: &[(&str, &str)],
        stdin: &[u8],
    ) -> Result<RemoteExitStatus, RemoteShellError> {
        // The same input validation every real backend applies.
        validate_argv(argv)?;
        validate_env(env)?;
        if !env.is_empty() || !stdin.is_empty() {
            return Err(RemoteShellError::InvalidInput {
                message: "the restore must carry no env and no stdin".to_owned(),
            });
        }
        let mut state = self.lock();
        state
            .log
            .push(argv.iter().map(|arg| (*arg).to_owned()).collect());
        state.dispatch(argv)
    }

    fn tcp_send_recv(
        &self,
        addr: &str,
        _payload: &[u8],
        _timeout: std::time::Duration,
    ) -> Result<Vec<u8>, RemoteShellError> {
        Err(RemoteShellError::Unsupported {
            message: format!("tcp_send_recv({addr}) is not modelled"),
        })
    }
}

fn run_stage(guest: &SemanticExitGuest) -> Result<(), String> {
    validate_linux_exit_demotion_residue(guest, TEST_DAEMON, ALIAS)
}

fn assert_node_untouched(guest: &SemanticExitGuest, env_before: &[String]) {
    assert_eq!(
        guest.persisted_lines(),
        env_before,
        "the env file must be untouched"
    );
    assert_eq!(guest.live_primary(), PrimaryRole::Admin);
    assert!(guest.is_serving_exit(), "the exit must still be serving");
    assert_eq!(guest.env_writes(), 0, "nothing may rewrite the env file");
}

// ── Model-validity controls (hold on any version of the stage) ──────────────

/// CONTROL. The guest reproduces the three facts measured on the katana-xnet-146
/// exit: the demotion's `role set client` rewrote the env file, the restore's
/// `role set admin` wrote NOTHING (the live daemon still reported admin), and
/// the next daemon start read the persisted `client`.
#[test]
fn control_guest_reproduces_the_katana_xnet_146_measurements() {
    let guest = SemanticExitGuest::standard();
    demote_to_client(&guest).expect("the demotion pair must succeed");
    assert_eq!(
        guest.env_writes(),
        1,
        "role set client rewrites the env file"
    );
    assert_eq!(
        guest.live_primary(),
        PrimaryRole::Admin,
        "role set client does not restart the daemon: the live role stays admin"
    );
    assert!(
        guest
            .persisted_lines()
            .contains(&"RUSTYNET_NODE_ROLE=client".to_owned()),
        "the demotion persists client"
    );
    assert!(!guest.is_serving_exit(), "exit→admin retracted the exit");

    // The slice's restore: `role set admin` against a live admin plans NoOp.
    let restore = guest
        .run_argv(
            &["sudo", "-n", "env", SOCKET_ENV, CLI, "role", "set", "admin"],
            &[],
            &[],
        )
        .expect("role set dispatch");
    assert_eq!(restore.code, 0, "the restore command itself succeeds");
    assert_eq!(
        guest.env_writes(),
        1,
        "the restore role set admin wrote NOTHING (env mtime did not move at 15:40:30)"
    );
    assert!(
        guest
            .persisted_lines()
            .contains(&"RUSTYNET_NODE_ROLE=client".to_owned()),
        "client is still persisted"
    );

    guest.restart_daemon();
    assert_eq!(
        guest.live_primary(),
        PrimaryRole::Client,
        "the next daemon start reads the persisted client (managed-DNS restart, 15:45:23)"
    );
}

/// CONTROL. The planner facts the restore design stands on, pinned against the
/// real `plan_concrete_actions` (role_cli.rs) through the same adapter the guest
/// uses: exit→admin writes NOTHING to the env file; admin→client writes the env
/// file and nothing else (no restart); and `role set admin` on a daemon that
/// already reports admin plans exactly `NoOp` — which is why the slice's
/// restore wrote nothing. If the planner ever changes these, the restore design
/// must be re-derived.
#[test]
fn control_planner_actions_the_restore_design_stands_on() {
    let serving_exit = "node_id=n node_role=admin state=Ready serving_exit_node=true";
    let plain_admin = "node_id=n node_role=admin state=Ready serving_exit_node=false";

    assert_eq!(
        plan_role_set(serving_exit, "admin"),
        Ok(vec![
            ConcreteAction::UndeployExitService,
            ConcreteAction::RetractDefaultRoute,
        ]),
        "exit→admin only tears the exit down: no env write"
    );
    let demote = plan_role_set(plain_admin, "client").expect("admin→client is allowed");
    assert!(
        matches!(demote.as_slice(), [ConcreteAction::WriteNodeRoleEnv { new_primary, env_path, restart_required: true }]
            if *new_primary == PrimaryRole::Client
                && env_path == &PathBuf::from(DEFAULT_DAEMON_ENV_PATH)),
        "admin→client writes the persisted role and does nothing else: {demote:?}"
    );
    assert_eq!(
        plan_role_set(plain_admin, "admin"),
        Ok(vec![ConcreteAction::NoOp]),
        "role set admin on a live admin is a no-op: it cannot restore a persisted client"
    );
}

/// CONTROL. The guest drives the real planner: exit→client is blocked, so the
/// demotion must go exit→admin→client, and a client cannot advertise an exit.
#[test]
fn control_guest_applies_the_real_planner_verdicts() {
    let guest = SemanticExitGuest::standard();
    let direct = guest
        .run_argv(
            &[
                "sudo", "-n", "env", SOCKET_ENV, CLI, "role", "set", "client",
            ],
            &[],
            &[],
        )
        .expect("role set dispatch");
    assert_eq!(direct.code, 1, "exit→client is a blocked transition");
    assert!(
        String::from_utf8_lossy(&direct.stdout).contains("blocked"),
        "{direct:?}"
    );
    assert_eq!(guest.env_writes(), 0);
    assert!(
        guest.is_serving_exit(),
        "a blocked transition changes nothing"
    );
}

/// CONTROL. In the counterfactual world where a role write restarts the daemon
/// the OLD restore (`role set <recorded>`) already worked; the guest models both
/// worlds so the stage is shown correct in each.
#[test]
fn control_restart_on_env_write_world_applies_the_role_write_live() {
    let guest = SemanticExitGuest::standard().with_restart_policy(RestartPolicy::OnEnvWrite);
    demote_to_client(&guest).expect("the demotion pair must succeed");
    assert_eq!(guest.live_primary(), PrimaryRole::Client);
}

// ── Restore witnesses ───────────────────────────────────────────────────────

/// (a) After the whole stage sequence the persisted line equals the recorded
/// line, byte for byte, with the unrelated keys untouched. The slice leaves
/// `RUSTYNET_NODE_ROLE=client`: this is the witness of the live bug.
#[test]
fn stage_leaves_the_persisted_role_line_equal_to_the_recorded_line() {
    let guest = SemanticExitGuest::standard();
    run_stage(&guest).expect("a clean teardown on a faithful guest must pass");
    assert_eq!(
        guest.persisted_lines(),
        standard_env_lines(),
        "the stage must leave the env file exactly as it found it"
    );
    assert_eq!(guest.live_primary(), PrimaryRole::Admin);
    // Read it back through the shell, the way an operator would.
    let cat = guest
        .run_argv(&["sudo", "-n", "cat", DEFAULT_DAEMON_ENV_PATH], &[], &[])
        .expect("cat dispatch");
    let text = String::from_utf8_lossy(&cat.stdout).into_owned();
    assert!(text.contains("RUSTYNET_NODE_ROLE=admin\n"), "{text}");
    assert!(!text.contains("RUSTYNET_NODE_ROLE=client"), "{text}");
}

/// (a) with the legacy bare key: the line is restored under the key the
/// installer chose, and no second `RUSTYNET_NODE_ROLE` line appears.
#[test]
fn stage_restores_the_legacy_bare_key_under_the_same_key() {
    let env: Vec<String> = vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "NODE_ROLE=admin".to_owned(),
        "RUSTYNET_BACKEND=linux-wireguard".to_owned(),
    ];
    let guest = SemanticExitGuest::serving_exit(env.clone());
    run_stage(&guest).expect("a clean teardown on a faithful guest must pass");
    assert_eq!(guest.persisted_lines(), env);
    assert!(
        guest
            .commands()
            .iter()
            .any(|argv| argv.contains(&"s/^NODE_ROLE=.*$/NODE_ROLE=admin/".to_owned())),
        "the rewrite must target the bare NODE_ROLE key: {:?}",
        guest.commands()
    );
}

/// (b) A restart simulation after the stage (live := persisted) yields the
/// ORIGINAL role. The control half shows the demotion alone poisons the next
/// start; the stage must undo exactly that.
#[test]
fn restart_after_the_stage_yields_the_original_role() {
    let control = SemanticExitGuest::standard();
    demote_to_client(&control).expect("the demotion pair must succeed");
    control.restart_daemon();
    assert_eq!(
        control.live_primary(),
        PrimaryRole::Client,
        "control: the demotion without a restore poisons the next start"
    );

    let guest = SemanticExitGuest::standard();
    run_stage(&guest).expect("a clean teardown on a faithful guest must pass");
    guest.restart_daemon();
    assert_eq!(
        guest.live_primary(),
        PrimaryRole::Admin,
        "the next daemon start must read the original role"
    );
}

/// (b) in the counterfactual world where a role write restarts the daemon: the
/// stage must be correct there as well.
#[test]
fn counterfactual_stage_is_correct_when_a_role_write_restarts_the_daemon() {
    let guest = SemanticExitGuest::standard().with_restart_policy(RestartPolicy::OnEnvWrite);
    run_stage(&guest).expect("a clean teardown must pass in the restart-on-write world");
    assert_eq!(guest.persisted_lines(), standard_env_lines());
    assert_eq!(guest.live_primary(), PrimaryRole::Admin);
    guest.restart_daemon();
    assert_eq!(guest.live_primary(), PrimaryRole::Admin);
}

/// (c) An unrecordable persisted role fails the stage BEFORE any demotion
/// command: nothing is demoted, nothing is rewritten, and the error names the
/// persisted record.
#[test]
fn unrecordable_persisted_role_fails_closed_before_any_demotion() {
    let long = format!("RUSTYNET_NODE_ROLE={}", "a".repeat(33));
    let mut cases: Vec<(&str, Vec<String>)> = vec![
        ("absent", env_without_role_line()),
        ("empty file", Vec::new()),
        (
            "same key twice",
            vec![
                "RUSTYNET_NODE_ROLE=admin".to_owned(),
                "RUSTYNET_NODE_ROLE=client".to_owned(),
            ],
        ),
        (
            "both spellings",
            vec![
                "RUSTYNET_NODE_ROLE=admin".to_owned(),
                "NODE_ROLE=admin".to_owned(),
            ],
        ),
        ("empty value", vec!["RUSTYNET_NODE_ROLE=".to_owned()]),
        (
            "quoted value",
            vec!["RUSTYNET_NODE_ROLE=\"admin\"".to_owned()],
        ),
        (
            "uppercase value",
            vec!["RUSTYNET_NODE_ROLE=Admin".to_owned()],
        ),
        (
            "trailing space",
            vec!["RUSTYNET_NODE_ROLE=admin ".to_owned()],
        ),
        (
            "carriage return",
            vec!["RUSTYNET_NODE_ROLE=admin\r".to_owned()],
        ),
        (
            "shell metacharacter",
            vec!["RUSTYNET_NODE_ROLE=admin;reboot".to_owned()],
        ),
        (
            "sed delimiter",
            vec!["RUSTYNET_NODE_ROLE=ad/min".to_owned()],
        ),
        (
            "sed backreference",
            vec!["RUSTYNET_NODE_ROLE=ad&min".to_owned()],
        ),
        (
            "hyphenated",
            vec!["RUSTYNET_NODE_ROLE=blind-exit".to_owned()],
        ),
        ("digit", vec!["RUSTYNET_NODE_ROLE=admin2".to_owned()]),
        ("33 characters", vec![long]),
        ("bare key garbled", vec!["NODE_ROLE=".to_owned()]),
    ];
    // A multi-line value smuggled into one logical line: grep prints two lines.
    cases.push((
        "embedded newline",
        vec!["RUSTYNET_NODE_ROLE=admin\nRUSTYNET_NODE_ROLE=client".to_owned()],
    ));
    for (label, env) in cases {
        let guest = SemanticExitGuest::serving_exit(env.clone());
        let err = run_stage(&guest).expect_err(&format!("{label}: must fail closed"));
        assert!(
            err.contains("persisted node role") && err.contains("nothing was demoted"),
            "{label}: the refusal must be named: {err}"
        );
        assert!(
            guest.role_set_targets().is_empty(),
            "{label}: no demotion command may be issued: {:?}",
            guest.commands()
        );
        assert!(
            !guest
                .commands()
                .iter()
                .any(|argv| argv.iter().any(|arg| arg == "sed")),
            "{label}: no rewrite may be issued"
        );
        assert_node_untouched(&guest, &env);
    }
}

/// (c) A role file that cannot be read at all fails closed before any demotion,
/// and a sudo denial is not mislabelled as "absent".
#[test]
fn unreadable_env_file_fails_closed_before_any_demotion() {
    for (label, code, stderr, expect) in [
        (
            "grep error",
            2,
            "grep: /etc/default/rustynetd: Permission denied",
            "exited 2",
        ),
        (
            "sudo denied",
            1,
            "sudo: a password is required",
            "a password is required",
        ),
    ] {
        let guest = SemanticExitGuest::standard().with_faults(Faults {
            grep_fails: Some((code, stderr.to_owned())),
            ..Faults::default()
        });
        let err = run_stage(&guest).expect_err(&format!("{label}: must fail closed"));
        assert!(
            err.contains("persisted node role")
                && err.contains("nothing was demoted")
                && err.contains(expect),
            "{label}: {err}"
        );
        assert!(
            !(label == "sudo denied" && err.contains("persisted role absent")),
            "{label}: a sudo failure must not be reported as an absent line: {err}"
        );
        assert!(guest.role_set_targets().is_empty(), "{label}");
        assert_node_untouched(&guest, &standard_env_lines());
    }
}

/// (d) The rewrite fails: the error names the failure AND the persisted role
/// left behind (and the live role).
#[test]
fn restore_rewrite_failure_names_the_left_behind_persisted_role() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        sed_fails_untouched: Some(1),
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a failed rewrite must fail the stage");
    assert!(
        err.contains("post-validation restore") && err.contains("left demoted"),
        "{err}"
    );
    assert!(
        err.contains("persisted role rewrite") && err.contains("exited 1"),
        "the rewrite failure must be named: {err}"
    );
    assert!(
        err.contains("Permission denied"),
        "the sed stderr must be carried: {err}"
    );
    assert!(
        err.contains("left behind: persisted role client"),
        "the left-behind persisted role must be named: {err}"
    );
    assert!(
        err.contains("live role admin"),
        "the live role must be named: {err}"
    );
    assert!(
        err.contains("persisted \"RUSTYNET_NODE_ROLE=admin\" in /etc/default/rustynetd"),
        "the RECORDED persisted line must be named next to what was left behind: {err}"
    );
    assert!(
        guest
            .persisted_lines()
            .contains(&"RUSTYNET_NODE_ROLE=client".to_owned()),
        "the node really is left demoted"
    );
}

/// (d) on the demotion-failure path: the demotion wrote `client` and then
/// failed, and the best-effort rewrite fails too. The node is left
/// mid-transition and the error must say so, name the demotion failure, the
/// rewrite failure and the persisted role left behind.
#[test]
fn failed_demotion_with_failed_rewrite_names_mid_transition_and_the_left_behind_role() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        role_set_client_fails_after_env_write: true,
        sed_fails_untouched: Some(1),
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a failed demotion must fail the stage");
    assert!(
        err.contains("demotion (role set client) exited 1"),
        "the demotion failure must surface: {err}"
    );
    assert!(
        err.contains("mid-transition") && err.contains("persisted role rewrite"),
        "the failed best-effort restore must be named: {err}"
    );
    assert!(
        err.contains("left behind: persisted role client"),
        "the persisted role left behind must be named: {err}"
    );
}

/// (d) A rewrite that exits non-zero fails the stage even if the line happens
/// to read back right: a failing restore command is never swallowed.
#[test]
fn restore_rewrite_exit_failure_fails_even_when_the_line_reads_back_right() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        sed_fails_after_apply: Some(4),
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a failing rewrite command must fail the stage");
    assert!(
        err.contains("persisted role rewrite") && err.contains("exited 4"),
        "{err}"
    );
    assert!(
        err.contains("left behind: persisted role admin"),
        "the file did read back right, and the message must say so: {err}"
    );
    assert_eq!(guest.persisted_lines(), standard_env_lines());
}

/// (e) The rewrite "succeeds" but the file does not read back as the recorded
/// line: a verify mismatch is an error, whatever the wrong content is.
#[test]
fn restore_verify_mismatch_is_an_error() {
    let cases: Vec<(&str, Faults, &str)> = vec![
        (
            "silent no-op",
            Faults {
                sed_silent_noop: true,
                ..Faults::default()
            },
            "left behind: persisted role client",
        ),
        (
            "wrong value written",
            Faults {
                sed_writes_text: Some("RUSTYNET_NODE_ROLE=blind_exit".to_owned()),
                ..Faults::default()
            },
            "left behind: persisted role blind_exit",
        ),
        (
            "wrong key written",
            Faults {
                sed_writes_text: Some("NODE_ROLE=admin".to_owned()),
                ..Faults::default()
            },
            "left behind: persisted role admin",
        ),
    ];
    for (label, faults, left_behind) in cases {
        let guest = SemanticExitGuest::standard().with_faults(faults);
        let err = run_stage(&guest).expect_err(&format!("{label}: must fail the stage"));
        assert!(
            err.contains("persisted role verify mismatch"),
            "{label}: the mismatch must be named: {err}"
        );
        assert!(
            err.contains("\"RUSTYNET_NODE_ROLE=admin\""),
            "{label}: the expected line must be named: {err}"
        );
        assert!(err.contains(left_behind), "{label}: {err}");
    }
}

/// (e) A rewrite that leaves TWO role lines reads back as ambiguous: the
/// verification refuses it (it requires the identical SINGLE line).
#[test]
fn restore_verify_refuses_an_ambiguous_read_back() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        sed_writes_text: Some("RUSTYNET_NODE_ROLE=admin\nNODE_ROLE=admin".to_owned()),
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("an ambiguous read back must fail the stage");
    assert!(
        err.contains("persisted role verify read failed")
            && err.contains("2 role lines (persisted role ambiguous)"),
        "{err}"
    );
    assert!(err.contains("persisted role unreadable"), "{err}");
}

/// (f) The residue evaluation AND the restore both fail: both texts are
/// reported, and the left-behind roles are named.
#[test]
fn residue_and_restore_failures_report_both_texts() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        retract_leaves_nat: true,
        sed_fails_untouched: Some(1),
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("both failures must fail the stage");
    assert!(
        err.contains("post-validation restore") && err.contains("persisted role rewrite"),
        "the restore failure must be named: {err}"
    );
    assert!(
        err.contains("residual open relay") || err.contains("NAT table present after"),
        "the residue evidence must not be dropped: {err}"
    );
    assert!(err.contains("left behind: persisted role client"), "{err}");
}

/// The restore runs when only the residue evaluation fails: the stage fails
/// on the residue, and the node is still restored.
#[test]
fn persisted_role_is_restored_when_only_the_residue_evaluation_fails() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        retract_leaves_nat: true,
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a residual NAT table must fail the stage");
    assert!(
        err.contains("residual open relay") || err.contains("NAT table present after"),
        "{err}"
    );
    assert_eq!(guest.persisted_lines(), standard_env_lines());
}

/// The restore runs when the evaluation panics (D6).
#[test]
fn persisted_role_is_restored_when_the_evaluation_panics() {
    let guest = SemanticExitGuest::standard();
    INJECT_EVALUATION_PANIC.with(|flag| flag.set(true));
    let result = run_stage(&guest);
    INJECT_EVALUATION_PANIC.with(|flag| flag.set(false));
    let err = result.expect_err("an evaluation panic must fail the stage");
    assert!(err.contains("residue evaluation panicked"), "{err}");
    assert_eq!(guest.persisted_lines(), standard_env_lines());
}

/// The restore runs when the demotion itself fails AFTER its env write landed
/// (`role set client` wrote `client`, then exited 1): the best-effort restore
/// must put the persisted line back.
#[test]
fn persisted_role_is_restored_when_the_demotion_fails_after_its_env_write() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        role_set_client_fails_after_env_write: true,
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a failed demotion must fail the stage");
    assert!(
        err.contains("demotion (role set client) exited 1"),
        "the demotion failure must surface: {err}"
    );
    assert_eq!(
        guest.persisted_lines(),
        standard_env_lines(),
        "the best-effort restore must undo a demotion write that landed before the failure"
    );
}

/// The whole command sequence, pinned: the persisted record precedes every
/// demotion command, and the restore runs after the after-snapshot as
/// live-restore → rewrite → verify → live poll.
#[test]
fn restore_sequence_is_record_demote_snapshot_restore_verify_poll() {
    let guest = SemanticExitGuest::standard();
    run_stage(&guest).expect("a clean teardown on a faithful guest must pass");
    let labels: Vec<String> = guest
        .commands()
        .iter()
        .map(|argv| label_command(argv))
        .collect();
    assert_eq!(
        labels,
        [
            "discover-nat",
            "snapshot",
            "status",
            "grep-persisted",
            "role-set-admin",
            "role-set-client",
            "daemon-check",
            "settle",
            "snapshot",
            "role-set-admin",
            "sed-persisted",
            "grep-persisted",
            "status",
        ],
        "full dispatch sequence: {:?}",
        guest.commands()
    );
}

fn label_command(argv: &[String]) -> String {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["sudo", "-n", "nft", "list", "tables"] => "discover-nat".to_owned(),
        [_, "linux-exit-nat-lifecycle-snapshot", ..] => "snapshot".to_owned(),
        ["sudo", "-n", "env", _, _, "status"] => "status".to_owned(),
        ["sudo", "-n", "env", _, _, "role", "set", target] => format!("role-set-{target}"),
        ["sudo", "-n", "grep", ..] => "grep-persisted".to_owned(),
        ["sudo", "-n", "sed", ..] => "sed-persisted".to_owned(),
        ["systemctl", ..] => "daemon-check".to_owned(),
        ["sleep", _] => "settle".to_owned(),
        other => format!("unlabelled {other:?}"),
    }
}

/// Argv-only: no shell, no `-c`, and no element that could carry a second
/// command, a substitution or a newline. The sed program is the only element
/// built from data, and the guest has already refused any program that is not
/// the closed `s/^KEY=.*$/KEY=role/` shape.
#[test]
fn every_issued_argv_is_shell_free() {
    let guest = SemanticExitGuest::standard();
    run_stage(&guest).expect("a clean teardown on a faithful guest must pass");
    for argv in guest.commands() {
        assert!(
            !argv
                .iter()
                .any(|arg| matches!(arg.as_str(), "sh" | "bash" | "-c")),
            "no shell may be involved: {argv:?}"
        );
        for arg in &argv {
            assert!(
                !arg.chars()
                    .any(|c| matches!(c, ';' | '|' | '&' | '`' | '\n' | '\r' | '\\'))
                    && !arg.contains("$("),
                "argv element {arg:?} could carry shell syntax: {argv:?}"
            );
        }
    }
}

/// A live role that drifted away from the recorded one during the evaluation
/// (the daemon restarted and read the demoted file) is reported with the live
/// role left behind: the bounded `node_role=` poll is part of the restore.
#[test]
fn live_role_that_never_returns_is_reported_with_the_left_behind_live_role() {
    let guest = SemanticExitGuest::standard().with_faults(Faults {
        restart_during_evaluation: true,
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a live role stuck at client must fail the stage");
    assert!(
        err.contains("does not report node_role=admin") && err.contains("node_role=client"),
        "the poll failure must be named with the observed live role: {err}"
    );
    assert!(
        err.contains("left behind: persisted role admin")
            && err.contains("live role client (recorded admin)"),
        "both left-behind roles must be named: {err}"
    );
    assert_eq!(
        guest.persisted_lines(),
        standard_env_lines(),
        "the persisted line itself was restored and verified"
    );
}

/// The stage restores what it FOUND: a node whose persisted role already
/// disagreed with its live role before the stage ends up exactly as it was
/// found (the stage does not launder a pre-existing mismatch into a pass the
/// later enrollment precondition would then attribute to this stage).
#[test]
fn a_pre_existing_persisted_mismatch_is_restored_as_found() {
    let env: Vec<String> = vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "RUSTYNET_NODE_ROLE=client".to_owned(),
    ];
    let guest = SemanticExitGuest::serving_exit(env.clone());
    run_stage(&guest).expect("the stage proves the demotion residue, not the env consistency");
    assert_eq!(guest.persisted_lines(), env);
    assert_eq!(guest.live_primary(), PrimaryRole::Admin);
}

// ---- REVIEWER-PROPOSED (appended to the semantic tests file in a private tree) ----

/// Corner: a pre-existing persisted/live mismatch AND a daemon restart inside the
/// evaluation window (live := persisted = client). The restore's live `role set admin` then
/// plans client->admin and WRITES `admin` into the env file; the persisted rewrite must run
/// AFTER it so the recorded (as-found) line wins even though the stage fails on the live role.
#[test]
fn rrs_restart_in_window_with_a_pre_existing_mismatch_still_restores_the_recorded_line() {
    let env: Vec<String> = vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "RUSTYNET_NODE_ROLE=client".to_owned(),
    ];
    let guest = SemanticExitGuest::serving_exit(env.clone()).with_faults(Faults {
        restart_during_evaluation: true,
        ..Faults::default()
    });
    let err = run_stage(&guest).expect_err("a live role stuck at client must fail the stage");
    assert!(err.contains("does not report node_role=admin"), "{err}");
    assert_eq!(
        guest.persisted_lines(),
        env,
        "the recorded line must win over the live role set's own env write"
    );
}

/// Corner: the node starts as live `client` with a serving exit NAT table (synthetic), so the
/// demotion's `role set admin` PROMOTES the persisted role to admin. The restore must put the
/// recorded `client` line back (the old slice left `admin` persisted: a security-relevant
/// promotion).
#[test]
fn rrs_demotion_that_promotes_the_persisted_role_is_undone() {
    let env: Vec<String> = vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "RUSTYNET_NODE_ROLE=client".to_owned(),
    ];
    let guest = SemanticExitGuest::serving_exit(env.clone());
    guest.lock().live_primary = PrimaryRole::Client;
    let result = run_stage(&guest);
    assert_eq!(guest.persisted_lines(), env, "result={result:?}");
}

/// Kills "live restore targets the PERSISTED value": with a pre-existing mismatch the three
/// `role set` calls must be admin (demote), client (demote), admin (RECORDED LIVE role).
#[test]
fn rrs_pre_existing_mismatch_restore_targets_the_recorded_live_role() {
    let env: Vec<String> = vec![
        "RUSTYNET_NODE_ID=katana-exit-1".to_owned(),
        "RUSTYNET_NODE_ROLE=client".to_owned(),
    ];
    let guest = SemanticExitGuest::serving_exit(env.clone());
    run_stage(&guest).expect("the stage proves the demotion residue, not the env consistency");
    assert_eq!(
        guest.role_set_targets(),
        vec!["admin".to_owned(), "client".to_owned(), "admin".to_owned()],
        "the live restore must target the RECORDED LIVE role, never the persisted value"
    );
    assert_eq!(guest.persisted_lines(), env);
}

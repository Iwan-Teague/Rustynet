#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroize;

use crate::env_file::format_env_assignment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebianTwoNodeE2eConfig {
    pub exit_host: String,
    pub client_host: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub ssh_identity: Option<PathBuf>,
    pub ssh_known_hosts_file: Option<PathBuf>,
    pub ssh_allow_cidrs: String,
    pub ssh_sudo_mode: SshSudoMode,
    pub sudo_password_file: Option<PathBuf>,
    pub exit_node_id: String,
    pub client_node_id: String,
    pub network_id: String,
    pub remote_root: PathBuf,
    pub repo_ref: String,
    pub skip_apt: bool,
    pub report_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshSudoMode {
    Auto,
    Always,
    Never,
}

impl SshSudoMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            _ => Err(format!(
                "invalid --ssh-sudo value: {value} (expected auto|always|never)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    qualified: String,
    address: String,
}

struct Workspace {
    temp_dir: PathBuf,
    control_dir: PathBuf,
    known_hosts: PathBuf,
    local_archive: PathBuf,
    membership_snapshot_local: PathBuf,
    membership_log_local: PathBuf,
    assignment_pub_local: PathBuf,
    assignment_exit_local: PathBuf,
    assignment_client_local: PathBuf,
    assignment_refresh_exit_local: PathBuf,
    assignment_refresh_client_local: PathBuf,
}

impl Workspace {
    fn new(seed_known_hosts: &Path) -> Result<Self, String> {
        let unique = unique_suffix();
        let temp_dir = PathBuf::from(format!("/tmp/rustynet-remote-e2e.{unique}"));
        fs::create_dir_all(&temp_dir).map_err(|err| {
            format!(
                "failed to create temporary workspace {}: {err}",
                temp_dir.display()
            )
        })?;
        set_unix_mode(temp_dir.as_path(), 0o700)?;
        let control_dir = temp_dir.join("control");
        fs::create_dir_all(&control_dir).map_err(|err| {
            format!(
                "failed to create ssh control dir {}: {err}",
                control_dir.display()
            )
        })?;
        set_unix_mode(control_dir.as_path(), 0o700)?;
        let known_hosts = temp_dir.join("known_hosts");
        fs::copy(seed_known_hosts, &known_hosts).map_err(|err| {
            format!(
                "failed to seed {} from {}: {err}",
                known_hosts.display(),
                seed_known_hosts.display()
            )
        })?;
        set_unix_mode(known_hosts.as_path(), 0o600)?;

        Ok(Self {
            temp_dir: temp_dir.clone(),
            control_dir,
            known_hosts,
            local_archive: temp_dir.join("repo.tar"),
            membership_snapshot_local: temp_dir.join("membership.snapshot"),
            membership_log_local: temp_dir.join("membership.log"),
            assignment_pub_local: temp_dir.join("assignment.pub"),
            assignment_exit_local: temp_dir.join("exit.assignment"),
            assignment_client_local: temp_dir.join("client.assignment"),
            assignment_refresh_exit_local: temp_dir.join("assignment-refresh-exit.env"),
            assignment_refresh_client_local: temp_dir.join("assignment-refresh-client.env"),
        })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

#[derive(Default)]
struct CheckReport {
    checks: Vec<(String, String, String)>,
    fail_count: usize,
}

impl CheckReport {
    fn add(&mut self, name: &str, status: &str, detail: String) {
        self.checks
            .push((name.to_string(), status.to_string(), detail));
        if status != "PASS" {
            self.fail_count += 1;
        }
    }

    fn contains_or_fail(&mut self, name: &str, haystack: &str, needle: &str) {
        if haystack.contains(needle) {
            self.add(name, "PASS", format!("found '{needle}'"));
        } else {
            self.add(name, "FAIL", format!("missing '{needle}'"));
        }
    }
}

pub fn execute_ops_e2e_bootstrap_host(
    role: String,
    node_id: String,
    network_id: String,
    src_dir: PathBuf,
    ssh_allow_cidrs: String,
    skip_apt: bool,
) -> Result<String, String> {
    ensure_running_as_root()?;
    ensure_safe_token("role", role.as_str())?;
    ensure_safe_token("node-id", node_id.as_str())?;
    ensure_safe_token("network-id", network_id.as_str())?;
    ensure_safe_token("ssh-allow-cidrs", ssh_allow_cidrs.as_str())?;
    if !src_dir.is_absolute() {
        return Err(format!("--src-dir must be absolute: {}", src_dir.display()));
    }
    let src_dir_text = src_dir.display().to_string();
    ensure_safe_token("src-dir", src_dir_text.as_str())?;
    if !src_dir.is_dir() {
        return Err(format!("source dir is missing: {}", src_dir.display()));
    }

    if !skip_apt {
        install_linux_e2e_prerequisites()?;
        let required_toolchain = ensure_pinned_rust_toolchain(src_dir.as_path())?;
        let cargo_proxy = rustup_proxy_path("cargo")?;
        let cargo_proxy_text = cargo_proxy.display().to_string();
        let manifest_path = format!("{}/Cargo.toml", src_dir.display());
        run_status(
            cargo_proxy_text.as_str(),
            &[
                "build",
                "--release",
                "-p",
                "rustynetd",
                "-p",
                "rustynet-cli",
                "--manifest-path",
                manifest_path.as_str(),
            ],
            &[],
            format!(
                "remote release build failed during e2e bootstrap with toolchain {required_toolchain}"
            )
            .as_str(),
        )?;

        let daemon_binary = format!("{}/target/release/rustynetd", src_dir.display());
        run_status(
            "install",
            &[
                "-m",
                "0755",
                daemon_binary.as_str(),
                "/usr/local/bin/rustynetd",
            ],
            &[],
            "installing rustynetd failed during e2e bootstrap",
        )?;
        let cli_binary = format!("{}/target/release/rustynet-cli", src_dir.display());
        run_status(
            "install",
            &["-m", "0755", cli_binary.as_str(), "/usr/local/bin/rustynet"],
            &[],
            "installing rustynet CLI failed during e2e bootstrap",
        )?;
    } else {
        ensure_executable_file(
            Path::new("/usr/local/bin/rustynetd"),
            "installed rustynetd binary",
        )?;
        ensure_executable_file(
            Path::new("/usr/local/bin/rustynet"),
            "installed rustynet CLI",
        )?;
    }

    for service in [
        "rustynetd.service",
        "rustynetd-privileged-helper.service",
        "rustynetd-trust-refresh.service",
        "rustynetd-trust-refresh.timer",
    ] {
        run_allow_failure("systemctl", &["disable", "--now", service], &[]);
    }
    run_allow_failure("pkill", &["-f", "rustynetd daemon"], &[]);
    run_allow_failure("pkill", &["-f", "rustynetd privileged-helper"], &[]);
    run_allow_failure("ip", &["link", "delete", "rustynet0"], &[]);
    clear_rustynet_nftables_state()?;

    let _ = fs::remove_dir_all("/etc/rustynet");
    let _ = fs::remove_dir_all("/var/lib/rustynet");
    let _ = fs::remove_dir_all("/run/rustynet");

    run_status(
        "install",
        &["-d", "-m", "0700", "/etc/rustynet/credentials"],
        &[],
        "creating credentials directory failed",
    )?;
    run_status(
        "install",
        &["-d", "-m", "0700", "/var/lib/rustynet/keys"],
        &[],
        "creating key directory failed",
    )?;
    run_status(
        "install",
        &["-d", "-m", "0700", "/run/rustynet"],
        &[],
        "creating runtime directory failed",
    )?;

    let passphrase_path = format!(
        "/tmp/rustynet-passphrase.{}.{}",
        std::process::id(),
        unique_suffix()
    );
    let bootstrap_result = (|| -> Result<(), String> {
        let mut passphrase_bytes = [0u8; 48];
        OsRng.fill_bytes(&mut passphrase_bytes);
        let mut passphrase_hex = String::with_capacity(passphrase_bytes.len() * 2 + 1);
        for byte in passphrase_bytes {
            write!(&mut passphrase_hex, "{byte:02x}")
                .map_err(|err| format!("formatting bootstrap passphrase failed: {err}"))?;
        }
        passphrase_hex.push('\n');
        fs::write(passphrase_path.as_str(), passphrase_hex.as_bytes())
            .map_err(|err| format!("writing bootstrap passphrase failed: {err}"))?;
        set_unix_mode(Path::new(passphrase_path.as_str()), 0o600)?;
        passphrase_hex.zeroize();
        passphrase_bytes.zeroize();

        run_status(
            "rustynetd",
            &[
                "key",
                "init",
                "--runtime-private-key",
                "/run/rustynet/wireguard.key",
                "--encrypted-private-key",
                "/var/lib/rustynet/keys/wireguard.key.enc",
                "--public-key",
                "/var/lib/rustynet/keys/wireguard.pub",
                "--passphrase-file",
                passphrase_path.as_str(),
                "--force",
            ],
            &[],
            "rustynetd key init failed during e2e bootstrap",
        )?;

        run_status(
            "systemd-creds",
            &[
                "encrypt",
                "--name=wg_key_passphrase",
                passphrase_path.as_str(),
                "/etc/rustynet/credentials/wg_key_passphrase.cred",
            ],
            &[],
            "encrypting wg passphrase credential failed",
        )?;
        run_status(
            "chown",
            &[
                "root:root",
                "/etc/rustynet/credentials/wg_key_passphrase.cred",
            ],
            &[],
            "chown wg credential failed",
        )?;
        run_status(
            "chmod",
            &["0600", "/etc/rustynet/credentials/wg_key_passphrase.cred"],
            &[],
            "chmod wg credential failed",
        )?;

        run_status(
            "systemd-creds",
            &[
                "encrypt",
                "--name=signing_key_passphrase",
                passphrase_path.as_str(),
                "/etc/rustynet/credentials/signing_key_passphrase.cred",
            ],
            &[],
            "encrypting signing passphrase credential failed",
        )?;
        run_status(
            "chown",
            &[
                "root:root",
                "/etc/rustynet/credentials/signing_key_passphrase.cred",
            ],
            &[],
            "chown signing credential failed",
        )?;
        run_status(
            "chmod",
            &[
                "0600",
                "/etc/rustynet/credentials/signing_key_passphrase.cred",
            ],
            &[],
            "chmod signing credential failed",
        )?;
        run_allow_failure("rm", &["-f", "/run/rustynet/wireguard.key"], &[]);

        run_status(
            "rustynetd",
            &[
                "membership",
                "init",
                "--snapshot",
                "/var/lib/rustynet/membership.snapshot",
                "--log",
                "/var/lib/rustynet/membership.log",
                "--watermark",
                "/var/lib/rustynet/membership.watermark",
                "--owner-signing-key",
                "/etc/rustynet/membership.owner.key",
                "--owner-signing-key-passphrase-file",
                passphrase_path.as_str(),
                "--node-id",
                node_id.as_str(),
                "--network-id",
                network_id.as_str(),
                "--force",
            ],
            &[],
            "membership init failed during e2e bootstrap",
        )?;

        run_status(
            "rustynet",
            &[
                "trust",
                "keygen",
                "--signing-key-output",
                "/etc/rustynet/trust-evidence.key",
                "--signing-key-passphrase-file",
                passphrase_path.as_str(),
                "--verifier-key-output",
                "/etc/rustynet/trust-evidence.pub",
                "--force",
            ],
            &[],
            "trust keygen failed during e2e bootstrap",
        )?;
        run_status(
            "chmod",
            &["0644", "/etc/rustynet/trust-evidence.pub"],
            &[],
            "chmod trust verifier key failed",
        )?;

        run_status(
            "rustynet",
            &[
                "assignment",
                "init-signing-secret",
                "--output",
                "/etc/rustynet/assignment.signing.secret",
                "--signing-secret-passphrase-file",
                passphrase_path.as_str(),
                "--force",
            ],
            &[],
            "assignment signing secret init failed during e2e bootstrap",
        )?;

        run_status(
            "rustynet",
            &["ops", "refresh-trust"],
            &[
                (
                    "RUSTYNET_TRUST_EVIDENCE",
                    "/var/lib/rustynet/rustynetd.trust",
                ),
                (
                    "RUSTYNET_TRUST_SIGNER_KEY",
                    "/etc/rustynet/trust-evidence.key",
                ),
                (
                    "RUSTYNET_TRUST_SIGNING_KEY_PASSPHRASE_FILE",
                    passphrase_path.as_str(),
                ),
                ("RUSTYNET_DAEMON_GROUP", "rustynetd"),
                ("RUSTYNET_TRUST_AUTO_REFRESH", "true"),
            ],
            "refresh trust failed during e2e bootstrap",
        )?;

        run_status(
            "rustynet",
            &["ops", "install-systemd"],
            &[
                ("RUSTYNET_NODE_ID", node_id.as_str()),
                ("RUSTYNET_NODE_ROLE", role.as_str()),
                ("RUSTYNET_TRUST_AUTO_REFRESH", "true"),
                ("RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false"),
                ("RUSTYNET_AUTO_TUNNEL_ENFORCE", "false"),
                ("RUSTYNET_WG_LISTEN_PORT", "51820"),
                ("RUSTYNET_FAIL_CLOSED_SSH_ALLOW", "true"),
                (
                    "RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS",
                    ssh_allow_cidrs.as_str(),
                ),
                ("RUSTYNET_INSTALL_SOURCE_ROOT", src_dir_text.as_str()),
            ],
            "install-systemd failed during e2e bootstrap",
        )?;
        Ok(())
    })();
    secure_remove_file(Path::new(passphrase_path.as_str()));
    bootstrap_result?;

    Ok(format!(
        "e2e bootstrap host complete: role={} node_id={} src_dir={}",
        role,
        node_id,
        src_dir.display()
    ))
}

pub fn execute_ops_e2e_enforce_host(
    role: String,
    node_id: String,
    src_dir: PathBuf,
    ssh_allow_cidrs: String,
) -> Result<String, String> {
    ensure_running_as_root()?;
    ensure_safe_token("role", role.as_str())?;
    ensure_safe_token("node-id", node_id.as_str())?;
    ensure_safe_token("ssh-allow-cidrs", ssh_allow_cidrs.as_str())?;
    if !src_dir.is_absolute() {
        return Err(format!("--src-dir must be absolute: {}", src_dir.display()));
    }
    let src_dir_text = src_dir.display().to_string();
    ensure_safe_token("src-dir", src_dir_text.as_str())?;
    let auto_refresh = Path::new("/etc/rustynet/trust-evidence.key").is_file();
    let assignment_auto_refresh = Path::new("/etc/rustynet/assignment.signing.secret").is_file()
        && Path::new("/etc/rustynet/assignment-refresh.env").is_file();

    run_status(
        "rustynet",
        &["ops", "install-systemd"],
        &[
            ("RUSTYNET_NODE_ID", node_id.as_str()),
            ("RUSTYNET_NODE_ROLE", role.as_str()),
            (
                "RUSTYNET_TRUST_AUTO_REFRESH",
                if auto_refresh { "true" } else { "false" },
            ),
            (
                "RUSTYNET_ASSIGNMENT_AUTO_REFRESH",
                if assignment_auto_refresh {
                    "true"
                } else {
                    "false"
                },
            ),
            ("RUSTYNET_AUTO_TUNNEL_ENFORCE", "true"),
            ("RUSTYNET_WG_LISTEN_PORT", "51820"),
            ("RUSTYNET_FAIL_CLOSED_SSH_ALLOW", "true"),
            (
                "RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS",
                ssh_allow_cidrs.as_str(),
            ),
            ("RUSTYNET_INSTALL_SOURCE_ROOT", src_dir_text.as_str()),
        ],
        "install-systemd enforce pass failed",
    )?;

    Ok(format!(
        "e2e enforce host complete: role={role} node_id={node_id}",
    ))
}

pub fn execute_ops_e2e_membership_add(
    client_node_id: String,
    client_pubkey_hex: String,
    owner_approver_id: String,
) -> Result<String, String> {
    ensure_running_as_root()?;
    ensure_safe_token("client-node-id", client_node_id.as_str())?;
    ensure_safe_token("owner-approver-id", owner_approver_id.as_str())?;
    ensure_hex_32("client-pubkey-hex", client_pubkey_hex.as_str())?;

    let passphrase_path = format!(
        "/tmp/rustynet-membership-passphrase.{}.{}",
        std::process::id(),
        unique_suffix()
    );
    let work_dir = PathBuf::from(format!(
        "/tmp/rustynet-membership-update.{}.{}",
        std::process::id(),
        unique_suffix()
    ));
    fs::create_dir_all(work_dir.as_path())
        .map_err(|err| format!("failed creating {}: {err}", work_dir.display()))?;
    set_unix_mode(work_dir.as_path(), 0o700)?;
    let record_path = work_dir.join("add.record");
    let signed_path = work_dir.join("add.signed");

    let result = (|| -> Result<(), String> {
        run_status(
            "systemd-creds",
            &[
                "decrypt",
                "--name=signing_key_passphrase",
                "/etc/rustynet/credentials/signing_key_passphrase.cred",
                passphrase_path.as_str(),
            ],
            &[],
            "decrypting signing passphrase credential failed",
        )?;
        set_unix_mode(Path::new(passphrase_path.as_str()), 0o600)?;

        run_status(
            "rustynet",
            &[
                "membership",
                "propose-add",
                "--node-id",
                client_node_id.as_str(),
                "--node-pubkey",
                client_pubkey_hex.as_str(),
                "--owner",
                client_node_id.as_str(),
                "--output",
                record_path.to_string_lossy().as_ref(),
                "--snapshot",
                "/var/lib/rustynet/membership.snapshot",
                "--log",
                "/var/lib/rustynet/membership.log",
            ],
            &[],
            "membership propose-add failed",
        )?;
        run_status(
            "rustynet",
            &[
                "membership",
                "sign-update",
                "--record",
                record_path.to_string_lossy().as_ref(),
                "--approver-id",
                owner_approver_id.as_str(),
                "--signing-key",
                "/etc/rustynet/membership.owner.key",
                "--signing-key-passphrase-file",
                passphrase_path.as_str(),
                "--output",
                signed_path.to_string_lossy().as_ref(),
            ],
            &[],
            "membership sign-update failed",
        )?;
        run_status(
            "rustynet",
            &[
                "membership",
                "apply-update",
                "--signed-update",
                signed_path.to_string_lossy().as_ref(),
                "--snapshot",
                "/var/lib/rustynet/membership.snapshot",
                "--log",
                "/var/lib/rustynet/membership.log",
            ],
            &[],
            "membership apply-update failed",
        )?;
        Ok(())
    })();
    secure_remove_file(Path::new(passphrase_path.as_str()));
    let _ = fs::remove_dir_all(work_dir);
    result?;

    Ok(format!(
        "e2e membership add complete: client_node_id={client_node_id}",
    ))
}

pub fn execute_ops_e2e_issue_assignments(
    exit_node_id: String,
    client_node_id: String,
    exit_endpoint: String,
    client_endpoint: String,
    exit_pubkey_hex: String,
    client_pubkey_hex: String,
) -> Result<String, String> {
    ensure_running_as_root()?;
    for (label, value) in [
        ("exit-node-id", exit_node_id.as_str()),
        ("client-node-id", client_node_id.as_str()),
        ("exit-endpoint", exit_endpoint.as_str()),
        ("client-endpoint", client_endpoint.as_str()),
    ] {
        ensure_safe_token(label, value)?;
    }
    ensure_hex_32("exit-pubkey-hex", exit_pubkey_hex.as_str())?;
    ensure_hex_32("client-pubkey-hex", client_pubkey_hex.as_str())?;

    let passphrase_path = format!(
        "/tmp/rustynet-assignment-passphrase.{}.{}",
        std::process::id(),
        unique_suffix()
    );
    let result = (|| -> Result<(), String> {
        run_status(
            "systemd-creds",
            &[
                "decrypt",
                "--name=signing_key_passphrase",
                "/etc/rustynet/credentials/signing_key_passphrase.cred",
                passphrase_path.as_str(),
            ],
            &[],
            "decrypting assignment signing passphrase failed",
        )?;
        set_unix_mode(Path::new(passphrase_path.as_str()), 0o600)?;

        if !Path::new("/etc/rustynet/assignment.signing.secret").is_file() {
            run_status(
                "rustynet",
                &[
                    "assignment",
                    "init-signing-secret",
                    "--output",
                    "/etc/rustynet/assignment.signing.secret",
                    "--signing-secret-passphrase-file",
                    passphrase_path.as_str(),
                    "--force",
                ],
                &[],
                "initializing assignment signing secret failed",
            )?;
        }

        let nodes_spec = format!(
            "{exit_node_id}|{exit_endpoint}|{exit_pubkey_hex};{client_node_id}|{client_endpoint}|{client_pubkey_hex}",
        );
        let allow_spec =
            format!("{client_node_id}|{exit_node_id};{exit_node_id}|{client_node_id}",);

        run_status(
            "rustynet",
            &[
                "assignment",
                "issue",
                "--target-node-id",
                exit_node_id.as_str(),
                "--nodes",
                nodes_spec.as_str(),
                "--allow",
                allow_spec.as_str(),
                "--signing-secret",
                "/etc/rustynet/assignment.signing.secret",
                "--signing-secret-passphrase-file",
                passphrase_path.as_str(),
                "--output",
                "/tmp/rustynet-exit.assignment",
                "--verifier-key-output",
                "/tmp/rustynet-assignment.pub",
                "--ttl-secs",
                "300",
            ],
            &[],
            "issuing exit assignment failed",
        )?;
        run_status(
            "rustynet",
            &[
                "assignment",
                "issue",
                "--target-node-id",
                client_node_id.as_str(),
                "--nodes",
                nodes_spec.as_str(),
                "--allow",
                allow_spec.as_str(),
                "--signing-secret",
                "/etc/rustynet/assignment.signing.secret",
                "--signing-secret-passphrase-file",
                passphrase_path.as_str(),
                "--output",
                "/tmp/rustynet-client.assignment",
                "--verifier-key-output",
                "/tmp/rustynet-assignment.pub",
                "--exit-node-id",
                exit_node_id.as_str(),
                "--ttl-secs",
                "300",
            ],
            &[],
            "issuing client assignment failed",
        )?;
        Ok(())
    })();
    secure_remove_file(Path::new(passphrase_path.as_str()));
    result?;

    Ok(format!(
        "e2e assignment issuance complete: exit_node_id={exit_node_id} client_node_id={client_node_id}",
    ))
}

pub fn execute_ops_run_debian_two_node_e2e(
    config: DebianTwoNodeE2eConfig,
) -> Result<String, String> {
    validate_config(&config)?;

    let repo_root = resolve_repo_root()?;
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        repo_root.join(&config.report_path)
    };
    ensure_command_exists("git")?;
    ensure_command_exists("ssh")?;
    ensure_command_exists("ssh-keygen")?;
    ensure_command_exists("tar")?;
    let known_hosts_source = resolve_ssh_known_hosts_file(config.ssh_known_hosts_file.as_deref())?;

    let commit_sha = rev_parse_short(repo_root.as_path(), config.repo_ref.as_str())?;
    let workspace = Workspace::new(known_hosts_source.as_path())?;

    let exit_target = qualify_target(config.exit_host.as_str(), config.ssh_user.as_str());
    let client_target = qualify_target(config.client_host.as_str(), config.ssh_user.as_str());
    ensure_known_hosts_has_entry(
        known_hosts_source.as_path(),
        exit_target.address.as_str(),
        config.ssh_port,
    )?;
    ensure_known_hosts_has_entry(
        known_hosts_source.as_path(),
        client_target.address.as_str(),
        config.ssh_port,
    )?;
    let ssh_opts =
        build_ssh_base_options(&workspace, config.ssh_port, config.ssh_identity.as_ref());

    let needs_exit_sudo = target_needs_sudo(exit_target.qualified.as_str(), config.ssh_sudo_mode);
    let needs_client_sudo =
        target_needs_sudo(client_target.qualified.as_str(), config.ssh_sudo_mode);
    let sudo_password = load_sudo_password(
        config.sudo_password_file.as_deref(),
        needs_exit_sudo || needs_client_sudo,
    )?;

    let mut open_targets = Vec::new();
    open_master(ssh_opts.as_slice(), exit_target.qualified.as_str())?;
    open_targets.push(exit_target.qualified.clone());
    open_master(ssh_opts.as_slice(), client_target.qualified.as_str())?;
    open_targets.push(client_target.qualified.clone());

    if needs_exit_sudo {
        run_remote_program_checked(
            ssh_opts.as_slice(),
            exit_target.qualified.as_str(),
            Some(sudo_password.as_str()),
            "true",
            &[],
            &[],
        )?;
    }
    if needs_client_sudo {
        run_remote_program_checked(
            ssh_opts.as_slice(),
            client_target.qualified.as_str(),
            Some(sudo_password.as_str()),
            "true",
            &[],
            &[],
        )?;
    }

    create_git_archive(
        repo_root.as_path(),
        config.repo_ref.as_str(),
        workspace.local_archive.as_path(),
    )?;

    let remote_src_dir = format!("{}/src", config.remote_root.display());

    copy_local_archive_to_host(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        workspace.local_archive.as_path(),
        remote_src_dir.as_str(),
    )?;
    copy_local_archive_to_host(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.local_archive.as_path(),
        remote_src_dir.as_str(),
    )?;

    run_remote_cargo_ops_command(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        remote_src_dir.as_str(),
        &[
            "e2e-bootstrap-host",
            "--role",
            "admin",
            "--node-id",
            config.exit_node_id.as_str(),
            "--network-id",
            config.network_id.as_str(),
            "--src-dir",
            remote_src_dir.as_str(),
            "--ssh-allow-cidrs",
            config.ssh_allow_cidrs.as_str(),
            if config.skip_apt { "--skip-apt" } else { "" },
        ],
    )?;
    run_remote_cargo_ops_command(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        remote_src_dir.as_str(),
        &[
            "e2e-bootstrap-host",
            "--role",
            "client",
            "--node-id",
            config.client_node_id.as_str(),
            "--network-id",
            config.network_id.as_str(),
            "--src-dir",
            remote_src_dir.as_str(),
            "--ssh-allow-cidrs",
            config.ssh_allow_cidrs.as_str(),
            if config.skip_apt { "--skip-apt" } else { "" },
        ],
    )?;

    normalize_membership_permissions(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
    )?;
    normalize_membership_permissions(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
    )?;

    let exit_wg_pub = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "cat",
        &["/var/lib/rustynet/keys/wireguard.pub"],
        &[],
        false,
    )?
    .trim()
    .to_string();
    let client_wg_pub = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "cat",
        &["/var/lib/rustynet/keys/wireguard.pub"],
        &[],
        false,
    )?
    .trim()
    .to_string();
    if exit_wg_pub.is_empty() || client_wg_pub.is_empty() {
        close_open_masters(ssh_opts.as_slice(), &open_targets);
        return Err("failed to collect wireguard public keys".to_string());
    }
    let exit_wg_pub_hex = base64_to_hex(exit_wg_pub.as_str())?;
    let client_wg_pub_hex = base64_to_hex(client_wg_pub.as_str())?;

    let owner_approver_id = format!("{}-owner", config.exit_node_id);
    run_remote_rustynet_ops_command(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        &[
            "e2e-membership-add",
            "--client-node-id",
            config.client_node_id.as_str(),
            "--client-pubkey-hex",
            client_wg_pub_hex.as_str(),
            "--owner-approver-id",
            owner_approver_id.as_str(),
        ],
    )?;

    copy_remote_file_to_local(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/var/lib/rustynet/membership.snapshot",
        workspace.membership_snapshot_local.as_path(),
    )?;
    copy_remote_file_to_local(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/var/lib/rustynet/membership.log",
        workspace.membership_log_local.as_path(),
    )?;

    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.membership_snapshot_local.as_path(),
        "/var/lib/rustynet/membership.snapshot",
        "root",
        "root",
        "0600",
    )?;
    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.membership_log_local.as_path(),
        "/var/lib/rustynet/membership.log",
        "root",
        "root",
        "0600",
    )?;
    run_remote_program_checked(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rm",
        &["-f", "/var/lib/rustynet/membership.watermark"],
        &[],
    )?;
    normalize_membership_permissions(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
    )?;

    let exit_endpoint = format!("{}:51820", exit_target.address);
    let client_endpoint = format!("{}:51820", client_target.address);
    run_remote_rustynet_ops_command(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        &[
            "e2e-issue-assignments",
            "--exit-node-id",
            config.exit_node_id.as_str(),
            "--client-node-id",
            config.client_node_id.as_str(),
            "--exit-endpoint",
            exit_endpoint.as_str(),
            "--client-endpoint",
            client_endpoint.as_str(),
            "--exit-pubkey-hex",
            exit_wg_pub_hex.as_str(),
            "--client-pubkey-hex",
            client_wg_pub_hex.as_str(),
        ],
    )?;

    copy_remote_file_to_local(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/tmp/rustynet-assignment.pub",
        workspace.assignment_pub_local.as_path(),
    )?;
    copy_remote_file_to_local(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/tmp/rustynet-exit.assignment",
        workspace.assignment_exit_local.as_path(),
    )?;
    copy_remote_file_to_local(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/tmp/rustynet-client.assignment",
        workspace.assignment_client_local.as_path(),
    )?;

    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        workspace.assignment_pub_local.as_path(),
        "/etc/rustynet/assignment.pub",
        "root",
        "root",
        "0644",
    )?;
    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        workspace.assignment_exit_local.as_path(),
        "/var/lib/rustynet/rustynetd.assignment",
        "root",
        "rustynetd",
        "0640",
    )?;
    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.assignment_pub_local.as_path(),
        "/etc/rustynet/assignment.pub",
        "root",
        "root",
        "0644",
    )?;
    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.assignment_client_local.as_path(),
        "/var/lib/rustynet/rustynetd.assignment",
        "root",
        "rustynetd",
        "0640",
    )?;

    run_remote_program_checked(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rm",
        &[
            "-f",
            "/var/lib/rustynet/rustynetd.assignment.watermark",
            "/tmp/rustynet-assignment.pub",
            "/tmp/rustynet-exit.assignment",
            "/tmp/rustynet-client.assignment",
        ],
        &[],
    )?;
    run_remote_program_checked(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rm",
        &["-f", "/var/lib/rustynet/rustynetd.assignment.watermark"],
        &[],
    )?;

    let assignment_nodes_spec = format!(
        "{}|{}:51820|{};{}|{}:51820|{}",
        config.exit_node_id,
        exit_target.address,
        exit_wg_pub_hex,
        config.client_node_id,
        client_target.address,
        client_wg_pub_hex
    );
    let assignment_allow_spec = format!(
        "{}|{};{}|{}",
        config.client_node_id, config.exit_node_id, config.exit_node_id, config.client_node_id
    );

    write_assignment_refresh_env(
        workspace.assignment_refresh_exit_local.as_path(),
        AssignmentRefreshEnv {
            target_node_id: config.exit_node_id.clone(),
            nodes_spec: assignment_nodes_spec.clone(),
            allow_spec: assignment_allow_spec.clone(),
            exit_node_id: None,
        },
    )?;
    write_assignment_refresh_env(
        workspace.assignment_refresh_client_local.as_path(),
        AssignmentRefreshEnv {
            target_node_id: config.client_node_id.clone(),
            nodes_spec: assignment_nodes_spec,
            allow_spec: assignment_allow_spec,
            exit_node_id: Some(config.exit_node_id.clone()),
        },
    )?;

    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        workspace.assignment_refresh_exit_local.as_path(),
        "/etc/rustynet/assignment-refresh.env",
        "root",
        "root",
        "0600",
    )?;
    copy_local_file_to_remote(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        workspace.assignment_refresh_client_local.as_path(),
        "/etc/rustynet/assignment-refresh.env",
        "root",
        "root",
        "0600",
    )?;

    run_remote_rustynet_ops_command(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        needs_exit_sudo,
        sudo_password.as_str(),
        &[
            "e2e-enforce-host",
            "--role",
            "admin",
            "--node-id",
            config.exit_node_id.as_str(),
            "--src-dir",
            remote_src_dir.as_str(),
            "--ssh-allow-cidrs",
            config.ssh_allow_cidrs.as_str(),
        ],
    )?;
    run_remote_rustynet_ops_command(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        needs_client_sudo,
        sudo_password.as_str(),
        &[
            "e2e-enforce-host",
            "--role",
            "client",
            "--node-id",
            config.client_node_id.as_str(),
            "--src-dir",
            remote_src_dir.as_str(),
            "--ssh-allow-cidrs",
            config.ssh_allow_cidrs.as_str(),
        ],
    )?;

    retry_remote_program(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        RemoteRetryProgram {
            attempts: 20,
            sleep_secs: 2,
            program: "test",
            args: &["-S", "/run/rustynet/rustynetd.sock"],
            envs: &[],
        },
    )?;
    retry_remote_program(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        RemoteRetryProgram {
            attempts: 20,
            sleep_secs: 2,
            program: "test",
            args: &["-S", "/run/rustynet/rustynetd.sock"],
            envs: &[],
        },
    )?;
    retry_remote_program(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        RemoteRetryProgram {
            attempts: 10,
            sleep_secs: 2,
            program: "rustynet",
            args: &["route", "advertise", "0.0.0.0/0"],
            envs: &[("RUSTYNET_DAEMON_SOCKET", "/run/rustynet/rustynetd.sock")],
        },
    )?;

    std::thread::sleep(std::time::Duration::from_secs(3));

    let exit_status = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rustynet",
        &["status"],
        &[("RUSTYNET_DAEMON_SOCKET", "/run/rustynet/rustynetd.sock")],
        false,
    )?;
    let client_status = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rustynet",
        &["status"],
        &[("RUSTYNET_DAEMON_SOCKET", "/run/rustynet/rustynetd.sock")],
        false,
    )?;
    let client_route = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "ip",
        &["-4", "route", "get", "1.1.1.1"],
        &[],
        true,
    )?;
    let exit_wg_show = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "wg",
        &["show", "rustynet0"],
        &[],
        true,
    )?;
    let exit_nft_ruleset = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "nft",
        &["list", "ruleset"],
        &[],
        true,
    )?;
    let exit_tunnel_addr_output = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "ip",
        &["-4", "-o", "addr", "show", "dev", "rustynet0"],
        &[],
        true,
    )?;
    let exit_tunnel_ip = extract_first_ipv4(exit_tunnel_addr_output.as_str())
        .unwrap_or_default()
        .to_string();
    let exit_assignment_timer_state = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "systemctl",
        &["is-active", "rustynetd-assignment-refresh.timer"],
        &[],
        true,
    )?
    .trim()
    .to_string();
    let client_assignment_timer_state = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "systemctl",
        &["is-active", "rustynetd-assignment-refresh.timer"],
        &[],
        true,
    )?
    .trim()
    .to_string();

    if !exit_tunnel_ip.is_empty() {
        run_remote_program_checked(
            ssh_opts.as_slice(),
            client_target.qualified.as_str(),
            if needs_client_sudo {
                Some(sudo_password.as_str())
            } else {
                None
            },
            "ping",
            &["-c", "2", "-W", "2", exit_tunnel_ip.as_str()],
            &[],
        )?;
    }

    let exit_handshakes = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "wg",
        &["show", "rustynet0", "latest-handshakes"],
        &[],
        false,
    )?;

    let client_plaintext_keys = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "ls",
        &[
            "-1",
            "/var/lib/rustynet/keys/wireguard.passphrase",
            "/etc/rustynet/wireguard.passphrase",
        ],
        &[],
        true,
    )?;
    let exit_plaintext_keys = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "ls",
        &[
            "-1",
            "/var/lib/rustynet/keys/wireguard.passphrase",
            "/etc/rustynet/wireguard.passphrase",
        ],
        &[],
        true,
    )?;
    let client_cred_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/credentials/wg_key_passphrase.cred",
    )?;
    let exit_cred_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/credentials/wg_key_passphrase.cred",
    )?;
    let client_signing_cred_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/credentials/signing_key_passphrase.cred",
    )?;
    let exit_signing_cred_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/credentials/signing_key_passphrase.cred",
    )?;
    let client_key_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/var/lib/rustynet/keys/wireguard.key.enc",
    )?;
    let exit_key_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/var/lib/rustynet/keys/wireguard.key.enc",
    )?;
    let client_assignment_secret_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/assignment.signing.secret",
    )?;
    let exit_assignment_secret_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/assignment.signing.secret",
    )?;
    let client_trust_signer_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/trust-evidence.key",
    )?;
    let exit_trust_signer_mode = remote_stat_mode(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "/etc/rustynet/trust-evidence.key",
    )?;

    let exit_assignment_generated_before = extract_last_assignment_generated(exit_status.as_str());
    let client_assignment_generated_before =
        extract_last_assignment_generated(client_status.as_str());

    std::thread::sleep(std::time::Duration::from_secs(230));

    let exit_status_after_refresh = capture_remote_program_output(
        ssh_opts.as_slice(),
        exit_target.qualified.as_str(),
        if needs_exit_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rustynet",
        &["status"],
        &[("RUSTYNET_DAEMON_SOCKET", "/run/rustynet/rustynetd.sock")],
        false,
    )?;
    let client_status_after_refresh = capture_remote_program_output(
        ssh_opts.as_slice(),
        client_target.qualified.as_str(),
        if needs_client_sudo {
            Some(sudo_password.as_str())
        } else {
            None
        },
        "rustynet",
        &["status"],
        &[("RUSTYNET_DAEMON_SOCKET", "/run/rustynet/rustynetd.sock")],
        false,
    )?;
    let exit_assignment_generated_after =
        extract_last_assignment_generated(exit_status_after_refresh.as_str());
    let client_assignment_generated_after =
        extract_last_assignment_generated(client_status_after_refresh.as_str());

    let mut report = CheckReport::default();
    report.contains_or_fail(
        "exit-status-active",
        exit_status.as_str(),
        "state=ExitActive",
    );
    report.contains_or_fail(
        "exit-serving-enabled",
        exit_status.as_str(),
        "serving_exit_node=true",
    );
    report.contains_or_fail(
        "exit-not-restricted",
        exit_status.as_str(),
        "restricted_safe_mode=false",
    );
    report.contains_or_fail(
        "client-status-active",
        client_status.as_str(),
        "state=ExitActive",
    );
    report.contains_or_fail(
        "client-exit-selected",
        client_status.as_str(),
        format!("exit_node={}", config.exit_node_id).as_str(),
    );
    report.contains_or_fail(
        "client-not-restricted",
        client_status.as_str(),
        "restricted_safe_mode=false",
    );
    report.contains_or_fail(
        "client-route-via-tunnel",
        client_route.as_str(),
        "dev rustynet0",
    );
    report.contains_or_fail(
        "exit-nat-masquerade",
        exit_nft_ruleset.as_str(),
        "masquerade",
    );
    report.contains_or_fail(
        "exit-forward-from-tunnel",
        exit_nft_ruleset.as_str(),
        "iifname \"rustynet0\"",
    );
    if exit_assignment_timer_state == "active" {
        report.add(
            "exit-assignment-refresh-timer",
            "PASS",
            "rustynetd-assignment-refresh.timer is active".to_string(),
        );
    } else {
        report.add(
            "exit-assignment-refresh-timer",
            "FAIL",
            format!(
                "timer state={}",
                if exit_assignment_timer_state.is_empty() {
                    "unknown"
                } else {
                    exit_assignment_timer_state.as_str()
                }
            ),
        );
    }
    if client_assignment_timer_state == "active" {
        report.add(
            "client-assignment-refresh-timer",
            "PASS",
            "rustynetd-assignment-refresh.timer is active".to_string(),
        );
    } else {
        report.add(
            "client-assignment-refresh-timer",
            "FAIL",
            format!(
                "timer state={}",
                if client_assignment_timer_state.is_empty() {
                    "unknown"
                } else {
                    client_assignment_timer_state.as_str()
                }
            ),
        );
    }
    if exit_tunnel_ip.is_empty() {
        report.add(
            "exit-tunnel-ip",
            "FAIL",
            "unable to detect tunnel IP".to_string(),
        );
    } else {
        report.add("exit-tunnel-ip", "PASS", exit_tunnel_ip.clone());
    }

    let handshake_ok = exit_handshakes.lines().any(|line| {
        line.split_whitespace()
            .last()
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .map(|value| value > 0)
            .unwrap_or(false)
    });
    if handshake_ok {
        report.add(
            "wg-latest-handshake",
            "PASS",
            "latest-handshakes includes non-zero timestamp".to_string(),
        );
    } else {
        report.add(
            "wg-latest-handshake",
            "FAIL",
            "no non-zero handshake timestamp observed".to_string(),
        );
    }

    if client_plaintext_keys.trim().is_empty() && exit_plaintext_keys.trim().is_empty() {
        report.add(
            "no-plaintext-passphrase-files",
            "PASS",
            "legacy plaintext passphrase files absent".to_string(),
        );
    } else {
        report.add(
            "no-plaintext-passphrase-files",
            "FAIL",
            "found plaintext passphrase file(s)".to_string(),
        );
    }

    if client_cred_mode == "root:root 600" && exit_cred_mode == "root:root 600" {
        report.add(
            "credential-blob-permissions",
            "PASS",
            "wg credential blob mode is 0600 root:root on both hosts".to_string(),
        );
    } else {
        report.add(
            "credential-blob-permissions",
            "FAIL",
            format!("client={client_cred_mode}; exit={exit_cred_mode}"),
        );
    }

    if client_signing_cred_mode == "root:root 600" && exit_signing_cred_mode == "root:root 600" {
        report.add(
            "signing-credential-blob-permissions",
            "PASS",
            "signing credential blob mode is 0600 root:root on both hosts".to_string(),
        );
    } else {
        report.add(
            "signing-credential-blob-permissions",
            "FAIL",
            format!("client={client_signing_cred_mode}; exit={exit_signing_cred_mode}"),
        );
    }

    if client_key_mode == "rustynetd:rustynetd 600" && exit_key_mode == "rustynetd:rustynetd 600" {
        report.add(
            "encrypted-key-permissions",
            "PASS",
            "encrypted key mode is 0600 rustynetd:rustynetd on both hosts".to_string(),
        );
    } else {
        report.add(
            "encrypted-key-permissions",
            "FAIL",
            format!("client={client_key_mode}; exit={exit_key_mode}"),
        );
    }

    if client_assignment_secret_mode == "root:root 600"
        && exit_assignment_secret_mode == "root:root 600"
    {
        report.add(
            "assignment-signing-secret-permissions",
            "PASS",
            "encrypted assignment signing secret mode is 0600 root:root on both hosts".to_string(),
        );
    } else {
        report.add(
            "assignment-signing-secret-permissions",
            "FAIL",
            format!("client={client_assignment_secret_mode}; exit={exit_assignment_secret_mode}"),
        );
    }

    if client_trust_signer_mode == "root:root 600" && exit_trust_signer_mode == "root:root 600" {
        report.add(
            "trust-signer-key-permissions",
            "PASS",
            "encrypted trust signer key mode is 0600 root:root on both hosts".to_string(),
        );
    } else {
        report.add(
            "trust-signer-key-permissions",
            "FAIL",
            format!("client={client_trust_signer_mode}; exit={exit_trust_signer_mode}"),
        );
    }

    if exit_assignment_generated_before
        .zip(exit_assignment_generated_after)
        .map(|(before, after)| after > before)
        .unwrap_or(false)
    {
        report.add(
            "exit-assignment-refresh-rotation",
            "PASS",
            format!(
                "generated_at advanced from {} to {}",
                exit_assignment_generated_before.unwrap_or(0),
                exit_assignment_generated_after.unwrap_or(0)
            ),
        );
    } else {
        report.add(
            "exit-assignment-refresh-rotation",
            "FAIL",
            format!(
                "generated_at before={} after={}",
                exit_assignment_generated_before
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                exit_assignment_generated_after
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
        );
    }

    if client_assignment_generated_before
        .zip(client_assignment_generated_after)
        .map(|(before, after)| after > before)
        .unwrap_or(false)
    {
        report.add(
            "client-assignment-refresh-rotation",
            "PASS",
            format!(
                "generated_at advanced from {} to {}",
                client_assignment_generated_before.unwrap_or(0),
                client_assignment_generated_after.unwrap_or(0)
            ),
        );
    } else {
        report.add(
            "client-assignment-refresh-rotation",
            "FAIL",
            format!(
                "generated_at before={} after={}",
                client_assignment_generated_before
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                client_assignment_generated_after
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
        );
    }

    let fail_count = report.fail_count;
    write_report(
        report_path.as_path(),
        ReportInputs {
            generated_at_utc: utc_timestamp(),
            commit_sha,
            exit_target: exit_target.qualified,
            client_target: client_target.qualified,
            exit_node_id: config.exit_node_id,
            client_node_id: config.client_node_id,
            network_id: config.network_id,
            ssh_allow_cidrs: config.ssh_allow_cidrs,
            report,
            exit_status,
            exit_status_after_refresh,
            client_status,
            client_status_after_refresh,
            client_route,
            exit_wg_show,
        },
    )?;

    close_open_masters(ssh_opts.as_slice(), &open_targets);

    if fail_count > 0 {
        return Err(format!(
            "validation failed with failing checks; see report: {}",
            report_path.display()
        ));
    }

    Ok(format!(
        "validation passed; report written to {}",
        report_path.display()
    ))
}

fn validate_config(config: &DebianTwoNodeE2eConfig) -> Result<(), String> {
    if config.exit_host.trim().is_empty()
        || config.client_host.trim().is_empty()
        || config.ssh_allow_cidrs.trim().is_empty()
    {
        return Err("--exit-host, --client-host, and --ssh-allow-cidrs are required".to_string());
    }
    if !config.remote_root.is_absolute() {
        return Err(format!(
            "--remote-root must be absolute: {}",
            config.remote_root.display()
        ));
    }
    if let Some(identity) = config.ssh_identity.as_ref()
        && !identity.is_file()
    {
        return Err(format!(
            "--ssh-identity does not exist: {}",
            identity.display()
        ));
    }
    for (label, value) in [
        ("exit-node-id", config.exit_node_id.as_str()),
        ("client-node-id", config.client_node_id.as_str()),
        ("network-id", config.network_id.as_str()),
        ("remote-root", &config.remote_root.display().to_string()),
        ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
    ] {
        ensure_safe_token(label, value)?;
    }
    Ok(())
}

fn ensure_safe_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-')
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

fn ensure_safe_remote_path(path: &str) -> Result<(), String> {
    ensure_safe_token("remote-path", path)
}

fn ensure_hex_32(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be 64 hex characters"));
    }
    Ok(())
}

fn ensure_running_as_root() -> Result<(), String> {
    if Uid::effective().is_root() {
        return Ok(());
    }
    Err("this operation requires root".to_string())
}

fn run_status(
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    context: &str,
) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|err| format!("{context}: failed to spawn {program}: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "{context}: status={} stderr={}",
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run_allow_failure(program: &str, args: &[&str], envs: &[(&str, &str)]) {
    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let _ = command.status();
}

fn capture_stdout(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to spawn {program}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited unsuccessfully: {}",
            program,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn extract_first_ipv4(output: &str) -> Option<&str> {
    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        for (index, token) in tokens.iter().enumerate() {
            if *token == "inet" {
                let cidr = tokens.get(index + 1)?;
                let address = cidr.split('/').next().unwrap_or_default();
                if !address.is_empty() {
                    return Some(address);
                }
            }
        }
    }
    None
}

fn secure_remove_file(path: &Path) {
    if !path.is_file() {
        return;
    }
    if ensure_command_exists("shred").is_ok() {
        let _ = Command::new("shred")
            .args(["--force", "--remove"])
            .arg(path)
            .status();
        return;
    }
    let _ = fs::write(path, []);
    let _ = fs::remove_file(path);
}

fn install_linux_e2e_prerequisites() -> Result<(), String> {
    let os_release = fs::read_to_string("/etc/os-release")
        .map_err(|err| format!("failed to read /etc/os-release: {err}"))?;
    let os_id = parse_os_release_value(os_release.as_str(), "ID");
    let os_like = parse_os_release_value(os_release.as_str(), "ID_LIKE");
    let is_fedora_like = os_id == "fedora"
        || os_like
            .split_whitespace()
            .any(|value| value == "fedora" || value == "rhel");
    let is_debian_like = os_id == "debian"
        || os_id == "ubuntu"
        || os_id == "linuxmint"
        || os_like
            .split_whitespace()
            .any(|value| value == "debian" || value == "ubuntu");

    if is_fedora_like {
        run_status(
            "dnf",
            &[
                "install",
                "-y",
                "ca-certificates",
                "curl",
                "git",
                "gcc",
                "gcc-c++",
                "make",
                "pkgconf-pkg-config",
                "openssl-devel",
                "sqlite-devel",
                "clang",
                "llvm",
                "nftables",
                "wireguard-tools",
                "openssl",
                "rustup",
            ],
            &[],
            "dnf install failed during e2e bootstrap",
        )?;
        return Ok(());
    }

    if is_debian_like {
        run_status(
            "apt-get",
            &["update"],
            &[],
            "apt update failed during e2e bootstrap",
        )?;
        run_status(
            "apt-get",
            &[
                "install",
                "-y",
                "--no-install-recommends",
                "ca-certificates",
                "curl",
                "git",
                "build-essential",
                "pkg-config",
                "libssl-dev",
                "libsqlite3-dev",
                "clang",
                "llvm",
                "nftables",
                "wireguard-tools",
                "openssl",
                "rustup",
            ],
            &[],
            "apt install failed during e2e bootstrap",
        )?;
        return Ok(());
    }

    Err(format!(
        "unsupported Linux distribution for e2e bootstrap (ID={os_id}, ID_LIKE={os_like})"
    ))
}

fn parse_os_release_value(contents: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    contents
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_default()
}

fn rust_toolchain_channel(repo_root: &Path) -> Result<String, String> {
    let toolchain_path = repo_root.join("rust-toolchain.toml");
    let contents = fs::read_to_string(toolchain_path.as_path()).map_err(|err| {
        format!(
            "failed to read required toolchain file {}: {err}",
            toolchain_path.display()
        )
    })?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("channel") {
            continue;
        }
        let Some((_, value)) = trimmed.split_once('=') else {
            continue;
        };
        let channel = value.trim().trim_matches('"').to_string();
        if !channel.is_empty() {
            return Ok(channel);
        }
    }
    Err(format!(
        "failed to parse required toolchain channel from {}",
        toolchain_path.display()
    ))
}

fn rustup_proxy_path(tool: &str) -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let path = home.join(".cargo").join("bin").join(tool);
    if is_executable(path.as_path()) {
        return Ok(path);
    }
    Err(format!(
        "missing rustup-managed {tool} proxy at {}; run rustup toolchain bootstrap first",
        path.display()
    ))
}

fn rustup_bootstrap_path() -> Result<PathBuf, String> {
    if let Ok(path) = rustup_proxy_path("rustup") {
        return Ok(path);
    }
    for candidate in [
        "/usr/bin/rustup",
        "/bin/rustup",
        "/usr/bin/rustup-init",
        "/bin/rustup-init",
    ] {
        let path = PathBuf::from(candidate);
        if is_executable(path.as_path()) {
            return Ok(path);
        }
    }
    Err("missing rustup bootstrap binary; expected rustup or rustup-init".to_string())
}

fn ensure_pinned_rust_toolchain(repo_root: &Path) -> Result<String, String> {
    let toolchain = rust_toolchain_channel(repo_root)?;
    let bootstrap_path = rustup_bootstrap_path()?;
    let bootstrap_text = bootstrap_path.display().to_string();
    if rustup_proxy_path("rustup").is_err()
        && bootstrap_path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name == "rustup-init")
    {
        run_status(
            bootstrap_text.as_str(),
            &[
                "-y",
                "--profile",
                "minimal",
                "--default-toolchain",
                toolchain.as_str(),
                "--component",
                "rustfmt",
                "--component",
                "clippy",
            ],
            &[],
            "initializing rustup failed during e2e bootstrap",
        )?;
    }
    let rustup_cli = rustup_proxy_path("rustup").unwrap_or(bootstrap_path);
    let rustup_cli_text = rustup_cli.display().to_string();
    let existing_rustc = capture_stdout(
        rustup_cli_text.as_str(),
        &["run", toolchain.as_str(), "rustc", "--version"],
        &[],
    );
    let existing_cargo = capture_stdout(
        rustup_cli_text.as_str(),
        &["run", toolchain.as_str(), "cargo", "--version"],
        &[],
    );
    run_status(
        rustup_cli_text.as_str(),
        &["set", "profile", "minimal"],
        &[],
        "setting rustup profile failed during e2e bootstrap",
    )?;
    if existing_rustc.is_err() || existing_cargo.is_err() {
        run_status(
            rustup_cli_text.as_str(),
            &[
                "toolchain",
                "install",
                toolchain.as_str(),
                "--profile",
                "minimal",
                "--component",
                "rustfmt",
                "--component",
                "clippy",
            ],
            &[],
            "installing pinned rust toolchain failed during e2e bootstrap",
        )?;
    }
    run_status(
        rustup_cli_text.as_str(),
        &["default", toolchain.as_str()],
        &[],
        "setting default rust toolchain failed during e2e bootstrap",
    )?;
    let rustc_version = capture_stdout(
        rustup_cli_text.as_str(),
        &["run", toolchain.as_str(), "rustc", "--version"],
        &[],
    )
    .map_err(|err| format!("verifying pinned rust toolchain failed: {err}"))?;
    if rustc_version.trim().is_empty() {
        return Err("pinned rust toolchain verification returned empty rustc version".to_string());
    }
    rustup_proxy_path("cargo")?;
    rustup_proxy_path("rustc")?;
    Ok(toolchain)
}

fn resolve_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("failed to resolve repository root via git: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err("repository root path is empty".to_string());
    }
    Ok(PathBuf::from(root))
}

fn rev_parse_short(repo_root: &Path, repo_ref: &str) -> Result<String, String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", &format!("{repo_ref}^{{commit}}")])
        .status()
        .map_err(|err| format!("git rev-parse verify failed to start: {err}"))?;
    if !status.success() {
        return Err(format!("invalid git ref: {repo_ref}"));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--short", &format!("{repo_ref}^{{commit}}")])
        .output()
        .map_err(|err| format!("git rev-parse short failed to start: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse short failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn ensure_command_exists(command: &str) -> Result<(), String> {
    let Some(paths) = env::var_os("PATH") else {
        return Err(format!(
            "PATH is not set; missing required local command: {command}"
        ));
    };
    for dir in env::split_paths(&paths) {
        let candidate = dir.join(command);
        if is_executable(candidate.as_path()) {
            return Ok(());
        }
    }
    Err(format!("missing required local command: {command}"))
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(path) {
            return metadata.permissions().mode() & 0o111 != 0;
        }
        false
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn ensure_executable_file(path: &Path, label: &str) -> Result<(), String> {
    if is_executable(path) {
        return Ok(());
    }
    Err(format!(
        "{label} is missing or not executable: {}",
        path.display()
    ))
}

fn resolve_ssh_known_hosts_file(path: Option<&Path>) -> Result<PathBuf, String> {
    let resolved = if let Some(path) = path {
        path.to_path_buf()
    } else {
        let Some(home) = env::var_os("HOME") else {
            return Err(
                "missing pinned known_hosts file; provide --ssh-known-hosts-file or set HOME"
                    .to_string(),
            );
        };
        PathBuf::from(home).join(".ssh/known_hosts")
    };
    let metadata = fs::symlink_metadata(&resolved).map_err(|err| {
        format!(
            "pinned known_hosts file check failed for {}: {err}",
            resolved.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "pinned known_hosts file must not be a symlink: {}",
            resolved.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "pinned known_hosts file is not a regular file: {}",
            resolved.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(format!(
                "pinned known_hosts file must not be group/world writable: {:03o} ({})",
                mode,
                resolved.display()
            ));
        }
    }
    Ok(resolved)
}

fn ensure_known_hosts_has_entry(known_hosts: &Path, host: &str, port: u16) -> Result<(), String> {
    let lookup_host = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let output = Command::new("ssh-keygen")
        .args(["-F", lookup_host.as_str(), "-f"])
        .arg(known_hosts)
        .output()
        .map_err(|err| {
            format!("failed checking pinned known_hosts entry for {lookup_host}: {err}")
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "pinned known_hosts file {} lacks host key for {lookup_host}",
        known_hosts.display()
    ))
}

fn clear_rustynet_nftables_state() -> Result<(), String> {
    let table_listing = capture_stdout("nft", &["list", "tables"], &[]).unwrap_or_default();
    for line in table_listing.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.len() == 3 && tokens[0] == "table" && tokens[2].starts_with("rustynet") {
            run_allow_failure("nft", &["flush", "table", tokens[1], tokens[2]], &[]);
            run_allow_failure("nft", &["delete", "table", tokens[1], tokens[2]], &[]);
        }
    }
    let residual = capture_stdout("nft", &["list", "tables"], &[]).unwrap_or_default();
    if residual.lines().any(|line| {
        line.split_whitespace()
            .nth(2)
            .is_some_and(|name| name.starts_with("rustynet"))
    }) {
        return Err("residual rustynet nftables state remained after cleanup".to_string());
    }
    Ok(())
}

fn qualify_target(raw: &str, ssh_user: &str) -> Target {
    if raw.contains('@') {
        let address = raw.split('@').nth(1).unwrap_or_default().to_string();
        return Target {
            qualified: raw.to_string(),
            address,
        };
    }
    Target {
        qualified: format!("{ssh_user}@{raw}"),
        address: raw.to_string(),
    }
}

fn target_needs_sudo(target: &str, mode: SshSudoMode) -> bool {
    match mode {
        SshSudoMode::Always => true,
        SshSudoMode::Never => false,
        SshSudoMode::Auto => target.split('@').next().unwrap_or_default() != "root",
    }
}

fn load_sudo_password(path: Option<&Path>, required: bool) -> Result<String, String> {
    if !required {
        return Ok(String::new());
    }
    let Some(path) = path else {
        return Err(
            "sudo is required for non-root SSH targets; provide --sudo-password-file".to_string(),
        );
    };
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("sudo password file check failed: {err}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "--sudo-password-file must not be a symlink: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "--sudo-password-file must be mode 0600; found {:03o} ({})",
                mode,
                path.display()
            ));
        }
    }
    let contents = fs::read_to_string(path).map_err(|err| {
        format!(
            "failed to read sudo password file {}: {err}",
            path.display()
        )
    })?;
    let first_line = contents
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if first_line.is_empty() {
        return Err(
            "--sudo-password-file must contain a non-empty password on first line".to_string(),
        );
    }
    Ok(first_line)
}

fn build_ssh_base_options(
    workspace: &Workspace,
    port: u16,
    identity: Option<&PathBuf>,
) -> Vec<OsString> {
    let mut options = vec![
        OsString::from("-o"),
        OsString::from("ConnectTimeout=20"),
        OsString::from("-o"),
        OsString::from("ServerAliveInterval=20"),
        OsString::from("-o"),
        OsString::from("ServerAliveCountMax=3"),
        OsString::from("-o"),
        OsString::from("StrictHostKeyChecking=yes"),
        OsString::from("-o"),
        OsString::from(format!(
            "UserKnownHostsFile={}",
            workspace.known_hosts.display()
        )),
        OsString::from("-o"),
        OsString::from("ControlMaster=auto"),
        OsString::from("-o"),
        OsString::from("ControlPersist=600"),
        OsString::from("-o"),
        OsString::from(format!(
            "ControlPath={}/%C",
            workspace.control_dir.display()
        )),
        OsString::from("-p"),
        OsString::from(port.to_string()),
    ];
    if let Some(identity) = identity {
        options.push(OsString::from("-i"));
        options.push(identity.as_os_str().to_os_string());
        options.push(OsString::from("-o"));
        options.push(OsString::from("IdentitiesOnly=yes"));
    }
    options
}

fn open_master(options: &[OsString], host: &str) -> Result<(), String> {
    let output = Command::new("ssh")
        .args(options)
        .arg(host)
        .arg("true")
        .output()
        .map_err(|err| format!("failed opening ssh control master for {host}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "failed opening ssh control master for {host}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn close_open_masters(options: &[OsString], hosts: &[String]) {
    for host in hosts {
        let _ = Command::new("ssh")
            .args(options)
            .arg("-O")
            .arg("exit")
            .arg(host)
            .status();
    }
}

fn create_git_archive(repo_root: &Path, repo_ref: &str, output_path: &Path) -> Result<(), String> {
    let output_file = File::create(output_path)
        .map_err(|err| format!("failed to create {}: {err}", output_path.display()))?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["archive", "--format=tar", repo_ref])
        .stdout(Stdio::from(output_file))
        .status()
        .map_err(|err| format!("git archive failed to start: {err}"))?;
    if !status.success() {
        return Err("git archive failed".to_string());
    }
    Ok(())
}

fn run_remote_program(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    allow_failure: bool,
) -> Result<Output, String> {
    let mut command = Command::new("ssh");
    command.args(options).arg(host);
    if sudo_password.is_some() {
        command.arg("sudo").arg("-S").arg("-p").arg("");
    }
    if !envs.is_empty() {
        command.arg("env");
        for (key, value) in envs {
            ensure_safe_token("remote-env-key", key)?;
            ensure_safe_token("remote-env-value", value)?;
            command.arg(format!("{key}={value}"));
        }
    }
    command.arg(program);
    command.args(args);

    let mut payload = Vec::new();
    if let Some(password) = sudo_password {
        payload.extend_from_slice(password.as_bytes());
        payload.push(b'\n');
    }

    let output = run_command_with_input_allow_failure(command, payload.as_slice())?;
    if !allow_failure && !output.status.success() {
        return Err(format!(
            "remote command failed on {host}: {program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn run_remote_program_checked(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<(), String> {
    run_remote_program(options, host, sudo_password, program, args, envs, false).map(|_| ())
}

fn capture_remote_program_output(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    allow_failure: bool,
) -> Result<String, String> {
    let output = run_remote_program(
        options,
        host,
        sudo_password,
        program,
        args,
        envs,
        allow_failure,
    )?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn copy_local_archive_to_host(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
    local_archive: &Path,
    remote_src_dir: &str,
) -> Result<(), String> {
    ensure_safe_remote_path(remote_src_dir)?;
    let sudo = if needs_sudo {
        Some(sudo_password)
    } else {
        None
    };
    run_remote_program_checked(options, host, sudo, "rm", &["-rf", remote_src_dir], &[])?;
    run_remote_program_checked(
        options,
        host,
        sudo,
        "install",
        &["-d", "-m", "0755", remote_src_dir],
        &[],
    )?;

    let archive_bytes = fs::read(local_archive)
        .map_err(|err| format!("failed to read {}: {err}", local_archive.display()))?;
    let mut command = Command::new("ssh");
    command.args(options).arg(host);
    if needs_sudo {
        command
            .arg("sudo")
            .arg("-S")
            .arg("-p")
            .arg("")
            .arg("tar")
            .arg("-xf")
            .arg("-")
            .arg("-C")
            .arg(remote_src_dir);
    } else {
        command
            .arg("tar")
            .arg("-xf")
            .arg("-")
            .arg("-C")
            .arg(remote_src_dir);
    }
    let mut payload = Vec::new();
    if needs_sudo {
        payload.extend_from_slice(sudo_password.as_bytes());
        payload.push(b'\n');
    }
    payload.extend_from_slice(&archive_bytes);
    run_command_with_input(command, payload.as_slice()).map(|_| ())
}

fn run_remote_cargo_ops_command(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
    remote_src_dir: &str,
    ops_args: &[&str],
) -> Result<(), String> {
    ensure_safe_remote_path(remote_src_dir)?;
    let manifest_path = format!("{remote_src_dir}/Cargo.toml");
    let mut remote_args = vec![
        "run".to_string(),
        "--release".to_string(),
        "--manifest-path".to_string(),
        manifest_path,
        "-p".to_string(),
        "rustynet-cli".to_string(),
        "--".to_string(),
        "ops".to_string(),
    ];
    for arg in ops_args {
        if arg.is_empty() {
            continue;
        }
        ensure_safe_token("remote-arg", arg)?;
        remote_args.push((*arg).to_string());
    }
    let remote_refs = remote_args.iter().map(String::as_str).collect::<Vec<_>>();
    run_remote_program_command(
        options,
        host,
        needs_sudo,
        sudo_password,
        "cargo",
        &remote_refs,
    )
}

fn run_remote_rustynet_ops_command(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
    ops_args: &[&str],
) -> Result<(), String> {
    let mut remote_args = vec!["ops".to_string()];
    for arg in ops_args {
        ensure_safe_token("remote-arg", arg)?;
        remote_args.push((*arg).to_string());
    }
    let remote_refs = remote_args.iter().map(String::as_str).collect::<Vec<_>>();
    run_remote_program_command(
        options,
        host,
        needs_sudo,
        sudo_password,
        "/usr/local/bin/rustynet",
        &remote_refs,
    )
}

fn run_remote_program_command(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
    program: &str,
    args: &[&str],
) -> Result<(), String> {
    let mut command = Command::new("ssh");
    command.args(options).arg(host);
    if needs_sudo {
        command.arg("sudo").arg("-S").arg("-p").arg("").arg(program);
    } else {
        command.arg(program);
    }
    command.args(args);

    let mut payload = Vec::new();
    if needs_sudo {
        payload.extend_from_slice(sudo_password.as_bytes());
        payload.push(b'\n');
    }
    run_command_with_input(command, payload.as_slice()).map(|_| ())
}

fn copy_remote_file_to_local(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    ensure_safe_remote_path(remote_path)?;
    let output = capture_remote_program_output(
        options,
        host,
        sudo_password,
        "cat",
        &[remote_path],
        &[],
        false,
    )?;
    fs::write(local_path, output.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", local_path.display()))
}

#[allow(clippy::too_many_arguments)]
fn copy_local_file_to_remote(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
    local_path: &Path,
    remote_path: &str,
    owner_user: &str,
    owner_group: &str,
    mode: &str,
) -> Result<(), String> {
    ensure_safe_remote_path(remote_path)?;
    ensure_safe_token("owner-user", owner_user)?;
    ensure_safe_token("owner-group", owner_group)?;
    ensure_safe_token("mode", mode)?;
    let bytes = fs::read(local_path)
        .map_err(|err| format!("failed to read {}: {err}", local_path.display()))?;
    let mut command = Command::new("ssh");
    command.args(options).arg(host);
    if needs_sudo {
        command.arg("sudo").arg("-S").arg("-p").arg("");
    }
    command
        .arg("install")
        .arg("-D")
        .arg("-m")
        .arg(mode)
        .arg("-o")
        .arg(owner_user)
        .arg("-g")
        .arg(owner_group)
        .arg("/dev/stdin")
        .arg(remote_path);
    let mut payload = Vec::new();
    if needs_sudo {
        payload.extend_from_slice(sudo_password.as_bytes());
        payload.push(b'\n');
    }
    payload.extend_from_slice(bytes.as_slice());
    run_command_with_input(command, payload.as_slice()).map(|_| ())
}

struct RemoteRetryProgram<'a> {
    attempts: u32,
    sleep_secs: u64,
    program: &'a str,
    args: &'a [&'a str],
    envs: &'a [(&'a str, &'a str)],
}

fn retry_remote_program(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    retry: RemoteRetryProgram<'_>,
) -> Result<(), String> {
    for attempt in 1..=retry.attempts {
        match run_remote_program_checked(
            options,
            host,
            sudo_password,
            retry.program,
            retry.args,
            retry.envs,
        ) {
            Ok(()) => return Ok(()),
            Err(err) if attempt < retry.attempts => {
                let _ = err;
                std::thread::sleep(std::time::Duration::from_secs(retry.sleep_secs));
            }
            Err(err) => return Err(err),
        }
    }
    Err("retry exhausted".to_string())
}

fn normalize_membership_permissions(
    options: &[OsString],
    host: &str,
    needs_sudo: bool,
    sudo_password: &str,
) -> Result<(), String> {
    let sudo = if needs_sudo {
        Some(sudo_password)
    } else {
        None
    };
    run_remote_program_checked(
        options,
        host,
        sudo,
        "chown",
        &[
            "root:root",
            "/var/lib/rustynet/membership.snapshot",
            "/var/lib/rustynet/membership.log",
        ],
        &[],
    )?;
    run_remote_program_checked(
        options,
        host,
        sudo,
        "chmod",
        &[
            "0600",
            "/var/lib/rustynet/membership.snapshot",
            "/var/lib/rustynet/membership.log",
        ],
        &[],
    )?;
    Ok(())
}

fn remote_stat_mode(
    options: &[OsString],
    host: &str,
    sudo_password: Option<&str>,
    path: &str,
) -> Result<String, String> {
    ensure_safe_remote_path(path)?;
    let output = capture_remote_program_output(
        options,
        host,
        sudo_password,
        "stat",
        &["-c", "%U:%G,%a", path],
        &[],
        false,
    )?;
    Ok(output.trim().replace(',', " "))
}

fn run_command_with_input(command: Command, input: &[u8]) -> Result<Output, String> {
    let output = run_command_with_input_allow_failure(command, input)?;
    if !output.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

fn run_command_with_input_allow_failure(
    mut command: Command,
    input: &[u8],
) -> Result<Output, String> {
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn command: {err}"))?;
    let mut child = child;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|err| format!("failed to write command stdin: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting for command: {err}"))?;
    Ok(output)
}

fn set_unix_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)
            .map_err(|err| format!("failed setting permissions on {}: {err}", path.display()))?;
    }
    Ok(())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{nanos}", std::process::id())
}

fn base64_to_hex(value: &str) -> Result<String, String> {
    let decoded = decode_base64(value.trim())?;
    let mut output = String::with_capacity(decoded.len() * 2);
    for byte in decoded {
        output.push_str(format!("{byte:02x}").as_str());
    }
    Ok(output)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    const TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut reverse = BTreeMap::new();
    for (index, ch) in TABLE.chars().enumerate() {
        reverse.insert(ch, index as u8);
    }
    let clean = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return Err("invalid base64 wireguard public key".to_string());
    }
    let mut output = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let mut sextets = [0u8; 4];
        let mut padding = 0usize;
        for (index, ch) in chunk.iter().enumerate() {
            if *ch == '=' {
                sextets[index] = 0;
                padding += 1;
            } else if let Some(value) = reverse.get(ch) {
                sextets[index] = *value;
            } else {
                return Err("invalid base64 wireguard public key".to_string());
            }
        }
        let b0 = (sextets[0] << 2) | (sextets[1] >> 4);
        let b1 = ((sextets[1] & 0x0f) << 4) | (sextets[2] >> 2);
        let b2 = ((sextets[2] & 0x03) << 6) | sextets[3];
        output.push(b0);
        if padding < 2 {
            output.push(b1);
        }
        if padding < 1 {
            output.push(b2);
        }
    }
    Ok(output)
}

fn extract_last_assignment_generated(status_line: &str) -> Option<u64> {
    let marker = "last_assignment=";
    let start = status_line.find(marker)?;
    let rest = &status_line[start + marker.len()..];
    let generated = rest.split(':').next()?;
    generated.trim().parse::<u64>().ok()
}

struct AssignmentRefreshEnv {
    target_node_id: String,
    nodes_spec: String,
    allow_spec: String,
    exit_node_id: Option<String>,
}

fn write_assignment_refresh_env(path: &Path, env: AssignmentRefreshEnv) -> Result<(), String> {
    let mut content = String::new();
    content.push_str(format_env_assignment("RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "true")?.as_str());
    content.push('\n');
    content.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID",
            env.target_node_id.as_str(),
        )?
        .as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment("RUSTYNET_ASSIGNMENT_NODES", env.nodes_spec.as_str())?.as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment("RUSTYNET_ASSIGNMENT_ALLOW", env.allow_spec.as_str())?.as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
            "/etc/rustynet/assignment.signing.secret",
        )?
        .as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE",
            "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase",
        )?
        .as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_OUTPUT",
            "/var/lib/rustynet/rustynetd.assignment",
        )?
        .as_str(),
    );
    content.push('\n');
    content.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_VERIFIER_KEY_OUTPUT",
            "/etc/rustynet/assignment.pub",
        )?
        .as_str(),
    );
    content.push('\n');
    content.push_str(format_env_assignment("RUSTYNET_ASSIGNMENT_TTL_SECS", "300")?.as_str());
    content.push('\n');
    content
        .push_str(format_env_assignment("RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS", "180")?.as_str());
    content.push('\n');
    if let Some(exit_node_id) = env.exit_node_id {
        content.push_str(
            format_env_assignment("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", exit_node_id.as_str())?
                .as_str(),
        );
        content.push('\n');
    }
    fs::write(path, content.as_bytes())
        .map_err(|err| format!("failed writing {}: {err}", path.display()))?;
    set_unix_mode(path, 0o600)?;
    Ok(())
}

struct ReportInputs {
    generated_at_utc: String,
    commit_sha: String,
    exit_target: String,
    client_target: String,
    exit_node_id: String,
    client_node_id: String,
    network_id: String,
    ssh_allow_cidrs: String,
    report: CheckReport,
    exit_status: String,
    exit_status_after_refresh: String,
    client_status: String,
    client_status_after_refresh: String,
    client_route: String,
    exit_wg_show: String,
}

fn write_report(path: &Path, input: ReportInputs) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed creating report directory {}: {err}",
                parent.display()
            )
        })?;
    }
    let mut report = String::new();
    report.push_str("# Debian Two-Node Clean Install + Tunnel Validation\n\n");
    report.push_str(format!("- generated_at_utc: {}\n", input.generated_at_utc).as_str());
    report.push_str(format!("- commit: {}\n", input.commit_sha).as_str());
    report.push_str(format!("- exit_host: {}\n", input.exit_target).as_str());
    report.push_str(format!("- client_host: {}\n", input.client_target).as_str());
    report.push_str(format!("- exit_node_id: {}\n", input.exit_node_id).as_str());
    report.push_str(format!("- client_node_id: {}\n", input.client_node_id).as_str());
    report.push_str(format!("- network_id: {}\n", input.network_id).as_str());
    report.push_str(format!("- ssh_allow_cidrs: {}\n\n", input.ssh_allow_cidrs).as_str());
    report.push_str("## Checks\n\n");
    report.push_str("| Check | Status | Detail |\n|---|---|---|\n");
    for (name, status, detail) in input.report.checks {
        report.push_str(format!("| {name} | {status} | {detail} |\n").as_str());
    }
    report.push_str("\n## Exit Status\n\n```text\n");
    report.push_str(input.exit_status.as_str());
    report.push_str("\n```\n\n## Exit Status After Assignment Refresh Window\n\n```text\n");
    report.push_str(input.exit_status_after_refresh.as_str());
    report.push_str("\n```\n\n## Client Status\n\n```text\n");
    report.push_str(input.client_status.as_str());
    report.push_str("\n```\n\n## Client Status After Assignment Refresh Window\n\n```text\n");
    report.push_str(input.client_status_after_refresh.as_str());
    report.push_str("\n```\n\n## Client Route Check\n\n```text\n");
    report.push_str(input.client_route.as_str());
    report.push_str("\n```\n\n## Exit WireGuard\n\n```text\n");
    report.push_str(input.exit_wg_show.as_str());
    report.push_str("\n```\n");

    fs::write(path, report.as_bytes())
        .map_err(|err| format!("failed writing report {}: {err}", path.display()))
}

fn utc_timestamp() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        AssignmentRefreshEnv, decode_base64, ensure_safe_token, extract_last_assignment_generated,
        write_assignment_refresh_env,
    };

    #[test]
    fn safe_token_accepts_expected_charset() {
        assert!(ensure_safe_token("token", "abc-DEF_123:/,@+=").is_ok());
        assert!(ensure_safe_token("token", "bad value with spaces").is_err());
    }

    #[test]
    fn decode_base64_roundtrip_wireguard_pubkey_shape() {
        let bytes = decode_base64("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=").unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[31], 32);
    }

    #[test]
    fn extract_assignment_generated_from_status_line() {
        let value = extract_last_assignment_generated("state=ExitActive last_assignment=12345:999");
        assert_eq!(value, Some(12345));
        assert_eq!(extract_last_assignment_generated("state=ExitActive"), None);
    }

    #[test]
    fn assignment_refresh_env_quotes_structured_values() {
        let path = std::env::temp_dir().join(format!(
            "rustynet-assignment-refresh-env-test-{}.env",
            std::process::id()
        ));
        let env = AssignmentRefreshEnv {
            target_node_id: "client-50".to_string(),
            nodes_spec: "client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def"
                .to_string(),
            allow_spec: "client-50|exit-49;exit-49|client-50".to_string(),
            exit_node_id: Some("exit-49".to_string()),
        };
        write_assignment_refresh_env(path.as_path(), env).expect("write assignment refresh env");
        let body = fs::read_to_string(path.as_path()).expect("read assignment refresh env");
        let _ = fs::remove_file(path.as_path());
        assert!(body.contains("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"client-50\""));
        assert!(body.contains(
            "RUSTYNET_ASSIGNMENT_NODES=\"client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def\""
        ));
        assert!(body.contains("RUSTYNET_ASSIGNMENT_ALLOW=\"client-50|exit-49;exit-49|client-50\""));
        assert!(body.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"exit-49\""));
    }
}

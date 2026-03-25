use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use crate::env_file::{format_env_assignment, parse_env_value};
use nix::unistd::{Gid, Group, Uid, User, chown};
use rand::{RngCore, rngs::OsRng};
use rustynet_dns_zone::canonicalize_dns_zone_name;
use rustynetd::daemon::{
    DEFAULT_DNS_RESOLVER_BIND_ADDR, DEFAULT_DNS_ZONE_BUNDLE_PATH, DEFAULT_DNS_ZONE_MAX_AGE_SECS,
    DEFAULT_DNS_ZONE_NAME, DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH, DEFAULT_DNS_ZONE_WATERMARK_PATH,
};

const ENV_DST: &str = "/etc/default/rustynetd";
const SERVICE_CREDENTIAL_BLOB_PATH: &str = concat!(
    "/etc/rustynet/credentials/",
    "w",
    "g",
    "_key_passphrase.cred"
);
const SERVICE_SIGNING_CREDENTIAL_BLOB_PATH: &str =
    "/etc/rustynet/credentials/signing_key_passphrase.cred";
const RUNTIME_WIREGUARD_PASSPHRASE_CREDENTIAL_NAME: &str = concat!("w", "g", "_key_passphrase");
const ASSIGNMENT_REFRESH_ENV_DST: &str = "/etc/rustynet/assignment-refresh.env";
const DEFAULT_EXIT_ROUTE_CIDR: &str = "0.0.0.0/0";
const MAX_ASSIGNMENT_ROUTE_SCAN: usize = 4096;
const MAX_ASSIGNMENT_PEER_SCAN: usize = 4096;

const SERVICE_DST: &str = "/etc/systemd/system/rustynetd.service";
const HELPER_SERVICE_DST: &str = "/etc/systemd/system/rustynetd-privileged-helper.service";
const TRUST_REFRESH_SERVICE_DST: &str = "/etc/systemd/system/rustynetd-trust-refresh.service";
const TRUST_REFRESH_TIMER_DST: &str = "/etc/systemd/system/rustynetd-trust-refresh.timer";
const ASSIGNMENT_REFRESH_SERVICE_DST: &str =
    "/etc/systemd/system/rustynetd-assignment-refresh.service";
const ASSIGNMENT_REFRESH_TIMER_DST: &str = "/etc/systemd/system/rustynetd-assignment-refresh.timer";
const MANAGED_DNS_SERVICE_DST: &str = "/etc/systemd/system/rustynetd-managed-dns.service";

#[derive(Debug, Clone)]
struct InstallSources {
    service: PathBuf,
    helper_service: PathBuf,
    trust_refresh_service: PathBuf,
    trust_refresh_timer: PathBuf,
    assignment_refresh_service: PathBuf,
    assignment_refresh_timer: PathBuf,
    managed_dns_service: PathBuf,
}

pub(super) fn execute_ops_install_systemd() -> Result<String, String> {
    require_root_execution()?;
    require_linux_host()?;

    let existing_env = read_env_file_values(Path::new(ENV_DST))?;
    let existing_assignment_refresh_env =
        read_env_file_values(Path::new(ASSIGNMENT_REFRESH_ENV_DST))?;
    let source_root = resolve_source_root()?;
    let sources = install_sources(source_root.as_path());
    validate_source_paths(&sources)?;

    let service_user = env_string_or_default_process("RUSTYNET_DAEMON_USER", "rustynetd")?;
    let service_group = env_string_or_default_process("RUSTYNET_DAEMON_GROUP", "rustynetd")?;
    validate_simple_value("RUSTYNET_DAEMON_USER", service_user.as_str())?;
    validate_simple_value("RUSTYNET_DAEMON_GROUP", service_group.as_str())?;

    ensure_group_exists(service_group.as_str())?;
    ensure_user_exists(service_user.as_str(), service_group.as_str())?;

    let daemon_uid = lookup_uid(service_user.as_str())?;
    let daemon_gid = lookup_gid(service_group.as_str())?;

    ensure_directory_with_owner_mode(
        Path::new("/etc/rustynet"),
        0o750,
        Uid::from_raw(0),
        daemon_gid,
    )?;
    ensure_directory_with_owner_mode(
        Path::new("/run/rustynet"),
        0o770,
        Uid::from_raw(0),
        daemon_gid,
    )?;
    ensure_directory_with_owner_mode(
        Path::new("/var/lib/rustynet"),
        0o700,
        daemon_uid,
        daemon_gid,
    )?;
    install_file(
        sources.service.as_path(),
        Path::new(SERVICE_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd.service",
    )?;
    install_file(
        sources.helper_service.as_path(),
        Path::new(HELPER_SERVICE_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-privileged-helper.service",
    )?;
    install_file(
        sources.trust_refresh_service.as_path(),
        Path::new(TRUST_REFRESH_SERVICE_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-trust-refresh.service",
    )?;
    install_file(
        sources.trust_refresh_timer.as_path(),
        Path::new(TRUST_REFRESH_TIMER_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-trust-refresh.timer",
    )?;
    install_file(
        sources.assignment_refresh_service.as_path(),
        Path::new(ASSIGNMENT_REFRESH_SERVICE_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-assignment-refresh.service",
    )?;
    install_file(
        sources.assignment_refresh_timer.as_path(),
        Path::new(ASSIGNMENT_REFRESH_TIMER_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-assignment-refresh.timer",
    )?;
    install_file(
        sources.managed_dns_service.as_path(),
        Path::new(MANAGED_DNS_SERVICE_DST),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        "rustynetd-managed-dns.service",
    )?;

    let socket_path = env_path_or_existing_default(
        "RUSTYNET_SOCKET",
        "/run/rustynet/rustynetd.sock",
        &existing_env,
    )?;
    let state_path = env_path_or_existing_default(
        "RUSTYNET_STATE",
        "/var/lib/rustynet/rustynetd.state",
        &existing_env,
    )?;
    let trust_evidence_path = env_path_or_existing_default(
        "RUSTYNET_TRUST_EVIDENCE",
        "/var/lib/rustynet/rustynetd.trust",
        &existing_env,
    )?;
    let trust_verifier_key_path = env_path_or_existing_default(
        "RUSTYNET_TRUST_VERIFIER_KEY",
        "/etc/rustynet/trust-evidence.pub",
        &existing_env,
    )?;
    let trust_watermark_path = env_path_or_existing_default(
        "RUSTYNET_TRUST_WATERMARK",
        "/var/lib/rustynet/rustynetd.trust.watermark",
        &existing_env,
    )?;
    let trust_signer_key_path = env_path_or_existing_default(
        "RUSTYNET_TRUST_SIGNER_KEY",
        "/etc/rustynet/trust-evidence.key",
        &existing_env,
    )?;
    let trust_auto_refresh_raw =
        env_string_or_existing_default("RUSTYNET_TRUST_AUTO_REFRESH", "false", &existing_env)?;
    let assignment_auto_refresh_raw =
        env_string_or_existing_default("RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "false", &existing_env)?;
    let membership_snapshot_path = env_path_or_existing_default(
        "RUSTYNET_MEMBERSHIP_SNAPSHOT",
        "/var/lib/rustynet/membership.snapshot",
        &existing_env,
    )?;
    let membership_log_path = env_path_or_existing_default(
        "RUSTYNET_MEMBERSHIP_LOG",
        "/var/lib/rustynet/membership.log",
        &existing_env,
    )?;
    let membership_watermark_path = env_path_or_existing_default(
        "RUSTYNET_MEMBERSHIP_WATERMARK",
        "/var/lib/rustynet/membership.watermark",
        &existing_env,
    )?;
    let membership_owner_signing_key_path = env_path_or_existing_default(
        "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY",
        "/etc/rustynet/membership.owner.key",
        &existing_env,
    )?;
    let auto_tunnel_enforce_raw =
        env_string_or_existing_default("RUSTYNET_AUTO_TUNNEL_ENFORCE", "true", &existing_env)?;
    let auto_tunnel_bundle_path = env_path_or_existing_default(
        "RUSTYNET_AUTO_TUNNEL_BUNDLE",
        "/var/lib/rustynet/rustynetd.assignment",
        &existing_env,
    )?;
    let auto_tunnel_verifier_key_path = env_path_or_existing_default(
        "RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY",
        "/etc/rustynet/assignment.pub",
        &existing_env,
    )?;
    let auto_tunnel_watermark_path = env_path_or_existing_default(
        "RUSTYNET_AUTO_TUNNEL_WATERMARK",
        "/var/lib/rustynet/rustynetd.assignment.watermark",
        &existing_env,
    )?;
    let auto_tunnel_max_age_secs =
        env_string_or_existing_default("RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS", "300", &existing_env)?;
    let traversal_bundle_path = env_path_or_existing_default(
        "RUSTYNET_TRAVERSAL_BUNDLE",
        "/var/lib/rustynet/rustynetd.traversal",
        &existing_env,
    )?;
    let traversal_verifier_key_path = env_path_or_existing_default(
        "RUSTYNET_TRAVERSAL_VERIFIER_KEY",
        "/etc/rustynet/traversal.pub",
        &existing_env,
    )?;
    let traversal_watermark_path = env_path_or_existing_default(
        "RUSTYNET_TRAVERSAL_WATERMARK",
        "/var/lib/rustynet/rustynetd.traversal.watermark",
        &existing_env,
    )?;
    let traversal_max_age_secs =
        env_string_or_existing_default("RUSTYNET_TRAVERSAL_MAX_AGE_SECS", "120", &existing_env)?;
    let dns_zone_max_age_default = DEFAULT_DNS_ZONE_MAX_AGE_SECS.to_string();
    let dns_zone_bundle_path = env_path_or_existing_default(
        "RUSTYNET_DNS_ZONE_BUNDLE",
        DEFAULT_DNS_ZONE_BUNDLE_PATH,
        &existing_env,
    )?;
    let dns_zone_verifier_key_path = env_path_or_existing_default(
        "RUSTYNET_DNS_ZONE_VERIFIER_KEY",
        DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH,
        &existing_env,
    )?;
    let dns_zone_watermark_path = env_path_or_existing_default(
        "RUSTYNET_DNS_ZONE_WATERMARK",
        DEFAULT_DNS_ZONE_WATERMARK_PATH,
        &existing_env,
    )?;
    let dns_zone_max_age_secs = env_string_or_existing_default(
        "RUSTYNET_DNS_ZONE_MAX_AGE_SECS",
        dns_zone_max_age_default.as_str(),
        &existing_env,
    )?;
    let dns_zone_name_raw = env_string_or_existing_default(
        "RUSTYNET_DNS_ZONE_NAME",
        DEFAULT_DNS_ZONE_NAME,
        &existing_env,
    )?;
    let dns_resolver_bind_addr_raw = env_string_or_existing_default(
        "RUSTYNET_DNS_RESOLVER_BIND_ADDR",
        DEFAULT_DNS_RESOLVER_BIND_ADDR,
        &existing_env,
    )?;
    let node_id = env_string_or_existing_required("RUSTYNET_NODE_ID", &existing_env)?;
    let assignment_refresh_default_target_node_id = node_id.clone();
    let node_role = env_string_or_existing_default("RUSTYNET_NODE_ROLE", "client", &existing_env)?;
    let backend_mode =
        env_string_or_existing_default("RUSTYNET_BACKEND", "linux-wireguard", &existing_env)?;
    let wireguard_interface =
        env_string_or_existing_default("RUSTYNET_WG_INTERFACE", "rustynet0", &existing_env)?;
    let wireguard_listen_port_raw =
        env_string_or_existing_default("RUSTYNET_WG_LISTEN_PORT", "51820", &existing_env)?;
    let wireguard_private_key_path = env_path_or_existing_default(
        "RUSTYNET_WG_PRIVATE_KEY",
        "/run/rustynet/wireguard.key",
        &existing_env,
    )?;
    let wireguard_encrypted_private_key_path = env_path_or_existing_default(
        "RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY",
        "/var/lib/rustynet/keys/wireguard.key.enc",
        &existing_env,
    )?;
    let wireguard_key_passphrase_credential_blob_path = env_path_or_existing_default(
        "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB",
        SERVICE_CREDENTIAL_BLOB_PATH,
        &existing_env,
    )?;
    let signing_key_passphrase_credential_blob_path = env_path_or_existing_default(
        "RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB",
        SERVICE_SIGNING_CREDENTIAL_BLOB_PATH,
        &existing_env,
    )?;
    let wireguard_public_key_path = env_path_or_existing_default(
        "RUSTYNET_WG_PUBLIC_KEY",
        "/var/lib/rustynet/keys/wireguard.pub",
        &existing_env,
    )?;
    let dataplane_mode =
        env_string_or_existing_default("RUSTYNET_DATAPLANE_MODE", "hybrid-native", &existing_env)?;
    let privileged_helper_socket = env_path_or_existing_default(
        "RUSTYNET_PRIVILEGED_HELPER_SOCKET",
        "/run/rustynet/rustynetd-privileged.sock",
        &existing_env,
    )?;
    let privileged_helper_timeout_ms_raw = env_string_or_existing_default(
        "RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS",
        "2000",
        &existing_env,
    )?;
    let reconcile_interval_ms =
        env_string_or_existing_default("RUSTYNET_RECONCILE_INTERVAL_MS", "1000", &existing_env)?;
    let max_reconcile_failures =
        env_string_or_existing_default("RUSTYNET_MAX_RECONCILE_FAILURES", "5", &existing_env)?;
    let fail_closed_ssh_allow_raw =
        env_string_or_existing_default("RUSTYNET_FAIL_CLOSED_SSH_ALLOW", "false", &existing_env)?;
    let fail_closed_ssh_allow_cidrs =
        env_string_or_existing_default("RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS", "", &existing_env)?;
    let auto_port_forward_exit_raw =
        env_string_or_existing_default("RUSTYNET_AUTO_PORT_FORWARD_EXIT", "false", &existing_env)?;
    let auto_port_forward_lease_secs_raw = env_string_or_existing_default(
        "RUSTYNET_AUTO_PORT_FORWARD_LEASE_SECS",
        "1200",
        &existing_env,
    )?;

    if wireguard_key_passphrase_credential_blob_path.as_path()
        != Path::new(SERVICE_CREDENTIAL_BLOB_PATH)
    {
        return Err(format!(
            "invalid credential blob path: expected {SERVICE_CREDENTIAL_BLOB_PATH}"
        ));
    }
    if signing_key_passphrase_credential_blob_path.as_path()
        != Path::new(SERVICE_SIGNING_CREDENTIAL_BLOB_PATH)
    {
        return Err(format!(
            "invalid signing credential blob path: expected {SERVICE_SIGNING_CREDENTIAL_BLOB_PATH}"
        ));
    }

    validate_node_role(node_role.as_str())?;
    let fail_closed_ssh_allow_enabled = parse_install_bool(
        "RUSTYNET_FAIL_CLOSED_SSH_ALLOW",
        fail_closed_ssh_allow_raw.as_str(),
    )?;
    let trust_auto_refresh_enabled = parse_install_bool(
        "RUSTYNET_TRUST_AUTO_REFRESH",
        trust_auto_refresh_raw.as_str(),
    )?;
    let assignment_auto_refresh_enabled = parse_install_bool(
        "RUSTYNET_ASSIGNMENT_AUTO_REFRESH",
        assignment_auto_refresh_raw.as_str(),
    )?;
    let auto_tunnel_enforce_enabled = parse_install_bool(
        "RUSTYNET_AUTO_TUNNEL_ENFORCE",
        auto_tunnel_enforce_raw.as_str(),
    )?;
    parse_install_bool(
        "RUSTYNET_AUTO_PORT_FORWARD_EXIT",
        auto_port_forward_exit_raw.as_str(),
    )?;
    parse_nonzero_u64(
        "RUSTYNET_AUTO_PORT_FORWARD_LEASE_SECS",
        auto_port_forward_lease_secs_raw.as_str(),
    )?;
    parse_nonzero_u64(
        "RUSTYNET_TRAVERSAL_MAX_AGE_SECS",
        traversal_max_age_secs.as_str(),
    )?;
    parse_nonzero_u64(
        "RUSTYNET_DNS_ZONE_MAX_AGE_SECS",
        dns_zone_max_age_secs.as_str(),
    )?;
    let dns_zone_name = canonicalize_dns_zone_name(dns_zone_name_raw.as_str())
        .map_err(|err| format!("invalid dns zone name: {err}"))?;
    let dns_resolver_bind_addr =
        parse_dns_resolver_bind_addr_install(dns_resolver_bind_addr_raw.as_str())?;

    if fail_closed_ssh_allow_enabled && fail_closed_ssh_allow_cidrs.trim().is_empty() {
        return Err(
            "fail-closed ssh allow enabled but no cidrs supplied (RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS)"
                .to_string(),
        );
    }

    let privileged_helper_timeout_ms = parse_nonzero_u64(
        "RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS",
        privileged_helper_timeout_ms_raw.as_str(),
    )?;
    let wireguard_listen_port = parse_wireguard_port(wireguard_listen_port_raw.as_str())?;

    let selected_exit_endpoint = detect_selected_exit_endpoint_for_egress(
        auto_tunnel_bundle_path.as_path(),
        Path::new(ASSIGNMENT_REFRESH_ENV_DST),
    )?;
    let egress_interface = resolve_egress_interface(
        env_optional_string("RUSTYNET_EGRESS_INTERFACE")?,
        existing_env.get("RUSTYNET_EGRESS_INTERFACE").cloned(),
        selected_exit_endpoint.as_deref(),
    )?;
    if egress_interface.trim().is_empty() {
        return Err(
            "unable to detect default egress interface; set RUSTYNET_EGRESS_INTERFACE".to_string(),
        );
    }
    ensure_interface_exists(egress_interface.as_str())?;

    for mutable_target in [
        state_path.as_path(),
        membership_snapshot_path.as_path(),
        membership_log_path.as_path(),
        trust_watermark_path.as_path(),
        membership_watermark_path.as_path(),
        auto_tunnel_watermark_path.as_path(),
        dns_zone_bundle_path.as_path(),
        dns_zone_watermark_path.as_path(),
        traversal_watermark_path.as_path(),
        wireguard_private_key_path.as_path(),
    ] {
        ensure_parent_dir_if_missing(mutable_target, daemon_uid, daemon_gid, 0o750)?;
    }

    for key_material_target in [
        wireguard_encrypted_private_key_path.as_path(),
        wireguard_public_key_path.as_path(),
    ] {
        let parent = key_material_target.parent().ok_or_else(|| {
            format!(
                "key material path has no parent: {}",
                key_material_target.display()
            )
        })?;
        ensure_directory_with_owner_mode(parent, 0o700, daemon_uid, daemon_gid)?;
    }

    let wireguard_cred_dir = wireguard_key_passphrase_credential_blob_path
        .parent()
        .ok_or_else(|| {
            format!(
                "wireguard credential blob has no parent: {}",
                wireguard_key_passphrase_credential_blob_path.display()
            )
        })?;
    ensure_directory_with_owner_mode(
        wireguard_cred_dir,
        0o700,
        Uid::from_raw(0),
        Gid::from_raw(0),
    )?;

    let signing_cred_dir = signing_key_passphrase_credential_blob_path
        .parent()
        .ok_or_else(|| {
            format!(
                "signing credential blob has no parent: {}",
                signing_key_passphrase_credential_blob_path.display()
            )
        })?;
    ensure_directory_with_owner_mode(signing_cred_dir, 0o700, Uid::from_raw(0), Gid::from_raw(0))?;

    ensure_parent_dir_if_missing(socket_path.as_path(), daemon_uid, daemon_gid, 0o750)?;
    ensure_parent_dir_if_missing(
        privileged_helper_socket.as_path(),
        Uid::from_raw(0),
        daemon_gid,
        0o750,
    )?;

    let legacy_encrypted_key_path = Path::new("/etc/rustynet/wireguard.key.enc");
    let legacy_public_key_path = Path::new("/etc/rustynet/wireguard.pub");
    let legacy_passphrase_path = Path::new("/etc/rustynet/wireguard.passphrase");
    let bootstrap_passphrase_path = Path::new("/var/lib/rustynet/keys/wireguard.passphrase");

    let legacy_encrypted_exists = match fs::symlink_metadata(legacy_encrypted_key_path) {
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(format!(
                "inspect legacy encrypted key path {} failed: {err}",
                legacy_encrypted_key_path.display()
            ));
        }
    };
    let legacy_public_exists = match fs::symlink_metadata(legacy_public_key_path) {
        Ok(_) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => {
            return Err(format!(
                "inspect legacy public key path {} failed: {err}",
                legacy_public_key_path.display()
            ));
        }
    };
    if legacy_encrypted_exists && !wireguard_encrypted_private_key_path.exists() {
        return Err(format!(
            "legacy encrypted key path detected at {} while canonical path {} is missing; implicit migration is disabled. Move/re-encrypt key material explicitly before running install-systemd",
            legacy_encrypted_key_path.display(),
            wireguard_encrypted_private_key_path.display()
        ));
    }
    if legacy_public_exists && !wireguard_public_key_path.exists() {
        return Err(format!(
            "legacy public key path detected at {} while canonical path {} is missing; implicit migration is disabled. Move/recreate key material explicitly before running install-systemd",
            legacy_public_key_path.display(),
            wireguard_public_key_path.display()
        ));
    }

    if !wireguard_key_passphrase_credential_blob_path.is_file() {
        return Err(format!(
            "missing encrypted credential blob: {}\nrun ./start.sh first-run setup to regenerate secure key custody artifacts",
            wireguard_key_passphrase_credential_blob_path.display()
        ));
    }
    if !signing_key_passphrase_credential_blob_path.is_file() {
        return Err(format!(
            "missing encrypted signing credential blob: {}\nrun ./start.sh first-run setup to regenerate secure signing custody artifacts",
            signing_key_passphrase_credential_blob_path.display()
        ));
    }

    set_owner_mode_if_exists(
        wireguard_key_passphrase_credential_blob_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
    )?;
    set_owner_mode_if_exists(
        signing_key_passphrase_credential_blob_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
    )?;

    secure_remove_file(bootstrap_passphrase_path)?;
    if legacy_passphrase_path != wireguard_key_passphrase_credential_blob_path.as_path() {
        secure_remove_file(legacy_passphrase_path)?;
    }
    secure_remove_file(legacy_encrypted_key_path)?;
    secure_remove_file(legacy_public_key_path)?;

    for readonly_target in [
        trust_evidence_path.as_path(),
        trust_verifier_key_path.as_path(),
        trust_signer_key_path.as_path(),
        auto_tunnel_bundle_path.as_path(),
        auto_tunnel_verifier_key_path.as_path(),
        traversal_bundle_path.as_path(),
        traversal_verifier_key_path.as_path(),
        membership_owner_signing_key_path.as_path(),
    ] {
        ensure_parent_dir_if_missing(readonly_target, Uid::from_raw(0), daemon_gid, 0o750)?;
    }

    set_owner_mode_if_exists(state_path.as_path(), daemon_uid, daemon_gid, 0o600)?;
    set_owner_mode_if_exists(
        membership_snapshot_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(membership_log_path.as_path(), daemon_uid, daemon_gid, 0o600)?;
    set_owner_mode_if_exists(
        trust_watermark_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        membership_watermark_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        auto_tunnel_watermark_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        traversal_watermark_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        wireguard_private_key_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        wireguard_encrypted_private_key_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_on_key_custody_artifacts(
        wireguard_encrypted_private_key_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o600,
    )?;
    set_owner_mode_if_exists(
        wireguard_public_key_path.as_path(),
        daemon_uid,
        daemon_gid,
        0o644,
    )?;

    set_owner_mode_if_exists(
        trust_evidence_path.as_path(),
        Uid::from_raw(0),
        daemon_gid,
        0o640,
    )?;
    set_owner_mode_if_exists(
        auto_tunnel_bundle_path.as_path(),
        Uid::from_raw(0),
        daemon_gid,
        0o640,
    )?;
    set_owner_mode_if_exists(
        traversal_bundle_path.as_path(),
        Uid::from_raw(0),
        daemon_gid,
        0o640,
    )?;
    set_owner_mode_if_exists(
        trust_verifier_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
    )?;
    set_owner_mode_if_exists(
        trust_signer_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
    )?;
    set_owner_mode_if_exists(
        auto_tunnel_verifier_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
    )?;
    set_owner_mode_if_exists(
        traversal_verifier_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
    )?;
    set_owner_mode_if_exists(
        dns_zone_verifier_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
    )?;
    set_owner_mode_if_exists(
        membership_owner_signing_key_path.as_path(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o600,
    )?;

    let trust_auto_refresh_normalized = if trust_auto_refresh_enabled {
        "true"
    } else {
        "false"
    };
    let assignment_auto_refresh_normalized = if assignment_auto_refresh_enabled {
        "true"
    } else {
        "false"
    };

    let env_entries = vec![
        ("RUSTYNET_NODE_ID".to_string(), node_id),
        ("RUSTYNET_NODE_ROLE".to_string(), node_role.clone()),
        (
            "RUSTYNET_SOCKET".to_string(),
            display_path(socket_path.as_path()),
        ),
        (
            "RUSTYNET_STATE".to_string(),
            display_path(state_path.as_path()),
        ),
        (
            "RUSTYNET_TRUST_EVIDENCE".to_string(),
            display_path(trust_evidence_path.as_path()),
        ),
        (
            "RUSTYNET_TRUST_VERIFIER_KEY".to_string(),
            display_path(trust_verifier_key_path.as_path()),
        ),
        (
            "RUSTYNET_TRUST_WATERMARK".to_string(),
            display_path(trust_watermark_path.as_path()),
        ),
        (
            "RUSTYNET_TRUST_SIGNER_KEY".to_string(),
            display_path(trust_signer_key_path.as_path()),
        ),
        (
            "RUSTYNET_TRUST_AUTO_REFRESH".to_string(),
            trust_auto_refresh_normalized.to_string(),
        ),
        (
            "RUSTYNET_ASSIGNMENT_AUTO_REFRESH".to_string(),
            assignment_auto_refresh_normalized.to_string(),
        ),
        (
            "RUSTYNET_MEMBERSHIP_SNAPSHOT".to_string(),
            display_path(membership_snapshot_path.as_path()),
        ),
        (
            "RUSTYNET_MEMBERSHIP_LOG".to_string(),
            display_path(membership_log_path.as_path()),
        ),
        (
            "RUSTYNET_MEMBERSHIP_WATERMARK".to_string(),
            display_path(membership_watermark_path.as_path()),
        ),
        (
            "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY".to_string(),
            display_path(membership_owner_signing_key_path.as_path()),
        ),
        (
            "RUSTYNET_AUTO_TUNNEL_ENFORCE".to_string(),
            auto_tunnel_enforce_raw,
        ),
        (
            "RUSTYNET_AUTO_TUNNEL_BUNDLE".to_string(),
            display_path(auto_tunnel_bundle_path.as_path()),
        ),
        (
            "RUSTYNET_AUTO_TUNNEL_VERIFIER_KEY".to_string(),
            display_path(auto_tunnel_verifier_key_path.as_path()),
        ),
        (
            "RUSTYNET_AUTO_TUNNEL_WATERMARK".to_string(),
            display_path(auto_tunnel_watermark_path.as_path()),
        ),
        (
            "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS".to_string(),
            auto_tunnel_max_age_secs,
        ),
        (
            "RUSTYNET_DNS_ZONE_BUNDLE".to_string(),
            display_path(dns_zone_bundle_path.as_path()),
        ),
        (
            "RUSTYNET_DNS_ZONE_VERIFIER_KEY".to_string(),
            display_path(dns_zone_verifier_key_path.as_path()),
        ),
        (
            "RUSTYNET_DNS_ZONE_WATERMARK".to_string(),
            display_path(dns_zone_watermark_path.as_path()),
        ),
        (
            "RUSTYNET_DNS_ZONE_MAX_AGE_SECS".to_string(),
            dns_zone_max_age_secs,
        ),
        ("RUSTYNET_DNS_ZONE_NAME".to_string(), dns_zone_name),
        (
            "RUSTYNET_DNS_RESOLVER_BIND_ADDR".to_string(),
            dns_resolver_bind_addr.to_string(),
        ),
        (
            "RUSTYNET_TRAVERSAL_BUNDLE".to_string(),
            display_path(traversal_bundle_path.as_path()),
        ),
        (
            "RUSTYNET_TRAVERSAL_VERIFIER_KEY".to_string(),
            display_path(traversal_verifier_key_path.as_path()),
        ),
        (
            "RUSTYNET_TRAVERSAL_WATERMARK".to_string(),
            display_path(traversal_watermark_path.as_path()),
        ),
        (
            "RUSTYNET_TRAVERSAL_MAX_AGE_SECS".to_string(),
            traversal_max_age_secs,
        ),
        ("RUSTYNET_BACKEND".to_string(), backend_mode),
        ("RUSTYNET_WG_INTERFACE".to_string(), wireguard_interface),
        (
            "RUSTYNET_WG_LISTEN_PORT".to_string(),
            wireguard_listen_port_raw,
        ),
        (
            "RUSTYNET_WG_PRIVATE_KEY".to_string(),
            display_path(wireguard_private_key_path.as_path()),
        ),
        (
            "RUSTYNET_WG_ENCRYPTED_PRIVATE_KEY".to_string(),
            display_path(wireguard_encrypted_private_key_path.as_path()),
        ),
        (
            "RUSTYNET_WG_KEY_PASSPHRASE".to_string(),
            format!(
                "/run/credentials/rustynetd.service/{RUNTIME_WIREGUARD_PASSPHRASE_CREDENTIAL_NAME}",
            ),
        ),
        (
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB".to_string(),
            display_path(wireguard_key_passphrase_credential_blob_path.as_path()),
        ),
        (
            "RUSTYNET_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB".to_string(),
            display_path(signing_key_passphrase_credential_blob_path.as_path()),
        ),
        (
            "RUSTYNET_WG_PUBLIC_KEY".to_string(),
            display_path(wireguard_public_key_path.as_path()),
        ),
        (
            "RUSTYNET_EGRESS_INTERFACE".to_string(),
            egress_interface.clone(),
        ),
        (
            "RUSTYNET_AUTO_PORT_FORWARD_EXIT".to_string(),
            auto_port_forward_exit_raw,
        ),
        (
            "RUSTYNET_AUTO_PORT_FORWARD_LEASE_SECS".to_string(),
            auto_port_forward_lease_secs_raw,
        ),
        ("RUSTYNET_DATAPLANE_MODE".to_string(), dataplane_mode),
        (
            "RUSTYNET_PRIVILEGED_HELPER_SOCKET".to_string(),
            display_path(privileged_helper_socket.as_path()),
        ),
        (
            "RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS".to_string(),
            privileged_helper_timeout_ms_raw,
        ),
        (
            "RUSTYNET_PRIVILEGED_HELPER_ALLOWED_UID".to_string(),
            daemon_uid.as_raw().to_string(),
        ),
        (
            "RUSTYNET_PRIVILEGED_HELPER_ALLOWED_GID".to_string(),
            daemon_gid.as_raw().to_string(),
        ),
        ("RUSTYNET_DAEMON_GROUP".to_string(), service_group),
        (
            "RUSTYNET_RECONCILE_INTERVAL_MS".to_string(),
            reconcile_interval_ms,
        ),
        (
            "RUSTYNET_MAX_RECONCILE_FAILURES".to_string(),
            max_reconcile_failures,
        ),
        (
            "RUSTYNET_FAIL_CLOSED_SSH_ALLOW".to_string(),
            fail_closed_ssh_allow_raw,
        ),
        (
            "RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS".to_string(),
            fail_closed_ssh_allow_cidrs,
        ),
    ];

    let mut rendered_env = String::new();
    for (key, value) in env_entries {
        validate_env_line(key.as_str(), value.as_str())?;
        rendered_env.push_str(key.as_str());
        rendered_env.push('=');
        rendered_env.push_str(value.as_str());
        rendered_env.push('\n');
    }
    write_atomic_text_file(
        Path::new(ENV_DST),
        rendered_env.as_str(),
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o644,
        Uid::from_raw(0),
        Gid::from_raw(0),
        0o755,
    )?;
    if assignment_auto_refresh_enabled {
        let rendered_assignment_refresh_env = render_assignment_refresh_env_contents(
            assignment_refresh_default_target_node_id.as_str(),
            env_optional_string("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID")?,
            env_optional_string("RUSTYNET_ASSIGNMENT_NODES")?,
            env_optional_string("RUSTYNET_ASSIGNMENT_ALLOW")?,
            env_optional_string("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID")?,
            &existing_assignment_refresh_env,
        )?;
        write_atomic_text_file(
            Path::new(ASSIGNMENT_REFRESH_ENV_DST),
            rendered_assignment_refresh_env.as_str(),
            Uid::from_raw(0),
            Gid::from_raw(0),
            0o600,
            Uid::from_raw(0),
            daemon_gid,
            0o750,
        )?;
    }

    ensure_managed_dns_control_plane_ready()?;
    run_command_checked("systemctl", &["daemon-reload"])?;
    run_command_checked(
        "systemctl",
        &["enable", "rustynetd-privileged-helper.service"],
    )?;
    run_command_checked("systemctl", &["enable", "rustynetd.service"])?;
    if auto_tunnel_enforce_enabled {
        run_command_checked("systemctl", &["enable", "rustynetd-managed-dns.service"])?;
    } else {
        let _ = run_command_checked(
            "systemctl",
            &["disable", "--now", "rustynetd-managed-dns.service"],
        );
    }

    if trust_auto_refresh_enabled {
        if !trust_signer_key_path.is_file() {
            return Err(format!(
                "trust auto-refresh enabled but signer key missing: {}",
                trust_signer_key_path.display()
            ));
        }
        run_command_checked("systemctl", &["enable", "rustynetd-trust-refresh.timer"])?;
    } else {
        let _ = run_command_checked(
            "systemctl",
            &["disable", "--now", "rustynetd-trust-refresh.timer"],
        );
    }

    if assignment_auto_refresh_enabled {
        if !auto_tunnel_verifier_key_path.is_file() {
            return Err(format!(
                "assignment auto-refresh enabled but verifier key missing: {}",
                auto_tunnel_verifier_key_path.display()
            ));
        }
        run_command_checked(
            "systemctl",
            &["enable", "rustynetd-assignment-refresh.timer"],
        )?;
    } else {
        let _ = run_command_checked(
            "systemctl",
            &["disable", "--now", "rustynetd-assignment-refresh.timer"],
        );
    }

    let _ = run_command_checked(
        "systemctl",
        &[
            "reset-failed",
            "rustynetd-privileged-helper.service",
            "rustynetd.service",
            "rustynetd-trust-refresh.service",
            "rustynetd-trust-refresh.timer",
            "rustynetd-assignment-refresh.service",
            "rustynetd-assignment-refresh.timer",
            "rustynetd-managed-dns.service",
        ],
    );

    run_command_checked(
        "systemctl",
        &["restart", "rustynetd-privileged-helper.service"],
    )?;

    run_command_checked("systemctl", &["restart", "rustynetd.service"])?;
    wait_for_unit_active("rustynetd.service", 40, 250)?;

    if assignment_auto_refresh_enabled {
        let _ = run_command_checked(
            "systemctl",
            &["start", "rustynetd-assignment-refresh.service"],
        );
    }
    if trust_auto_refresh_enabled {
        let _ = run_command_checked("systemctl", &["start", "rustynetd-trust-refresh.service"]);
    }
    if trust_auto_refresh_enabled || assignment_auto_refresh_enabled || auto_tunnel_enforce_enabled
    {
        wait_for_unix_socket(socket_path.as_path(), 40, 250)?;
        let socket_value = display_path(socket_path.as_path());
        run_command_checked_with_env(
            "rustynet",
            &["state", "refresh"],
            &[("RUSTYNET_DAEMON_SOCKET", socket_value.as_str())],
        )?;
    }
    if auto_tunnel_enforce_enabled {
        run_command_checked("systemctl", &["restart", "rustynetd-managed-dns.service"])?;
        wait_for_unit_active("rustynetd-managed-dns.service", 40, 250)?;
    }

    if trust_auto_refresh_enabled {
        run_command_checked("systemctl", &["restart", "rustynetd-trust-refresh.timer"])?;
    }
    if assignment_auto_refresh_enabled {
        run_command_checked(
            "systemctl",
            &["restart", "rustynetd-assignment-refresh.timer"],
        )?;
    }

    run_command_stream(
        "systemctl",
        &[
            "--no-pager",
            "--full",
            "status",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    if trust_auto_refresh_enabled {
        run_command_stream(
            "systemctl",
            &[
                "--no-pager",
                "--full",
                "status",
                "rustynetd-trust-refresh.timer",
            ],
        )?;
    }
    if assignment_auto_refresh_enabled {
        run_command_stream(
            "systemctl",
            &[
                "--no-pager",
                "--full",
                "status",
                "rustynetd-assignment-refresh.timer",
            ],
        )?;
    }
    run_systemctl_status_with_retry("rustynetd-managed-dns.service", 20, 250)?;
    run_command_stream(
        "systemctl",
        &["--no-pager", "--full", "status", "rustynetd.service"],
    )?;

    Ok(format!(
        "systemd installer completed: role={node_role} wireguard_listen_port={wireguard_listen_port} egress_interface={egress_interface} timeout_ms={privileged_helper_timeout_ms}",
    ))
}

fn require_root_execution() -> Result<(), String> {
    if Uid::effective().is_root() {
        return Ok(());
    }
    Err("run as root".to_string())
}

fn require_linux_host() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        return Ok(());
    }
    Err("ops install-systemd is only supported on Linux hosts".to_string())
}

fn resolve_source_root() -> Result<PathBuf, String> {
    if let Some(candidate) = env_optional_string("RUSTYNET_INSTALL_SOURCE_ROOT")? {
        let path = PathBuf::from(candidate);
        if !path.is_absolute() {
            return Err(format!(
                "RUSTYNET_INSTALL_SOURCE_ROOT must be an absolute path: {}",
                path.display()
            ));
        }
        if has_install_sources(path.as_path()) {
            return Ok(path);
        }
        return Err(format!(
            "RUSTYNET_INSTALL_SOURCE_ROOT missing required systemd files: {}",
            path.display()
        ));
    }

    let cwd = std::env::current_dir().map_err(|err| format!("resolve cwd failed: {err}"))?;
    if has_install_sources(cwd.as_path()) {
        return Ok(cwd);
    }

    Err(
        "unable to resolve installer source root; set RUSTYNET_INSTALL_SOURCE_ROOT to repository root"
            .to_string(),
    )
}

fn install_sources(root: &Path) -> InstallSources {
    InstallSources {
        service: root.join("scripts/systemd/rustynetd.service"),
        helper_service: root.join("scripts/systemd/rustynetd-privileged-helper.service"),
        trust_refresh_service: root.join("scripts/systemd/rustynetd-trust-refresh.service"),
        trust_refresh_timer: root.join("scripts/systemd/rustynetd-trust-refresh.timer"),
        assignment_refresh_service: root
            .join("scripts/systemd/rustynetd-assignment-refresh.service"),
        assignment_refresh_timer: root.join("scripts/systemd/rustynetd-assignment-refresh.timer"),
        managed_dns_service: root.join("scripts/systemd/rustynetd-managed-dns.service"),
    }
}

fn has_install_sources(root: &Path) -> bool {
    let sources = install_sources(root);
    [
        sources.service,
        sources.helper_service,
        sources.trust_refresh_service,
        sources.trust_refresh_timer,
        sources.assignment_refresh_service,
        sources.assignment_refresh_timer,
        sources.managed_dns_service,
    ]
    .iter()
    .all(|path| path.is_file())
}

fn validate_source_paths(paths: &InstallSources) -> Result<(), String> {
    for (label, path) in [
        ("rustynetd.service", paths.service.as_path()),
        (
            "rustynetd-privileged-helper.service",
            paths.helper_service.as_path(),
        ),
        (
            "rustynetd-trust-refresh.service",
            paths.trust_refresh_service.as_path(),
        ),
        (
            "rustynetd-trust-refresh.timer",
            paths.trust_refresh_timer.as_path(),
        ),
        (
            "rustynetd-assignment-refresh.service",
            paths.assignment_refresh_service.as_path(),
        ),
        (
            "rustynetd-assignment-refresh.timer",
            paths.assignment_refresh_timer.as_path(),
        ),
        (
            "rustynetd-managed-dns.service",
            paths.managed_dns_service.as_path(),
        ),
    ] {
        validate_regular_file_non_symlink(path, label)?;
    }
    Ok(())
}

fn validate_regular_file_non_symlink(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("missing {label}: {} ({err})", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn read_env_file_values(path: &Path) -> Result<HashMap<String, String>, String> {
    let mut values = HashMap::new();
    if !path.exists() {
        return Ok(values);
    }
    let content = fs::read_to_string(path)
        .map_err(|err| format!("read environment file {} failed: {err}", path.display()))?;
    for raw_line in content.lines() {
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = raw_line.split_once('=') {
            if key.is_empty() || values.contains_key(key) {
                continue;
            }
            let parsed = parse_env_value(value).map_err(|err| {
                format!(
                    "parse environment file {} failed for key {key}: {err}",
                    path.display()
                )
            })?;
            values.insert(key.to_string(), parsed);
        }
    }
    Ok(values)
}

fn env_optional_string(key: &str) -> Result<Option<String>, String> {
    match std::env::var(key) {
        Ok(value) => {
            if value.is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} contains non-utf8 data"))
        }
    }
}

fn env_string_or_existing_default(
    key: &str,
    default: &str,
    existing: &HashMap<String, String>,
) -> Result<String, String> {
    match env_optional_string(key)? {
        Some(value) => Ok(value),
        None => match existing.get(key) {
            Some(value) if !value.is_empty() => Ok(value.clone()),
            _ => Ok(default.to_string()),
        },
    }
}

fn env_string_or_existing_required(
    key: &str,
    existing: &HashMap<String, String>,
) -> Result<String, String> {
    match env_optional_string(key)? {
        Some(value) => Ok(value),
        None => match existing.get(key) {
            Some(value) if !value.is_empty() => Ok(value.clone()),
            _ => Err(format!(
                "missing required environment value: {key} (set it explicitly before install)"
            )),
        },
    }
}

fn env_string_or_default_process(key: &str, default: &str) -> Result<String, String> {
    match env_optional_string(key)? {
        Some(value) => Ok(value),
        None => Ok(default.to_string()),
    }
}

fn env_path_or_existing_default(
    key: &str,
    default: &str,
    existing: &HashMap<String, String>,
) -> Result<PathBuf, String> {
    let value = env_string_or_existing_default(key, default, existing)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "{key} must be an absolute path: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn validate_node_role(value: &str) -> Result<(), String> {
    match value {
        "admin" | "client" | "blind_exit" => Ok(()),
        _ => Err(format!(
            "invalid node role: {value} (expected admin|client|blind_exit)"
        )),
    }
}

fn parse_install_bool(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!(
            "invalid {} value: {} (expected true|false)",
            key.to_lowercase().replace('_', " "),
            value
        )),
    }
}

fn parse_nonzero_u64(key: &str, value: &str) -> Result<u64, String> {
    let parsed = value.parse::<u64>().map_err(|_| {
        format!(
            "invalid {}: {}",
            key.to_lowercase().replace('_', " "),
            value
        )
    })?;
    if parsed == 0 {
        return Err(format!(
            "invalid {}: {}",
            key.to_lowercase().replace('_', " "),
            value
        ));
    }
    Ok(parsed)
}

fn parse_dns_resolver_bind_addr_install(value: &str) -> Result<SocketAddr, String> {
    let addr = value
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid dns resolver bind addr: {err}"))?;
    if !addr.ip().is_loopback() {
        return Err("dns resolver bind addr must be loopback".to_string());
    }
    if !matches!(addr.ip(), IpAddr::V4(_)) {
        return Err(
            "dns resolver bind addr for managed DNS routing must be an IPv4 loopback address"
                .to_string(),
        );
    }
    Ok(addr)
}

fn parse_wireguard_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid wireguard listen port: {value} (expected 1-65535)"))?;
    if port == 0 {
        return Err(format!(
            "invalid wireguard listen port: {value} (expected 1-65535)"
        ));
    }
    Ok(port)
}

fn detect_default_egress_interface() -> Result<String, String> {
    let output = run_command_capture("ip", &["-o", "-4", "route", "show", "to", "default"])?;
    if let Some(interface) = parse_first_route_interface(output.as_str()) {
        return Ok(interface);
    }
    Err("unable to detect default egress interface; set RUSTYNET_EGRESS_INTERFACE".to_string())
}

fn resolve_egress_interface(
    explicit_egress: Option<String>,
    existing_egress: Option<String>,
    selected_exit_endpoint: Option<&str>,
) -> Result<String, String> {
    if let Some(endpoint) = selected_exit_endpoint {
        let derived = detect_egress_interface_for_endpoint(endpoint)?;
        if let Some(explicit_value) = explicit_egress.as_deref()
            && !explicit_value.trim().is_empty()
            && explicit_value != derived
        {
            return Err(format!(
                "explicit egress interface {explicit_value} does not route to selected exit endpoint {endpoint}; expected {derived}"
            ));
        }
        return Ok(derived);
    }

    if let Some(value) = explicit_egress
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if let Some(value) = existing_egress
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    detect_default_egress_interface()
}

fn detect_egress_interface_for_endpoint(endpoint: &str) -> Result<String, String> {
    let socket_addr = endpoint
        .parse::<SocketAddr>()
        .map_err(|_| format!("invalid selected-exit endpoint format: {endpoint}"))?;
    detect_egress_interface_for_ip(socket_addr.ip())
}

fn detect_egress_interface_for_ip(ip: IpAddr) -> Result<String, String> {
    let (args_prefix, ip_arg) = match ip {
        IpAddr::V4(value) => (vec!["-o", "-4", "route", "get"], value.to_string()),
        IpAddr::V6(value) => (vec!["-o", "-6", "route", "get"], value.to_string()),
    };
    let mut args = args_prefix;
    args.push(ip_arg.as_str());
    let output = run_command_capture("ip", args.as_slice())?;
    if let Some(interface) = parse_first_route_interface(output.as_str()) {
        return Ok(interface);
    }
    Err(format!(
        "unable to detect egress interface for selected exit destination {ip}"
    ))
}

fn parse_first_route_interface(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(parse_dev_interface_token)
        .map(|value| value.to_string())
}

fn parse_dev_interface_token(line: &str) -> Option<&str> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == "dev" {
            return tokens.get(idx + 1).copied();
        }
    }
    tokens.get(4).copied()
}

fn detect_selected_exit_endpoint_for_egress(
    assignment_bundle_path: &Path,
    assignment_refresh_env_path: &Path,
) -> Result<Option<String>, String> {
    let preferred_exit_node_id = read_assignment_refresh_exit_node_id(assignment_refresh_env_path)?;
    if !assignment_bundle_path.exists() {
        if let Some(exit_node_id) = preferred_exit_node_id {
            return Err(format!(
                "selected exit node {exit_node_id} is set but assignment bundle is missing: {}",
                assignment_bundle_path.display()
            ));
        }
        return Ok(None);
    }
    if !assignment_bundle_path.is_file() {
        return Err(format!(
            "assignment bundle path must be a regular file: {}",
            assignment_bundle_path.display()
        ));
    }
    let fields = read_env_file_values(assignment_bundle_path)?;
    let selected_exit_node_id =
        resolve_selected_exit_node_id(&fields, preferred_exit_node_id.as_deref());
    let Some(exit_node_id) = selected_exit_node_id else {
        return Ok(None);
    };
    let endpoint = assignment_peer_endpoint(&fields, exit_node_id.as_str())?;
    Ok(Some(endpoint))
}

fn read_assignment_refresh_exit_node_id(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let values = read_env_file_values(path)?;
    let raw = match values.get("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID") {
        Some(value) => value.trim(),
        None => return Ok(None),
    };
    if raw.is_empty() {
        return Ok(None);
    }
    if !is_valid_assignment_node_id(raw) {
        return Err(format!(
            "invalid RUSTYNET_ASSIGNMENT_EXIT_NODE_ID in {}: {}",
            path.display(),
            raw
        ));
    }
    Ok(Some(raw.to_string()))
}

fn render_assignment_refresh_env_contents(
    fallback_target_node_id: &str,
    target_node_id_raw: Option<String>,
    nodes_spec_raw: Option<String>,
    allow_spec_raw: Option<String>,
    exit_node_id_raw: Option<String>,
    existing: &HashMap<String, String>,
) -> Result<String, String> {
    let target_node_id = resolve_assignment_refresh_value(
        "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID",
        target_node_id_raw,
        existing,
        Some(fallback_target_node_id),
    )?;
    if !is_valid_assignment_node_id(target_node_id.as_str()) {
        return Err(format!(
            "assignment auto-refresh requires a valid RUSTYNET_ASSIGNMENT_TARGET_NODE_ID; unsupported characters in {target_node_id}",
        ));
    }

    let nodes_spec = resolve_assignment_refresh_value(
        "RUSTYNET_ASSIGNMENT_NODES",
        nodes_spec_raw,
        existing,
        None,
    )?;
    let allow_spec = resolve_assignment_refresh_value(
        "RUSTYNET_ASSIGNMENT_ALLOW",
        allow_spec_raw,
        existing,
        None,
    )?;
    let exit_node_id = resolve_assignment_refresh_optional_value(
        "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID",
        exit_node_id_raw,
        existing,
    )?;
    if let Some(value) = exit_node_id.as_deref()
        && !is_valid_assignment_node_id(value)
    {
        return Err(format!(
            "assignment auto-refresh requires a valid RUSTYNET_ASSIGNMENT_EXIT_NODE_ID; unsupported characters in {value}",
        ));
    }

    let mut rendered = String::new();
    rendered.push_str(
        format_env_assignment(
            "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID",
            target_node_id.as_str(),
        )?
        .as_str(),
    );
    rendered.push('\n');
    rendered.push_str(
        format_env_assignment("RUSTYNET_ASSIGNMENT_NODES", nodes_spec.as_str())?.as_str(),
    );
    rendered.push('\n');
    rendered.push_str(
        format_env_assignment("RUSTYNET_ASSIGNMENT_ALLOW", allow_spec.as_str())?.as_str(),
    );
    rendered.push('\n');
    if let Some(value) = exit_node_id {
        rendered.push_str(
            format_env_assignment("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", value.as_str())?.as_str(),
        );
        rendered.push('\n');
    }
    Ok(rendered)
}

fn resolve_assignment_refresh_value(
    key: &str,
    explicit: Option<String>,
    existing: &HashMap<String, String>,
    fallback: Option<&str>,
) -> Result<String, String> {
    let resolved = explicit
        .or_else(|| existing.get(key).cloned())
        .unwrap_or_else(|| fallback.unwrap_or_default().to_string())
        .trim()
        .to_string();
    if resolved.is_empty() {
        return Err(format!(
            "assignment auto-refresh requires {key}; set it explicitly or provide it in {ASSIGNMENT_REFRESH_ENV_DST}"
        ));
    }
    validate_env_line(key, resolved.as_str())?;
    Ok(resolved)
}

fn resolve_assignment_refresh_optional_value(
    key: &str,
    explicit: Option<String>,
    existing: &HashMap<String, String>,
) -> Result<Option<String>, String> {
    let Some(raw) = explicit.or_else(|| existing.get(key).cloned()) else {
        return Ok(None);
    };
    let normalized = raw.trim().to_string();
    if normalized.is_empty() {
        return Ok(None);
    }
    validate_env_line(key, normalized.as_str())?;
    Ok(Some(normalized))
}

fn is_valid_assignment_node_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

fn resolve_selected_exit_node_id(
    fields: &HashMap<String, String>,
    preferred_exit_node_id: Option<&str>,
) -> Option<String> {
    if let Some(value) = preferred_exit_node_id
        && !value.trim().is_empty()
    {
        return Some(value.to_string());
    }

    let route_count = fields
        .get("route_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_ASSIGNMENT_ROUTE_SCAN);

    for index in 0..route_count {
        let destination_key = format!("route.{index}.destination_cidr");
        let kind_key = format!("route.{index}.kind");
        let via_key = format!("route.{index}.via_node");
        let Some(destination) = fields.get(destination_key.as_str()) else {
            continue;
        };
        let Some(kind) = fields.get(kind_key.as_str()) else {
            continue;
        };
        let Some(via_node) = fields.get(via_key.as_str()) else {
            continue;
        };
        let destination = destination.trim();
        let kind = kind.trim();
        let via_node = via_node.trim();
        if destination == DEFAULT_EXIT_ROUTE_CIDR && kind == "exit_default" && !via_node.is_empty()
        {
            return Some(via_node.to_string());
        }
    }

    for (key, value) in fields {
        let Some(index) = parse_indexed_key_component(key.as_str(), "route.", ".destination_cidr")
        else {
            continue;
        };
        if value.trim() != DEFAULT_EXIT_ROUTE_CIDR {
            continue;
        }
        let kind_key = format!("route.{index}.kind");
        let via_key = format!("route.{index}.via_node");
        let Some(kind) = fields.get(kind_key.as_str()) else {
            continue;
        };
        let Some(via_node) = fields.get(via_key.as_str()) else {
            continue;
        };
        let kind = kind.trim();
        let via_node = via_node.trim();
        if kind == "exit_default" && !via_node.is_empty() {
            return Some(via_node.to_string());
        }
    }

    None
}

fn assignment_peer_endpoint(
    fields: &HashMap<String, String>,
    target_node_id: &str,
) -> Result<String, String> {
    let peer_count = fields
        .get("peer_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_ASSIGNMENT_PEER_SCAN);

    for index in 0..peer_count {
        let node_id_key = format!("peer.{index}.node_id");
        let endpoint_key = format!("peer.{index}.endpoint");
        let Some(node_id) = fields.get(node_id_key.as_str()) else {
            continue;
        };
        if node_id.trim() != target_node_id {
            continue;
        }
        let endpoint = fields.get(endpoint_key.as_str()).ok_or_else(|| {
            format!("assignment bundle missing endpoint for selected exit node {target_node_id}")
        })?;
        let endpoint = endpoint.trim();
        endpoint.parse::<SocketAddr>().map_err(|_| {
            format!("assignment bundle has invalid endpoint for selected exit node {target_node_id}: {endpoint}")
        })?;
        return Ok(endpoint.to_string());
    }

    for (key, value) in fields {
        let Some(index) = parse_indexed_key_component(key.as_str(), "peer.", ".node_id") else {
            continue;
        };
        if value.trim() != target_node_id {
            continue;
        }
        let endpoint_key = format!("peer.{index}.endpoint");
        let endpoint = fields.get(endpoint_key.as_str()).ok_or_else(|| {
            format!("assignment bundle missing endpoint for selected exit node {target_node_id}")
        })?;
        let endpoint = endpoint.trim();
        endpoint.parse::<SocketAddr>().map_err(|_| {
            format!("assignment bundle has invalid endpoint for selected exit node {target_node_id}: {endpoint}")
        })?;
        return Ok(endpoint.to_string());
    }

    Err(format!(
        "assignment bundle missing selected exit node peer entry: {target_node_id}"
    ))
}

fn parse_indexed_key_component(key: &str, prefix: &str, suffix: &str) -> Option<usize> {
    if !key.starts_with(prefix) || !key.ends_with(suffix) {
        return None;
    }
    let middle = &key[prefix.len()..key.len().saturating_sub(suffix.len())];
    if middle.is_empty() || !middle.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    middle.parse::<usize>().ok()
}

fn ensure_interface_exists(interface: &str) -> Result<(), String> {
    run_command_checked("ip", &["link", "show", interface])
        .map_err(|_| format!("egress interface does not exist: {interface}"))
}

fn ensure_group_exists(group_name: &str) -> Result<(), String> {
    if lookup_gid_optional(group_name)?.is_some() {
        return Ok(());
    }
    run_command_checked("groupadd", &["--system", group_name])?;
    if lookup_gid_optional(group_name)?.is_none() {
        return Err(format!("failed to create system group: {group_name}"));
    }
    Ok(())
}

fn ensure_user_exists(user_name: &str, group_name: &str) -> Result<(), String> {
    if lookup_uid_optional(user_name)?.is_some() {
        return Ok(());
    }
    run_command_checked(
        "useradd",
        &[
            "--system",
            "--gid",
            group_name,
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            user_name,
        ],
    )?;
    if lookup_uid_optional(user_name)?.is_none() {
        return Err(format!("failed to create system user: {user_name}"));
    }
    Ok(())
}

fn lookup_gid_optional(group_name: &str) -> Result<Option<Gid>, String> {
    Group::from_name(group_name)
        .map_err(|err| format!("resolve group {group_name} failed: {err}"))
        .map(|group| group.map(|entry| entry.gid))
}

fn lookup_gid(group_name: &str) -> Result<Gid, String> {
    lookup_gid_optional(group_name)?
        .ok_or_else(|| format!("group not found after setup: {group_name}"))
}

fn lookup_uid_optional(user_name: &str) -> Result<Option<Uid>, String> {
    User::from_name(user_name)
        .map_err(|err| format!("resolve user {user_name} failed: {err}"))
        .map(|user| user.map(|entry| entry.uid))
}

fn lookup_uid(user_name: &str) -> Result<Uid, String> {
    lookup_uid_optional(user_name)?
        .ok_or_else(|| format!("user not found after setup: {user_name}"))
}

fn ensure_directory_with_owner_mode(
    path: &Path,
    mode: u32,
    owner: Uid,
    group: Gid,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "directory must not be a symlink: {}",
                    path.display()
                ));
            }
            if !metadata.file_type().is_dir() {
                return Err(format!("path must be a directory: {}", path.display()));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|create_err| {
                format!("create directory {} failed: {create_err}", path.display())
            })?;
        }
        Err(err) => {
            return Err(format!(
                "inspect directory {} failed: {err}",
                path.display()
            ));
        }
    }

    chown(path, Some(owner), Some(group))
        .map_err(|err| format!("set directory owner {} failed: {err}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("set directory mode {} failed: {err}", path.display()))?;
    Ok(())
}

fn ensure_parent_dir_if_missing(
    target: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("target path has no parent directory: {}", target.display()))?;
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "parent directory must not be a symlink: {}",
                    parent.display()
                ));
            }
            if !metadata.file_type().is_dir() {
                return Err(format!(
                    "parent path is not a directory: {}",
                    parent.display()
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|create_err| {
                format!("create directory {} failed: {create_err}", parent.display())
            })?;
            chown(parent, Some(owner), Some(group)).map_err(|chown_err| {
                format!(
                    "set directory owner {} failed: {chown_err}",
                    parent.display()
                )
            })?;
            fs::set_permissions(parent, fs::Permissions::from_mode(mode)).map_err(|perm_err| {
                format!("set directory mode {} failed: {perm_err}", parent.display())
            })?;
            Ok(())
        }
        Err(err) => Err(format!(
            "inspect directory {} failed: {err}",
            parent.display()
        )),
    }
}

fn install_file(
    source: &Path,
    destination: &Path,
    mode: u32,
    owner: Uid,
    group: Gid,
    label: &str,
) -> Result<(), String> {
    copy_file_with_owner_mode(source, destination, owner, group, mode, label)
}

fn copy_file_with_owner_mode(
    source: &Path,
    destination: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
    label: &str,
) -> Result<(), String> {
    validate_regular_file_non_symlink(source, label)?;

    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "destination must not be a symlink: {}",
                    destination.display()
                ));
            }
            if metadata.file_type().is_dir() {
                return Err(format!(
                    "destination must be a file path: {}",
                    destination.display()
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "inspect destination {} failed: {err}",
                destination.display()
            ));
        }
    }

    fs::copy(source, destination).map_err(|err| {
        format!(
            "install {label} {} -> {} failed: {err}",
            source.display(),
            destination.display()
        )
    })?;

    chown(destination, Some(owner), Some(group))
        .map_err(|err| format!("set {label} owner {} failed: {err}", destination.display()))?;
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))
        .map_err(|err| format!("set {label} mode {} failed: {err}", destination.display()))?;
    Ok(())
}

fn set_owner_mode_if_exists(path: &Path, owner: Uid, group: Gid, mode: u32) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!("path must not be a symlink: {}", path.display()));
            }
            chown(path, Some(owner), Some(group))
                .map_err(|err| format!("set owner {} failed: {err}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .map_err(|err| format!("set mode {} failed: {err}", path.display()))?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("inspect {} failed: {err}", path.display())),
    }
}

fn set_owner_mode_on_key_custody_artifacts(
    encrypted_key_path: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
) -> Result<(), String> {
    let parent = encrypted_key_path.parent().ok_or_else(|| {
        format!(
            "encrypted key path has no parent directory: {}",
            encrypted_key_path.display()
        )
    })?;
    let entries = fs::read_dir(parent).map_err(|err| {
        format!(
            "read key custody directory {} failed: {err}",
            parent.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            format!(
                "read key custody entry in {} failed: {err}",
                parent.display()
            )
        })?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !is_private_key_custody_artifact_name(file_name.as_ref()) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(path.as_path()).map_err(|err| {
            format!(
                "inspect key custody artifact {} failed: {err}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "key custody artifact must not be a symlink: {}",
                path.display()
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(format!(
                "key custody artifact must be a regular file: {}",
                path.display()
            ));
        }
        chown(path.as_path(), Some(owner), Some(group)).map_err(|err| {
            format!(
                "set key custody artifact owner {} failed: {err}",
                path.display()
            )
        })?;
        fs::set_permissions(path.as_path(), fs::Permissions::from_mode(mode)).map_err(|err| {
            format!(
                "set key custody artifact mode {} failed: {err}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn is_private_key_custody_artifact_name(file_name: &str) -> bool {
    const PREFIX: [u8; 11] = [
        b'w', b'g', b'-', b'p', b'r', b'i', b'v', b'a', b't', b'e', b'-',
    ];
    let bytes = file_name.as_bytes();
    bytes.len() >= PREFIX.len() && bytes[..PREFIX.len()] == PREFIX && file_name.ends_with(".enc")
}

fn secure_remove_file(path: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("inspect {} failed: {err}", path.display())),
    };

    if metadata.file_type().is_symlink() {
        fs::remove_file(path)
            .map_err(|err| format!("remove symlink {} failed: {err}", path.display()))?;
        return Ok(());
    }

    if !metadata.file_type().is_file() {
        return Err(format!(
            "secure remove requires a regular file: {}",
            path.display()
        ));
    }

    scrub_file_contents(path)?;
    fs::remove_file(path).map_err(|err| format!("remove {} failed: {err}", path.display()))?;
    Ok(())
}

fn scrub_file_contents(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|err| format!("inspect file {} failed: {err}", path.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| format!("open {} failed: {err}", path.display()))?;
    let mut remaining = metadata.len();
    let zero_chunk = [0u8; 8192];
    while remaining > 0 {
        let write_len = usize::try_from(std::cmp::min(remaining, zero_chunk.len() as u64))
            .map_err(|_| "internal length conversion failed".to_string())?;
        file.write_all(&zero_chunk[..write_len])
            .map_err(|err| format!("scrub write {} failed: {err}", path.display()))?;
        remaining = remaining.saturating_sub(write_len as u64);
    }
    file.sync_all()
        .map_err(|err| format!("sync {} failed: {err}", path.display()))?;
    file.set_len(0)
        .map_err(|err| format!("truncate {} failed: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("sync {} after truncate failed: {err}", path.display()))?;
    Ok(())
}

fn bytes_to_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn create_secure_temp_file(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    let mut random_bytes = [0u8; 8];
    for _ in 0..32 {
        OsRng.fill_bytes(&mut random_bytes);
        let candidate = dir.join(format!("{prefix}{}", bytes_to_hex(&random_bytes)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create temporary file {} failed: {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate secure temporary file in {}",
        dir.display()
    ))
}

fn publish_file_with_owner_mode(
    source_tmp_path: &Path,
    destination_path: &Path,
    owner: Uid,
    group: Gid,
    mode: u32,
    label: &str,
) -> Result<(), String> {
    chown(source_tmp_path, Some(owner), Some(group)).map_err(|err| {
        format!(
            "set {label} owner {} failed: {err}",
            source_tmp_path.display()
        )
    })?;
    fs::set_permissions(source_tmp_path, fs::Permissions::from_mode(mode)).map_err(|err| {
        format!(
            "set {label} mode {} failed: {err}",
            source_tmp_path.display()
        )
    })?;
    fs::rename(source_tmp_path, destination_path).map_err(|err| {
        format!(
            "publish {label} to {} failed: {err}",
            destination_path.display()
        )
    })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_atomic_text_file(
    target: &Path,
    body: &str,
    owner: Uid,
    group: Gid,
    mode: u32,
    parent_owner: Uid,
    parent_group: Gid,
    parent_mode: u32,
) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("target path has no parent: {}", target.display()))?;
    ensure_directory_with_owner_mode(parent, parent_mode, parent_owner, parent_group)?;

    let tmp = create_secure_temp_file(parent, "rustynetd.env.tmp.")?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp.as_path())
            .map_err(|err| format!("open temporary file {} failed: {err}", tmp.display()))?;
        file.write_all(body.as_bytes())
            .map_err(|err| format!("write temporary file {} failed: {err}", tmp.display()))?;
        file.sync_all()
            .map_err(|err| format!("sync temporary file {} failed: {err}", tmp.display()))?;
    }
    publish_file_with_owner_mode(
        tmp.as_path(),
        target,
        owner,
        group,
        mode,
        "environment file",
    )
}

fn run_command_capture(command: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .map_err(|err| format!("execute {} failed: {err}", format_command(command, args)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!(
            "command failed ({}): {}",
            format_command(command, args),
            details
        ));
    }

    String::from_utf8(output.stdout).map_err(|err| {
        format!(
            "decode output for {} failed: {err}",
            format_command(command, args)
        )
    })
}

fn run_command_checked(command: &str, args: &[&str]) -> Result<(), String> {
    run_command_capture(command, args).map(|_| ())
}

fn run_command_capture_with_env(
    command: &str,
    args: &[&str],
    env_vars: &[(&str, &str)],
) -> Result<String, String> {
    let mut command_builder = Command::new(command);
    command_builder.args(args);
    for (key, value) in env_vars {
        command_builder.env(key, value);
    }
    let output = command_builder
        .output()
        .map_err(|err| format!("execute {} failed: {err}", format_command(command, args)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let details = if !stderr.is_empty() { stderr } else { stdout };
        return Err(format!(
            "command failed ({}): {}",
            format_command(command, args),
            details
        ));
    }

    String::from_utf8(output.stdout).map_err(|err| {
        format!(
            "decode output for {} failed: {err}",
            format_command(command, args)
        )
    })
}

fn run_command_checked_with_env(
    command: &str,
    args: &[&str],
    env_vars: &[(&str, &str)],
) -> Result<(), String> {
    run_command_capture_with_env(command, args, env_vars).map(|_| ())
}

fn wait_for_unix_socket(path: &Path, attempts: usize, sleep_ms: u64) -> Result<(), String> {
    let mut last_state = "missing".to_string();
    for attempt in 1..=attempts {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    last_state = "symlink".to_string();
                } else if metadata.file_type().is_socket() {
                    return Ok(());
                } else {
                    last_state = "not-socket".to_string();
                }
            }
            Err(err) => {
                last_state = err.to_string();
            }
        }
        if attempt < attempts {
            sleep(Duration::from_millis(sleep_ms));
        }
    }
    Err(format!(
        "daemon socket {} failed to become available after {attempts} attempts (last_state={last_state})",
        path.display()
    ))
}

fn wait_for_unit_active(unit: &str, attempts: usize, sleep_ms: u64) -> Result<(), String> {
    let mut last_state = String::new();
    for attempt in 1..=attempts {
        let output = Command::new("systemctl")
            .args(["is-active", unit])
            .output()
            .map_err(|err| format!("execute systemctl is-active {unit} failed: {err}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        last_state = if !stdout.is_empty() {
            stdout
        } else if !stderr.is_empty() {
            stderr
        } else {
            "unknown".to_string()
        };
        if output.status.success() && last_state == "active" {
            return Ok(());
        }
        if attempt < attempts {
            sleep(Duration::from_millis(sleep_ms));
        }
    }
    Err(format!(
        "systemd unit {unit} failed to reach active state after {attempts} attempts (last_state={last_state})",
    ))
}

fn ensure_managed_dns_control_plane_ready() -> Result<(), String> {
    if !Path::new("/usr/bin/resolvectl").is_file() {
        return Err(
            "managed DNS routing requires /usr/bin/resolvectl; install and enable systemd-resolved before running install-systemd"
                .to_string(),
        );
    }

    if let Err(initial_err) = run_command_checked("resolvectl", &["status"]) {
        run_command_checked("systemctl", &["reload", "dbus"])?;
        run_command_checked("systemctl", &["restart", "systemd-resolved.service"])?;
        if let Err(retry_err) = run_command_checked("resolvectl", &["status"]) {
            return Err(format!(
                "managed DNS control plane is unhealthy after dbus reload and systemd-resolved restart: initial_check={initial_err}; retry_check={retry_err}"
            ));
        }
    }

    Ok(())
}

fn run_command_stream(command: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(command)
        .args(args)
        .status()
        .map_err(|err| format!("execute {} failed: {err}", format_command(command, args)))?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "command failed: {} (exit={})",
        format_command(command, args),
        status
    ))
}

fn run_systemctl_status_with_retry(
    unit: &str,
    attempts: usize,
    sleep_ms: u64,
) -> Result<(), String> {
    let status_args = ["--no-pager", "--full", "status", unit];
    let command_text = format_command("systemctl", &status_args);
    let mut last_state = "unknown".to_string();
    let mut last_exit = "unknown".to_string();
    for attempt in 1..=attempts {
        let output = Command::new("systemctl")
            .args(status_args)
            .output()
            .map_err(|err| format!("execute {command_text} failed: {err}"))?;
        if !output.stdout.is_empty() {
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        if output.status.success() {
            return Ok(());
        }
        last_exit = format!("{}", output.status);
        last_state = systemctl_unit_active_state(unit)?;
        if attempt < attempts && systemctl_state_retryable(last_state.as_str()) {
            sleep(Duration::from_millis(sleep_ms));
            continue;
        }
        return Err(format!(
            "command failed: {command_text} (exit={last_exit}, active_state={last_state}, attempt={attempt}/{attempts})"
        ));
    }
    Err(format!(
        "command failed: {command_text} (exit={last_exit}, active_state={last_state})"
    ))
}

fn systemctl_unit_active_state(unit: &str) -> Result<String, String> {
    let output = Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .map_err(|err| format!("execute systemctl is-active {unit} failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Ok(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Ok(stderr);
    }
    Ok("unknown".to_string())
}

fn systemctl_state_retryable(state: &str) -> bool {
    matches!(
        state,
        "activating" | "deactivating" | "reloading" | "inactive" | "unknown"
    )
}

fn format_command(command: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return command.to_string();
    }
    format!("{} {}", command, args.join(" "))
}

#[cfg(test)]
fn installer_unit_start_order(
    trust_auto_refresh_enabled: bool,
    assignment_auto_refresh_enabled: bool,
    auto_tunnel_enforce_enabled: bool,
) -> Vec<&'static str> {
    let mut order = vec![
        "restart rustynetd-privileged-helper.service",
        "restart rustynetd.service",
        "wait rustynetd.service active",
    ];
    if assignment_auto_refresh_enabled {
        order.push("start rustynetd-assignment-refresh.service (best-effort post-daemon)");
    }
    if trust_auto_refresh_enabled {
        order.push("start rustynetd-trust-refresh.service (best-effort post-daemon)");
    }
    if trust_auto_refresh_enabled || assignment_auto_refresh_enabled || auto_tunnel_enforce_enabled
    {
        order.push("run rustynet state refresh (strict)");
    }
    if auto_tunnel_enforce_enabled {
        order.push("restart rustynetd-managed-dns.service");
        order.push("wait rustynetd-managed-dns.service active");
    }
    if trust_auto_refresh_enabled {
        order.push("restart rustynetd-trust-refresh.timer");
    }
    if assignment_auto_refresh_enabled {
        order.push("restart rustynetd-assignment-refresh.timer");
    }
    order
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn validate_simple_value(key: &str, value: &str) -> Result<(), String> {
    validate_env_line(key, value)
}

fn validate_env_line(key: &str, value: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("environment key must not be empty".to_string());
    }
    if key.contains('\n') || key.contains('\r') || key.contains('\0') {
        return Err(format!("environment key contains unsafe characters: {key}"));
    }
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return Err(format!(
            "environment value contains unsafe characters: {key}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::{
        assignment_peer_endpoint, bytes_to_hex, installer_unit_start_order,
        parse_dev_interface_token, parse_dns_resolver_bind_addr_install, parse_install_bool,
        read_env_file_values, render_assignment_refresh_env_contents,
        resolve_selected_exit_node_id, systemctl_state_retryable, wait_for_unix_socket,
    };

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let short_prefix = prefix.chars().take(4).collect::<String>();
        let nonce = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        PathBuf::from("/tmp").join(format!("rn-{short_prefix}-{nonce}"))
    }

    #[test]
    fn parse_install_bool_accepts_expected_variants() {
        assert!(parse_install_bool("TEST", "true").expect("true should parse"));
        assert!(parse_install_bool("TEST", "1").expect("1 should parse"));
        assert!(parse_install_bool("TEST", "yes").expect("yes should parse"));
        assert!(!parse_install_bool("TEST", "false").expect("false should parse"));
        assert!(!parse_install_bool("TEST", "0").expect("0 should parse"));
        assert!(!parse_install_bool("TEST", "no").expect("no should parse"));
        assert!(parse_install_bool("TEST", "TRUE").is_err());
    }

    #[test]
    fn systemctl_state_retryable_is_strict() {
        assert!(systemctl_state_retryable("activating"));
        assert!(systemctl_state_retryable("deactivating"));
        assert!(systemctl_state_retryable("reloading"));
        assert!(systemctl_state_retryable("inactive"));
        assert!(!systemctl_state_retryable("failed"));
        assert!(!systemctl_state_retryable("active"));
    }

    #[test]
    fn installer_order_runs_single_strict_state_refresh_after_best_effort_priming() {
        let order = installer_unit_start_order(true, true, true);
        let daemon_idx = order
            .iter()
            .position(|entry| *entry == "restart rustynetd.service")
            .expect("daemon restart should be present");
        let best_effort_assignment_idx = order
            .iter()
            .position(|entry| {
                *entry == "start rustynetd-assignment-refresh.service (best-effort post-daemon)"
            })
            .expect("best-effort assignment refresh start should be present");
        let best_effort_trust_idx = order
            .iter()
            .position(|entry| {
                *entry == "start rustynetd-trust-refresh.service (best-effort post-daemon)"
            })
            .expect("best-effort trust refresh start should be present");
        let strict_state_refresh_idx = order
            .iter()
            .position(|entry| *entry == "run rustynet state refresh (strict)")
            .expect("strict state refresh should be present");
        let managed_dns_restart_idx = order
            .iter()
            .position(|entry| *entry == "restart rustynetd-managed-dns.service")
            .expect("managed DNS restart should be present");
        assert!(
            daemon_idx < best_effort_assignment_idx,
            "daemon restart must precede best-effort assignment refresh start"
        );
        assert!(
            daemon_idx < best_effort_trust_idx,
            "daemon restart must precede best-effort trust refresh start"
        );
        assert!(
            best_effort_assignment_idx < strict_state_refresh_idx,
            "best-effort assignment priming must precede strict state refresh"
        );
        assert!(
            best_effort_trust_idx < strict_state_refresh_idx,
            "best-effort trust priming must precede strict state refresh"
        );
        assert!(
            strict_state_refresh_idx < managed_dns_restart_idx,
            "strict state refresh must precede managed DNS routing restart"
        );
    }

    #[test]
    fn installer_order_skips_managed_dns_when_auto_tunnel_is_disabled() {
        let order = installer_unit_start_order(true, false, false);
        assert!(
            !order
                .iter()
                .any(|entry| entry.contains("rustynetd-managed-dns")),
            "managed DNS routing must not start before auto-tunnel enforcement is enabled"
        );
    }

    #[test]
    fn parse_dns_resolver_bind_addr_install_requires_ipv4_loopback() {
        let loopback = parse_dns_resolver_bind_addr_install("127.0.0.1:53535")
            .expect("ipv4 loopback should parse");
        assert_eq!(loopback.to_string(), "127.0.0.1:53535");

        let non_loopback = parse_dns_resolver_bind_addr_install("192.0.2.10:53535")
            .expect_err("non-loopback resolver should be rejected");
        assert!(non_loopback.contains("loopback"));

        let ipv6_loopback = parse_dns_resolver_bind_addr_install("[::1]:53535")
            .expect_err("ipv6 loopback resolver should be rejected");
        assert!(ipv6_loopback.contains("IPv4 loopback"));
    }

    #[test]
    fn refresh_service_templates_execute_refresh_ops_before_state_refresh() {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let assignment_template = std::fs::read_to_string(
            repo_root.join("scripts/systemd/rustynetd-assignment-refresh.service"),
        )
        .expect("assignment refresh template should be readable");
        assert!(
            assignment_template
                .contains("ExecStart=/usr/local/bin/rustynet ops refresh-assignment"),
            "assignment refresh service must execute the Rust assignment refresh path"
        );
        assert!(
            assignment_template.contains("ExecStartPost=/usr/local/bin/rustynet state refresh"),
            "assignment refresh service must revalidate daemon state after refreshing signed assignment state"
        );

        let trust_template = std::fs::read_to_string(
            repo_root.join("scripts/systemd/rustynetd-trust-refresh.service"),
        )
        .expect("trust refresh template should be readable");
        assert!(
            trust_template.contains("ExecStart=/usr/local/bin/rustynet ops refresh-trust"),
            "trust refresh service must execute the Rust trust refresh path"
        );
        assert!(
            trust_template.contains("ExecStartPost=/usr/local/bin/rustynet state refresh"),
            "trust refresh service must revalidate daemon state after refreshing signed trust state"
        );
    }

    #[test]
    fn wait_for_unix_socket_accepts_valid_socket() {
        let dir = unique_temp_dir("sock");
        std::fs::create_dir_all(&dir).expect("temp dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir perms should be strict");
        let socket_path = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket_path).expect("socket should bind");

        let result = wait_for_unix_socket(&socket_path, 1, 0);
        assert!(result.is_ok(), "socket path should validate");

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wait_for_unix_socket_rejects_symlink_path() {
        let dir = unique_temp_dir("link");
        std::fs::create_dir_all(&dir).expect("temp dir should exist");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir perms should be strict");
        let socket_path = dir.join("rustynetd.sock");
        let listener = UnixListener::bind(&socket_path).expect("socket should bind");
        let symlink_path = dir.join("rustynetd.sock.link");
        symlink(&socket_path, &symlink_path).expect("symlink should be created");

        let err =
            wait_for_unix_socket(&symlink_path, 1, 0).expect_err("symlink path must be rejected");
        assert!(err.contains("last_state=symlink"));

        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn read_env_file_values_takes_first_assignment_only() {
        let unique = format!(
            "rustynet-cli-env-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(format!("{unique}.env"));
        std::fs::write(
            &path,
            "# comment\nRUSTYNET_NODE_ID=a\nRUSTYNET_NODE_ID=b\nRUSTYNET_NODE_ROLE=client\n",
        )
        .expect("env file should be written");

        let values = read_env_file_values(path.as_path()).expect("env should parse");
        assert_eq!(values.get("RUSTYNET_NODE_ID").expect("node id"), "a");
        assert_eq!(
            values.get("RUSTYNET_NODE_ROLE").expect("node role"),
            "client"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn read_env_file_values_decodes_quoted_values() {
        let unique = format!(
            "rustynet-cli-env-quoted-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(format!("{unique}.env"));
        std::fs::write(
            &path,
            concat!(
                "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=\"exit-49\"\n",
                "RUSTYNET_ASSIGNMENT_ALLOW=\"client-50|exit-49;exit-49|client-50\"\n"
            ),
        )
        .expect("env file should be written");

        let values = read_env_file_values(path.as_path()).expect("env should parse");
        assert_eq!(
            values
                .get("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID")
                .expect("exit node id"),
            "exit-49"
        );
        assert_eq!(
            values
                .get("RUSTYNET_ASSIGNMENT_ALLOW")
                .expect("allow rules"),
            "client-50|exit-49;exit-49|client-50"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bytes_to_hex_encodes_expected_value() {
        assert_eq!(bytes_to_hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn parse_dev_interface_token_extracts_interface() {
        let line = "1.1.1.1 via 192.168.18.1 dev enp0s9 src 192.168.18.51 uid 0";
        assert_eq!(parse_dev_interface_token(line), Some("enp0s9"));
    }

    #[test]
    fn resolve_selected_exit_node_prefers_explicit_exit_id() {
        let mut fields = HashMap::new();
        fields.insert("route_count".to_string(), "1".to_string());
        fields.insert(
            "route.0.destination_cidr".to_string(),
            "0.0.0.0/0".to_string(),
        );
        fields.insert("route.0.kind".to_string(), "exit_default".to_string());
        fields.insert("route.0.via_node".to_string(), "exit-a".to_string());

        let resolved = resolve_selected_exit_node_id(&fields, Some("exit-b"));
        assert_eq!(resolved.as_deref(), Some("exit-b"));
    }

    #[test]
    fn resolve_selected_exit_node_from_default_route() {
        let mut fields = HashMap::new();
        fields.insert("route_count".to_string(), "1".to_string());
        fields.insert(
            "route.0.destination_cidr".to_string(),
            "0.0.0.0/0".to_string(),
        );
        fields.insert("route.0.kind".to_string(), "exit_default".to_string());
        fields.insert("route.0.via_node".to_string(), "exit-a".to_string());

        let resolved = resolve_selected_exit_node_id(&fields, None);
        assert_eq!(resolved.as_deref(), Some("exit-a"));
    }

    #[test]
    fn assignment_peer_endpoint_resolves_peer_endpoint() {
        let mut fields = HashMap::new();
        fields.insert("peer_count".to_string(), "2".to_string());
        fields.insert("peer.0.node_id".to_string(), "entry".to_string());
        fields.insert(
            "peer.0.endpoint".to_string(),
            "192.168.18.50:51820".to_string(),
        );
        fields.insert("peer.1.node_id".to_string(), "final-exit".to_string());
        fields.insert(
            "peer.1.endpoint".to_string(),
            "192.168.18.49:51820".to_string(),
        );

        let endpoint =
            assignment_peer_endpoint(&fields, "final-exit").expect("peer endpoint should resolve");
        assert_eq!(endpoint, "192.168.18.49:51820");
    }

    #[test]
    fn render_assignment_refresh_env_defaults_target_node_id_and_quotes_values() {
        let mut existing = HashMap::new();
        existing.insert(
            "RUSTYNET_ASSIGNMENT_NODES".to_string(),
            "client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def".to_string(),
        );
        existing.insert(
            "RUSTYNET_ASSIGNMENT_ALLOW".to_string(),
            "client-50|exit-49;exit-49|client-50".to_string(),
        );

        let rendered =
            render_assignment_refresh_env_contents("client-50", None, None, None, None, &existing)
                .expect("assignment refresh env should render");

        assert!(rendered.contains("RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=\"client-50\""));
        assert!(rendered.contains(
            "RUSTYNET_ASSIGNMENT_NODES=\"client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def\""
        ));
        assert!(
            rendered.contains("RUSTYNET_ASSIGNMENT_ALLOW=\"client-50|exit-49;exit-49|client-50\"")
        );
    }

    #[test]
    fn render_assignment_refresh_env_requires_nodes_and_allow() {
        let err = render_assignment_refresh_env_contents(
            "client-50",
            None,
            None,
            None,
            None,
            &HashMap::new(),
        )
        .expect_err("missing assignment refresh fields should fail");
        assert!(err.contains("RUSTYNET_ASSIGNMENT_NODES"));
    }

    #[test]
    fn render_assignment_refresh_env_rejects_invalid_exit_node_id() {
        let mut existing = HashMap::new();
        existing.insert(
            "RUSTYNET_ASSIGNMENT_NODES".to_string(),
            "client-50|192.168.18.50:51820|abc;exit-49|192.168.18.49:51820|def".to_string(),
        );
        existing.insert(
            "RUSTYNET_ASSIGNMENT_ALLOW".to_string(),
            "client-50|exit-49;exit-49|client-50".to_string(),
        );

        let err = render_assignment_refresh_env_contents(
            "client-50",
            None,
            None,
            None,
            Some("exit 49".to_string()),
            &existing,
        )
        .expect_err("invalid exit node id should fail");
        assert!(err.contains("RUSTYNET_ASSIGNMENT_EXIT_NODE_ID"));
    }
}

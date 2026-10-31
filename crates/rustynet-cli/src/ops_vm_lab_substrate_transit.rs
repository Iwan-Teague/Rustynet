//! `ops vm-lab-write-substrate-transit` and
//! `ops vm-lab-remove-substrate-transit`: the host side of the vxlan
//! substrate-transit attestation contract
//! (`VxlanSubstrateKillswitchDesign_2026-10-03.md`).
//!
//! The daemon (feature `lab-substrate`) refuses to enable the substrate
//! transit ruleset unless this attestation file exists on the same guest:
//! root-owned (uid 0), not group/other-writable (mode 0644), a regular
//! (never symlinked) file at [`LAB_SUBSTRATE_TRANSIT_PATH`], inside a
//! root-owned, non-symlink, not group/other-writable directory (0755
//! root:root), with exactly the strict line set the daemon re-validates on
//! every status read. The vxlan substrate writes it on each participating
//! guest via this subcommand, invoked as argv over the leaf-runner seam
//! (`substrate.rs`); removal is the teardown half.
//!
//! Why 0644 and not 0600: the daemon runs as the unprivileged user
//! `rustynetd` with an empty capability set, so it cannot read a 0600 root
//! file. The content is two device names plus private lab IPs, which is
//! topology already visible to any local user via `ip -d link` and
//! `bridge fdb`; confidentiality is not the property protected here.
//! Integrity is: only root can create or replace the file or its directory
//! (the daemon's validator refuses anything else).
//!
//! This module is vm-lab-gated because it only ever runs inside the lab:
//! the validation is deliberately identical to the daemon's so a bad
//! attestation can never be minted here and blame the daemon.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The daemon's attestation contract pins this exact path.
pub const LAB_SUBSTRATE_TRANSIT_PATH: &str = "/etc/rustynet/lab/substrate-transit";
/// The directory holding the attestation (mode 0755, root:root).
pub const LAB_SUBSTRATE_DIR_PATH: &str = "/etc/rustynet/lab";
/// Mode of the attestation directory: world-searchable so the unprivileged
/// daemon user can reach the file, never group/other-writable.
const LAB_SUBSTRATE_DIR_MODE: u32 = 0o755;
/// Mode of the attestation file: world-readable (the daemon runs as an
/// unprivileged user), never group/other-writable.
const LAB_SUBSTRATE_FILE_MODE: u32 = 0o644;

/// Required owner of the attestation file and directory. Production is always
/// root:root; the tests substitute the running user so the real write path
/// (including the chown and the ownership refusal) executes unprivileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Owner {
    uid: u32,
    gid: u32,
}

const ROOT_OWNER: Owner = Owner { uid: 0, gid: 0 };

/// Overlay interfaces the daemon accepts; must stay in lockstep with the
/// daemon's allowlist (and `substrate.rs`, which provisions these links).
pub const LAB_SUBSTRATE_OVERLAY_INTERFACES: [&str; 2] = ["rustynet-vx0", "rustynet-vxl"];

/// Most peers one attestation may name (the design's 1..=32 bound).
pub const LAB_SUBSTRATE_MAX_PEERS: usize = 32;

/// Options of `ops vm-lab-write-substrate-transit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabWriteSubstrateTransitConfig {
    pub overlay_interface: String,
    pub underlay_interface: String,
    pub peers: Vec<String>,
}

/// A validated attestation ready to be serialized.
struct ValidatedTransit {
    overlay_interface: String,
    underlay_interface: String,
    peers: Vec<String>,
}

/// Serialize a validated attestation into the daemon's exact line format.
/// The order is fixed so a byte comparison against the daemon's parser is
/// stable across runs.
fn build_attestation_content(validated: &ValidatedTransit) -> String {
    let mut content = String::new();
    content.push_str("version=1\n");
    content.push_str(&format!(
        "overlay_interface={}\n",
        validated.overlay_interface
    ));
    content.push_str(&format!(
        "underlay_interface={}\n",
        validated.underlay_interface
    ));
    for peer in &validated.peers {
        content.push_str(&format!("peer={peer}\n"));
    }
    content
}

/// The overlay allowlist check, shared by the writer and the tests.
fn validate_overlay_interface(name: &str) -> Result<(), String> {
    if LAB_SUBSTRATE_OVERLAY_INTERFACES.contains(&name) {
        Ok(())
    } else {
        Err(format!(
            "overlay interface {name:?} is not a substrate overlay interface; \
             expected one of {LAB_SUBSTRATE_OVERLAY_INTERFACES:?}"
        ))
    }
}

/// Whether `name` is an acceptable underlay device name. This is the SAME
/// classification as the daemon's `is_attestable_underlay_interface`
/// (`rustynetd::lab_substrate_transit`): 1..=15 characters of `[A-Za-z0-9_-]`
/// (no `.`), and never a rustynet-owned link (an underlay that names the
/// overlay would route the encapsulated traffic into the tunnel it is
/// building). The differential test `validators_match_the_daemon_*` pins the
/// equivalence over a large enumerated and fuzzed input set.
fn is_attestable_underlay_interface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        && !name.starts_with("rustynet")
}

fn validate_underlay_interface(name: &str) -> Result<(), String> {
    if is_attestable_underlay_interface(name) {
        Ok(())
    } else {
        Err(format!(
            "underlay interface {name:?} must be 1..=15 characters of [A-Za-z0-9_-] (no '.') \
             and not a rustynet-owned link; the substrate never tunnels over its own overlay"
        ))
    }
}

/// Whether `peer` is an address class the attestation may name: RFC 1918
/// private space or RFC 6598 shared (CGNAT) space, never unspecified,
/// loopback, multicast or broadcast. Byte-for-byte the daemon's
/// `is_attestable_transit_peer` (differentially tested).
fn is_attestable_transit_peer(peer: Ipv4Addr) -> bool {
    if peer.is_unspecified() || peer.is_loopback() || peer.is_multicast() || peer.is_broadcast() {
        return false;
    }
    let [a, b, _, _] = peer.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        // 100.64.0.0/10
        || (a == 100 && (64..=127).contains(&b))
}

/// The peer check: a bare, canonically spelled private/CGNAT IPv4 literal,
/// exactly the address space the daemon accepts.
fn validate_peer(peer: &str) -> Result<(), String> {
    let ip: Ipv4Addr = peer.parse().map_err(|_| {
        format!("peer {peer:?} is not a bare IPv4 literal (no prefixes, no hostnames)")
    })?;
    // Canonical spelling only, like the daemon: the address must round-trip.
    if ip.to_string() != peer {
        return Err(format!(
            "peer {peer:?} is not in canonical dotted-quad form"
        ));
    }
    if !is_attestable_transit_peer(ip) {
        return Err(format!(
            "peer {peer:?} is not a private (10/8, 172.16/12, 192.168/16) or CGNAT (100.64/10) \
             address, or is a special-purpose address; the substrate transit never leaves the \
             lab address space"
        ));
    }
    Ok(())
}

/// Validate CLI options into a [`ValidatedTransit`], refusing duplicates
/// (the strictest reading of the contract: the daemon counts peer lines, so
/// a repeated address would desync the rule/attestation count).
fn validate_transit(config: &VmLabWriteSubstrateTransitConfig) -> Result<ValidatedTransit, String> {
    validate_overlay_interface(&config.overlay_interface)?;
    validate_underlay_interface(&config.underlay_interface)?;
    if config.peers.is_empty() {
        return Err("at least one --peer is required".to_owned());
    }
    if config.peers.len() > LAB_SUBSTRATE_MAX_PEERS {
        return Err(format!(
            "at most {LAB_SUBSTRATE_MAX_PEERS} --peer values are supported; got {}",
            config.peers.len()
        ));
    }
    let mut peers = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        validate_peer(peer)?;
        if peers.contains(peer) {
            return Err(format!(
                "duplicate --peer {peer}; each peer may appear once"
            ));
        }
        peers.push(peer.clone());
    }
    peers.sort();
    Ok(ValidatedTransit {
        overlay_interface: config.overlay_interface.clone(),
        underlay_interface: config.underlay_interface.clone(),
        peers,
    })
}

/// Parse the `dev <name>` out of `ip route get <address>` stdout.
/// Returns `None` when the route line does not name a device — the caller
/// fails closed on that instead of guessing.
fn parse_route_get_dev(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?;
    let mut fields = line.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next().map(str::to_owned);
        }
    }
    None
}

/// The route check: EVERY peer must actually route over the declared
/// underlay interface on this host. Without this the attestation could
/// describe a data path that does not exist, and the daemon's nftables
/// `oifname` rules would silently never match.
fn check_routes(
    config: &VmLabWriteSubstrateTransitConfig,
    probe: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    for peer in &config.peers {
        let stdout = probe(peer).map_err(|err| format!("ip route get {peer} failed: {err}"))?;
        match parse_route_get_dev(&stdout) {
            Some(dev) if dev == config.underlay_interface => {}
            Some(dev) => {
                return Err(format!(
                    "peer {peer} routes over {dev:?}, not the declared underlay interface {:?}; \
                     refusing to attest a transit path that does not exist",
                    config.underlay_interface
                ));
            }
            None => {
                return Err(format!(
                    "ip route get {peer} did not name a device; cannot verify the underlay"
                ));
            }
        }
    }
    Ok(())
}

fn real_route_probe(peer: &str) -> Result<String, String> {
    // The peer already passed `validate_peer`, so it is a bare IPv4 literal
    // and cannot smuggle extra argv through `Command`.
    let output = Command::new("ip")
        .args(["route", "get", peer])
        .output()
        .map_err(|err| err.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if output.status.success() {
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(stderr)
    }
}

/// Refuse anything but a regular file at the attestation path. A symlink
/// there would let the daemon read a file an operator never minted.
fn assert_regular_file_or_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                Err(format!(
                    "refusing symlink at {}; the attestation must be a regular file",
                    path.display()
                ))
            } else if !metadata.is_file() {
                Err(format!(
                    "refusing non-regular file at {}; the attestation must be a regular file",
                    path.display()
                ))
            } else {
                Ok(())
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("stat failed ({}): {err}", path.display())),
    }
}

/// The daemon reads the attestation from `/etc/rustynet/lab`, and its
/// validator requires the parent directory to be a root-owned real directory
/// that is neither a symlink nor group/other-writable. Absent: create it
/// 0755 owned by `owner`. Present: it must ALREADY be exactly that (real
/// directory, owned by `owner`, mode 0755); anything else (symlink, other
/// owner, looser or tighter mode) is refused rather than silently rewritten,
/// so an operator-visible mistake is never papered over.
fn prepare_attestation_dir(dir: &Path, owner: Owner) -> Result<bool, String> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "refusing symlink at {}; the attestation directory must be a real directory",
                    dir.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(format!(
                    "refusing: {} exists but is not a directory",
                    dir.display()
                ));
            }
            if (metadata.uid(), metadata.gid()) != (owner.uid, owner.gid) {
                return Err(format!(
                    "refusing {}: owned by {}:{}, expected {}:{}",
                    dir.display(),
                    metadata.uid(),
                    metadata.gid(),
                    owner.uid,
                    owner.gid
                ));
            }
            let mode = metadata.permissions().mode() & 0o7777;
            if mode != LAB_SUBSTRATE_DIR_MODE {
                return Err(format!(
                    "refusing {}: mode {:04o}, expected {:04o}",
                    dir.display(),
                    mode,
                    LAB_SUBSTRATE_DIR_MODE
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(dir)
                .map_err(|err| format!("create dir failed ({}): {err}", dir.display()))?;
            // chown before chmod: the directory is never world-searchable
            // while owned by someone else, and the explicit chmod makes the
            // result independent of the process umask. A half-made directory
            // (create succeeded, chown or chmod did not) is rolled back so a
            // failed write never leaves a wrong-owner directory behind for the
            // next attempt to refuse.
            let finish = || -> Result<(), String> {
                std::os::unix::fs::chown(dir, Some(owner.uid), Some(owner.gid))
                    .map_err(|err| format!("chown failed ({}): {err}", dir.display()))?;
                fs::set_permissions(dir, fs::Permissions::from_mode(LAB_SUBSTRATE_DIR_MODE))
                    .map_err(|err| format!("chmod 0755 failed ({}): {err}", dir.display()))
            };
            if let Err(err) = finish() {
                let _ = fs::remove_dir(dir);
                return Err(err);
            }
            return Ok(true);
        }
        Err(err) => return Err(format!("stat failed ({}): {err}", dir.display())),
    }
    Ok(false)
}

/// Atomic write: content lands in a sibling temp file (same filesystem, so
/// the final rename is atomic), is pinned to mode 0644 + owner (root:root in
/// production) BEFORE it becomes the attestation, and the rename swaps it in
/// whole. A crash can
/// only leave the old attestation or the new one, never a half-written one.
fn write_attestation_file(path: &Path, content: &str, owner: Owner) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("attestation path {} has no parent", path.display()))?;
    let temp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("substrate-transit"),
        std::process::id()
    ));
    let cleanup = |temp: &PathBuf| {
        let _ = fs::remove_file(temp);
    };
    let result = (|| -> Result<(), String> {
        // A stale temp name left by a crashed earlier process with the same
        // pid (or a planted symlink) is unlinked, never followed or reused;
        // `remove_file` does not follow a symlink. `create_new` then adds
        // O_EXCL, so the open can only create a brand-new file, and the mode is
        // requested at creation (0644, never the 0666 default) so the file is
        // never briefly world-writable under a permissive umask.
        let _ = fs::remove_file(&temp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(LAB_SUBSTRATE_FILE_MODE)
            .open(&temp)
            .map_err(|err| format!("create temp file failed ({}): {err}", temp.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|err| format!("write failed ({}): {err}", temp.display()))?;
        // fchmod/fchown on the open descriptor: the mode is exact whatever the
        // umask removed at creation, and ownership is fixed BEFORE the rename
        // makes the file the attestation.
        file.set_permissions(fs::Permissions::from_mode(LAB_SUBSTRATE_FILE_MODE))
            .map_err(|err| format!("chmod 0644 failed ({}): {err}", temp.display()))?;
        std::os::unix::fs::fchown(&file, Some(owner.uid), Some(owner.gid))
            .map_err(|err| format!("chown failed ({}): {err}", temp.display()))?;
        file.sync_all()
            .map_err(|err| format!("fsync failed ({}): {err}", temp.display()))?;
        drop(file);
        fs::rename(&temp, path)
            .map_err(|err| format!("rename failed ({}): {err}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        cleanup(&temp);
    }
    result
}

/// The write path, parameterized over the attestation location and the route
/// probe so tests run against a temp dir without touching `/etc`.
fn write_substrate_transit_with(
    dir: &Path,
    path: &Path,
    owner: Owner,
    config: &VmLabWriteSubstrateTransitConfig,
    probe: &dyn Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    let validated = validate_transit(config)?;
    check_routes(config, probe)?;
    assert_regular_file_or_absent(path)?;
    let created_dir = prepare_attestation_dir(dir, owner)?;
    let content = build_attestation_content(&validated);
    if let Err(err) = write_attestation_file(path, &content, owner) {
        if created_dir {
            // Roll back the directory this call made (remove_dir only removes
            // an empty directory, so it can never delete someone's file).
            let _ = fs::remove_dir(dir);
        }
        return Err(err);
    }
    Ok(format!(
        "wrote {} (overlay={} underlay={} peers={})",
        path.display(),
        validated.overlay_interface,
        validated.underlay_interface,
        validated.peers.len()
    ))
}

/// `ops vm-lab-write-substrate-transit`
pub fn execute_ops_vm_lab_write_substrate_transit(
    config: VmLabWriteSubstrateTransitConfig,
) -> Result<String, String> {
    write_substrate_transit_with(
        Path::new(LAB_SUBSTRATE_DIR_PATH),
        Path::new(LAB_SUBSTRATE_TRANSIT_PATH),
        ROOT_OWNER,
        &config,
        &real_route_probe,
    )
}

/// `ops vm-lab-remove-substrate-transit`: idempotent removal. A missing file
/// is the success case (teardown runs on every exit path); a symlink at the
/// path is still removed — removing residue must not fail on residue.
pub fn execute_ops_vm_lab_remove_substrate_transit() -> Result<String, String> {
    remove_substrate_transit_at(Path::new(LAB_SUBSTRATE_TRANSIT_PATH))
}

fn remove_substrate_transit_at(path: &Path) -> Result<String, String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(format!("removed {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(format!("{} already absent", path.display()))
        }
        Err(err) => Err(format!("remove failed ({}): {err}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(
        overlay: &str,
        underlay: &str,
        peers: &[&str],
    ) -> VmLabWriteSubstrateTransitConfig {
        VmLabWriteSubstrateTransitConfig {
            overlay_interface: overlay.to_owned(),
            underlay_interface: underlay.to_owned(),
            peers: peers.iter().map(|peer| (*peer).to_owned()).collect(),
        }
    }

    fn ok_probe(expected_dev: &str) -> impl Fn(&str) -> Result<String, String> {
        let expected_dev = expected_dev.to_owned();
        move |_| Ok(format!("10.9.9.9 dev {expected_dev} src 10.9.9.1 uid 0"))
    }

    #[test]
    fn content_matches_the_daemon_contract_byte_for_byte() {
        let validated = validate_transit(&write_config(
            "rustynet-vx0",
            "enp0s8",
            &["10.9.0.3", "10.9.0.2"],
        ))
        .expect("valid");
        assert_eq!(
            build_attestation_content(&validated),
            "version=1\n\
             overlay_interface=rustynet-vx0\n\
             underlay_interface=enp0s8\n\
             peer=10.9.0.2\n\
             peer=10.9.0.3\n"
        );
    }

    #[test]
    fn overlay_allowlist_refuses_everything_but_the_two_substrate_links() {
        assert!(validate_overlay_interface("rustynet-vx0").is_ok());
        assert!(validate_overlay_interface("rustynet-vxl").is_ok());
        assert!(validate_overlay_interface("eth0").is_err());
        assert!(validate_overlay_interface("rustynet-vx1").is_err());
        assert!(validate_overlay_interface("").is_err());
    }

    #[test]
    fn underlay_refuses_rustynet_owned_and_hostile_names() {
        assert!(validate_underlay_interface("enp0s8").is_ok());
        assert!(validate_underlay_interface("eth0").is_ok());
        // '.' is not in the daemon's device-name charset (a VLAN underlay such
        // as eth0.100 would be written and then refused by the daemon).
        assert!(validate_underlay_interface("br-lan.dev").is_err());
        assert!(validate_underlay_interface("eth0.100").is_err());
        assert!(validate_underlay_interface("br-lan_dev").is_ok());
        assert!(validate_underlay_interface("rustynet-vx0").is_err());
        assert!(validate_underlay_interface("").is_err());
        assert!(validate_underlay_interface("eth0;rm").is_err());
        assert!(validate_underlay_interface("a-very-long-interface-name-over-15").is_err());
    }

    #[test]
    fn peer_allowlist_is_private_and_cgnat_only() {
        for peer in [
            "10.9.0.2",
            "172.16.5.5",
            "172.31.255.254",
            "192.168.1.1",
            "100.64.0.9",
            "100.127.255.254",
        ] {
            assert!(validate_peer(peer).is_ok(), "{peer} must pass");
        }
        for peer in [
            "127.0.0.1",
            "0.0.0.0",
            "8.8.8.8",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "100.128.0.1",
            "100.0.1.1",
            "100.1.1.1",
            "100.63.255.255",
            "172.15.0.1",
            "172.32.0.1",
            "172.0.0.1",
            "192.0.2.1",
            "192.167.0.1",
            "192.169.0.1",
            "10.9.0.2/24",
            "10.9.0.2:80",
            " 10.9.0.2",
            "010.9.0.2",
            "node-a",
            "",
        ] {
            assert!(validate_peer(peer).is_err(), "{peer} must fail");
        }
    }

    #[test]
    fn duplicate_peers_are_refused_and_peers_are_bounded() {
        assert!(
            validate_transit(&write_config(
                "rustynet-vx0",
                "eth0",
                &["10.0.0.2", "10.0.0.2"]
            ))
            .is_err()
        );
        assert!(validate_transit(&write_config("rustynet-vx0", "eth0", &[])).is_err());
        let many: Vec<String> = (0..=32).map(|i| format!("10.0.{i}.2")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(validate_transit(&write_config("rustynet-vx0", "eth0", &refs)).is_err());
        let ok: Vec<String> = (0..32).map(|i| format!("10.0.{i}.2")).collect();
        let refs: Vec<&str> = ok.iter().map(String::as_str).collect();
        assert!(validate_transit(&write_config("rustynet-vx0", "eth0", &refs)).is_ok());
    }

    #[test]
    fn route_parse_extracts_the_dev_token() {
        assert_eq!(
            parse_route_get_dev("10.9.0.2 dev enp0s8 src 10.9.0.1 uid 0\n"),
            Some("enp0s8".to_owned())
        );
        assert_eq!(
            parse_route_get_dev("10.9.0.2 via 10.9.0.1 dev gw0\n"),
            Some("gw0".to_owned())
        );
        assert_eq!(
            parse_route_get_dev("RTNETLINK answers: Network is unreachable\n"),
            None
        );
        assert_eq!(parse_route_get_dev(""), None);
    }

    #[test]
    fn every_peer_must_route_over_the_declared_underlay() {
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2", "10.0.0.3"]);
        assert!(check_routes(&config, &ok_probe("enp0s8")).is_ok());
        assert!(check_routes(&config, &ok_probe("eth1")).is_err());
        assert!(check_routes(&config, &|_| Err("boom".to_owned())).is_err());
        assert!(check_routes(&config, &|_| Ok("10.0.0.2\n".to_owned())).is_err());
    }

    /// A fresh temp directory pinned to the attestation-directory mode, plus
    /// the running user as the stand-in "root" owner so the real write path
    /// (chown, ownership check) executes without privileges.
    fn temp_attestation_dir(tag: &str) -> (PathBuf, Owner) {
        let dir =
            std::env::temp_dir().join(format!("rn-substrate-transit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(LAB_SUBSTRATE_DIR_MODE))
            .expect("chmod dir");
        let metadata = fs::metadata(&dir).expect("dir metadata");
        let owner = Owner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        (dir, owner)
    }

    #[test]
    fn production_owner_is_root_root_and_modes_are_daemon_readable() {
        assert_eq!(ROOT_OWNER, Owner { uid: 0, gid: 0 });
        // The unprivileged `rustynetd` user must be able to read the file
        // and search the directory; nobody but the owner may write either.
        assert_eq!(LAB_SUBSTRATE_FILE_MODE, 0o644);
        assert_eq!(LAB_SUBSTRATE_DIR_MODE, 0o755);
        assert_eq!(LAB_SUBSTRATE_FILE_MODE & 0o022, 0);
        assert_eq!(LAB_SUBSTRATE_DIR_MODE & 0o022, 0);
    }

    #[test]
    fn write_is_atomic_mode_0644_owned_and_verifies_routes() {
        let (dir, owner) = temp_attestation_dir("write");
        let path = dir.join("substrate-transit");
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        let summary =
            write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s8"))
                .expect("write");
        assert!(summary.contains("peers=1"));
        let metadata = fs::metadata(&path).expect("written");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o644);
        assert_eq!((metadata.uid(), metadata.gid()), (owner.uid, owner.gid));
        let content = fs::read_to_string(&path).expect("read");
        assert!(content.starts_with("version=1\noverlay_interface=rustynet-vx0\n"));
        // No temp residue.
        let residue: Vec<_> = fs::read_dir(&dir)
            .expect("dir")
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(residue.is_empty(), "temp file must be renamed, not left");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_refuses_when_a_peer_routes_elsewhere() {
        let (dir, owner) = temp_attestation_dir("routefail");
        let path = dir.join("substrate-transit");
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        assert!(
            write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("eth1")).is_err()
        );
        assert!(
            !path.exists(),
            "nothing may be written when routes disagree"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_refuses_a_symlink_at_the_target_or_the_parent() {
        let (dir, owner) = temp_attestation_dir("symlink");
        let victim = dir.join("victim");
        fs::write(&victim, "x").expect("victim");
        let path = dir.join("substrate-transit");
        std::os::unix::fs::symlink(&victim, &path).expect("symlink");
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        assert!(
            write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s8")).is_err()
        );
        assert!(
            fs::read_to_string(&victim).expect("victim intact") == "x",
            "symlink target must never be overwritten"
        );
        // A symlinked parent directory is refused too, and nothing is written
        // through it.
        let real = dir.join("real");
        fs::create_dir(&real).expect("real dir");
        let link_dir = dir.join("linkdir");
        std::os::unix::fs::symlink(&real, &link_dir).expect("dir symlink");
        let via_link = link_dir.join("substrate-transit");
        let err =
            write_substrate_transit_with(&link_dir, &via_link, owner, &config, &ok_probe("enp0s8"))
                .expect_err("symlinked parent refused");
        assert!(err.contains("refusing symlink"), "{err}");
        assert!(!real.join("substrate-transit").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn existing_directory_with_wrong_mode_or_owner_is_refused_not_rewritten() {
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        for (tag, mode) in [("g-w", 0o775), ("o-w", 0o757), ("tight", 0o700)] {
            let (dir, owner) = temp_attestation_dir(&format!("badmode-{tag}"));
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).expect("chmod");
            let path = dir.join("substrate-transit");
            let err =
                write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s8"))
                    .expect_err("wrong mode refused");
            assert!(err.contains("expected 0755"), "{tag}: {err}");
            assert!(!path.exists(), "{tag}: nothing written");
            let after = fs::metadata(&dir).expect("dir").permissions().mode() & 0o7777;
            assert_eq!(after, mode, "{tag}: a wrong-mode dir is never rewritten");
            let _ = fs::remove_dir_all(&dir);
        }
        let (dir, owner) = temp_attestation_dir("badowner");
        let path = dir.join("substrate-transit");
        let other = Owner {
            uid: owner.uid.wrapping_add(1),
            gid: owner.gid,
        };
        let err = write_substrate_transit_with(&dir, &path, other, &config, &ok_probe("enp0s8"))
            .expect_err("wrong owner refused");
        assert!(err.contains("expected"), "{err}");
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_directory_is_created_0755_owned_regardless_of_umask() {
        let (parent, owner) = temp_attestation_dir("create");
        let dir = parent.join("lab");
        let path = dir.join("substrate-transit");
        let config = write_config("rustynet-vxl", "enp0s9", &["10.0.0.2"]);
        write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s9"))
            .expect("write creates the dir");
        let metadata = fs::metadata(&dir).expect("dir");
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
        assert_eq!((metadata.uid(), metadata.gid()), (owner.uid, owner.gid));
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn rewrite_is_idempotent_and_keeps_dir_and_file_modes() {
        let (dir, owner) = temp_attestation_dir("rewrite");
        let path = dir.join("substrate-transit");
        let config = write_config("rustynet-vxl", "enp0s9", &["10.0.0.2", "10.0.0.3"]);
        write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s9"))
            .expect("first write");
        write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s9"))
            .expect("rewrite over an existing attestation");
        let dir_mode = fs::metadata(&dir).expect("dir").permissions().mode() & 0o7777;
        assert_eq!(dir_mode, 0o755);
        let file_mode = fs::metadata(&path).expect("file").permissions().mode() & 0o7777;
        assert_eq!(file_mode, 0o644);
        let content = fs::read_to_string(&path).expect("read");
        assert!(content.contains("overlay_interface=rustynet-vxl"));
        assert!(content.matches("peer=").count() == 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_temp_file_is_chowned_to_the_required_owner_before_the_rename() {
        let (dir, owner) = temp_attestation_dir("chown");
        if owner.uid == 0 {
            // Root can chown to anyone, so the refusal below is unobservable.
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let path = dir.join("substrate-transit");
        let someone_else = Owner {
            uid: owner.uid.wrapping_add(1),
            gid: owner.gid,
        };
        // An unprivileged process cannot give a file away, so writing for
        // another owner must fail LOUDLY on the chown, never silently leave a
        // file owned by the wrong user as the attestation.
        let err = write_attestation_file(&path, "version=1\n", someone_else)
            .expect_err("chown to another uid must fail unprivileged");
        assert!(err.contains("chown failed"), "{err}");
        assert!(!path.exists(), "no attestation may be installed");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .expect("dir")
            .filter_map(std::result::Result::ok)
            .collect();
        assert!(leftovers.is_empty(), "temp file must be cleaned up");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_half_made_directory_is_rolled_back() {
        let (parent, owner) = temp_attestation_dir("rollback");
        if owner.uid == 0 {
            let _ = fs::remove_dir_all(&parent);
            return;
        }
        let dir = parent.join("lab");
        let path = dir.join("substrate-transit");
        let someone_else = Owner {
            uid: owner.uid.wrapping_add(1),
            gid: owner.gid,
        };
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        let err =
            write_substrate_transit_with(&dir, &path, someone_else, &config, &ok_probe("enp0s8"))
                .expect_err("unprivileged chown of the new directory fails");
        assert!(err.contains("chown failed"), "{err}");
        assert!(
            !dir.exists(),
            "the directory this call created must not survive a failed write"
        );
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_planted_symlink_at_the_temp_name_is_never_followed() {
        let (dir, owner) = temp_attestation_dir("tempsym");
        let victim = dir.join("victim");
        fs::write(&victim, "keep").expect("victim");
        let temp = dir.join(format!(".substrate-transit.tmp.{}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temp).expect("plant symlink");
        let path = dir.join("substrate-transit");
        let config = write_config("rustynet-vx0", "enp0s8", &["10.0.0.2"]);
        write_substrate_transit_with(&dir, &path, owner, &config, &ok_probe("enp0s8"))
            .expect("write succeeds around the planted symlink");
        assert_eq!(
            fs::read_to_string(&victim).expect("victim"),
            "keep",
            "the planted symlink target must never be written through"
        );
        let metadata = fs::symlink_metadata(&path).expect("attestation");
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o644);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn peers_that_are_not_canonical_are_refused_like_the_daemon() {
        for peer in [
            "010.0.0.1",
            "10.0.0.01",
            "10.0.0.1 ",
            "+10.0.0.1",
            "0x0a.0.0.1",
        ] {
            assert!(validate_peer(peer).is_err(), "{peer:?} must be refused");
        }
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "rn-substrate-transit-remove-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("substrate-transit");
        assert_eq!(
            remove_substrate_transit_at(&path).expect("absent is Ok"),
            format!("{} already absent", path.display())
        );
        fs::write(&path, "version=1\n").expect("seed");
        assert_eq!(
            remove_substrate_transit_at(&path).expect("present removes"),
            format!("removed {}", path.display())
        );
        assert_eq!(
            remove_substrate_transit_at(&path).expect("second remove"),
            format!("{} already absent", path.display())
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// Differential test against the DAEMON'S OWN validator
/// (`rustynetd::lab_substrate_transit`, enabled for tests through the
/// dev-dependency feature): the write tool must classify every input exactly
/// as the daemon does, so a bad attestation can never be minted here and
/// blame the daemon, and a legitimate one is never refused here.
#[cfg(all(test, target_os = "linux"))]
mod daemon_parity {
    use super::*;
    use rustynetd::lab_substrate_transit as daemon;

    /// Deterministic xorshift64* so a failure reproduces.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    fn write_config(
        overlay: &str,
        underlay: &str,
        peers: &[&str],
    ) -> VmLabWriteSubstrateTransitConfig {
        VmLabWriteSubstrateTransitConfig {
            overlay_interface: overlay.to_owned(),
            underlay_interface: underlay.to_owned(),
            peers: peers.iter().map(|peer| (*peer).to_owned()).collect(),
        }
    }

    fn document(overlay: &str, underlay: &str, peer_lines: &[&str]) -> String {
        let mut doc =
            format!("version=1\noverlay_interface={overlay}\nunderlay_interface={underlay}\n");
        for peer in peer_lines {
            doc.push_str(&format!("peer={peer}\n"));
        }
        doc
    }

    fn daemon_accepts_peer(peer: &str) -> bool {
        daemon::parse_attestation(&document("rustynet-vx0", "eth0", &[peer])).is_ok()
    }

    fn daemon_accepts_underlay(name: &str) -> bool {
        daemon::parse_attestation(&document("rustynet-vx0", name, &["10.0.0.2"])).is_ok()
    }

    fn daemon_accepts_overlay(name: &str) -> bool {
        daemon::parse_attestation(&document(name, "eth0", &["10.0.0.2"])).is_ok()
    }

    #[test]
    fn the_overlay_allowlist_is_the_daemons() {
        assert_eq!(
            LAB_SUBSTRATE_OVERLAY_INTERFACES,
            [
                daemon::VXLAN_OVERLAY_INTERFACE,
                daemon::SITE_LAN_OVERLAY_INTERFACE
            ]
        );
        assert_eq!(LAB_SUBSTRATE_MAX_PEERS, daemon::MAX_SUBSTRATE_TRANSIT_PEERS);
        assert_eq!(
            LAB_SUBSTRATE_TRANSIT_PATH,
            daemon::SUBSTRATE_TRANSIT_ATTESTATION_PATH
        );
        for name in [
            "rustynet-vx0",
            "rustynet-vxl",
            "rustynet-vx1",
            "rustynet0",
            "RUSTYNET-VX0",
            "rustynet-vx0 ",
            "",
            "eth0",
            "veth0",
        ] {
            assert_eq!(
                validate_overlay_interface(name).is_ok(),
                daemon_accepts_overlay(name),
                "overlay {name:?}"
            );
        }
    }

    #[test]
    fn every_peer_class_is_classified_like_the_daemon() {
        // Every (a, b) first-two-octet pair with four representative tails:
        // the class boundaries (10/8, 172.16/12, 192.168/16, 100.64/10,
        // loopback, multicast, broadcast, unspecified) all fall on /8../16
        // edges, so this covers the whole /16 space.
        let mut checked = 0usize;
        for a in 0..=255u32 {
            for b in 0..=255u32 {
                for (c, d) in [(0u32, 0u32), (0, 1), (255, 254), (255, 255)] {
                    let peer = format!("{a}.{b}.{c}.{d}");
                    assert_eq!(
                        validate_peer(&peer).is_ok(),
                        daemon_accepts_peer(&peer),
                        "peer {peer}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 256 * 256 * 4);
        // Predicate-level (no string parsing) over a deterministic fuzz of the
        // full 32-bit space.
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..400_000 {
            let raw = rng.next() as u32;
            let ip = Ipv4Addr::from(raw);
            assert_eq!(
                is_attestable_transit_peer(ip),
                daemon::is_attestable_transit_peer(ip),
                "peer {ip}"
            );
        }
    }

    #[test]
    fn peer_spellings_are_classified_like_the_daemon() {
        for peer in [
            "",
            " ",
            "10.0.0.1 ",
            " 10.0.0.1",
            "10.0.0.1/32",
            "10.0.0.1:4789",
            "10.0.0",
            "10.0.0.1.1",
            "10.0.0.256",
            "010.0.0.1",
            "10.0.0.01",
            "0x0a.0.0.1",
            "+10.0.0.1",
            "-10.0.0.1",
            "10..0.1",
            "::ffff:10.0.0.1",
            "fd00::1",
            "node-a",
            "10.0.0.1\t",
            "10.0.0.1\r",
            "٣.٣.٣.٣",
            "10.0.0.1=",
            "peer=10.0.0.1",
            "localhost",
        ] {
            assert_eq!(
                validate_peer(peer).is_ok(),
                daemon_accepts_peer(peer),
                "peer spelling {peer:?}"
            );
        }
    }

    #[test]
    fn underlay_names_are_classified_like_the_daemon() {
        // Exhaustive over a 14-character alphabet for lengths 0..=3.
        let alphabet: Vec<char> = "aZ09-_. /:=\té@".chars().collect();
        let mut names = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for ch in &alphabet {
                    let mut name = prefix.clone();
                    name.push(*ch);
                    next.push(name);
                }
            }
            names.extend(next.iter().cloned());
            frontier = next;
        }
        // Length and prefix boundaries, plus rustynet-owned links.
        for len in 12..=17usize {
            names.push("a".repeat(len));
            names.push(format!(
                "{}{}",
                "rustynet",
                "0".repeat(len.saturating_sub(8))
            ));
        }
        for name in [
            "rustynet",
            "rustynet0",
            "rustynet-vx0",
            "rustyne",
            "rustynet.",
            "Rustynet0",
            "xrustynet",
            "eth0.100",
            "enp0s8",
            "br-lan_dev",
            ".eth0",
            "eth0.",
            "é",
            "eth0\n",
        ] {
            names.push(name.to_owned());
        }
        // Fuzz over the same alphabet at the 15/16 length boundary.
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        for _ in 0..20_000 {
            let len = 1 + (rng.next() % 17) as usize;
            let name: String = (0..len)
                .map(|_| {
                    alphabet
                        .get((rng.next() % alphabet.len() as u64) as usize)
                        .copied()
                        .unwrap_or('a')
                })
                .collect();
            names.push(name);
        }
        let mut checked = 0usize;
        for name in &names {
            // A name with a newline would split the document; the tool must
            // still refuse it, and the daemon refuses the resulting document.
            if name.contains('\n') {
                assert!(validate_underlay_interface(name).is_err(), "{name:?}");
                continue;
            }
            assert_eq!(
                validate_underlay_interface(name).is_ok(),
                daemon_accepts_underlay(name),
                "underlay {name:?}"
            );
            assert_eq!(
                is_attestable_underlay_interface(name),
                daemon::is_attestable_underlay_interface(name),
                "underlay predicate {name:?}"
            );
            checked += 1;
        }
        assert!(checked > 3_000, "corpus too small: {checked}");
    }

    /// Whole-config parity: whatever the tool accepts, the daemon parses to
    /// the same fields; the only config the tool refuses and the daemon
    /// accepts is a repeated peer (the tool is deliberately stricter there).
    #[test]
    fn whole_configs_are_classified_like_the_daemon() {
        let mut rng = Rng(0xA076_1D64_78BD_642F);
        let overlays = ["rustynet-vx0", "rustynet-vxl", "rustynet-vx9", "eth0"];
        let underlays = ["eth0", "enp0s8", "eth0.5", "rustynet0", "", "a b"];
        let peer_pool = [
            "10.0.0.2",
            "10.0.0.3",
            "172.16.0.9",
            "172.17.0.9",
            "172.32.0.9",
            "192.168.1.1",
            "192.0.2.1",
            "100.64.0.1",
            "100.1.1.1",
            "8.8.8.8",
            "127.0.0.1",
            "10.0.0.2/24",
        ];
        let valid_overlays = ["rustynet-vx0", "rustynet-vxl"];
        let valid_underlays = ["eth0", "enp0s8", "br-lan_dev"];
        let valid_peers = [
            "10.0.0.2",
            "10.0.0.3",
            "172.16.0.9",
            "172.31.0.9",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.0.1",
        ];
        let mut accepted_by_both = 0usize;
        for round in 0..30_000u32 {
            // Every other round draws from the VALID pools (with the odd junk
            // value mixed in via the junk pools below) so the "both accept"
            // arm is exercised heavily, not just the "both refuse" one.
            let biased = round % 2 == 0;
            let overlay = if biased {
                valid_overlays
                    .get((rng.next() % valid_overlays.len() as u64) as usize)
                    .copied()
                    .unwrap_or("rustynet-vx0")
            } else {
                overlays
                    .get((rng.next() % overlays.len() as u64) as usize)
                    .copied()
                    .unwrap_or("eth0")
            };
            let underlay = if biased {
                valid_underlays
                    .get((rng.next() % valid_underlays.len() as u64) as usize)
                    .copied()
                    .unwrap_or("eth0")
            } else {
                underlays
                    .get((rng.next() % underlays.len() as u64) as usize)
                    .copied()
                    .unwrap_or("eth0")
            };
            let peer_count = if biased {
                1 + (rng.next() % 3) as usize
            } else {
                (rng.next() % 36) as usize
            };
            let pool: &[&str] = if biased { &valid_peers } else { &peer_pool };
            let peers: Vec<&str> = (0..peer_count)
                .map(|_| {
                    pool.get((rng.next() % pool.len() as u64) as usize)
                        .copied()
                        .unwrap_or("10.0.0.2")
                })
                .collect();
            let config = write_config(overlay, underlay, &peers);
            let tool = validate_transit(&config);
            let daemon_parse = daemon::parse_attestation(&document(overlay, underlay, &peers));
            let has_duplicate = {
                let mut seen = std::collections::BTreeSet::new();
                peers.iter().any(|peer| !seen.insert(*peer))
            };
            match (&tool, &daemon_parse) {
                (Ok(validated), Ok(parsed)) => {
                    accepted_by_both += 1;
                    assert_eq!(validated.overlay_interface, parsed.overlay_interface());
                    assert_eq!(validated.underlay_interface, parsed.underlay_interface());
                    assert_eq!(validated.peers.len(), parsed.peers().len());
                    // The exact bytes the tool would write parse to the same
                    // transit.
                    let written = daemon::parse_attestation(&build_attestation_content(validated))
                        .expect("daemon parses the tool's own output");
                    assert_eq!(&written, parsed);
                }
                (Err(_), Err(_)) => {}
                (Err(_), Ok(_)) => assert!(
                    has_duplicate,
                    "tool refused a config the daemon accepts and it has no duplicate peer: \
                     overlay={overlay} underlay={underlay} peers={peers:?}"
                ),
                (Ok(_), Err(err)) => panic!(
                    "tool accepted a config the daemon refuses ({err}): overlay={overlay} \
                     underlay={underlay} peers={peers:?}"
                ),
            }
        }
        assert!(
            accepted_by_both > 1_000,
            "corpus too thin: {accepted_by_both}"
        );
    }
}

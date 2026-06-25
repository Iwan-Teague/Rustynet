//! Linux DNS fail-closed enforcement for protected mode — Option 2: the
//! rustynet resolver owns loopback DNS.
//!
//! # Why this exists
//! In protected mode the node must not resolve via off-host DNS
//! (`SecurityMinimumBar`: preserve DNS fail-closed in protected modes). The
//! `dns-failclosed` verifier ([`crate::linux_dns_failclosed`]) requires every
//! `/etc/resolv.conf` nameserver to be loopback, rejects pointing at the
//! systemd-resolved stub `127.0.0.53` while systemd-resolved holds it, and
//! flags NetworkManager `dns=default` (NM can rewrite resolv.conf off-loopback
//! on any link change). The reviewed posture is therefore: resolv.conf points
//! only at the rustynet resolver's loopback address; the resolver serves
//! mesh-zone names and refuses everything else; the nft killswitch blocks
//! off-host egress as defense-in-depth.
//!
//! # The empty-caps constraint (proven design)
//! The hardened `rustynetd.service` runs with `CapabilityBoundingSet=` /
//! `AmbientCapabilities=` empty (the service-hardening verifier requires this),
//! so the daemon cannot bind the privileged port 53. The resolver therefore
//! stays on its unprivileged loopback `dns_resolver_bind_addr` (default
//! `127.0.0.1:53535`) and an nft `redirect` rule maps loopback `:53` →
//! `:53535`. This was PROVEN live on `debian-headless-1`: with the redirect
//! installed, a UDP DNS query to `127.0.0.1:53` was answered by the resolver
//! listening on `127.0.0.1:53535`.
//!
//! # What this module provides
//! 1. Pure, side-effect-free builders for the exact argv vectors and file
//!    contents the protected-mode apply/teardown needs, so every privileged step
//!    stays argv-only and unit-testable.
//! 2. The `dns-failclosed-file` privileged-helper builtin
//!    ([`apply_dns_failclosed_file`] + [`is_valid_dns_failclosed_file_selector`]):
//!    a tightly-constrained file-write capability for the two fixed paths
//!    ([`RESOLV_CONF_PATH`], [`NETWORK_MANAGER_DNS_DROPIN_PATH`]). The caller
//!    passes only a fixed *selector*; the helper owns the path→content mapping,
//!    so no path or file content ever crosses the privileged boundary. Every
//!    write is symlink-safe. The resolv.conf write strategy is OS-specific: on
//!    Linux the helper's `ProtectSystem=strict` sandbox keeps `/etc` read-only
//!    (only the resolv.conf inode is writable via a narrow `ReadWritePaths`), so
//!    it writes in place with `O_NOFOLLOW`; on macOS `/etc` is writable and
//!    resolv.conf is a configd symlink, so it uses an atomic `O_EXCL` temp +
//!    `rename` (which swaps the symlink for a regular file). The NM drop-in and
//!    the backup always use the atomic temp+rename in a writable dir. The change
//!    is reversible: the original resolv.conf is backed up to
//!    [`RESOLV_CONF_FAILCLOSED_BACKUP_PATH`] for teardown.
//!
//! # Wiring status
//! - **Privileged-helper validation** (`privileged_helper.rs`): the `dns_redirect`
//!   `nat`/`redirect` chain+rule arms and the `dns-failclosed-file` builtin are
//!   live, with exhaustive negative tests proving nothing else is permitted.
//! - **Apply/teardown** (`phase10::LinuxCommandSystem`): protected-mode entry
//!   installs the redirect, backs up & rewrites resolv.conf, and writes the NM
//!   drop-in (when NM is present); teardown restores both files and deletes the
//!   table, tied to the killswitch lifecycle so DNS protection rolls back
//!   together. `phase10::MacosCommandSystem` reuses the same `resolv-conf-apply`
//!   /`resolv-conf-restore` builtin alongside its pf DNS rules (macOS has no NM
//!   and uses pf, not nft, for the egress block).
//! - **Validator interaction**: the redirect table `rustynet_g<gen>_dns` is a
//!   benign owned table — `is_owned_nft_table_token` permits add/delete, the
//!   cleanup sweep (`/^rustynet/`) removes it, and `linux_runtime_nftables`
//!   records it as a non-reviewed rustynet table without flagging drift (it only
//!   checks the reviewed killswitch/NAT tables), so RuntimeAcls does not regress.
//! - **Remaining**: Windows NRPT parity for the Windows dataplane.

use std::net::Ipv4Addr;
#[cfg(unix)]
use std::path::Path;

/// Loopback address `/etc/resolv.conf` points at in protected mode. The nft
/// redirect rewrites `:53` on this address to the resolver's bind port.
pub const DNS_REDIRECT_LOOPBACK_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Reviewed `/etc/resolv.conf` path (matches `linux_dns_failclosed`).
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Path of the NetworkManager `dns=none` drop-in, so NM stops managing
/// resolv.conf and cannot reintroduce off-loopback nameservers on a link
/// change (the verifier's NM-precedence check).
pub const NETWORK_MANAGER_DNS_DROPIN_PATH: &str =
    "/etc/NetworkManager/conf.d/rustynet-dns-failclosed.conf";

/// Name of the dedicated nft table holding the loopback DNS redirect for
/// dataplane `generation`. The `rustynet_g…` prefix is intentional: the
/// privileged helper's `is_owned_nft_table_token` already permits add/delete on
/// it, and the cleanup leftover-table sweep (`/^rustynet/`) removes it.
pub fn dns_redirect_table_name(generation: u64) -> String {
    format!("rustynet_g{generation}_dns")
}

/// The ordered `nft …` argv vectors that install the loopback DNS redirect on
/// `table_name`, mapping udp+tcp `:53` on [`DNS_REDIRECT_LOOPBACK_IP`] to
/// `resolver_port`. Each vector is one helper `nft` invocation. Mirrors the
/// rule proven live on debian.
pub fn dns_redirect_nft_apply_argvs(table_name: &str, resolver_port: u16) -> Vec<Vec<String>> {
    let ip = DNS_REDIRECT_LOOPBACK_IP.to_string();
    let to = format!(":{resolver_port}");
    let redirect_rule = |proto: &str| -> Vec<String> {
        vec![
            "add".into(),
            "rule".into(),
            "inet".into(),
            table_name.into(),
            "dns_redirect".into(),
            "meta".into(),
            "l4proto".into(),
            proto.into(),
            "ip".into(),
            "daddr".into(),
            ip.clone(),
            proto.into(),
            "dport".into(),
            "53".into(),
            "redirect".into(),
            "to".into(),
            to.clone(),
        ]
    };
    vec![
        vec![
            "add".into(),
            "table".into(),
            "inet".into(),
            table_name.into(),
        ],
        vec![
            "add".into(),
            "chain".into(),
            "inet".into(),
            table_name.into(),
            "dns_redirect".into(),
            "{".into(),
            "type".into(),
            "nat".into(),
            "hook".into(),
            "output".into(),
            "priority".into(),
            "dstnat".into(),
            ";".into(),
            "policy".into(),
            "accept".into(),
            ";".into(),
            "}".into(),
        ],
        redirect_rule("udp"),
        redirect_rule("tcp"),
    ]
}

/// The `nft …` argv that tears down the redirect table. Deleting the whole
/// table removes the chain + both rules in one idempotent step.
pub fn dns_redirect_nft_teardown_argv(table_name: &str) -> Vec<String> {
    vec![
        "delete".into(),
        "table".into(),
        "inet".into(),
        table_name.into(),
    ]
}

/// `/etc/resolv.conf` contents for protected mode: a single loopback nameserver
/// (the rustynet resolver, reached via the nft redirect). No off-host
/// nameserver — the floor the dns-failclosed verifier checks.
pub fn loopback_resolv_conf_contents() -> String {
    format!("# rustynet protected-mode DNS fail-closed\nnameserver {DNS_REDIRECT_LOOPBACK_IP}\n")
}

/// NetworkManager drop-in contents that stop NM managing resolv.conf, so it
/// cannot reintroduce off-loopback nameservers on a link change.
pub fn network_manager_dns_none_dropin() -> String {
    "[main]\ndns=none\n".to_owned()
}

// ===========================================================================
// Protected-mode DNS file-write builtin (privileged boundary)
// ===========================================================================
//
// The privileged helper is otherwise argv-only EXEC (ip/nft/wg/…). Pointing
// `/etc/resolv.conf` at the loopback resolver — and disabling NetworkManager's
// resolv.conf management — requires writing files, which no exec'd binary can do
// safely (`tee`/`cp` with caller-supplied content would be an arbitrary-write
// hole). Instead the helper grows ONE tightly-constrained builtin: the caller
// passes a single *selector* token naming one of four fixed operations; the
// helper owns the path→content mapping entirely. No path and no file content
// ever crosses the privileged boundary, so the only attack surface is the
// finite selector set — validated against [`DNS_FAILCLOSED_FILE_SELECTORS`].

/// Privileged-helper "program" token for the DNS fail-closed file-write builtin.
/// Not an external binary: it is an in-helper operation that writes ONLY the two
/// reviewed fixed paths with ONLY the byte-exact fixed contents this module
/// produces.
pub const DNS_FAILCLOSED_FILE_PROGRAM: &str = "dns-failclosed-file";

/// Selector: back up the current resolv.conf (once) and replace it with the
/// loopback-only fail-closed contents ([`loopback_resolv_conf_contents`]).
pub const DNS_FILE_SELECTOR_RESOLV_APPLY: &str = "resolv-conf-apply";
/// Selector: restore resolv.conf from the fail-closed backup (teardown).
pub const DNS_FILE_SELECTOR_RESOLV_RESTORE: &str = "resolv-conf-restore";
/// Selector: write the NetworkManager `dns=none` drop-in
/// ([`network_manager_dns_none_dropin`]).
pub const DNS_FILE_SELECTOR_NM_APPLY: &str = "nm-dropin-apply";
/// Selector: remove the NetworkManager `dns=none` drop-in (teardown).
pub const DNS_FILE_SELECTOR_NM_REMOVE: &str = "nm-dropin-remove";

/// Fixed path where the pre-fail-closed resolv.conf is stashed so teardown can
/// restore the host's original resolver configuration. Root-only (0o600). Lives
/// in the privileged helper's writable runtime directory (session-scoped tmpfs,
/// the right lifetime — the backup only feeds same-boot teardown; a reboot
/// re-runs bootstrap + enforce). On Linux that dir is `/run/rustynet` (the
/// helper's `ProtectSystem=strict` sandbox keeps `/etc` read-only except the
/// single `resolv.conf` inode, so a backup sibling in `/etc` is not writable);
/// on macOS it is `/private/var/run/rustynet`.
#[cfg(target_os = "linux")]
pub const RESOLV_CONF_FAILCLOSED_BACKUP_PATH: &str = "/run/rustynet/resolv.conf.failclosed.bak";
#[cfg(target_os = "macos")]
pub const RESOLV_CONF_FAILCLOSED_BACKUP_PATH: &str =
    "/private/var/run/rustynet/resolv.conf.failclosed.bak";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub const RESOLV_CONF_FAILCLOSED_BACKUP_PATH: &str = "/tmp/rustynet-resolv.conf.failclosed.bak";

/// The complete, fixed set of selectors the builtin accepts. Anything outside
/// this set is rejected at the privileged boundary, so callers can never name a
/// path or supply content of their own.
pub const DNS_FAILCLOSED_FILE_SELECTORS: [&str; 4] = [
    DNS_FILE_SELECTOR_RESOLV_APPLY,
    DNS_FILE_SELECTOR_RESOLV_RESTORE,
    DNS_FILE_SELECTOR_NM_APPLY,
    DNS_FILE_SELECTOR_NM_REMOVE,
];

/// True iff `selector` is exactly one of the four reviewed builtin operations.
/// The privileged-helper validator gates the builtin on this and nothing else.
pub fn is_valid_dns_failclosed_file_selector(selector: &str) -> bool {
    DNS_FAILCLOSED_FILE_SELECTORS.contains(&selector)
}

/// Execute the DNS fail-closed file operation named by `selector`. The
/// privileged boundary calls this for the `dns-failclosed-file` builtin after
/// [`is_valid_dns_failclosed_file_selector`] has accepted the selector. Performs
/// ONLY fixed-path, fixed-content writes; the selector is re-validated here as
/// defense in depth.
#[cfg(unix)]
pub(crate) fn apply_dns_failclosed_file(selector: &str) -> Result<(), String> {
    if !is_valid_dns_failclosed_file_selector(selector) {
        return Err(format!(
            "unsupported dns-failclosed-file selector: {selector:?}"
        ));
    }
    // The fail-closed resolver posture (loopback resolv.conf, optionally a
    // NetworkManager drop-in) applies to Linux and macOS. The builtin compiles
    // on every Unix (so the primitives can be unit-tested on the dev host) but
    // refuses to mutate host files on any other OS — the helper is the
    // privileged boundary.
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(
            "dns-failclosed-file operations are only supported on Linux and macOS".to_owned(),
        );
    }
    match selector {
        DNS_FILE_SELECTOR_RESOLV_APPLY => {
            // Back up the current resolv.conf into the helper runtime dir (a
            // writable dir, so the atomic backup works), then rewrite
            // /etc/resolv.conf to the loopback resolver.
            backup_file_once(
                Path::new(RESOLV_CONF_PATH),
                Path::new(RESOLV_CONF_FAILCLOSED_BACKUP_PATH),
            )?;
            write_loopback_resolv_conf(Path::new(RESOLV_CONF_PATH))
        }
        DNS_FILE_SELECTOR_RESOLV_RESTORE => restore_resolv_conf_from_backup(
            Path::new(RESOLV_CONF_PATH),
            Path::new(RESOLV_CONF_FAILCLOSED_BACKUP_PATH),
        ),
        // NetworkManager exists only on Linux; on macOS the daemon never
        // requests these (no NM), and they are a no-op-with-error if it does.
        DNS_FILE_SELECTOR_NM_APPLY => write_network_manager_dropin(),
        DNS_FILE_SELECTOR_NM_REMOVE => {
            remove_file_if_present(Path::new(NETWORK_MANAGER_DNS_DROPIN_PATH))
        }
        // Unreachable: the guard above already rejected unknown selectors.
        other => Err(format!(
            "unsupported dns-failclosed-file selector: {other:?}"
        )),
    }
}

#[cfg(not(unix))]
pub(crate) fn apply_dns_failclosed_file(selector: &str) -> Result<(), String> {
    let _ = selector;
    Err("dns-failclosed-file operations are only supported on Linux".to_owned())
}

/// Write the NetworkManager `dns=none` drop-in, creating `conf.d` only when
/// NetworkManager itself is installed. Refuses to materialise a drop-in (and the
/// directory tree) on a host with no NetworkManager — the daemon only requests
/// this when NM is present, and refusing here keeps the write meaningful.
#[cfg(unix)]
fn write_network_manager_dropin() -> Result<(), String> {
    let path = Path::new(NETWORK_MANAGER_DNS_DROPIN_PATH);
    let conf_d = path
        .parent()
        .ok_or_else(|| "NetworkManager drop-in path has no parent directory".to_owned())?;
    let nm_root = conf_d
        .parent()
        .ok_or_else(|| "NetworkManager drop-in path has no grandparent directory".to_owned())?;
    if !nm_root.is_dir() {
        return Err(format!(
            "NetworkManager is not installed ({} absent); refusing to create a drop-in",
            nm_root.display()
        ));
    }
    if !conf_d.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(conf_d).map_err(|err| format!("create {}: {err}", conf_d.display()))?;
        let _ = std::fs::set_permissions(conf_d, std::fs::Permissions::from_mode(0o755));
    }
    atomically_replace_file(path, network_manager_dns_none_dropin().as_bytes(), 0o644)
}

/// Atomically replace `path` with `contents` at `mode`. Security-critical: the
/// bytes go to a fresh temp file in the SAME directory opened `O_CREAT|O_EXCL`
/// (so a pre-planted temp symlink can never be followed), then `rename(2)`
/// swaps it over `path`. `rename` replaces the directory entry itself — if
/// `path` was a symlink, the symlink is replaced, never written *through*. The
/// final mode is pinned explicitly because the create mode is masked by umask.
#[cfg(unix)]
fn atomically_replace_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().ok_or_else(|| {
        format!(
            "refusing to write a path with no parent: {}",
            path.display()
        )
    })?;
    if !parent.is_dir() {
        return Err(format!(
            "parent directory missing for {}: {} is not a directory",
            path.display(),
            parent.display()
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "refusing to write a path with no file name: {}",
                path.display()
            )
        })?;
    let tmp = parent.join(format!(
        ".{file_name}.rustynet-dns.{}.tmp",
        std::process::id()
    ));

    // Best-effort sweep of a temp leaked by a crashed prior run; the O_EXCL open
    // below is the real guard against a hostile pre-plant.
    let _ = std::fs::remove_file(&tmp);

    let staged = (|| -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|err| format!("create temp file {}: {err}", tmp.display()))?;
        file.write_all(contents)
            .map_err(|err| format!("write temp file {}: {err}", tmp.display()))?;
        file.flush()
            .map_err(|err| format!("flush temp file {}: {err}", tmp.display()))?;
        file.sync_all()
            .map_err(|err| format!("fsync temp file {}: {err}", tmp.display()))?;
        // create_new's mode is masked by umask; pin the exact final mode.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))
            .map_err(|err| format!("set mode on temp file {}: {err}", tmp.display()))?;
        Ok(())
    })();
    if let Err(err) = staged {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }

    std::fs::rename(&tmp, path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        format!("atomically replace {}: {err}", path.display())
    })
}

/// Capture `src` into `backup` exactly once. Idempotent: an existing backup is
/// never clobbered, so a re-apply over our own fail-closed file cannot overwrite
/// the captured original. `std::fs::read` follows a systemd-resolved symlink to
/// record the effective resolver content; an absent source records an empty
/// backup so teardown stays well-defined.
#[cfg(unix)]
fn backup_file_once(src: &Path, backup: &Path) -> Result<(), String> {
    if backup.symlink_metadata().is_ok() {
        return Ok(());
    }
    match std::fs::read(src) {
        Ok(bytes) => atomically_replace_file(backup, &bytes, 0o600),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            atomically_replace_file(backup, b"", 0o600)
        }
        Err(err) => Err(format!("read {} for backup: {err}", src.display())),
    }
}

/// Write the loopback-resolver contents to `path` (the protected-mode
/// resolv.conf rewrite). Delegates to the OS-appropriate write strategy.
#[cfg(unix)]
fn write_loopback_resolv_conf(path: &Path) -> Result<(), String> {
    write_resolv_conf_bytes(path, loopback_resolv_conf_contents().as_bytes())
}

/// Write `bytes` to the resolv.conf `path`. The strategy differs by the helper's
/// OS sandbox: Linux runs `ProtectSystem=strict` with only the resolv.conf inode
/// writable (its parent `/etc` is read-only → no temp sibling for a rename), so
/// it writes in place with `O_NOFOLLOW`; macOS has a writable `/etc` and a
/// configd `resolv.conf` symlink, so an atomic temp+rename (which swaps the
/// symlink for a regular file, never writing through it) is both possible and
/// preferable.
#[cfg(target_os = "linux")]
fn write_resolv_conf_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    write_file_in_place_no_symlink(path, bytes)
}
#[cfg(target_os = "macos")]
fn write_resolv_conf_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomically_replace_file(path, bytes, 0o644)
}
// Other Unix (e.g. BSD): `Path` is in scope via the `#[cfg(unix)]` import, but
// resolv.conf ownership is unsupported. NOT compiled on Windows (non-Unix), where
// the whole builtin chain is the non-Unix stub and `Path` is not imported.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn write_resolv_conf_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let _ = (path, bytes);
    Err("resolv.conf write is only supported on Linux and macOS".to_owned())
}

/// Restore `path` from `backup`, then remove the backup. A missing backup is a
/// no-op (fail-closed: never disturb a resolver config we did not create). An
/// empty backup means the original was absent at apply time; the loopback file
/// is left in place (still fail-closed — mesh DNS only). Uses the same
/// OS-appropriate write strategy as the apply.
#[cfg(unix)]
fn restore_resolv_conf_from_backup(path: &Path, backup: &Path) -> Result<(), String> {
    if backup.symlink_metadata().is_err() {
        return Ok(());
    }
    let bytes =
        std::fs::read(backup).map_err(|err| format!("read backup {}: {err}", backup.display()))?;
    if !bytes.is_empty() {
        write_resolv_conf_bytes(path, &bytes)?;
    }
    remove_file_if_present(backup)
}

/// Rewrite an existing regular file's contents in place, refusing to follow a
/// final symlink (`O_NOFOLLOW`). Used for `/etc/resolv.conf`, whose parent
/// directory the helper's `ProtectSystem=strict` sandbox keeps read-only — so
/// the atomic temp+rename strategy (which needs a writable parent) is
/// unavailable and only the existing inode can be written. No `O_CREAT`: the
/// file must already exist (the bootstrap pins a regular-file resolv.conf), and
/// `O_NOFOLLOW` fail-closes rather than write through an unexpected symlink.
/// The single truncate+write of a tiny buffer is effectively atomic for readers.
///
/// Used by the Linux resolv.conf write path; on macOS the atomic temp+rename is
/// used instead, so this is exercised only by tests there (hence the dead-code
/// allow off-Linux).
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_file_in_place_no_symlink(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // `nix::libc` (not the bare `libc` crate, which is only a macOS-target
    // dependency here) so this resolves on every Unix target including the Linux
    // daemon build.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            format!(
                "open {} for in-place write (must be an existing regular file): {err}",
                path.display()
            )
        })?;
    file.write_all(contents)
        .map_err(|err| format!("write {}: {err}", path.display()))?;
    file.flush()
        .map_err(|err| format!("flush {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("fsync {}: {err}", path.display()))?;
    Ok(())
}

/// Remove `path` if present; absent is success. Uses `remove_file`, which
/// unlinks a symlink itself rather than its target.
#[cfg(unix)]
fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove {}: {err}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_name_is_generation_scoped_and_helper_owned() {
        let name = dns_redirect_table_name(1);
        assert_eq!(name, "rustynet_g1_dns");
        // Must be permitted by the privileged helper's owned-table check so the
        // add/delete commands pass without weakening the allowlist.
        assert!(
            name.starts_with("rustynet_g"),
            "DNS table must keep the rustynet_g prefix the helper already owns"
        );
    }

    #[test]
    fn apply_argvs_match_the_proven_redirect_shape() {
        let argvs = dns_redirect_nft_apply_argvs("rustynet_g1_dns", 53535);
        assert_eq!(
            argvs.len(),
            4,
            "expect: add table, add chain, udp rule, tcp rule"
        );

        // add table inet rustynet_g1_dns
        assert_eq!(argvs[0], vec!["add", "table", "inet", "rustynet_g1_dns"]);
        // nat hook output chain
        let chain = argvs[1].join(" ");
        assert!(
            chain.contains("type nat hook output priority dstnat"),
            "{chain}"
        );
        assert!(chain.contains("policy accept"), "{chain}");

        // udp redirect rule — the exact shape proven live on debian
        let udp = argvs[2].join(" ");
        assert_eq!(
            udp,
            "add rule inet rustynet_g1_dns dns_redirect meta l4proto udp ip daddr 127.0.0.1 udp dport 53 redirect to :53535"
        );
        // tcp companion (DNS falls back to TCP for large responses)
        let tcp = argvs[3].join(" ");
        assert!(tcp.contains("meta l4proto tcp"), "{tcp}");
        assert!(tcp.ends_with("tcp dport 53 redirect to :53535"), "{tcp}");

        // Every argv is an `add` verb (install-only; teardown deletes the table).
        for argv in &argvs {
            assert_eq!(argv[0].as_str(), "add", "{argv:?}");
        }
    }

    #[test]
    fn redirect_port_is_threaded_from_the_resolver_bind() {
        let argvs = dns_redirect_nft_apply_argvs("rustynet_g7_dns", 5333);
        assert!(argvs[2].join(" ").ends_with("redirect to :5333"));
        assert!(argvs[3].join(" ").ends_with("redirect to :5333"));
    }

    #[test]
    fn teardown_deletes_the_whole_table() {
        assert_eq!(
            dns_redirect_nft_teardown_argv("rustynet_g1_dns"),
            vec!["delete", "table", "inet", "rustynet_g1_dns"]
        );
    }

    #[test]
    fn resolv_conf_is_loopback_only() {
        let body = loopback_resolv_conf_contents();
        assert!(body.contains("nameserver 127.0.0.1"));
        // No off-host nameserver may appear — the fail-closed floor.
        assert!(!body.contains("1.1.1.1"));
        assert!(!body.contains("8.8.8.8"));
        // Must not point at the systemd-resolved stub (verifier rejects that
        // while systemd-resolved holds 127.0.0.53:53).
        assert!(!body.contains("127.0.0.53"));
    }

    #[test]
    fn network_manager_dropin_disables_nm_dns_management() {
        let body = network_manager_dns_none_dropin();
        assert!(body.contains("[main]"));
        assert!(body.contains("dns=none"));
    }

    // ---- file-write builtin: selector allowlist (cross-platform) ----------

    #[test]
    fn selector_allowlist_is_exactly_the_four_reviewed_operations() {
        assert!(is_valid_dns_failclosed_file_selector(
            DNS_FILE_SELECTOR_RESOLV_APPLY
        ));
        assert!(is_valid_dns_failclosed_file_selector(
            DNS_FILE_SELECTOR_RESOLV_RESTORE
        ));
        assert!(is_valid_dns_failclosed_file_selector(
            DNS_FILE_SELECTOR_NM_APPLY
        ));
        assert!(is_valid_dns_failclosed_file_selector(
            DNS_FILE_SELECTOR_NM_REMOVE
        ));
        assert_eq!(
            DNS_FAILCLOSED_FILE_SELECTORS.len(),
            4,
            "the reviewed selector set is fixed at four operations"
        );
    }

    #[test]
    fn selector_allowlist_rejects_everything_else() {
        for bad in [
            "",
            " resolv-conf-apply",
            "resolv-conf-apply ",
            "RESOLV-CONF-APPLY",
            "resolv-conf",
            "resolv-conf-apply\n",
            "resolv-conf-apply\0",
            "/etc/resolv.conf",
            "../../etc/shadow",
            "nameserver 8.8.8.8",
            "resolv-conf-apply;rm -rf /",
            "resolv-conf-apply resolv-conf-restore",
            DNS_FAILCLOSED_FILE_PROGRAM, // the program name is not a selector
        ] {
            assert!(
                !is_valid_dns_failclosed_file_selector(bad),
                "selector {bad:?} must be rejected"
            );
        }
    }

    // Selector validation only runs on the unix (`apply_dns_failclosed_file`)
    // path; on Windows the operation is blanket-unsupported ("only supported on
    // Linux") and never reaches selector parsing, so this assertion is unix-only.
    #[cfg(unix)]
    #[test]
    fn apply_rejects_unknown_selector_without_touching_the_filesystem() {
        let err = apply_dns_failclosed_file("not-a-real-selector").expect_err("must reject");
        assert!(err.contains("unsupported"), "{err}");
    }

    // ---- file-write builtin: filesystem primitives (Unix only) ------------

    #[cfg(unix)]
    mod fs_primitives {
        use super::super::{
            atomically_replace_file, backup_file_once, remove_file_if_present,
            restore_resolv_conf_from_backup, write_file_in_place_no_symlink,
        };
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

        fn mode_of(path: &std::path::Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        #[test]
        fn atomically_replace_writes_exact_bytes_and_mode() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            atomically_replace_file(&target, b"nameserver 127.0.0.1\n", 0o644).expect("write");
            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 127.0.0.1\n");
            assert_eq!(mode_of(&target), 0o644, "mode 0o{:o}", mode_of(&target));
        }

        #[test]
        fn atomically_replace_overwrites_existing_regular_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            std::fs::write(&target, b"nameserver 1.1.1.1\n").unwrap();
            atomically_replace_file(&target, b"nameserver 127.0.0.1\n", 0o644).expect("write");
            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 127.0.0.1\n");
        }

        /// THE security property: replacing a symlinked path swaps the symlink
        /// for a regular file and never writes *through* it to the link target.
        #[test]
        fn atomically_replace_does_not_follow_a_symlink_at_the_target() {
            let dir = tempfile::tempdir().expect("tempdir");
            let victim = dir.path().join("victim-do-not-touch");
            std::fs::write(&victim, b"ORIGINAL SECRET").unwrap();
            let link = dir.path().join("resolv.conf");
            symlink(&victim, &link).unwrap();

            atomically_replace_file(&link, b"nameserver 127.0.0.1\n", 0o644).expect("write");

            // The symlink target is untouched...
            assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL SECRET");
            // ...and the path is now a regular file holding our content.
            assert!(
                !std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "the symlink must have been replaced by a regular file"
            );
            assert_eq!(std::fs::read(&link).unwrap(), b"nameserver 127.0.0.1\n");
        }

        #[test]
        fn backup_is_idempotent_and_captures_the_true_original() {
            let dir = tempfile::tempdir().expect("tempdir");
            let src = dir.path().join("resolv.conf");
            let backup = dir.path().join("resolv.conf.bak");
            std::fs::write(&src, b"nameserver 1.1.1.1\n").unwrap();

            backup_file_once(&src, &backup).expect("first backup");
            // Mutate src as the apply step would, then back up again.
            std::fs::write(&src, b"nameserver 127.0.0.1\n").unwrap();
            backup_file_once(&src, &backup).expect("second backup is a no-op");

            // The backup still holds the FIRST (true original) content.
            assert_eq!(std::fs::read(&backup).unwrap(), b"nameserver 1.1.1.1\n");
            assert_eq!(mode_of(&backup), 0o600, "backup must be root-only");
        }

        #[test]
        fn backup_records_empty_when_source_absent() {
            let dir = tempfile::tempdir().expect("tempdir");
            let src = dir.path().join("resolv.conf");
            let backup = dir.path().join("resolv.conf.bak");
            backup_file_once(&src, &backup).expect("backup of absent source");
            assert_eq!(std::fs::read(&backup).unwrap(), b"");
        }

        #[test]
        fn in_place_write_rewrites_an_existing_regular_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            std::fs::write(&target, b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n").unwrap();
            // Same inode is reused (in-place); content (incl. shrink) is exact.
            let ino_before = std::fs::metadata(&target).unwrap().ino();
            write_file_in_place_no_symlink(&target, b"nameserver 127.0.0.1\n").expect("write");
            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 127.0.0.1\n");
            assert_eq!(
                std::fs::metadata(&target).unwrap().ino(),
                ino_before,
                "in-place write must reuse the existing inode"
            );
        }

        /// THE security property for the in-place writer: O_NOFOLLOW refuses to
        /// follow a final symlink, so the link target is never written through.
        #[test]
        fn in_place_write_refuses_to_follow_a_symlink() {
            let dir = tempfile::tempdir().expect("tempdir");
            let victim = dir.path().join("victim-do-not-touch");
            std::fs::write(&victim, b"ORIGINAL SECRET").unwrap();
            let link = dir.path().join("resolv.conf");
            symlink(&victim, &link).unwrap();

            let err = write_file_in_place_no_symlink(&link, b"nameserver 127.0.0.1\n")
                .expect_err("must refuse a symlink");
            assert!(err.contains("in-place write"), "{err}");
            // The symlink target is untouched.
            assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL SECRET");
        }

        #[test]
        fn in_place_write_refuses_an_absent_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("does-not-exist");
            // No O_CREAT: the file must already exist (the parent dir is
            // read-only under the helper sandbox, so creation is impossible).
            write_file_in_place_no_symlink(&target, b"x").expect_err("absent file must fail");
        }

        #[test]
        fn restore_round_trips_original_in_place_and_removes_backup() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            let backup = dir.path().join("resolv.conf.bak");
            std::fs::write(&target, b"nameserver 1.1.1.1\n").unwrap();

            backup_file_once(&target, &backup).expect("backup");
            write_file_in_place_no_symlink(&target, b"nameserver 127.0.0.1\n").expect("apply");
            restore_resolv_conf_from_backup(&target, &backup).expect("restore");

            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 1.1.1.1\n");
            assert!(!backup.exists(), "backup removed after restore");
        }

        #[test]
        fn restore_with_no_backup_leaves_the_current_file_untouched() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            let backup = dir.path().join("resolv.conf.bak");
            std::fs::write(&target, b"nameserver 127.0.0.1\n").unwrap();
            restore_resolv_conf_from_backup(&target, &backup).expect("no-op restore");
            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 127.0.0.1\n");
        }

        #[test]
        fn restore_with_empty_backup_leaves_managed_file_and_removes_backup() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("resolv.conf");
            let backup = dir.path().join("resolv.conf.bak");
            std::fs::write(&backup, b"").unwrap(); // original was absent at apply
            std::fs::write(&target, b"nameserver 127.0.0.1\n").unwrap();
            restore_resolv_conf_from_backup(&target, &backup).expect("restore");
            // Under read-only /etc the managed file cannot be unlinked, so the
            // loopback file is left (fail-closed); the backup is cleaned up.
            assert_eq!(std::fs::read(&target).unwrap(), b"nameserver 127.0.0.1\n");
            assert!(!backup.exists(), "backup removed");
        }

        #[test]
        fn remove_if_present_is_idempotent() {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("dropin.conf");
            std::fs::write(&target, b"[main]\ndns=none\n").unwrap();
            remove_file_if_present(&target).expect("first remove");
            remove_file_if_present(&target).expect("second remove is a no-op");
            assert!(!target.exists());
        }

        #[test]
        fn remove_if_present_unlinks_the_symlink_not_its_target() {
            let dir = tempfile::tempdir().expect("tempdir");
            let victim = dir.path().join("victim");
            std::fs::write(&victim, b"keep me").unwrap();
            let link = dir.path().join("dropin.conf");
            symlink(&victim, &link).unwrap();
            remove_file_if_present(&link).expect("remove symlink");
            assert!(!link.exists());
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        }
    }
}

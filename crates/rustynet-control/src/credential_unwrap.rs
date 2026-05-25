#![forbid(unsafe_code)]

//! Cross-platform credential unwrap for owner-signed membership mutations.
//!
//! The membership owner's signing-key passphrase is held in platform-
//! secure custody so the operator-staged `ops e2e-membership-...` verbs
//! can decrypt the owner key, sign an updated record, and apply the
//! mutation to the membership snapshot atomically. Custody per platform:
//!
//! - Linux: systemd-creds encrypted credential
//!   (`/etc/rustynet/credentials/signing_key_passphrase.cred`).
//! - macOS: Keychain item in the System keychain
//!   (service `signing_key_passphrase`, account
//!   `membership-owner-signing-key`).
//! - Windows: DPAPI-protected blob under
//!   `C:\ProgramData\RustyNet\secrets\` (LocalMachine scope so the
//!   service-account daemon and the Administrator-run CLI both unwrap
//!   the same plaintext).
//!
//! Each backend MUST:
//! - Validate the descriptor BEFORE invocation (no shell metacharacters
//!   reach `Command::arg`).
//! - Use argv-only `Command` invocation; no shell construction.
//! - Wrap plaintext output in `Zeroizing<Vec<u8>>` so it is wiped on
//!   drop (matches §3 control 4 of `documents/SecurityMinimumBar.md`).
//! - Fail closed with a precise error on missing credential, wrong
//!   format, or backend error (no silent success on empty output).
//!
//! Plaintext passphrase MUST NOT touch disk during unwrap; backends
//! read the plaintext via stdout/in-memory transfer only. Where the
//! consuming CLI needs a passphrase file for argv handoff to a helper
//! (`rustynet membership sign-update --signing-key-passphrase-file`),
//! the file lives under a 0700 directory created by the caller and is
//! shredded immediately afterwards.

use std::time::Duration;

use zeroize::Zeroizing;

/// Descriptor identifying a credential to unwrap.
///
/// `account` and `service` are validated by `validate()` against an
/// argv-safe character set so they cannot inject shell metacharacters
/// into the OS-helper invocation. The descriptor maps to:
/// - macOS: `security find-generic-password -a <account> -s <service> -w`
/// - Windows: a deterministic filename under
///   `C:\ProgramData\RustyNet\secrets\<service>.dpapi`
/// - Linux: `service` selects the credential basename, and the systemd
///   wrapper reads `<dir>/<service>.cred`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    pub account: String,
    pub service: String,
}

impl CredentialDescriptor {
    /// Reject descriptors that would let an attacker inject shell or
    /// path metacharacters into the backend invocation.
    ///
    /// The allowed character set is the intersection of:
    /// - macOS Keychain `service`/`account` name (RFC-style identifiers)
    /// - POSIX-safe argv tokens (no shell metacharacters)
    /// - DPAPI blob filenames (no path separators)
    pub fn validate(&self) -> Result<(), String> {
        validate_credential_token("account", &self.account)?;
        validate_credential_token("service", &self.service)?;
        Ok(())
    }
}

fn validate_credential_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!(
            "{label} exceeds 128 chars (got {} chars)",
            value.len()
        ));
    }
    if value.trim() != value {
        return Err(format!(
            "{label} must not contain leading or trailing whitespace",
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(format!(
            "{label} {value:?} contains characters unsafe for argv; \
             only ASCII alphanumerics and [. - _] are allowed",
        ));
    }
    Ok(())
}

/// Trait surface every credential-unwrap backend must implement.
///
/// Implementations fail closed on missing credentials, wrong format,
/// or backend error. Plaintext output is wrapped in `Zeroizing` so it
/// is wiped on drop, satisfying the in-memory zeroisation requirement
/// from §3 control 4 of `documents/SecurityMinimumBar.md`.
pub trait CredentialUnwrapBackend: Send + Sync {
    /// Backend identifier ("linux-systemd-creds", "macos-keychain",
    /// or "windows-dpapi"). Used in error messages and audit logs.
    fn name(&self) -> &'static str;

    /// Resolve the plaintext credential bytes for `descriptor`.
    ///
    /// The `timeout` bound is a wall-clock budget; backends that
    /// invoke external helpers (systemd-creds, security, the
    /// Windows DPAPI helper) MUST honour it so a stuck helper cannot
    /// wedge the caller indefinitely.
    fn unwrap_credential(
        &self,
        descriptor: &CredentialDescriptor,
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, String>;
}

// ─── Linux: systemd-creds backend ─────────────────────────────────────

/// Default Linux directory where reviewed systemd-creds blobs live.
pub const LINUX_DEFAULT_CREDENTIAL_DIR: &str = "/etc/rustynet/credentials";

/// Path to the Linux `systemd-creds` CLI. Hard-coded to the
/// distro-shipped absolute path so PATH manipulation cannot redirect
/// to a Trojan helper. Matches the macOS `MACOS_SECURITY_BIN`
/// convention.
///
/// Reviewed Linux installs ship `systemd-creds` at `/usr/bin/systemd-creds`
/// (Debian, Ubuntu, Fedora, RHEL). The path is pinned absolute so that
/// even if the daemon's effective `$PATH` carries a writable directory
/// ahead of `/usr/bin`, the backend still invokes the OS-shipped binary
/// and not an attacker-controlled shim.
#[cfg(target_os = "linux")]
pub const LINUX_SYSTEMD_CREDS_BIN: &str = "/usr/bin/systemd-creds";

/// Linux backend that decrypts a systemd-creds blob via
/// `systemd-creds decrypt --name=<service> <blob_path> -`.
///
/// The `--name=<name>` flag is the encrypted-credential name baked
/// into the blob; supplying it lets `systemd-creds` verify the blob
/// was minted for the expected purpose and not swapped on disk. The
/// trailing `-` writes plaintext to stdout so no plaintext file is
/// produced.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LinuxSystemdCredsBackend {
    credential_dir: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxSystemdCredsBackend {
    /// Construct a backend that reads encrypted blobs from
    /// `LINUX_DEFAULT_CREDENTIAL_DIR`.
    pub fn new() -> Self {
        Self {
            credential_dir: std::path::PathBuf::from(LINUX_DEFAULT_CREDENTIAL_DIR),
        }
    }

    /// Construct a backend that reads encrypted blobs from `credential_dir`.
    ///
    /// Used by tests to point at a per-test fixture directory without
    /// requiring root permissions on `/etc/rustynet/credentials`.
    pub fn with_dir(credential_dir: std::path::PathBuf) -> Self {
        Self { credential_dir }
    }

    pub(crate) fn build_argv(
        &self,
        descriptor: &CredentialDescriptor,
    ) -> Result<Vec<std::ffi::OsString>, String> {
        descriptor.validate()?;
        let blob_path = self
            .credential_dir
            .join(format!("{}.cred", descriptor.service));
        Ok(vec![
            std::ffi::OsString::from("decrypt"),
            std::ffi::OsString::from(format!("--name={}", descriptor.service)),
            blob_path.into_os_string(),
            std::ffi::OsString::from("-"),
        ])
    }
}

#[cfg(target_os = "linux")]
impl Default for LinuxSystemdCredsBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl CredentialUnwrapBackend for LinuxSystemdCredsBackend {
    fn name(&self) -> &'static str {
        "linux-systemd-creds"
    }

    fn unwrap_credential(
        &self,
        descriptor: &CredentialDescriptor,
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let argv = self.build_argv(descriptor)?;
        let blob_path = self
            .credential_dir
            .join(format!("{}.cred", descriptor.service));
        if !blob_path.is_file() {
            return Err(format!(
                "linux-systemd-creds: blob missing at {}",
                blob_path.display()
            ));
        }
        // Fail closed if the reviewed absolute helper path is missing.
        // PATH-based discovery is forbidden here (CWE-426): an attacker
        // who controls a writable directory earlier in $PATH could
        // otherwise substitute their own `systemd-creds` and read the
        // plaintext passphrase.
        if !std::path::Path::new(LINUX_SYSTEMD_CREDS_BIN).is_file() {
            return Err(format!(
                "linux-systemd-creds: required helper missing at {LINUX_SYSTEMD_CREDS_BIN}",
            ));
        }
        run_helper_and_capture(LINUX_SYSTEMD_CREDS_BIN, &argv, timeout)
    }
}

// ─── macOS: Keychain backend ──────────────────────────────────────────

/// Path to the macOS `security` CLI. Hard-coded to the OS-shipped
/// binary so PATH manipulation cannot redirect to a Trojan helper.
#[cfg(target_os = "macos")]
pub const MACOS_SECURITY_BIN: &str = "/usr/bin/security";

/// macOS System keychain path. The launchd-managed daemon has no user
/// session, so System keychain (not user keychain) is the lookup target.
#[cfg(target_os = "macos")]
pub const MACOS_SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

/// macOS backend that resolves a generic-password Keychain item via
/// `/usr/bin/security find-generic-password -a <account> -s <service> -w
/// /Library/Keychains/System.keychain`.
///
/// `-w` writes the password to stdout (no plaintext file). The
/// `System.keychain` argument forces lookup in the system keychain so
/// service-account runs work without a GUI session.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct MacosKeychainBackend;

#[cfg(target_os = "macos")]
impl MacosKeychainBackend {
    pub fn new() -> Self {
        Self
    }

    pub(crate) fn build_argv(
        &self,
        descriptor: &CredentialDescriptor,
    ) -> Result<Vec<std::ffi::OsString>, String> {
        descriptor.validate()?;
        Ok(vec![
            std::ffi::OsString::from("find-generic-password"),
            std::ffi::OsString::from("-a"),
            std::ffi::OsString::from(&descriptor.account),
            std::ffi::OsString::from("-s"),
            std::ffi::OsString::from(&descriptor.service),
            std::ffi::OsString::from("-w"),
            std::ffi::OsString::from(MACOS_SYSTEM_KEYCHAIN_PATH),
        ])
    }
}

#[cfg(target_os = "macos")]
impl Default for MacosKeychainBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl CredentialUnwrapBackend for MacosKeychainBackend {
    fn name(&self) -> &'static str {
        "macos-keychain"
    }

    fn unwrap_credential(
        &self,
        descriptor: &CredentialDescriptor,
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let argv = self.build_argv(descriptor)?;
        // `security` prints the password followed by a newline.
        let mut value = run_helper_and_capture(MACOS_SECURITY_BIN, &argv, timeout)?;
        if value.last() == Some(&b'\n') {
            // Pop the trailing newline added by `security -w`; this
            // matches the encoding the existing key_material macOS
            // load path expects.
            let popped = value.pop();
            debug_assert_eq!(popped, Some(b'\n'));
        }
        if value.is_empty() {
            return Err(
                "macos-keychain: security returned an empty password (item missing or empty)"
                    .to_string(),
            );
        }
        Ok(value)
    }
}

// ─── Windows: DPAPI backend ───────────────────────────────────────────

/// Default Windows directory where reviewed DPAPI blobs live.
#[cfg(target_os = "windows")]
pub const WINDOWS_DEFAULT_SECRET_DIR: &str = r"C:\ProgramData\RustyNet\secrets";

/// Windows backend that unwraps a DPAPI-protected blob via the
/// in-process `rustynet_windows_native::dpapi_unprotect` helper.
///
/// The blob is expected to live at
/// `<secret_dir>\<service>.dpapi`, encoded with the
/// `RNYDPAPI` reviewed-blob magic (matching the existing WireGuard
/// passphrase blob shape in `crates/rustynetd/src/key_material.rs`).
/// DPAPI scope is `LocalMachine`, so a blob written by the operator
/// during install can be unwrapped both by the daemon service
/// account and by the Administrator-run CLI.
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsDpapiBackend {
    secret_dir: std::path::PathBuf,
}

#[cfg(target_os = "windows")]
impl WindowsDpapiBackend {
    pub fn new() -> Self {
        Self {
            secret_dir: std::path::PathBuf::from(WINDOWS_DEFAULT_SECRET_DIR),
        }
    }

    pub fn with_dir(secret_dir: std::path::PathBuf) -> Self {
        Self { secret_dir }
    }

    pub(crate) fn blob_path(
        &self,
        descriptor: &CredentialDescriptor,
    ) -> Result<std::path::PathBuf, String> {
        descriptor.validate()?;
        Ok(self
            .secret_dir
            .join(format!("{}.dpapi", descriptor.service)))
    }
}

#[cfg(target_os = "windows")]
impl Default for WindowsDpapiBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl CredentialUnwrapBackend for WindowsDpapiBackend {
    fn name(&self) -> &'static str {
        "windows-dpapi"
    }

    /// Honour the `timeout` contract from the trait docstring by
    /// running the in-process DPAPI unprotect on a worker thread and
    /// joining via a bounded `recv_timeout`. On timeout the worker
    /// continues until the syscall returns but the result is dropped
    /// in the channel, which runs `Zeroizing::drop` on the plaintext
    /// before the bytes escape; the caller sees a precise timeout
    /// error.
    fn unwrap_credential(
        &self,
        descriptor: &CredentialDescriptor,
        timeout: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let blob_path = self.blob_path(descriptor)?;
        if !blob_path.is_file() {
            return Err(format!(
                "windows-dpapi: blob missing at {}",
                blob_path.display()
            ));
        }
        let (tx, rx) = std::sync::mpsc::channel::<Result<Zeroizing<Vec<u8>>, String>>();
        let worker_blob_path = blob_path.clone();
        // Detach the worker; we never join it. If the syscall outlives
        // our `recv_timeout` budget the result lands in the channel,
        // the receiving end drops on scope exit, and `Zeroizing::drop`
        // wipes the plaintext before it can leak.
        let _ = std::thread::Builder::new()
            .name("windows-dpapi-unwrap".to_owned())
            .spawn(move || {
                let result = unwrap_dpapi_blob(&worker_blob_path);
                // Ignore send error: receiver may have timed out and
                // dropped the channel. The result `Zeroizing` then
                // drops here, wiping any plaintext that was produced.
                let _ = tx.send(result);
            })
            .map_err(|err| format!("windows-dpapi: failed to spawn worker thread: {err}"))?;
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
                "windows-dpapi: unwrap of {} exceeded {timeout:?} timeout",
                blob_path.display()
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(format!(
                "windows-dpapi: worker thread exited without delivering a result for {}",
                blob_path.display()
            )),
        }
    }
}

/// In-process DPAPI unwrap. Factored out of the trait impl so the
/// worker thread that honours the timeout contract can call it
/// without re-implementing the envelope-strip + newline-trim path.
#[cfg(target_os = "windows")]
fn unwrap_dpapi_blob(blob_path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw = std::fs::read(blob_path)
        .map_err(|err| format!("windows-dpapi: read {} failed: {err}", blob_path.display()))?;
    let protected_zeroizing = Zeroizing::new(raw);
    let protected = strip_dpapi_envelope(protected_zeroizing.as_slice(), blob_path)?;
    let plaintext = rustynet_windows_native::dpapi_unprotect(protected).map_err(|err| {
        format!(
            "windows-dpapi: unprotect {} failed: {err}",
            blob_path.display()
        )
    })?;
    drop(protected_zeroizing);
    if plaintext.is_empty() {
        return Err(format!(
            "windows-dpapi: unwrap produced empty plaintext for {}",
            blob_path.display()
        ));
    }
    // Trim trailing newline (if any) so callers see exactly the
    // passphrase bytes that were sealed.
    let mut zeroizing = Zeroizing::new(plaintext);
    if zeroizing.last() == Some(&b'\n') {
        zeroizing.pop();
    }
    Ok(zeroizing)
}

/// Verify the reviewed DPAPI envelope (matches the WireGuard passphrase
/// blob in `crates/rustynetd/src/key_material.rs`) and return the inner
/// CryptProtectData blob. Layout:
///   magic    : 8 bytes = b"RNYDPAPI"
///   version  : 1 byte  = 0x01
///   reserved : 1 byte  = 0x00
///   length   : 4 bytes (big-endian u32) = inner blob length
///   data     : <length> bytes = CryptProtectData output
#[cfg(target_os = "windows")]
fn strip_dpapi_envelope<'a>(blob: &'a [u8], path: &std::path::Path) -> Result<&'a [u8], String> {
    const MAGIC: &[u8; 8] = b"RNYDPAPI";
    const VERSION: u8 = 1;
    let header_len = MAGIC.len() + 1 + 1 + 4;
    if blob.len() < header_len {
        return Err(format!(
            "windows-dpapi: {} is shorter than the reviewed RNYDPAPI envelope (got {} bytes)",
            path.display(),
            blob.len()
        ));
    }
    if !blob.starts_with(MAGIC) {
        return Err(format!(
            "windows-dpapi: {} does not start with reviewed RNYDPAPI magic",
            path.display()
        ));
    }
    let version = blob[MAGIC.len()];
    if version != VERSION {
        return Err(format!(
            "windows-dpapi: {} uses unsupported RNYDPAPI version {version}",
            path.display()
        ));
    }
    let length_offset = MAGIC.len() + 2;
    let declared_len = u32::from_be_bytes([
        blob[length_offset],
        blob[length_offset + 1],
        blob[length_offset + 2],
        blob[length_offset + 3],
    ]) as usize;
    let data_offset = length_offset + 4;
    let actual_len = blob.len() - data_offset;
    if actual_len != declared_len {
        return Err(format!(
            "windows-dpapi: {} envelope length mismatch (declared {declared_len}, actual {actual_len})",
            path.display()
        ));
    }
    Ok(&blob[data_offset..])
}

// ─── Argv-only helper-runner ──────────────────────────────────────────

/// Spawn `program` with `argv`, wait up to `timeout`, capture stdout.
///
/// Stdin is set to `Stdio::null()` so a hostile helper cannot block
/// waiting on input. Stderr is captured and folded into the error
/// message on failure (with secret values absent from stderr by
/// design — `systemd-creds`/`security`/the DPAPI helper write the
/// secret to stdout only).
///
/// The returned `Zeroizing<Vec<u8>>` is wiped on drop so a transient
/// failure between unwrap and consumption does not leave plaintext
/// in the caller's stack.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_helper_and_capture(
    program: &str,
    argv: &[std::ffi::OsString],
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::process::{Command, Stdio};

    let start = std::time::Instant::now();
    let mut child = Command::new(program)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("{program}: failed to spawn: {err}"))?;

    // Poll for child exit, honouring `timeout`. We avoid the
    // `wait-timeout` crate dependency so the build stays minimal;
    // a 25 ms poll interval keeps p99 latency under 50 ms while
    // not burning CPU for a multi-second timeout.
    let poll_interval = Duration::from_millis(25);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{program}: helper exceeded {timeout:?} timeout"));
                }
                std::thread::sleep(poll_interval);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{program}: wait failed: {err}"));
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("{program}: wait_with_output failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(format!(
            "{program}: helper exited with status {code}: {stderr}"
        ));
    }
    let stdout = output.stdout;
    Ok(Zeroizing::new(stdout))
}

// ─── Default-credential helpers for the membership owner signing key ──

/// Canonical descriptor for the membership-owner signing-key passphrase.
///
/// The membership-mutation ops verbs use this descriptor to fetch the
/// passphrase needed to decrypt `membership.owner.key` and sign an
/// update record.
pub fn membership_signing_key_passphrase_descriptor() -> CredentialDescriptor {
    // Account + service map to:
    //   macOS:   keychain item (service=signing_key_passphrase,
    //                           account=membership-owner-signing-key)
    //   Linux:   /etc/rustynet/credentials/signing_key_passphrase.cred
    //   Windows: C:\ProgramData\RustyNet\secrets\signing_key_passphrase.dpapi
    //
    // The Linux service string matches the legacy systemd-creds
    // credential name (`signing_key_passphrase`) so existing operator
    // playbooks and the pre-Phase-22 `e2e-bootstrap-host` artifacts
    // continue to work without re-provisioning.
    CredentialDescriptor {
        account: "membership-owner-signing-key".to_owned(),
        service: "signing_key_passphrase".to_owned(),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_validation_rejects_injection_vectors() {
        let unsafe_accounts: &[&str] = &[
            "",
            " ",
            "a b",
            "a;rm -rf /",
            "a\nb",
            "a$b",
            "a&b",
            "../etc/passwd",
            "/usr/local/etc/rustynet",
            "a|b",
            "a`b`",
            "a\"b",
            "a'b",
            "a\\b",
            "a:b",       // colon: blocked because Windows interprets <drive>: paths
            "a@example", // @ blocked: keychain item names may not contain @
        ];
        for bad in unsafe_accounts {
            let descriptor = CredentialDescriptor {
                account: (*bad).to_string(),
                service: "service".to_owned(),
            };
            assert!(
                descriptor.validate().is_err(),
                "must reject account {bad:?}"
            );
        }
        for bad in unsafe_accounts {
            let descriptor = CredentialDescriptor {
                account: "account".to_owned(),
                service: (*bad).to_string(),
            };
            assert!(
                descriptor.validate().is_err(),
                "must reject service {bad:?}"
            );
        }
        // Oversize
        let huge: String = "a".repeat(200);
        let descriptor = CredentialDescriptor {
            account: huge,
            service: "service".to_owned(),
        };
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn descriptor_validation_accepts_reviewed_tokens() {
        let descriptor = CredentialDescriptor {
            account: "membership-owner-signing-key".to_owned(),
            service: "signing_key_passphrase".to_owned(),
        };
        assert!(descriptor.validate().is_ok());

        // Pin the production-canonical macOS descriptor pair so the
        // validator never tightens to reject the descriptor the
        // membership-mutation ops verbs actually use.
        // Phase 27 reviewer fold-in (MED 2): the previous fixture
        // used `net.rustynet.signing-key-passphrase`, a service name
        // no production code path ever generates (the canonical
        // service is `signing_key_passphrase`, set by
        // `membership_signing_key_passphrase_descriptor`).
        let descriptor = CredentialDescriptor {
            account: "membership-owner-signing-key".to_owned(),
            service: "signing_key_passphrase".to_owned(),
        };
        assert!(descriptor.validate().is_ok());
    }

    #[test]
    fn default_descriptor_is_reviewed_and_valid() {
        let descriptor = membership_signing_key_passphrase_descriptor();
        assert!(descriptor.validate().is_ok());
        assert_eq!(descriptor.account, "membership-owner-signing-key");
        assert_eq!(descriptor.service, "signing_key_passphrase");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn source_pins_windows_dpapi_backend_contract_on_non_windows_hosts() {
        let source = include_str!("credential_unwrap.rs");
        let implementation = source
            .split("// ─── Tests")
            .next()
            .expect("implementation section must precede tests");
        for expected in [
            "pub struct WindowsDpapiBackend",
            "WINDOWS_DEFAULT_SECRET_DIR",
            "signing_key_passphrase.dpapi",
            "rustynet_windows_native::dpapi_unprotect",
            "strip_dpapi_envelope",
            "RNYDPAPI",
            "recv_timeout(timeout)",
        ] {
            assert!(
                implementation.contains(expected),
                "Windows DPAPI backend contract missing source marker: {expected}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_systemd_creds_path_is_absolute_and_canonical() {
        // Pin the reviewed Linux helper path so a future refactor
        // cannot silently revert to PATH-based lookup (CWE-426).
        // Matches `MACOS_SECURITY_BIN` pattern.
        assert_eq!(LINUX_SYSTEMD_CREDS_BIN, "/usr/bin/systemd-creds");
        assert!(
            LINUX_SYSTEMD_CREDS_BIN.starts_with('/'),
            "linux systemd-creds helper path must be absolute, got {LINUX_SYSTEMD_CREDS_BIN}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_argv_uses_decrypt_name_pair() {
        let backend = LinuxSystemdCredsBackend::with_dir(std::path::PathBuf::from(
            "/etc/rustynet/credentials",
        ));
        let descriptor = CredentialDescriptor {
            account: "ignored".to_owned(),
            service: "signing_key_passphrase".to_owned(),
        };
        let argv = backend.build_argv(&descriptor).expect("argv builds");
        assert_eq!(argv[0], "decrypt");
        assert_eq!(argv[1], "--name=signing_key_passphrase");
        assert_eq!(
            std::path::Path::new(&argv[2]),
            std::path::Path::new("/etc/rustynet/credentials/signing_key_passphrase.cred"),
        );
        assert_eq!(argv[3], "-");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_argv_rejects_injection_in_service() {
        let backend = LinuxSystemdCredsBackend::new();
        let descriptor = CredentialDescriptor {
            account: "account".to_owned(),
            service: "signing;rm -rf /".to_owned(),
        };
        let err = backend
            .build_argv(&descriptor)
            .expect_err("injection must reject");
        assert!(err.contains("service"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_backend_fails_closed_when_blob_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = LinuxSystemdCredsBackend::with_dir(dir.path().to_path_buf());
        let descriptor = CredentialDescriptor {
            account: "account".to_owned(),
            service: "missing_blob".to_owned(),
        };
        let err = backend
            .unwrap_credential(&descriptor, Duration::from_secs(1))
            .expect_err("missing blob must fail closed");
        assert!(err.contains("missing"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_argv_pins_system_keychain() {
        // Phase 27 reviewer fold-in (MED 2): the previous fixture
        // exercised `net.rustynet.signing-key-passphrase`, a service
        // name no production code path ever generates. Pin the
        // production descriptor from
        // `membership_signing_key_passphrase_descriptor` so the test
        // exercises the exact argv the membership-mutation ops verbs
        // build at runtime.
        let backend = MacosKeychainBackend::new();
        let descriptor = membership_signing_key_passphrase_descriptor();
        let argv = backend.build_argv(&descriptor).expect("argv builds");
        assert_eq!(argv[0], "find-generic-password");
        assert_eq!(argv[1], "-a");
        assert_eq!(argv[2], "membership-owner-signing-key");
        assert_eq!(argv[3], "-s");
        assert_eq!(argv[4], "signing_key_passphrase");
        assert_eq!(argv[5], "-w");
        assert_eq!(argv[6], MACOS_SYSTEM_KEYCHAIN_PATH);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_argv_rejects_injection_in_account() {
        let backend = MacosKeychainBackend::new();
        let descriptor = CredentialDescriptor {
            account: "a; sudo rm -rf /".to_owned(),
            service: "service".to_owned(),
        };
        let err = backend
            .build_argv(&descriptor)
            .expect_err("injection must reject");
        assert!(err.contains("account"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_fails_closed_when_keychain_item_missing() {
        // Pinned against the reviewed `/usr/bin/security` behaviour:
        //   $ /usr/bin/security find-generic-password \
        //       -a __nonexistent_test_account__ \
        //       -s __nonexistent_test_service__ \
        //       /Library/Keychains/System.keychain ; echo $?
        //   security: SecKeychainSearchCopyNext: The specified item
        //   could not be found in the keychain.
        //   44
        //
        // Exit 44 is `errSecItemNotFound`. The substring matches the
        // canonical Security framework error text. Pinning both
        // signals keeps the assertion meaningful even if Apple
        // reworks the error wording (we keep failing on the exit
        // code) or changes the exit code (we keep failing on the
        // text). The previous loose-substring assertion accepted
        // the literal "security" (the program name appears in every
        // error message) and would silently pass on an unrelated
        // failure mode.
        // Phase 27 reviewer fold-in (MED 2): the previous fixture
        // used `net.rustynet.signing-key-passphrase-test-missing`, a
        // service name disconnected from the production descriptor.
        // Use the production service name with a known-bad account
        // suffix so the negative test exercises the exact descriptor
        // shape the membership-mutation ops verbs build at runtime
        // (`signing_key_passphrase`).
        let backend = MacosKeychainBackend::new();
        let descriptor = CredentialDescriptor {
            account: "membership-owner-signing-key-test-missing".to_owned(),
            service: "signing_key_passphrase".to_owned(),
        };
        let err = backend
            .unwrap_credential(&descriptor, Duration::from_secs(2))
            .expect_err("missing keychain item must fail closed");
        let exit_code_pinned = err.contains("status 44");
        let canonical_text_pinned = err.contains("could not be found in the keychain");
        assert!(
            exit_code_pinned && canonical_text_pinned,
            "expected fail-closed error to carry both exit-code 44 and canonical \
             \"could not be found in the keychain\" text, got: {err}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_backend_blob_path_is_deterministic() {
        let backend = WindowsDpapiBackend::with_dir(std::path::PathBuf::from(
            r"C:\ProgramData\RustyNet\secrets",
        ));
        let descriptor = CredentialDescriptor {
            account: "ignored".to_owned(),
            service: "signing_key_passphrase".to_owned(),
        };
        let path = backend.blob_path(&descriptor).expect("blob path");
        assert_eq!(
            path,
            std::path::PathBuf::from(
                r"C:\ProgramData\RustyNet\secrets\signing_key_passphrase.dpapi"
            )
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_backend_blob_path_rejects_injection_in_service() {
        let backend = WindowsDpapiBackend::new();
        let descriptor = CredentialDescriptor {
            account: "account".to_owned(),
            service: "..\\..\\Windows\\System32".to_owned(),
        };
        let err = backend
            .blob_path(&descriptor)
            .expect_err("path traversal must reject");
        assert!(err.contains("service"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_backend_fails_closed_when_blob_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = WindowsDpapiBackend::with_dir(dir.path().to_path_buf());
        let descriptor = CredentialDescriptor {
            account: "account".to_owned(),
            service: "missing_dpapi".to_owned(),
        };
        let err = backend
            .unwrap_credential(&descriptor, Duration::from_secs(1))
            .expect_err("missing blob must fail closed");
        assert!(err.contains("missing"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_strip_envelope_rejects_wrong_magic() {
        let blob = b"NOTMAGIC\x01\x00\x00\x00\x00\x00\xff";
        let path = std::path::Path::new(r"C:\dummy.dpapi");
        let err = strip_dpapi_envelope(blob, path).expect_err("wrong magic must reject");
        assert!(err.contains("RNYDPAPI magic"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_strip_envelope_rejects_length_mismatch() {
        // length=0x10 declared, but data is only 1 byte
        let blob = b"RNYDPAPI\x01\x00\x00\x00\x00\x10\xff";
        let path = std::path::Path::new(r"C:\dummy.dpapi");
        let err = strip_dpapi_envelope(blob, path).expect_err("length mismatch must reject");
        assert!(err.contains("length mismatch"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_strip_envelope_accepts_well_formed_blob() {
        // header (14 bytes) + 4 bytes of declared protected payload
        let mut blob = Vec::new();
        blob.extend_from_slice(b"RNYDPAPI");
        blob.push(0x01);
        blob.push(0x00);
        blob.extend_from_slice(&4u32.to_be_bytes());
        blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let path = std::path::Path::new(r"C:\dummy.dpapi");
        let inner = strip_dpapi_envelope(&blob, path).expect("well-formed blob");
        assert_eq!(inner, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}

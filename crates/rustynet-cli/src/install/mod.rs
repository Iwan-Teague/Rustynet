//! The `rustynet install` engine.
//!
//! Turns a bare macOS / Windows / Linux machine into a hardened rustynet node in
//! one command. This module is the engine spine: request parsing, host detection
//! (`rustynet_sysinfo::host_facts`), input validation, and the ordered install
//! PLAN. The per-step live execution (acquire binaries, provision prereqs, place
//! binaries + identities, key custody, trust-anchor delivery, service
//! registration) is delegated to the existing hardened `ops install-*` /
//! `install-trust-material` / `rustynetd key init` verbs and lands incrementally;
//! until a step is wired, live execution fails closed rather than half-install.
//!
//! `--dry-run` is fully functional today: it detects the host and prints exactly
//! what a live run would do, per OS, mutating nothing.

mod acquire;
mod common;
mod live_linux;
mod live_macos;
mod preflight;

use rustynet_sysinfo::{HostFacts, OsFamily, PkgFamily, host_facts};
use std::path::PathBuf;

/// The node role the installed service should take. Maps to the existing
/// per-OS `ops install-*` service verbs at registration time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRole {
    Node,
    Relay,
    Exit,
    Anchor,
}

impl InstallRole {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "node" | "client" => Ok(Self::Node),
            "relay" => Ok(Self::Relay),
            "exit" => Ok(Self::Exit),
            "anchor" => Ok(Self::Anchor),
            other => Err(format!(
                "unknown --role '{other}' (expected node|relay|exit|anchor)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Relay => "relay",
            Self::Exit => "exit",
            Self::Anchor => "anchor",
        }
    }
}

/// Where the installer gets the rustynet binaries. Pluggable so the engine works
/// before the signed-release pipeline exists and lands verified-download as the
/// default once it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionMode {
    /// Fetch from the signed release and verify each binary against the pinned
    /// manifest key before use (SR-017). The default.
    VerifiedDownload,
    /// Use locally-provided prebuilt binaries in this directory (still
    /// manifest-verified if a manifest is present).
    FromDir(PathBuf),
    /// Build from source on the target (dev/fallback; needs the toolchain).
    BuildFromSource,
}

impl AcquisitionMode {
    fn label(&self) -> String {
        match self {
            Self::VerifiedDownload => {
                "verified-download (signed release, pinned-key verified)".to_owned()
            }
            Self::FromDir(p) => format!("from-dir {}", p.display()),
            Self::BuildFromSource => "build-from-source (dev/fallback)".to_owned(),
        }
    }
}

/// The trust-anchor (membership owner public key) to deliver per SecurityMinimumBar
/// §6.B: an owner-pubkey file and its expected sha256 thumbprint to verify after
/// placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorSource {
    pub owner_key_file: Option<PathBuf>,
    pub expected_thumbprint: Option<String>,
}

/// A fully-resolved install request — the single funnel both the interactive
/// wizard and `--unattended` argv parsing converge on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    pub role: InstallRole,
    pub acquisition: AcquisitionMode,
    pub trust_anchor: TrustAnchorSource,
    /// The node identity (`RUSTYNET_NODE_ID`). Defaults to the hostname when the
    /// live install runs; `--node-id` overrides.
    pub node_id: Option<String>,
    pub unattended: bool,
    pub dry_run: bool,
    pub uninstall: bool,
}

impl InstallRequest {
    /// Parse `rustynet install` flags. Enforces mutually-exclusive acquisition
    /// overrides and absolute paths; leaves interactive-vs-unattended completion
    /// of optional fields to the caller (the wizard is a follow-up).
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut role = InstallRole::Node;
        let mut from_dir: Option<PathBuf> = None;
        let mut build_from_source = false;
        let mut owner_key_file: Option<PathBuf> = None;
        let mut expected_thumbprint: Option<String> = None;
        let mut node_id: Option<String> = None;
        let mut unattended = false;
        let mut dry_run = false;
        let mut uninstall = false;

        let mut i = 0;
        while i < args.len() {
            let arg = args[i].clone();
            match arg.as_str() {
                "--role" => role = InstallRole::parse(&next_value(args, &mut i, "--role")?)?,
                "--from-dir" => {
                    from_dir = Some(require_absolute(
                        &next_value(args, &mut i, "--from-dir")?,
                        "--from-dir",
                    )?)
                }
                "--build-from-source" => build_from_source = true,
                "--owner-key-file" => {
                    owner_key_file = Some(require_absolute(
                        &next_value(args, &mut i, "--owner-key-file")?,
                        "--owner-key-file",
                    )?)
                }
                "--owner-key-thumbprint" => {
                    expected_thumbprint = Some(next_value(args, &mut i, "--owner-key-thumbprint")?)
                }
                "--node-id" => node_id = Some(next_value(args, &mut i, "--node-id")?),
                "--unattended" => unattended = true,
                "--dry-run" => dry_run = true,
                "--uninstall" => uninstall = true,
                other => return Err(format!("unknown flag for `rustynet install`: {other}")),
            }
            i += 1;
        }

        if from_dir.is_some() && build_from_source {
            return Err("--from-dir and --build-from-source are mutually exclusive".to_owned());
        }
        let acquisition = match (from_dir, build_from_source) {
            (Some(dir), false) => AcquisitionMode::FromDir(dir),
            (None, true) => AcquisitionMode::BuildFromSource,
            (None, false) => AcquisitionMode::VerifiedDownload,
            (Some(_), true) => unreachable!("guarded above"),
        };

        Ok(Self {
            role,
            acquisition,
            trust_anchor: TrustAnchorSource {
                owner_key_file,
                expected_thumbprint,
            },
            node_id,
            unattended,
            dry_run,
            uninstall,
        })
    }
}

fn require_absolute(value: &str, flag: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{flag} must be an absolute path (got '{value}')"));
    }
    Ok(path)
}

/// Advance `*i` to the next argv slot and return it as the value for `name`.
fn next_value(args: &[String], i: &mut usize, name: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

/// Engine entry point. Detects the host, validates the request against it, and
/// builds the ordered plan. `--dry-run` renders the plan (no mutation). A live
/// run currently fails closed: the OS-mutating steps are delegated to the
/// existing hardened verbs and are wired in follow-up increments.
pub fn run(req: InstallRequest) -> Result<String, String> {
    let facts = host_facts();
    validate_host(&facts)?;
    let triple = facts.target_triple().ok_or_else(|| {
        format!(
            "no published rustynet build for this host ({:?} / {}); use --build-from-source",
            facts.family, facts.arch
        )
    })?;
    validate_request(&req)?;

    let plan = build_plan(&req, &facts, triple);
    let rendered = render_plan(&req, &facts, triple, &plan);

    if req.dry_run {
        return Ok(rendered);
    }
    if req.uninstall {
        return Err(format!(
            "{rendered}\n\nlive uninstall is not yet wired; it lands with the install mutation steps."
        ));
    }

    // Live install. Elevation first (never self-elevate), then acquire, then the
    // OS-specific install. Steps are wired incrementally; execution fail-closes
    // where a step is not yet landed rather than half-installing.
    preflight::require_elevation(facts.family)?;
    let ext = binary_ext(facts.family);
    let staging =
        std::env::temp_dir().join(format!("rustynet-install-staging-{}", std::process::id()));
    let acquired = acquire::acquire(&req.acquisition, triple, ext, &staging)?;
    let outcome = match facts.family {
        OsFamily::Linux => live_linux::install(&req, facts.pkg_family, &acquired),
        OsFamily::Macos => live_macos::install(&req, &acquired),
        OsFamily::Windows => Err(format!(
            "live install for {} is not yet wired in the engine (Linux + macOS are wired first); \
             its existing per-OS bootstrap does the work. Preview with --dry-run.",
            os_label(facts.family)
        )),
        OsFamily::Unsupported => unreachable!("validated in validate_host"),
    };
    // Only the placement step copies out of staging; nothing else consumes it.
    let _ = std::fs::remove_dir_all(&staging);
    match outcome {
        Ok(msg) => Ok(format!("{rendered}\n\n{msg}")),
        Err(msg) => Err(format!("{rendered}\n\n{msg}")),
    }
}

fn binary_ext(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Windows => ".exe",
        _ => "",
    }
}

fn validate_host(facts: &HostFacts) -> Result<(), String> {
    if facts.family == OsFamily::Unsupported {
        return Err("rustynet install: this operating system is not supported".to_owned());
    }
    Ok(())
}

fn validate_request(req: &InstallRequest) -> Result<(), String> {
    // In unattended, non-uninstall, non-dry-run installs the trust anchor must be
    // supplied (fail-closed §6.B): no interactive fallback for a security input.
    if req.unattended && !req.uninstall && !req.dry_run && req.trust_anchor.owner_key_file.is_none()
    {
        return Err(
            "--unattended install requires --owner-key-file (the membership owner public key); \
             no interactive fallback for the trust anchor"
                .to_owned(),
        );
    }
    Ok(())
}

/// Build the ordered, human-readable install plan for this host. Kept as a pure
/// function of `(req, facts, triple)` so every OS branch is unit-testable off
/// that OS.
fn build_plan(req: &InstallRequest, facts: &HostFacts, triple: &str) -> Vec<String> {
    if req.uninstall {
        return vec![
            format!(
                "stop + disable the rustynet service and reverse each `ops install-*`/custody/trust step ({})",
                service_mechanism(facts.family)
            ),
            "remove placed binaries + state dirs (owner-only), leaving no residue".to_owned(),
        ];
    }
    let mut steps = Vec::new();
    steps.push(format!(
        "1. detect: {os} / {arch} → target {triple}{distro}",
        os = os_label(facts.family),
        arch = facts.arch,
        triple = triple,
        distro = facts
            .distro_id
            .as_deref()
            .map(|d| format!(" (distro {d})"))
            .unwrap_or_default(),
    ));
    steps.push(format!(
        "2. preflight: require {elevation}; probe backend prerequisites",
        elevation = elevation_requirement(facts.family)
    ));
    steps.push(format!(
        "3. acquire binaries (rustynetd, rustynet, rustynet-relay): {}",
        req.acquisition.label()
    ));
    steps.push(format!("4. prerequisites: {}", prereq_plan(facts)));
    steps.push(format!(
        "5. place binaries + create the unprivileged `rustynetd` identity and state dirs ({})",
        binary_location(facts.family)
    ));
    steps.push(format!("6. key custody: {}", custody_plan(facts.family)));
    steps.push(format!(
        "7. trust anchor: deliver + verify the membership owner public key{} ({})",
        thumbprint_note(&req.trust_anchor),
        anchor_location(facts.family)
    ));
    steps.push(format!(
        "8. register service: `{}` ({} role)",
        service_verb(facts.family, req.role),
        req.role.as_str()
    ));
    steps.push(
        "9. verify: key-custody report + trust-anchor thumbprint + service active".to_owned(),
    );
    steps
}

fn render_plan(req: &InstallRequest, facts: &HostFacts, triple: &str, plan: &[String]) -> String {
    let mode = if req.uninstall {
        "uninstall"
    } else if req.dry_run {
        "install (dry-run)"
    } else {
        "install"
    };
    let mut out = format!(
        "# rustynet {mode} plan\n\nHost: {os} {arch} (target {triple}){distro}\n\n",
        os = os_label(facts.family),
        arch = facts.arch,
        triple = triple,
        distro = facts
            .distro_id
            .as_deref()
            .map(|d| format!("\nDistro: {d}"))
            .unwrap_or_default(),
    );
    for step in plan {
        out.push_str("- ");
        out.push_str(step);
        out.push('\n');
    }
    out
}

fn os_label(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux => "Linux",
        OsFamily::Macos => "macOS",
        OsFamily::Windows => "Windows",
        OsFamily::Unsupported => "unsupported",
    }
}

fn elevation_requirement(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux | OsFamily::Macos => "root (re-run under sudo if not elevated)",
        OsFamily::Windows => "Administrator (run from an elevated shell)",
        OsFamily::Unsupported => "elevation",
    }
}

fn prereq_plan(facts: &HostFacts) -> String {
    match facts.family {
        OsFamily::Linux => match facts.pkg_family {
            Some(PkgFamily::Apt) => {
                "apt-get install wireguard-tools iproute2 nftables (+ systemd-resolved)".to_owned()
            }
            Some(PkgFamily::Dnf) => "dnf install wireguard-tools iproute2 nftables".to_owned(),
            None => format!(
                "unknown Linux distro ({}) — package manager not recognized; install wireguard-tools/iproute2/nftables manually",
                facts.distro_id.as_deref().unwrap_or("?")
            ),
        },
        OsFamily::Macos => {
            "wireguard-tools (provides `wg` for key genkey/pubkey); brew install wireguard-tools \
             if absent. The dataplane is bundled boringtun (userspace-shared backend), so \
             wireguard-go is NOT required"
                .to_owned()
        }
        OsFamily::Windows => {
            "ensure WireGuard for Windows is present (provides wireguard.exe/wg.exe + wintun)"
                .to_owned()
        }
        OsFamily::Unsupported => "n/a".to_owned(),
    }
}

fn binary_location(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux | OsFamily::Macos => "/usr/local/bin",
        OsFamily::Windows => r"C:\Program Files\RustyNet",
        OsFamily::Unsupported => "n/a",
    }
}

fn custody_plan(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux => "encrypted key + systemd LoadCredentialEncrypted passphrase",
        OsFamily::Macos => "encrypted key + macOS Keychain passphrase",
        OsFamily::Windows => "encrypted key + DPAPI passphrase (SYSTEM identity)",
        OsFamily::Unsupported => "n/a",
    }
}

fn anchor_location(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux => "/etc/rustynet/membership.owner.key.pub, root-only",
        OsFamily::Macos => "/etc/rustynet/membership.owner.key.pub, root-owned",
        OsFamily::Windows => r"C:\ProgramData\RustyNet\trust\membership.owner.key.pub, SYSTEM-only",
        OsFamily::Unsupported => "n/a",
    }
}

fn service_mechanism(family: OsFamily) -> &'static str {
    match family {
        OsFamily::Linux => "systemd",
        OsFamily::Macos => "launchd",
        OsFamily::Windows => "Windows SCM",
        OsFamily::Unsupported => "n/a",
    }
}

fn service_verb(family: OsFamily, role: InstallRole) -> String {
    match (family, role) {
        (OsFamily::Linux, InstallRole::Node) => "ops install-systemd".to_owned(),
        (OsFamily::Linux, InstallRole::Relay) => "ops install-systemd-relay".to_owned(),
        (OsFamily::Linux, InstallRole::Exit) => "ops install-systemd-exit".to_owned(),
        (OsFamily::Linux, InstallRole::Anchor) => {
            "ops install-systemd (+ anchor profile)".to_owned()
        }
        (OsFamily::Macos, InstallRole::Relay) => "ops install-macos-relay".to_owned(),
        (OsFamily::Macos, InstallRole::Anchor) => "ops install-macos-anchor".to_owned(),
        (OsFamily::Macos, InstallRole::Exit) => "ops install-macos-exit".to_owned(),
        (OsFamily::Macos, InstallRole::Node) => {
            "install the com.rustynet.daemon launchd job".to_owned()
        }
        (OsFamily::Windows, InstallRole::Relay) => "ops install-windows-relay-service".to_owned(),
        (OsFamily::Windows, InstallRole::Exit) => "ops install-windows-exit-service".to_owned(),
        (OsFamily::Windows, _) => "ops install-windows-service".to_owned(),
        (OsFamily::Unsupported, _) => "n/a".to_owned(),
    }
}

fn thumbprint_note(anchor: &TrustAnchorSource) -> String {
    match (&anchor.owner_key_file, &anchor.expected_thumbprint) {
        (Some(_), Some(_)) => " (thumbprint-verified)".to_owned(),
        (Some(_), None) => " (WARNING: no --owner-key-thumbprint; delivery unverified)".to_owned(),
        (None, _) => " (WARNING: no --owner-key-file supplied)".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        family: OsFamily,
        arch: &str,
        distro: Option<&str>,
        pkg: Option<PkgFamily>,
    ) -> HostFacts {
        HostFacts {
            family,
            distro_id: distro.map(str::to_owned),
            distro_like: Vec::new(),
            arch: arch.to_owned(),
            pkg_family: pkg,
        }
    }

    #[test]
    fn from_args_defaults_and_overrides() {
        let d = InstallRequest::from_args(&[]).unwrap();
        assert_eq!(d.role, InstallRole::Node);
        assert_eq!(d.acquisition, AcquisitionMode::VerifiedDownload);
        assert!(!d.unattended && !d.dry_run && !d.uninstall);

        let relay_args = ["--role", "relay", "--dry-run", "--build-from-source"].map(str::to_owned);
        let r = InstallRequest::from_args(&relay_args).unwrap();
        assert_eq!(r.role, InstallRole::Relay);
        assert!(r.dry_run);
        assert_eq!(r.acquisition, AcquisitionMode::BuildFromSource);
    }

    #[test]
    fn from_args_rejects_conflicts_and_relative_paths_and_unknown_flags() {
        let conflict_args = ["--from-dir", "/tmp/x", "--build-from-source"].map(str::to_owned);
        assert!(InstallRequest::from_args(&conflict_args).is_err());
        assert!(
            InstallRequest::from_args(&["--from-dir".to_owned(), "relative/path".to_owned()])
                .is_err()
        );
        assert!(
            InstallRequest::from_args(&["--owner-key-file".to_owned(), "rel".to_owned()]).is_err()
        );
        assert!(InstallRequest::from_args(&["--bogus".to_owned()]).is_err());
        assert!(InstallRequest::from_args(&["--role".to_owned(), "wizard".to_owned()]).is_err());
    }

    #[test]
    fn validate_request_requires_trust_anchor_for_unattended() {
        let mut req = InstallRequest::from_args(&["--unattended".to_owned()]).unwrap();
        assert!(validate_request(&req).is_err());
        // dry-run or uninstall relaxes it; supplying the key satisfies it.
        req.dry_run = true;
        assert!(validate_request(&req).is_ok());
        req.dry_run = false;
        req.trust_anchor.owner_key_file = Some(PathBuf::from("/etc/rustynet/owner.pub"));
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn plan_covers_all_steps_and_is_os_specific() {
        let req = InstallRequest {
            role: InstallRole::Node,
            acquisition: AcquisitionMode::VerifiedDownload,
            trust_anchor: TrustAnchorSource {
                owner_key_file: Some(PathBuf::from("/etc/rustynet/owner.pub")),
                expected_thumbprint: Some("abcd".to_owned()),
            },
            node_id: None,
            unattended: true,
            dry_run: true,
            uninstall: false,
        };

        let linux = build_plan(
            &req,
            &facts(
                OsFamily::Linux,
                "x86_64",
                Some("fedora"),
                Some(PkgFamily::Dnf),
            ),
            "x86_64-unknown-linux-gnu",
        );
        let joined = linux.join("\n");
        assert!(joined.contains("dnf install wireguard-tools"), "{joined}");
        assert!(
            joined.contains("systemd LoadCredentialEncrypted"),
            "{joined}"
        );
        assert!(joined.contains("ops install-systemd"), "{joined}");
        assert_eq!(linux.len(), 9);

        let mac = build_plan(
            &req,
            &facts(OsFamily::Macos, "aarch64", None, None),
            "aarch64-apple-darwin",
        );
        let mj = mac.join("\n");
        assert!(mj.contains("wireguard-tools"), "{mj}");
        assert!(mj.contains("bundled boringtun"), "{mj}");
        assert!(mj.contains("Keychain"), "{mj}");

        let win = build_plan(
            &req,
            &facts(OsFamily::Windows, "x86_64", None, None),
            "x86_64-pc-windows-msvc",
        );
        let wj = win.join("\n");
        assert!(wj.contains("WireGuard for Windows"), "{wj}");
        assert!(wj.contains("DPAPI"), "{wj}");
        assert!(wj.contains("ops install-windows-service"), "{wj}");
    }

    #[test]
    fn apt_distro_gets_apt_prereqs_and_unknown_distro_warns() {
        let apt = prereq_plan(&facts(
            OsFamily::Linux,
            "x86_64",
            Some("ubuntu"),
            Some(PkgFamily::Apt),
        ));
        assert!(apt.contains("apt-get install wireguard-tools"), "{apt}");
        let unknown = prereq_plan(&facts(OsFamily::Linux, "x86_64", Some("arch"), None));
        assert!(unknown.contains("not recognized"), "{unknown}");
    }

    #[test]
    fn uninstall_plan_is_reversal_only() {
        let req = InstallRequest {
            role: InstallRole::Node,
            acquisition: AcquisitionMode::VerifiedDownload,
            trust_anchor: TrustAnchorSource {
                owner_key_file: None,
                expected_thumbprint: None,
            },
            node_id: None,
            unattended: false,
            dry_run: false,
            uninstall: true,
        };
        let plan = build_plan(
            &req,
            &facts(
                OsFamily::Linux,
                "x86_64",
                Some("debian"),
                Some(PkgFamily::Apt),
            ),
            "x86_64-unknown-linux-gnu",
        );
        let j = plan.join("\n");
        assert!(j.contains("stop + disable"), "{j}");
        assert!(j.contains("systemd"), "{j}");
    }
}

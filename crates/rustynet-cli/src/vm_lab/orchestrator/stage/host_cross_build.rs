//! Host-side cross-build primitives for the opt-in `host-cross-binary`
//! source mode (`CrossCompileThenCloneDesign_2026-09-04.md` §5/§6).
//!
//! These are the pure, side-effect-free building blocks of the eventual flow:
//! map a lab node's `(platform, arch)` onto a Rust target triple, and build the
//! exact `cargo` / `cargo zigbuild` argument vector that produces the node's
//! binaries on the host. Nothing here spawns a process, touches the filesystem,
//! or is wired into a live run yet — the dispatch site in
//! [`super::source_archive`] still fails closed. Keeping these isolated and
//! unit-tested is what lets the risky adapter/bootstrap wiring land later
//! against a verified foundation.
//!
//! Fail-closed everywhere: an unknown arch, an unsupported platform (iOS /
//! Android have no host-cross story), or a malformed input is an error, never a
//! silent default — a wrong triple would ship a binary that cannot run on the
//! guest.
#![allow(dead_code)]

use crate::vm_lab::VmGuestPlatform;

/// The package + feature set every node build produces, single-sourced so the
/// host-cross argv cannot drift from the on-guest bootstrap build
/// (`Bootstrap-RustyNetMacos.sh` / `rn_bootstrap.sh`) or the §6 measurement
/// command. Order is stable for deterministic argv assertions.
const BUILD_PACKAGES: &[&str] = &["rustynetd", "rustynet-cli", "rustynet-relay"];
/// Package-qualified features, comma-joined as `cargo --features` expects when
/// several `-p` packages are built at once.
const BUILD_FEATURES: &str = "rustynet-cli/vm-lab,rustynet-relay/daemon";

/// Map a node's platform + probed CPU arch (`uname -m`) onto the Rust target
/// triple the host must build for.
///
/// `arch` is the raw `uname -m` token; common aliases are normalised
/// (`amd64` → `x86_64`, `arm64` → `aarch64`). Any unrecognised arch, or a
/// platform with no host-cross path (iOS / Android in phase 1), is a hard
/// error — never a guessed triple.
pub fn target_triple(platform: VmGuestPlatform, arch: &str) -> Result<String, String> {
    let arch = normalise_arch(arch)?;
    let triple = match (platform, arch) {
        (VmGuestPlatform::Linux, Arch::X86_64) => "x86_64-unknown-linux-gnu",
        (VmGuestPlatform::Linux, Arch::Aarch64) => "aarch64-unknown-linux-gnu",
        (VmGuestPlatform::Macos, Arch::Aarch64) => "aarch64-apple-darwin",
        (VmGuestPlatform::Macos, Arch::X86_64) => "x86_64-apple-darwin",
        (VmGuestPlatform::Windows, Arch::X86_64) => "x86_64-pc-windows-gnu",
        (VmGuestPlatform::Windows, Arch::Aarch64) => {
            return Err(
                "aarch64 Windows host-cross target is not supported (no gnullvm build path wired)"
                    .to_owned(),
            );
        }
        (VmGuestPlatform::Ios | VmGuestPlatform::Android, _) => {
            return Err(format!(
                "platform {platform:?} has no host-cross-binary path; mobile clients build via \
                 their native toolchains, not the lab cross-clone flow"
            ));
        }
    };
    Ok(triple.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86_64,
    Aarch64,
}

fn normalise_arch(arch: &str) -> Result<Arch, String> {
    match arch.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" | "x64" => Ok(Arch::X86_64),
        "aarch64" | "arm64" => Ok(Arch::Aarch64),
        other => Err(format!(
            "unsupported CPU arch '{other}' for host-cross build; expected x86_64 or aarch64"
        )),
    }
}

/// Build the `cargo` argument vector (everything after the literal `cargo`)
/// that produces the standard node binary set for `triple` on the host.
///
/// - Apple-darwin triples build with plain `cargo build` (the host is
///   aarch64-apple-darwin; same-triple builds need no cross linker, and a
///   glibc floor is meaningless on macOS — passing one is an error).
/// - Linux (and, in phase 2, Windows-gnu) triples build with `cargo zigbuild`
///   so the zig linker supplies the cross toolchain; an optional glibc floor is
///   appended to the triple as `<triple>.<floor>` (e.g.
///   `x86_64-unknown-linux-gnu.2.31`) to cap the required glibc symbol
///   versions (§4.2).
///
/// Fail-closed: an empty triple, or a glibc floor requested for a non-linux
/// triple, is an error.
pub fn host_build_argv(triple: &str, glibc_floor: Option<&str>) -> Result<Vec<String>, String> {
    if triple.trim().is_empty() {
        return Err("host_build_argv: empty target triple".to_owned());
    }
    let is_linux = triple.contains("-linux-");
    let is_darwin = triple.contains("-apple-darwin");
    let is_windows = triple.contains("-windows-");

    if glibc_floor.is_some() && !is_linux {
        return Err(format!(
            "glibc floor is only meaningful for a linux-gnu triple, not '{triple}'"
        ));
    }

    let (subcommand, target_arg) = if is_darwin {
        ("build", triple.to_owned())
    } else if is_linux || is_windows {
        let target = match glibc_floor {
            Some(floor) => format!("{triple}.{floor}"),
            None => triple.to_owned(),
        };
        ("zigbuild", target)
    } else {
        return Err(format!(
            "host_build_argv: unrecognised triple '{triple}' (expected a linux-gnu, \
             apple-darwin, or windows-gnu target)"
        ));
    };

    let mut argv = vec![
        subcommand.to_owned(),
        "--release".to_owned(),
        "--target".to_owned(),
        target_arg,
    ];
    for pkg in BUILD_PACKAGES {
        argv.push("-p".to_owned());
        argv.push((*pkg).to_owned());
    }
    argv.push("--features".to_owned());
    argv.push(BUILD_FEATURES.to_owned());
    Ok(argv)
}

/// A parsed glibc symbol version (`GLIBC_2.31` → `[2, 31]`), ordered
/// numerically component-by-component so `2.9 < 2.29 < 2.31 < 2.34.1` (a plain
/// string sort gets `2.29` vs `2.3` backwards, which is exactly the kind of
/// mistake that would wave a too-new binary through the floor check).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlibcVersion(Vec<u32>);

impl std::fmt::Display for GlibcVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(u32::to_string).collect();
        write!(f, "{}", parts.join("."))
    }
}

/// Parse a dotted glibc version string (`"2.31"`, `"2.34.1"`) into ordered
/// numeric components. Any non-numeric or empty component makes it `None` —
/// never a partial/guessed version.
fn parse_glibc_version(s: &str) -> Option<GlibcVersion> {
    if s.is_empty() {
        return None;
    }
    let comps: Option<Vec<u32>> = s.split('.').map(|c| c.parse::<u32>().ok()).collect();
    comps.map(GlibcVersion)
}

/// Scan `objdump -T` (dynamic symbol table) output for the highest
/// `GLIBC_<version>` symbol version the binary requires. `None` if the binary
/// references no versioned glibc symbols (a static or non-glibc binary — which
/// is trivially within any floor).
pub fn parse_max_glibc_version(objdump_output: &str) -> Option<GlibcVersion> {
    objdump_output
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix("GLIBC_"))
        .filter_map(parse_glibc_version)
        .max()
}

/// Fail-closed glibc-floor check (§4.2): the binary's highest required glibc
/// symbol version must be ≤ the declared floor, so the artifact runs on any
/// distro at or above that floor. A binary requiring a HIGHER version than the
/// floor is rejected — shipping it would fault on a guest at the floor. This is
/// the single guard that keeps a host cross-build from being mistaken for a
/// portable artifact.
pub fn check_glibc_floor(
    objdump_output: &str,
    floor: &str,
) -> Result<Option<GlibcVersion>, String> {
    let floor_v =
        parse_glibc_version(floor).ok_or_else(|| format!("malformed glibc floor '{floor}'"))?;
    match parse_max_glibc_version(objdump_output) {
        // No versioned glibc deps — trivially within any floor.
        None => Ok(None),
        Some(max) if max <= floor_v => Ok(Some(max)),
        Some(max) => Err(format!(
            "binary requires glibc {max} which exceeds the declared floor {floor_v}; \
             it would fail on a guest at the floor (fail closed)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triple_maps_known_platform_arch_pairs() {
        assert_eq!(
            target_triple(VmGuestPlatform::Linux, "x86_64").unwrap(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(
            target_triple(VmGuestPlatform::Linux, "aarch64").unwrap(),
            "aarch64-unknown-linux-gnu"
        );
        assert_eq!(
            target_triple(VmGuestPlatform::Macos, "arm64").unwrap(),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            target_triple(VmGuestPlatform::Windows, "amd64").unwrap(),
            "x86_64-pc-windows-gnu"
        );
    }

    #[test]
    fn triple_fails_closed_on_unknown_arch_and_mobile() {
        assert!(target_triple(VmGuestPlatform::Linux, "riscv64").is_err());
        assert!(target_triple(VmGuestPlatform::Linux, "").is_err());
        assert!(target_triple(VmGuestPlatform::Ios, "aarch64").is_err());
        assert!(target_triple(VmGuestPlatform::Android, "aarch64").is_err());
        // aarch64 Windows has no wired build path — must not silently pick a triple.
        assert!(target_triple(VmGuestPlatform::Windows, "aarch64").is_err());
    }

    #[test]
    fn linux_argv_uses_zigbuild_with_glibc_floor() {
        let argv = host_build_argv("x86_64-unknown-linux-gnu", Some("2.31")).unwrap();
        assert_eq!(argv[0], "zigbuild");
        assert_eq!(argv[1], "--release");
        assert_eq!(argv[2], "--target");
        assert_eq!(argv[3], "x86_64-unknown-linux-gnu.2.31");
        // The exact package/feature set the guest bootstrap builds.
        assert!(argv.windows(2).any(|w| w == ["-p", "rustynetd"]));
        assert!(argv.windows(2).any(|w| w == ["-p", "rustynet-cli"]));
        assert!(argv.windows(2).any(|w| w == ["-p", "rustynet-relay"]));
        assert!(
            argv.windows(2)
                .any(|w| w == ["--features", "rustynet-cli/vm-lab,rustynet-relay/daemon"])
        );
    }

    #[test]
    fn macos_argv_is_plain_cargo_build_no_zig() {
        let argv = host_build_argv("aarch64-apple-darwin", None).unwrap();
        assert_eq!(argv[0], "build");
        assert_eq!(argv[3], "aarch64-apple-darwin");
    }

    #[test]
    fn argv_fails_closed_on_bad_inputs() {
        // Empty triple.
        assert!(host_build_argv("", None).is_err());
        // glibc floor on a non-linux triple is meaningless — reject, don't ignore.
        assert!(host_build_argv("aarch64-apple-darwin", Some("2.31")).is_err());
        // An unrecognised triple family.
        assert!(host_build_argv("wasm32-unknown-unknown", None).is_err());
    }

    #[test]
    fn glibc_scan_finds_max_numerically_not_lexically() {
        // Real objdump -T shape; 2.29 must beat 2.3 (numeric), and 2.2.5.
        let dump = "\
0000000000000000  DF *UND*  0000000000000000  GLIBC_2.2.5 memcpy
0000000000000000  DF *UND*  0000000000000000  GLIBC_2.3   __register_atfork
0000000000000000  DF *UND*  0000000000000000  GLIBC_2.29  pow
";
        assert_eq!(parse_max_glibc_version(dump).unwrap().to_string(), "2.29");
    }

    #[test]
    fn glibc_floor_passes_within_and_fails_when_exceeded() {
        let dump = "GLIBC_2.29 pow\nGLIBC_2.17 clock_gettime\n";
        // This is the real measured zigbuild result: max 2.29 under a 2.31 floor.
        assert_eq!(
            check_glibc_floor(dump, "2.31")
                .unwrap()
                .unwrap()
                .to_string(),
            "2.29"
        );
        // Exactly at the floor passes.
        assert_eq!(
            check_glibc_floor(dump, "2.29")
                .unwrap()
                .unwrap()
                .to_string(),
            "2.29"
        );
        // One below the max fails closed — this is the guard that matters.
        assert!(check_glibc_floor(dump, "2.28").is_err());
    }

    #[test]
    fn glibc_scan_handles_no_versioned_symbols_and_bad_floor() {
        assert!(parse_max_glibc_version("nothing versioned here").is_none());
        assert_eq!(check_glibc_floor("no glibc symbols", "2.31").unwrap(), None);
        assert!(check_glibc_floor("GLIBC_2.29 x", "not-a-version").is_err());
    }
}

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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::vm_lab::VmGuestPlatform;

/// The three node binaries a host build produces, by their cargo binary name
/// (as they appear under `target/<triple>/release/`). Single-sourced with
/// [`BUILD_PACKAGES`]; `rustynet-cli`'s binary keeps its crate name here (the
/// install step may rename it on the guest — that is the adapter's concern).
pub const NODE_BINARY_NAMES: &[&str] = &["rustynetd", "rustynet-cli", "rustynet-relay"];

/// The release output directory for `triple` under a per-run
/// `CARGO_TARGET_DIR`. Cargo writes cross-target artifacts to
/// `<target_dir>/<triple>/release/`.
pub fn host_build_release_dir(target_dir: &Path, triple: &str) -> PathBuf {
    target_dir.join(triple).join("release")
}

/// A distinct host build to run: one target triple, built once and shared by
/// every node that maps to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBuildTask {
    pub triple: String,
    /// glibc floor for a linux-gnu triple; always `None` for darwin/windows.
    pub glibc_floor: Option<String>,
}

/// Collapse a set of node `(platform, arch)` pairs into the distinct set of
/// host builds to run — deduplicated by triple, so N nodes sharing a triple
/// cost one build. Order follows first appearance for determinism.
///
/// Fail-closed: a node whose `(platform, arch)` has no host-cross triple aborts
/// the WHOLE plan rather than being dropped — a silently short plan would leave
/// that node with no binary and fall through to some other path.
pub fn plan_host_builds(
    nodes: &[(VmGuestPlatform, String)],
    linux_glibc_floor: Option<&str>,
) -> Result<Vec<HostBuildTask>, String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut tasks = Vec::new();
    for (platform, arch) in nodes {
        let triple = target_triple(*platform, arch)?;
        if seen.insert(triple.clone()) {
            let glibc_floor = triple
                .contains("-linux-")
                .then(|| linux_glibc_floor.map(str::to_owned))
                .flatten();
            tasks.push(HostBuildTask {
                triple,
                glibc_floor,
            });
        }
    }
    Ok(tasks)
}

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

/// The verified result of a successful host build for one triple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBuildArtifact {
    pub triple: String,
    /// Absolute paths to the built node binaries, in [`NODE_BINARY_NAMES`] order.
    pub binaries: Vec<PathBuf>,
    /// The highest glibc version any binary requires (linux only; `None` for a
    /// darwin/windows triple or a binary with no versioned glibc symbols).
    pub glibc_max: Option<GlibcVersion>,
}

/// Run every planned host build and verify each artifact — fail-closed.
///
/// The three effects are injected so the orchestration (per-task build, glibc
/// enforcement, artifact collection, fail-closed) is unit-testable without a
/// real multi-minute cargo build:
/// - `run_build(argv, target_root)` runs `cargo <argv>` with
///   `CARGO_TARGET_DIR=target_root`.
/// - `binary_exists(path)` reports whether an expected artifact was produced.
/// - `objdump_dynamic(path)` returns the binary's `objdump -T` output.
///
/// For a linux task carrying a floor, every binary's required glibc must be
/// within that floor ([`check_glibc_floor`]) or the whole run fails: a host
/// cross-build that would fault on a guest must never reach the deploy step.
pub fn execute_host_builds<B, E, D>(
    target_root: &Path,
    tasks: &[HostBuildTask],
    run_build: B,
    binary_exists: E,
    objdump_dynamic: D,
) -> Result<Vec<HostBuildArtifact>, String>
where
    B: Fn(&[String], &Path) -> Result<(), String>,
    E: Fn(&Path) -> bool,
    D: Fn(&Path) -> Result<String, String>,
{
    let mut artifacts = Vec::with_capacity(tasks.len());
    for task in tasks {
        let argv = host_build_argv(&task.triple, task.glibc_floor.as_deref())?;
        run_build(&argv, target_root)
            .map_err(|e| format!("host build failed for {}: {e}", task.triple))?;

        let rel = host_build_release_dir(target_root, &task.triple);
        let is_linux = task.triple.contains("-linux-");
        let mut binaries = Vec::with_capacity(NODE_BINARY_NAMES.len());
        let mut glibc_max: Option<GlibcVersion> = None;

        for name in NODE_BINARY_NAMES {
            let bin = rel.join(name);
            if !binary_exists(&bin) {
                return Err(format!(
                    "host build for {} produced no {name} at {} (fail closed)",
                    task.triple,
                    bin.display()
                ));
            }
            if is_linux {
                let dump = objdump_dynamic(&bin)
                    .map_err(|e| format!("objdump {} failed: {e}", bin.display()))?;
                // With a floor, enforce it (error propagates on violation); without
                // one, still record the max for provenance.
                let this_max = match task.glibc_floor.as_deref() {
                    Some(floor) => check_glibc_floor(&dump, floor)
                        .map_err(|e| format!("{} {name}: {e}", task.triple))?,
                    None => parse_max_glibc_version(&dump),
                };
                if let Some(m) = this_max {
                    glibc_max = Some(match glibc_max {
                        Some(existing) => existing.max(m),
                        None => m,
                    });
                }
            }
            binaries.push(bin);
        }

        artifacts.push(HostBuildArtifact {
            triple: task.triple.clone(),
            binaries,
            glibc_max,
        });
    }
    Ok(artifacts)
}

/// Production entry point: run the planned host builds with real `cargo` /
/// `cargo zigbuild` + `objdump` invocations, in `repo_dir`, writing artifacts
/// under `target_root` (a run-local `CARGO_TARGET_DIR`). Thin wrapper over
/// [`execute_host_builds`] — the orchestration + fail-closed logic is what the
/// unit tests cover; these two closures are the only untested surface and are
/// exactly the `cargo`/`objdump` commands validated by the §6 measurements.
pub fn run_planned_host_builds(
    repo_dir: &Path,
    target_root: &Path,
    tasks: &[HostBuildTask],
) -> Result<Vec<HostBuildArtifact>, String> {
    execute_host_builds(
        target_root,
        tasks,
        |argv, tr| run_host_cargo(repo_dir, argv, tr),
        |bin| bin.is_file(),
        objdump_dynamic_symbols,
    )
}

/// Spawn `cargo <argv>` (argv[0] is `build` or `zigbuild`) in `repo_dir` with
/// `CARGO_TARGET_DIR=target_root`. Inherits the caller's stdio so build output
/// is visible in the run log. Fail-closed on spawn failure or a non-zero exit.
fn run_host_cargo(repo_dir: &Path, argv: &[String], target_root: &Path) -> Result<(), String> {
    let status = std::process::Command::new("cargo")
        .args(argv)
        .current_dir(repo_dir)
        .env("CARGO_TARGET_DIR", target_root)
        .status()
        .map_err(|e| format!("spawn cargo failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "cargo {} exited with {status}",
            argv.first().map_or("", |s| s.as_str())
        ))
    }
}

/// Run `objdump -T <bin>` and return its stdout (the dynamic symbol table the
/// glibc-floor scan parses).
fn objdump_dynamic_symbols(bin: &Path) -> Result<String, String> {
    let out = std::process::Command::new("objdump")
        .arg("-T")
        .arg(bin)
        .output()
        .map_err(|e| format!("spawn objdump failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("objdump exited with {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

    #[test]
    fn plan_dedups_shared_triples_and_scopes_floor_to_linux() {
        let nodes = vec![
            (VmGuestPlatform::Linux, "aarch64".to_owned()),
            (VmGuestPlatform::Linux, "aarch64".to_owned()), // same triple → deduped
            (VmGuestPlatform::Macos, "arm64".to_owned()),
        ];
        let tasks = plan_host_builds(&nodes, Some("2.31")).unwrap();
        assert_eq!(tasks.len(), 2, "two distinct triples");
        let linux = tasks
            .iter()
            .find(|t| t.triple == "aarch64-unknown-linux-gnu")
            .unwrap();
        assert_eq!(linux.glibc_floor.as_deref(), Some("2.31"));
        let macos = tasks
            .iter()
            .find(|t| t.triple == "aarch64-apple-darwin")
            .unwrap();
        // Floors are linux-only — a darwin task must never carry one.
        assert_eq!(macos.glibc_floor, None);
    }

    #[test]
    fn plan_fails_closed_on_any_unmappable_node() {
        // One bad node aborts the whole plan — never a silently short list.
        let nodes = vec![
            (VmGuestPlatform::Linux, "aarch64".to_owned()),
            (VmGuestPlatform::Linux, "riscv64".to_owned()),
        ];
        assert!(plan_host_builds(&nodes, None).is_err());
        // iOS/Android nodes have no host-cross path either.
        assert!(plan_host_builds(&[(VmGuestPlatform::Ios, "aarch64".to_owned())], None).is_err());
    }

    #[test]
    fn release_dir_is_target_triple_release() {
        let dir = host_build_release_dir(Path::new("/tmp/xc"), "aarch64-unknown-linux-gnu");
        assert_eq!(dir, Path::new("/tmp/xc/aarch64-unknown-linux-gnu/release"));
    }

    fn linux_task() -> Vec<HostBuildTask> {
        vec![HostBuildTask {
            triple: "aarch64-unknown-linux-gnu".to_owned(),
            glibc_floor: Some("2.31".to_owned()),
        }]
    }

    #[test]
    fn executor_happy_path_collects_binaries_and_glibc_max() {
        let root = Path::new("/tmp/xc-happy");
        let out = execute_host_builds(
            root,
            &linux_task(),
            |argv, tr| {
                assert_eq!(argv[0], "zigbuild");
                assert_eq!(tr, root);
                Ok(())
            },
            |_bin| true,
            |_bin| Ok("GLIBC_2.17 clock_gettime\nGLIBC_2.29 pow\n".to_owned()),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].binaries.len(), NODE_BINARY_NAMES.len());
        assert_eq!(out[0].glibc_max.as_ref().unwrap().to_string(), "2.29");
        assert!(out[0].binaries[0].ends_with("aarch64-unknown-linux-gnu/release/rustynetd"));
    }

    #[test]
    fn executor_fails_closed_when_build_fails() {
        let err = execute_host_builds(
            Path::new("/tmp/x"),
            &linux_task(),
            |_argv, _tr| Err("linker exploded".to_owned()),
            |_bin| true,
            |_bin| Ok(String::new()),
        )
        .unwrap_err();
        assert!(err.contains("host build failed"));
    }

    #[test]
    fn executor_fails_closed_on_glibc_floor_violation() {
        let err = execute_host_builds(
            Path::new("/tmp/x"),
            &linux_task(),
            |_argv, _tr| Ok(()),
            |_bin| true,
            // 2.40 exceeds the 2.31 floor — must abort, never ship.
            |_bin| Ok("GLIBC_2.40 some_new_symbol\n".to_owned()),
        )
        .unwrap_err();
        assert!(err.contains("exceeds the declared floor"));
    }

    #[test]
    fn executor_fails_closed_on_missing_binary() {
        let err = execute_host_builds(
            Path::new("/tmp/x"),
            &linux_task(),
            |_argv, _tr| Ok(()),
            |_bin| false,
            |_bin| Ok(String::new()),
        )
        .unwrap_err();
        assert!(err.contains("produced no"));
    }

    #[test]
    fn executor_skips_glibc_scan_for_darwin() {
        let task = vec![HostBuildTask {
            triple: "aarch64-apple-darwin".to_owned(),
            glibc_floor: None,
        }];
        let out = execute_host_builds(
            Path::new("/tmp/x"),
            &task,
            |argv, _tr| {
                assert_eq!(argv[0], "build");
                Ok(())
            },
            |_bin| true,
            |_bin| panic!("objdump must not be called for a darwin triple"),
        )
        .unwrap();
        assert_eq!(out[0].glibc_max, None);
    }
}

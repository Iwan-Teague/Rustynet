//! Host-side cross-build primitives for the opt-in `host-cross-binary`
//! source mode (`CrossCompileThenCloneDesign_2026-09-04.md` §5/§6).
//!
//! Layers: pure helpers ([`target_triple`], [`host_build_argv`],
//! [`plan_host_builds`], [`check_glibc_floor`]) map a lab node's
//! `(platform, arch)` onto a triple, build the exact `cargo`/`cargo zigbuild`
//! argv, and enforce the glibc floor; [`execute_host_builds`] orchestrates them
//! with the build/objdump effects INJECTED so it is unit-tested fail-closed;
//! [`run_planned_host_builds`] is the production wrapper that spawns real
//! `cargo`/`objdump`. Wired live by `native.rs` when `--source-mode
//! host-cross-binary` is selected (increment 3c). The fail-closed guarantee is
//! enforced here (build error / glibc-floor violation aborts the run before
//! deploy), not at the source-archive dispatch.
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
///
/// The `GLIBC_` marker is matched as a SUBSTRING anywhere in the text, not as a
/// whitespace-delimited token: Apple's LLVM `objdump -T` (the host's objdump
/// when cross-inspecting a Linux ELF) prints the version parenthesised —
/// `(GLIBC_2.17) __libc_start_main` — so a `strip_prefix("GLIBC_")` on a
/// `(GLIBC_2.17)` token finds nothing and the floor check would silently pass
/// (fail-open). Matching the substring makes the guard robust to both GNU and
/// LLVM objdump formats.
pub fn parse_max_glibc_version(objdump_output: &str) -> Option<GlibcVersion> {
    objdump_output
        .match_indices("GLIBC_")
        .filter_map(|(i, marker)| {
            let rest = &objdump_output[i + marker.len()..];
            let ver: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            parse_glibc_version(ver.trim_end_matches('.'))
        })
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

/// Filename of the run-local alias→prebuilt-binaries manifest, written under
/// the report dir by the host-cross build step and read by the install adapter.
pub const HOST_CROSS_MANIFEST_FILENAME: &str = "host_cross_binaries.json";

/// Write the alias→binary-paths manifest that the install adapter reads to
/// decide whether (and what) to ship as prebuilt binaries. A `BTreeMap` for
/// deterministic output. Its presence is the signal that this run is host-cross;
/// absence means a normal build-on-guest run.
pub fn write_host_cross_manifest(
    report_dir: &Path,
    alias_to_binaries: &std::collections::BTreeMap<String, Vec<PathBuf>>,
) -> Result<PathBuf, String> {
    let path = report_dir.join(HOST_CROSS_MANIFEST_FILENAME);
    let json = serde_json::to_string_pretty(alias_to_binaries)
        .map_err(|e| format!("serialize host-cross manifest: {e}"))?;
    std::fs::write(&path, json)
        .map_err(|e| format!("write host-cross manifest {}: {e}", path.display()))?;
    Ok(path)
}

/// Read the prebuilt binary paths for `alias` from the manifest. `Ok(None)` when
/// the manifest is absent (not a host-cross run) or carries no entry for the
/// alias — the caller then takes the normal build-on-guest path.
pub fn read_host_cross_binaries(
    report_dir: &Path,
    alias: &str,
) -> Result<Option<Vec<PathBuf>>, String> {
    let path = report_dir.join(HOST_CROSS_MANIFEST_FILENAME);
    if !path.is_file() {
        return Ok(None);
    }
    let json = std::fs::read_to_string(&path)
        .map_err(|e| format!("read host-cross manifest {}: {e}", path.display()))?;
    let map: std::collections::BTreeMap<String, Vec<PathBuf>> =
        serde_json::from_str(&json).map_err(|e| format!("parse host-cross manifest: {e}"))?;
    Ok(map.get(alias).cloned())
}

/// Default glibc floor for `--prebuilt-node-binaries` directories: the
/// hand-built Linux binaries come from a Mac cross-build (zig) against the
/// newest lab guest's glibc, so the floor is deliberately looser than the
/// `2.31` cap the orchestrator's own host-cross build enforces.
pub const DEFAULT_PREBUILT_GLIBC_FLOOR: &str = "2.39";

/// Provenance descriptor every `--prebuilt-node-binaries` directory must carry
/// next to its three binaries (written by `scripts/lab/make_prebuilt_manifest.sh`).
pub const PREBUILT_DESCRIPTOR_FILENAME: &str = "PREBUILT.json";

/// Run-local provenance record for the prebuilt binaries actually shipped,
/// under the report dir; also the source of the hashes the install adapter
/// re-verifies on the node after the copy.
pub const PREBUILT_PROVENANCE_RELATIVE_PATH: &str = "state/prebuilt_binaries_provenance.json";

/// `PREBUILT.json`: the commit the binaries claim to be built from and the
/// sha256 of each. Both are SELF-DECLARED by whoever wrote the directory (see
/// `scripts/lab/make_prebuilt_manifest.sh`): checking them proves the directory
/// is internally consistent, that its label equals the orchestrator's HEAD and
/// (via the remote re-hash) that the bytes arrived intact — NOT that the build
/// really came from that commit. Unknown fields are refused so a typo cannot
/// silently drop a check.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrebuiltDescriptor {
    source_commit: String,
    sha256: std::collections::BTreeMap<String, String>,
}

/// What [`validate_prebuilt_dir`] proved about one prebuilt directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPrebuiltDir {
    /// Absolute paths in [`NODE_BINARY_NAMES`] order.
    pub binaries: Vec<PathBuf>,
    /// Binary name -> lowercase hex sha256 (verified against `PREBUILT.json`).
    pub sha256: std::collections::BTreeMap<String, String>,
    pub source_commit: String,
    /// Highest glibc symbol version any of the binaries requires.
    pub glibc_max: Option<GlibcVersion>,
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse one `--prebuilt-node-binaries <alias>=<dir>` value. The dir must be
/// absolute (the manifest stores absolute paths and the orchestrator's cwd is a
/// snapshot repo, so a relative path would silently mean something else).
pub fn parse_prebuilt_node_binaries_arg(raw: &str) -> Result<(String, PathBuf), String> {
    let (alias, dir) = raw.split_once('=').ok_or_else(|| {
        format!("invalid --prebuilt-node-binaries value '{raw}': expected <alias>=<dir>")
    })?;
    if alias.is_empty() || dir.is_empty() {
        return Err(format!(
            "invalid --prebuilt-node-binaries value '{raw}': alias and dir must be non-empty"
        ));
    }
    let dir = PathBuf::from(dir);
    if !dir.is_absolute() {
        return Err(format!(
            "invalid --prebuilt-node-binaries value '{raw}': dir must be an absolute path"
        ));
    }
    Ok((alias.to_owned(), dir))
}

/// Resolve `--prebuilt-glibc-floor` (default [`DEFAULT_PREBUILT_GLIBC_FLOOR`]);
/// a malformed floor is an error here rather than deep inside a validation.
pub fn resolve_prebuilt_glibc_floor(raw: Option<&str>) -> Result<String, String> {
    let floor = raw.unwrap_or(DEFAULT_PREBUILT_GLIBC_FLOOR);
    parse_glibc_version(floor)
        .map(|_| floor.to_owned())
        .ok_or_else(|| format!("malformed --prebuilt-glibc-floor '{floor}'"))
}

/// Flag-level fail-closed checks shared by the CLI parser and the orchestrator:
/// prebuilt binaries replace the host cross-build, so the two are exclusive
/// (compared on the PARSED source mode, so `" host-cross-binary"` cannot slip
/// past); they are labelled with the orchestrator's HEAD commit, so a dirty
/// tree (`--allow-dirty`) makes that label meaningless and is refused; a glibc
/// floor without prebuilt binaries means nothing; an alias listed twice would
/// silently let the last dir win.
pub fn check_prebuilt_flags(
    source_mode: Option<&str>,
    prebuilt: &[(String, PathBuf)],
    glibc_floor: Option<&str>,
    allow_dirty: bool,
) -> Result<(), String> {
    if prebuilt.is_empty() {
        if glibc_floor.is_some() {
            return Err(
                "--prebuilt-glibc-floor requires at least one --prebuilt-node-binaries".to_owned(),
            );
        }
        return Ok(());
    }
    if crate::vm_lab::orchestrator::stage::source_archive::parse_archive_source_mode(source_mode)?
        == crate::vm_lab::orchestrator::stage::source_archive::ArchiveSourceMode::HostCrossBinary
    {
        return Err(
            "--prebuilt-node-binaries and --source-mode host-cross-binary are mutually exclusive"
                .to_owned(),
        );
    }
    if allow_dirty {
        return Err(
            "--prebuilt-node-binaries cannot be combined with --allow-dirty: the binaries are \
             labelled with the orchestrator's HEAD commit, which a dirty tree does not match"
                .to_owned(),
        );
    }
    let mut seen = BTreeSet::new();
    for (alias, _) in prebuilt {
        if !seen.insert(alias.as_str()) {
            return Err(format!(
                "--prebuilt-node-binaries lists alias '{alias}' more than once"
            ));
        }
    }
    resolve_prebuilt_glibc_floor(glibc_floor).map(|_| ())
}

/// Every prebuilt alias must be one of the run's `--node` aliases and a Linux
/// node (the binaries are x86_64 Linux ELF; nothing else can run them).
pub fn check_prebuilt_targets(
    prebuilt: &[(String, PathBuf)],
    nodes: &[(String, VmGuestPlatform)],
) -> Result<(), String> {
    for (alias, _) in prebuilt {
        match nodes.iter().find(|(a, _)| a == alias) {
            None => {
                return Err(format!(
                    "--prebuilt-node-binaries alias '{alias}' is not one of the --node aliases for this run"
                ));
            }
            Some((_, platform)) if *platform != VmGuestPlatform::Linux => {
                return Err(format!(
                    "--prebuilt-node-binaries alias '{alias}' is a {platform:?} node; prebuilt binaries are Linux x86_64 only"
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The probed `uname -m` of a prebuilt-binary node must be x86_64 (the only
/// architecture the prebuilt ELF check accepts).
pub fn require_prebuilt_arch(alias: &str, uname_m: &str) -> Result<(), String> {
    match normalise_arch(uname_m)? {
        Arch::X86_64 => Ok(()),
        Arch::Aarch64 => Err(format!(
            "prebuilt binaries for '{alias}': node reports arch '{}' but prebuilt binaries are x86_64 only",
            uname_m.trim()
        )),
    }
}

/// The prebuilt dir and its files must belong to the user running the
/// orchestrator and be writable by nobody else: anyone who could edit them
/// could also edit `PREBUILT.json` to match, defeating the hash check. Takes the
/// expected uid so the wrong-owner case is unit-testable without root.
#[cfg(unix)]
fn check_owner_and_mode(
    meta: &std::fs::Metadata,
    what: &str,
    path: &Path,
    uid: u32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != uid {
        return Err(format!(
            "prebuilt {what} {} is owned by uid {}, not the running user (uid {uid})",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "prebuilt {what} {} is group- or world-writable (mode {:o}); fix with `chmod go-w`",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn running_uid() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

/// The prebuilt directory itself: a real directory (never a symlink), owned by
/// the running user, not group/world-writable.
fn check_prebuilt_dir_trusted(dir: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| {
        format!(
            "prebuilt dir {} is missing or unreadable: {e}",
            dir.display()
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "prebuilt dir {} is a symlink (refusing to follow)",
            dir.display()
        ));
    }
    if !meta.file_type().is_dir() {
        return Err(format!("prebuilt dir {} is not a directory", dir.display()));
    }
    #[cfg(unix)]
    check_owner_and_mode(&meta, "dir", dir, running_uid())?;
    Ok(())
}

fn read_regular_file(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        format!(
            "prebuilt {what} {} is missing or unreadable: {e}",
            path.display()
        )
    })?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "prebuilt {what} {} is a symlink (refusing to follow)",
            path.display()
        ));
    }
    if !meta.file_type().is_file() {
        return Err(format!(
            "prebuilt {what} {} is not a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    check_owner_and_mode(&meta, what, path, running_uid())?;
    if meta.len() > MAX_PREBUILT_FILE_BYTES {
        return Err(format!(
            "prebuilt {what} {} is {} bytes, over the {MAX_PREBUILT_FILE_BYTES}-byte limit",
            path.display(),
            meta.len()
        ));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("read prebuilt {what} {}: {e}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("prebuilt {what} {} is empty", path.display()));
    }
    Ok(bytes)
}

/// ELF64 little-endian x86_64 header check on the file bytes.
fn check_elf_x86_64(name: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 64 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(format!("prebuilt {name} is not an ELF file (bad magic)"));
    }
    if bytes[4] != 2 {
        return Err(format!(
            "prebuilt {name} is not a 64-bit ELF (EI_CLASS {})",
            bytes[4]
        ));
    }
    if bytes[5] != 1 {
        return Err(format!(
            "prebuilt {name} is not little-endian ELF (EI_DATA {})",
            bytes[5]
        ));
    }
    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if e_type != 2 && e_type != 3 {
        return Err(format!(
            "prebuilt {name} has e_type {e_type}, expected ET_EXEC (2) or ET_DYN (3)"
        ));
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 0x3E {
        return Err(format!(
            "prebuilt {name} has e_machine {machine:#x}, expected 0x3e (x86_64)"
        ));
    }
    check_elf_interpreter(name, bytes)
}

/// The only dynamic loader the lab guests provide for x86_64 glibc binaries. A
/// PT_INTERP naming anything else (musl, a build-host path) would not start.
const X86_64_GLIBC_INTERPRETER: &[u8] = b"/lib64/ld-linux-x86-64.so.2";

fn malformed_phdrs(name: &str) -> String {
    format!("prebuilt {name} has a malformed ELF program header table")
}

fn le_u16(bytes: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_le_bytes(bytes.get(o..o.checked_add(2)?)?.try_into().ok()?) as usize)
}

fn le_u32(bytes: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn le_u64(bytes: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(o..o.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// One ELF64 program header, reduced to what the checks need.
#[derive(Debug, Clone, Copy)]
struct Segment {
    p_type: u32,
    offset: usize,
    vaddr: usize,
    filesz: usize,
}

/// Every program header, all bounds-checked. Offsets/sizes are returned
/// unvalidated against the file length: each consumer slices with
/// `bytes.get(..)` and treats a miss as malformed.
fn elf_segments(name: &str, bytes: &[u8]) -> Result<Vec<Segment>, String> {
    let malformed = || malformed_phdrs(name);
    let usz = |v: u64| usize::try_from(v).map_err(|_| malformed());
    let phnum = le_u16(bytes, 56).ok_or_else(malformed)?;
    if phnum == 0 {
        return Ok(Vec::new());
    }
    let phoff = usz(le_u64(bytes, 32).ok_or_else(malformed)?)?;
    let phentsize = le_u16(bytes, 54).ok_or_else(malformed)?;
    if phentsize != 56 {
        return Err(malformed());
    }
    let mut out = Vec::with_capacity(phnum);
    for i in 0..phnum {
        let ph = phoff
            .checked_add(i.checked_mul(phentsize).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        let field = |delta: usize| -> Result<usize, String> {
            usz(le_u64(bytes, ph.checked_add(delta).ok_or_else(malformed)?)
                .ok_or_else(malformed)?)
        };
        out.push(Segment {
            p_type: le_u32(bytes, ph).ok_or_else(malformed)?,
            offset: field(8)?,
            vaddr: field(16)?,
            filesz: field(32)?,
        });
    }
    Ok(out)
}

/// If the ELF has a PT_INTERP program header it must name
/// [`X86_64_GLIBC_INTERPRETER`]; a static binary (no PT_INTERP) is fine. Any
/// out-of-bounds program-header table or interpreter string is an error.
fn check_elf_interpreter(name: &str, bytes: &[u8]) -> Result<(), String> {
    for seg in elf_segments(name, bytes)? {
        if seg.p_type != 3 {
            continue; // not PT_INTERP
        }
        let end = seg
            .offset
            .checked_add(seg.filesz)
            .ok_or_else(|| malformed_phdrs(name))?;
        let interp = bytes
            .get(seg.offset..end)
            .ok_or_else(|| malformed_phdrs(name))?;
        // The loader requires the path to be NUL-terminated.
        let interp = interp
            .strip_suffix(&[0])
            .ok_or_else(|| malformed_phdrs(name))?;
        if interp != X86_64_GLIBC_INTERPRETER {
            return Err(format!(
                "prebuilt {name} requests interpreter '{}', expected '{}'",
                String::from_utf8_lossy(interp),
                String::from_utf8_lossy(X86_64_GLIBC_INTERPRETER)
            ));
        }
    }
    Ok(())
}

/// Longest `vna_name` the walk will look at (real ones are ~10 bytes).
const MAX_VERSION_NAME_LEN: usize = 256;
/// Largest prebuilt file (binary or descriptor) that will be read and hashed.
const MAX_PREBUILT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const DT_VERNEED: u64 = 0x6fff_fffe;
const DT_VERNEEDNUM: u64 = 0x6fff_ffff;

/// What the dynamic section says about glibc requirements.
#[derive(Debug, Default)]
struct DynamicInfo {
    strtab: Option<u64>,
    strsz: Option<u64>,
    verneed: Option<u64>,
    verneednum: Option<u64>,
    /// DT_RELR / DT_RELRSZ present (packed relative relocations).
    relr: bool,
}

fn set_once(slot: &mut Option<u64>, val: u64) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(val);
    Some(())
}

/// Read the PT_DYNAMIC entries up to DT_NULL. More than one PT_DYNAMIC is an
/// error (the loader uses one; which one would be ambiguous, and 65535
/// overlapping copies would be 65535 walks).
fn elf_dynamic_info(
    name: &str,
    bytes: &[u8],
    segs: &[Segment],
) -> Result<Option<DynamicInfo>, String> {
    let malformed = || malformed_phdrs(name);
    if segs.iter().filter(|s| s.p_type == PT_DYNAMIC).count() > 1 {
        return Err(malformed());
    }
    let Some(seg) = segs.iter().find(|s| s.p_type == PT_DYNAMIC) else {
        return Ok(None);
    };
    let end = seg.offset.checked_add(seg.filesz).ok_or_else(malformed)?;
    let dynamic = bytes.get(seg.offset..end).ok_or_else(malformed)?;
    let mut info = DynamicInfo::default();
    for entry in dynamic.chunks_exact(16) {
        let tag = le_u64(entry, 0).ok_or_else(malformed)?;
        let val = le_u64(entry, 8).ok_or_else(malformed)?;
        match tag {
            DT_NULL => break,
            // A repeated tag would make "which one counts" loader-specific.
            DT_STRTAB => set_once(&mut info.strtab, val).ok_or_else(malformed)?,
            DT_STRSZ => set_once(&mut info.strsz, val).ok_or_else(malformed)?,
            DT_VERNEED => set_once(&mut info.verneed, val).ok_or_else(malformed)?,
            DT_VERNEEDNUM => set_once(&mut info.verneednum, val).ok_or_else(malformed)?,
            DT_RELR | DT_RELRSZ => info.relr = true,
            _ => {}
        }
    }
    Ok(Some(info))
}

/// Map a virtual address to a file offset through the PT_LOAD segments.
fn elf_vaddr_to_offset(segs: &[Segment], vaddr: u64) -> Option<usize> {
    let vaddr = usize::try_from(vaddr).ok()?;
    // Exactly one PT_LOAD may map the address: overlapping segments would make
    // the file offset (and so the string/version data read) ambiguous.
    let mut hits = segs.iter().filter(|s| s.p_type == PT_LOAD).filter_map(|s| {
        let delta = vaddr.checked_sub(s.vaddr)?;
        (delta < s.filesz)
            .then(|| s.offset.checked_add(delta))
            .flatten()
    });
    let first = hits.next()?;
    if hits.next().is_some() {
        return None;
    }
    Some(first)
}

/// Highest glibc symbol version a dynamically-linked ELF requires, read the
/// way the loader reads it: DT_VERNEED's Verneed/Vernaux chain, with each
/// `vna_name` looked up in DT_STRTAB. (A whole-file text scan is NOT enough:
/// GNU ld tail-merges `.dynstr`, so `GLIBC_2.38` can live inside the bytes of
/// an imported symbol like `xGLIBC_2.38` and never appear NUL-delimited.)
/// Names other than `GLIBC_<digit>...` (GLIBC_PRIVATE, GLIBC_ABI_*) carry no
/// version. DT_RELR/DT_RELRSZ in a dynamically-linked (PT_INTERP) binary adds a
/// 2.36 requirement; a static-pie has no loader to care.
///
/// The chain is walked like ld.so walks it (follow `vn_next`/`vna_next` to the
/// 0 terminator) and then held to the counts its own headers claim
/// (DT_VERNEEDNUM, `vn_cnt`, `vn_version == 1`). Ambiguity is an error: more
/// than one PT_DYNAMIC, a repeated DT_STRTAB/DT_STRSZ/DT_VERNEED/DT_VERNEEDNUM,
/// or an address mapped by more than one PT_LOAD.
///
/// Fail closed: a program with PT_INTERP must have a PT_DYNAMIC with version
/// needs naming at least one `GLIBC_<version>` (a glibc program always does),
/// else its requirements are unverifiable;
/// any malformed chain/string table/mapping is an error. Work is bounded by
/// DT_VERNEEDNUM and by the file size (each Vernaux occupies 16 file bytes).
fn elf_required_glibc(name: &str, bytes: &[u8]) -> Result<Option<GlibcVersion>, String> {
    let malformed = || format!("prebuilt {name} has a malformed ELF version-needs table");
    let segs = elf_segments(name, bytes)?;
    let has_interp = segs.iter().any(|s| s.p_type == PT_INTERP);
    let Some(dynamic) = elf_dynamic_info(name, bytes, &segs)? else {
        return if has_interp {
            Err(format!(
                "prebuilt {name} has a dynamic loader but no PT_DYNAMIC; glibc requirements are unverifiable"
            ))
        } else {
            Ok(None) // static: no versioned glibc deps
        };
    };
    let mut max: Option<GlibcVersion> = None;
    let mut saw_version = false;
    if let Some(vn_addr) = dynamic.verneed {
        let strtab_addr = dynamic.strtab.ok_or_else(malformed)?;
        let strsz =
            usize::try_from(dynamic.strsz.ok_or_else(malformed)?).map_err(|_| malformed())?;
        let num =
            usize::try_from(dynamic.verneednum.ok_or_else(malformed)?).map_err(|_| malformed())?;
        let strtab_off = elf_vaddr_to_offset(&segs, strtab_addr).ok_or_else(malformed)?;
        let strtab = bytes
            .get(strtab_off..strtab_off.checked_add(strsz).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        // Every Verneed and Vernaux is 16 bytes of the file: more than
        // len/16 of them cannot be a real table.
        let budget = bytes.len() / 16;
        let over_budget =
            || format!("prebuilt {name} version-needs table exceeds the file-size bound");
        if num == 0 {
            return Err(malformed());
        }
        if num > budget {
            return Err(over_budget());
        }
        let mut remaining_aux = budget;
        let mut vn = elf_vaddr_to_offset(&segs, vn_addr).ok_or_else(malformed)?;
        // Walk exactly as ld.so does — follow vn_next / vna_next to the 0
        // terminator — and only then require the counts the headers claim
        // (DT_VERNEEDNUM, vn_cnt), so a table that disagrees with its own
        // headers cannot hide entries behind a short count.
        let mut seen_vn = 0usize;
        loop {
            seen_vn += 1;
            if seen_vn > num {
                return Err(malformed());
            }
            if le_u16(bytes, vn).ok_or_else(malformed)? != 1 {
                return Err(malformed()); // vn_version
            }
            let vn_cnt =
                le_u16(bytes, vn.checked_add(2).ok_or_else(malformed)?).ok_or_else(malformed)?;
            let vn_aux =
                le_u32(bytes, vn.checked_add(8).ok_or_else(malformed)?).ok_or_else(malformed)?;
            let vn_next =
                le_u32(bytes, vn.checked_add(12).ok_or_else(malformed)?).ok_or_else(malformed)?;
            let mut aux = vn.checked_add(vn_aux as usize).ok_or_else(malformed)?;
            let mut seen_aux = 0usize;
            loop {
                seen_aux += 1;
                remaining_aux = remaining_aux.checked_sub(1).ok_or_else(over_budget)?;
                let name_off = le_u32(bytes, aux.checked_add(8).ok_or_else(malformed)?)
                    .ok_or_else(malformed)? as usize;
                let vna_next = le_u32(bytes, aux.checked_add(12).ok_or_else(malformed)?)
                    .ok_or_else(malformed)?;
                let tail = strtab.get(name_off..).ok_or_else(malformed)?;
                // A version name is short; bounding the scan keeps a hostile
                // table (60000 names x a multi-MB string) from going quadratic.
                let len = tail
                    .iter()
                    .take(MAX_VERSION_NAME_LEN)
                    .position(|b| *b == 0)
                    .ok_or_else(malformed)?;
                let vna_name = &tail[..len];
                if vna_name == b"GLIBC_ABI_DT_RELR" {
                    // The linker's marker for DT_RELR: needs a 2.36 loader.
                    max = max.max(parse_glibc_version("2.36"));
                } else if let Some(rest) = vna_name.strip_prefix(b"GLIBC_")
                    && rest.first().is_some_and(u8::is_ascii_digit)
                {
                    let version = std::str::from_utf8(rest)
                        .ok()
                        .and_then(parse_glibc_version)
                        .ok_or_else(malformed)?;
                    saw_version = true;
                    max = max.max(Some(version));
                }
                if vna_next == 0 {
                    break;
                }
                aux = aux.checked_add(vna_next as usize).ok_or_else(malformed)?;
            }
            if seen_aux != vn_cnt {
                return Err(malformed());
            }
            if vn_next == 0 {
                break;
            }
            vn = vn.checked_add(vn_next as usize).ok_or_else(malformed)?;
        }
        if seen_vn != num {
            return Err(malformed());
        }
    } else if has_interp {
        return Err(format!(
            "prebuilt {name} is dynamically linked but has no DT_VERNEED; \
             its glibc requirements are unverifiable"
        ));
    }
    // A dynamically-linked glibc program names at least one GLIBC_<digit>
    // version; a table without any (only GLIBC_PRIVATE / garbage) proves nothing.
    if has_interp && !saw_version {
        return Err(format!(
            "prebuilt {name} names no GLIBC_<version> need; its glibc requirements are unverifiable"
        ));
    }
    if has_interp && dynamic.relr {
        max = max.max(parse_glibc_version("2.36"));
    }
    Ok(max)
}

/// Fail-closed validation of one `--prebuilt-node-binaries` directory: a flat
/// `<dir>/{rustynetd,rustynet-cli,rustynet-relay}` plus `PREBUILT.json`.
/// Every binary must be a non-empty regular file (no symlinks), an x86_64
/// ELF64, within the glibc `glibc_floor`, and match the descriptor's sha256;
/// the descriptor's `source_commit` must equal `expected_commit` exactly (the
/// orchestrator's own `git rev-parse HEAD`). The dir (not a symlink) and every
/// file must be owned by the running user and not group/world-writable. The
/// glibc requirement is read from the ELF itself ([`elf_required_glibc`]: the
/// DT_VERNEED version-needs table, walked like the loader does, plus DT_RELR),
/// so no `objdump` is needed and a name tail-merged into another `.dynstr`
/// string cannot hide.
///
/// The commit and hashes in `PREBUILT.json` are SELF-DECLARED by whoever wrote
/// the directory: passing proves internal consistency and label == HEAD, not
/// that the binaries were really built from that commit.
pub fn validate_prebuilt_dir(
    dir: &Path,
    expected_commit: &str,
    glibc_floor: &str,
) -> Result<ValidatedPrebuiltDir, String> {
    check_prebuilt_dir_trusted(dir)?;
    let descriptor_path = dir.join(PREBUILT_DESCRIPTOR_FILENAME);
    let descriptor_bytes = read_regular_file(&descriptor_path, PREBUILT_DESCRIPTOR_FILENAME)?;
    let descriptor: PrebuiltDescriptor = serde_json::from_slice(&descriptor_bytes)
        .map_err(|e| format!("parse {}: {e}", descriptor_path.display()))?;
    let expected_commit = expected_commit.trim();
    if expected_commit.is_empty() || descriptor.source_commit != expected_commit {
        return Err(format!(
            "prebuilt binaries in {} were built from commit '{}' but the orchestrator is at '{}'",
            dir.display(),
            descriptor.source_commit,
            expected_commit
        ));
    }
    if let Some(extra) = descriptor
        .sha256
        .keys()
        .find(|k| !NODE_BINARY_NAMES.contains(&k.as_str()))
    {
        return Err(format!(
            "{} lists unexpected binary '{extra}' in sha256",
            descriptor_path.display()
        ));
    }

    let mut binaries = Vec::with_capacity(NODE_BINARY_NAMES.len());
    let mut sha256 = std::collections::BTreeMap::new();
    let mut glibc_max: Option<GlibcVersion> = None;
    for name in NODE_BINARY_NAMES {
        let path = dir.join(name);
        let bytes = read_regular_file(&path, name)?;
        check_elf_x86_64(name, &bytes)?;
        // Reuse check_glibc_floor's floor parsing/comparison/message on the
        // version the ELF really requires.
        let required = elf_required_glibc(name, &bytes)?
            .map(|v| format!("GLIBC_{v}"))
            .unwrap_or_default();
        let this_max = check_glibc_floor(&required, glibc_floor)
            .map_err(|e| format!("prebuilt {name}: {e}"))?;
        if let Some(m) = this_max {
            glibc_max = Some(match glibc_max {
                Some(existing) => existing.max(m),
                None => m,
            });
        }
        let want = descriptor
            .sha256
            .get(*name)
            .ok_or_else(|| format!("{} has no sha256 for '{name}'", descriptor_path.display()))?;
        if !is_lower_hex(want, 64) {
            return Err(format!(
                "{} sha256 for '{name}' is not 64 lowercase hex digits",
                descriptor_path.display()
            ));
        }
        let got = crate::vm_lab::sha256_hex_bytes(&bytes);
        if &got != want {
            return Err(format!(
                "prebuilt {name} sha256 {got} does not match {PREBUILT_DESCRIPTOR_FILENAME} ({want})"
            ));
        }
        sha256.insert((*name).to_owned(), got);
        binaries.push(path);
    }
    Ok(ValidatedPrebuiltDir {
        binaries,
        sha256,
        source_commit: descriptor.source_commit,
        glibc_max,
    })
}

/// Validate every `--prebuilt-node-binaries` directory, then write the same
/// alias->binaries manifest the host-cross build writes — ONLY for the listed
/// aliases (unlisted aliases keep guest-building) — plus the run-local
/// provenance record. Returns the number of aliases. Nothing is written unless
/// every directory validated.
pub fn prepare_prebuilt_node_binaries(
    report_dir: &Path,
    prebuilt: &[(String, PathBuf)],
    expected_commit: &str,
    glibc_floor: &str,
) -> Result<usize, String> {
    let mut manifest: std::collections::BTreeMap<String, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    let mut nodes = serde_json::Map::new();
    for (alias, dir) in prebuilt {
        let validated = validate_prebuilt_dir(dir, expected_commit, glibc_floor)
            .map_err(|e| format!("prebuilt binaries for '{alias}': {e}"))?;
        nodes.insert(
            alias.clone(),
            serde_json::json!({
                "dir": dir.display().to_string(),
                "source_commit": validated.source_commit,
                "sha256": validated.sha256,
                "glibc_max": validated.glibc_max.as_ref().map(ToString::to_string),
            }),
        );
        manifest.insert(alias.clone(), validated.binaries);
    }
    let provenance = serde_json::json!({
        "schema_version": 1,
        // The commit and hashes are declared by whoever wrote PREBUILT.json;
        // this run only checked them for consistency (see validate_prebuilt_dir).
        "attestation": "self-declared",
        "orchestrator_commit": expected_commit.trim(),
        "glibc_floor": glibc_floor,
        "nodes": nodes,
    });
    let path = report_dir.join(PREBUILT_PROVENANCE_RELATIVE_PATH);
    // A resume/rerun over a report dir that already shipped prebuilt binaries
    // must ship the SAME ones: silently replacing the recorded hashes would
    // make the earlier evidence describe binaries that no longer exist.
    if path.is_file() {
        let existing = read_provenance(&path)?;
        if provenance_sums(&existing)? != provenance_sums(&provenance)? {
            return Err(format!(
                "{} already records different prebuilt binaries for this report dir; \
                 start a fresh report dir to change them",
                path.display()
            ));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create provenance dir {}: {e}", parent.display()))?;
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&provenance)
            .map_err(|e| format!("serialize prebuilt provenance: {e}"))?,
    )
    .map_err(|e| format!("write prebuilt provenance {}: {e}", path.display()))?;
    write_host_cross_manifest(report_dir, &manifest)?;
    Ok(manifest.len())
}

fn read_provenance(path: &Path) -> Result<serde_json::Value, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| format!("read prebuilt provenance {}: {e}", path.display()))?;
    serde_json::from_str(&json).map_err(|e| format!("parse prebuilt provenance: {e}"))
}

/// alias -> (binary name -> sha256) from a provenance document.
fn provenance_sums(
    value: &serde_json::Value,
) -> Result<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>, String>
{
    let nodes = value
        .get("nodes")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "prebuilt provenance has no nodes object".to_owned())?;
    nodes
        .iter()
        .map(|(alias, entry)| {
            let sums = serde_json::from_value(
                entry
                    .get("sha256")
                    .cloned()
                    .ok_or_else(|| format!("prebuilt provenance for '{alias}' has no sha256"))?,
            )
            .map_err(|e| format!("prebuilt provenance sha256 for '{alias}': {e}"))?;
            Ok((alias.clone(), sums))
        })
        .collect()
}

/// A run that will (re)install nodes over a report dir holding prebuilt
/// provenance — with or without `--prebuilt-node-binaries` on this invocation —
/// must be at the same commit the binaries were labelled with.
pub fn check_prebuilt_provenance_commit(
    report_dir: &Path,
    head_commit: &str,
    allow_dirty: bool,
) -> Result<(), String> {
    let path = report_dir.join(PREBUILT_PROVENANCE_RELATIVE_PATH);
    if !path.is_file() {
        return Ok(());
    }
    // Same rule as the flag-level check, for the resume branch where the flag
    // is absent: the recorded HEAD label means nothing for a dirty tree.
    if allow_dirty {
        return Err(format!(
            "{} records prebuilt binaries labelled with a HEAD commit; that does not hold \
             under --allow-dirty (use a fresh --report-dir or drop --allow-dirty)",
            path.display()
        ));
    }
    let recorded = read_provenance(&path)?;
    let recorded = recorded
        .get("orchestrator_commit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if recorded != head_commit.trim() {
        return Err(format!(
            "{} records prebuilt binaries for commit '{recorded}' but the orchestrator is at \
             '{}'; refusing to install them",
            path.display(),
            head_commit.trim()
        ));
    }
    Ok(())
}

/// The verified sha256 (binary name -> hex) recorded for `alias` by
/// [`prepare_prebuilt_node_binaries`]. `Ok(None)` only when this report dir has
/// NO prebuilt provenance at all (a plain host-cross run). Once provenance
/// exists, an alias without an entry — or a malformed record — is an error, so a
/// manifest entry can never be shipped unverified.
pub fn read_prebuilt_sha256(
    report_dir: &Path,
    alias: &str,
) -> Result<Option<std::collections::BTreeMap<String, String>>, String> {
    let path = report_dir.join(PREBUILT_PROVENANCE_RELATIVE_PATH);
    if !path.is_file() {
        return Ok(None);
    }
    let mut all = provenance_sums(&read_provenance(&path)?)?;
    all.remove(alias).map(Some).ok_or_else(|| {
        format!(
            "{} has no entry for '{alias}'; refusing to ship its binaries unverified",
            path.display()
        )
    })
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
        // EXACT Apple LLVM `objdump -T` shape (parenthesised version) — the host
        // format a token-prefix parser silently misses. 2.29 must beat 2.3
        // (numeric) and 2.2.5.
        let dump = "\
0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) memcpy
0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.3) __register_atfork
0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.29) pow
";
        assert_eq!(parse_max_glibc_version(dump).unwrap().to_string(), "2.29");
    }

    #[test]
    fn glibc_scan_handles_both_gnu_and_llvm_formats() {
        // GNU objdump prints a bare token, Apple LLVM parenthesises it. Both parse.
        assert_eq!(
            parse_max_glibc_version("... GLIBC_2.29 pow")
                .unwrap()
                .to_string(),
            "2.29"
        );
        assert_eq!(
            parse_max_glibc_version("... (GLIBC_2.29) pow")
                .unwrap()
                .to_string(),
            "2.29"
        );
    }

    #[test]
    fn glibc_floor_passes_within_and_fails_when_exceeded() {
        // Real host objdump lines (parenthesised) — the actual measured result.
        let dump = "(GLIBC_2.29) pow\n(GLIBC_2.17) clock_gettime\n";
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
            |_bin| Ok("(GLIBC_2.17) clock_gettime\n(GLIBC_2.29) pow\n".to_owned()),
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
            |_bin| Ok("(GLIBC_2.40) some_new_symbol\n".to_owned()),
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
    fn manifest_round_trips_and_absence_reads_none() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Absent manifest → None (a normal build-on-guest run).
        assert_eq!(read_host_cross_binaries(dir, "any").unwrap(), None);

        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "debian-headless-2".to_owned(),
            vec![
                PathBuf::from("/t/aarch64-unknown-linux-gnu/release/rustynetd"),
                PathBuf::from("/t/aarch64-unknown-linux-gnu/release/rustynet-cli"),
                PathBuf::from("/t/aarch64-unknown-linux-gnu/release/rustynet-relay"),
            ],
        );
        write_host_cross_manifest(dir, &m).unwrap();
        let got = read_host_cross_binaries(dir, "debian-headless-2")
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 3);
        assert!(got[0].ends_with("rustynetd"));
        // An alias not in the manifest reads None (fail-safe: takes normal path).
        assert_eq!(read_host_cross_binaries(dir, "not-listed").unwrap(), None);
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

    // ── --prebuilt-node-binaries ────────────────────────────────────────────

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    const BASE: u64 = 0x40_0000;
    /// Virtual base of the second PT_LOAD when `split_load` is set.
    const BASE2: u64 = 0x90_0000;
    const GOOD_INTERP: &[u8] = b"/lib64/ld-linux-x86-64.so.2";

    #[derive(Clone)]
    enum VerName {
        Plain(String),
        /// Stored inside the bytes of a longer string (`x<name>`), the way GNU
        /// ld tail-merges `.dynstr`: the name is never NUL-delimited on its left.
        TailMerged(String),
    }

    #[derive(Clone)]
    struct ElfSpec {
        class: u8,
        machine: u16,
        /// Extra bytes at the very end (stands in for code/rodata).
        tag: String,
        interp: Option<Vec<u8>>,
        names: Vec<VerName>,
        /// How many Verneed structures the names are split across.
        groups: usize,
        extra_dyn: Vec<(u64, u64)>,
        /// If non-empty, a second PT_DYNAMIC holding these entries.
        second_dynamic: Vec<(u64, u64)>,
        /// Two PT_LOADs with different vaddr-to-offset deltas (string table
        /// and version needs live in the second), as in a real binary.
        split_load: bool,
        /// A duplicate of the first PT_LOAD (overlapping mapping).
        dup_load: bool,
    }

    struct Layout {
        verneed: usize,
        dynamic: usize,
    }

    /// A dynamically-linked x86_64 glibc-shaped spec whose verneed names are
    /// the given raw strings (`GLIBC_2.34`, `GLIBC_PRIVATE`, ...).
    fn spec(names: &[&str]) -> ElfSpec {
        ElfSpec {
            class: 2,
            machine: 0x3E,
            tag: "x".to_owned(),
            interp: (!names.is_empty()).then(|| GOOD_INTERP.to_vec()),
            names: names
                .iter()
                .map(|n| VerName::Plain((*n).to_owned()))
                .collect(),
            groups: 1,
            extra_dyn: Vec::new(),
            second_dynamic: Vec::new(),
            split_load: false,
            dup_load: false,
        }
    }

    fn put16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn get64(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }
    fn put64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn dyn_bytes(entries: &[(u64, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, val) in entries.iter().chain(&[(0u64, 0u64)]) {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&val.to_le_bytes());
        }
        out
    }

    /// Lay out a real (if tiny) ELF64: header, program headers (one PT_LOAD
    /// mapping the whole file at BASE, optional PT_INTERP, PT_DYNAMIC and a
    /// second PT_DYNAMIC), interpreter, string table, Verneed/Vernaux chain,
    /// dynamic table, trailing `tag` bytes.
    fn build_elf(spec: &ElfSpec) -> (Vec<u8>, Layout) {
        let has_verneed = !spec.names.is_empty();
        let has_dyn = has_verneed || !spec.extra_dyn.is_empty();
        let has_second = !spec.second_dynamic.is_empty();
        let n_ph = 1
            + usize::from(spec.interp.is_some())
            + usize::from(has_dyn)
            + usize::from(has_second)
            + usize::from(spec.split_load)
            + usize::from(spec.dup_load);
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = spec.class;
        b[5] = 1;
        put16(&mut b, 16, 2); // ET_EXEC
        put16(&mut b, 18, spec.machine);
        put64(&mut b, 32, 64); // e_phoff
        put16(&mut b, 54, 56); // e_phentsize
        put16(&mut b, 56, n_ph as u16);
        b.resize(64 + n_ph * 56, 0);

        let interp_off = b.len();
        if let Some(i) = &spec.interp {
            b.extend_from_slice(i);
            b.push(0);
        }
        let interp_len = b.len() - interp_off;

        // String table: "\0libc.so.6\0" then the names.
        let strtab_off = b.len();
        // File offset -> virtual address. With `split_load`, everything from the
        // string table on is mapped at BASE2 (a different delta than BASE).
        let split = spec.split_load;
        let va = move |off: usize| -> u64 {
            if split && off >= strtab_off {
                BASE2 + (off - strtab_off) as u64
            } else {
                BASE + off as u64
            }
        };
        b.push(0);
        let file_off = b.len() - strtab_off;
        b.extend_from_slice(b"libc.so.6\0");
        let mut name_offs = Vec::new();
        for n in &spec.names {
            match n {
                VerName::Plain(s) => {
                    name_offs.push(b.len() - strtab_off);
                    b.extend_from_slice(s.as_bytes());
                }
                VerName::TailMerged(s) => {
                    b.push(b'x');
                    name_offs.push(b.len() - strtab_off);
                    b.extend_from_slice(s.as_bytes());
                }
            }
            b.push(0);
        }
        let strsz = b.len() - strtab_off;

        // Verneed structures, each followed by its Vernaux entries.
        let verneed_off = b.len();
        let groups = spec.groups.max(1);
        let per = spec.names.len().div_ceil(groups).max(1);
        let mut idx = 0usize;
        for g in 0..groups {
            let cnt = spec.names.len().saturating_sub(idx).min(per);
            if !has_verneed || cnt == 0 {
                break;
            }
            let base = b.len();
            let last = g + 1 == groups || idx + cnt >= spec.names.len();
            b.resize(base + 16 + 16 * cnt, 0);
            put16(&mut b, base, 1); // vn_version
            put16(&mut b, base + 2, cnt as u16); // vn_cnt
            put32(&mut b, base + 4, file_off as u32); // vn_file
            put32(&mut b, base + 8, 16); // vn_aux
            put32(
                &mut b,
                base + 12,
                if last { 0 } else { (16 + 16 * cnt) as u32 },
            );
            for k in 0..cnt {
                let aux = base + 16 + 16 * k;
                put16(&mut b, aux + 6, 2 + (idx + k) as u16); // vna_other
                put32(&mut b, aux + 8, name_offs[idx + k] as u32); // vna_name
                put32(&mut b, aux + 12, if k + 1 < cnt { 16 } else { 0 }); // vna_next
            }
            idx += cnt;
        }
        let real_groups = idx.div_ceil(per).max(1);

        // Dynamic table.
        let dyn_off = b.len();
        let mut entries = Vec::new();
        if has_dyn {
            entries.push((5, va(strtab_off))); // DT_STRTAB
            entries.push((10, strsz as u64)); // DT_STRSZ
        }
        if has_verneed {
            entries.push((0x6fff_fffe, va(verneed_off))); // DT_VERNEED
            entries.push((0x6fff_ffff, real_groups as u64)); // DT_VERNEEDNUM
        }
        entries.extend_from_slice(&spec.extra_dyn);
        let dyn_len = if has_dyn {
            let d = dyn_bytes(&entries);
            b.extend_from_slice(&d);
            d.len()
        } else {
            0
        };
        let dyn2_off = b.len();
        let dyn2_len = if has_second {
            let d = dyn_bytes(&spec.second_dynamic);
            b.extend_from_slice(&d);
            d.len()
        } else {
            0
        };
        b.extend_from_slice(spec.tag.as_bytes());

        // Program headers.
        let total = b.len();
        // (p_type, p_offset, p_vaddr, p_filesz)
        let mut phs: Vec<(u32, usize, u64, usize)> = if spec.split_load {
            vec![
                (1, 0, BASE, strtab_off),
                (1, strtab_off, BASE2, total - strtab_off),
            ]
        } else {
            vec![(1, 0, BASE, total)]
        };
        if spec.dup_load {
            phs.push((1, 0, BASE, total));
        }
        if spec.interp.is_some() {
            phs.push((3, interp_off, va(interp_off), interp_len));
        }
        if has_dyn {
            phs.push((2, dyn_off, va(dyn_off), dyn_len));
        }
        if has_second {
            phs.push((2, dyn2_off, va(dyn2_off), dyn2_len));
        }
        for (i, (t, off, vaddr, len)) in phs.iter().enumerate() {
            let ph = 64 + i * 56;
            put32(&mut b, ph, *t);
            put64(&mut b, ph + 8, *off as u64);
            put64(&mut b, ph + 16, *vaddr);
            put64(&mut b, ph + 32, *len as u64);
        }
        (
            b,
            Layout {
                verneed: verneed_off,
                dynamic: dyn_off,
            },
        )
    }

    fn elf(spec: &ElfSpec) -> Vec<u8> {
        build_elf(spec).0
    }

    /// Ordinary well-formed ELF: dynamic, glibc interpreter, verneed names
    /// `GLIBC_<v>` for each `v`; `tag` is trailing filler.
    fn synth_elf(class: u8, machine: u16, tag: &str, glibc: &[&str]) -> Vec<u8> {
        let names: Vec<String> = glibc.iter().map(|v| format!("GLIBC_{v}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut sp = spec(&refs);
        sp.class = class;
        sp.machine = machine;
        sp.tag = tag.to_owned();
        elf(&sp)
    }

    /// Same, with a chosen PT_INTERP string.
    fn synth_elf_interp(interp: &[u8]) -> Vec<u8> {
        let mut sp = spec(&["GLIBC_2.17"]);
        sp.interp = Some(interp.to_vec());
        elf(&sp)
    }

    fn write_descriptor(dir: &Path, commit: &str) {
        let mut sums = serde_json::Map::new();
        for name in NODE_BINARY_NAMES {
            let bytes = std::fs::read(dir.join(name)).unwrap();
            sums.insert(
                (*name).to_owned(),
                serde_json::Value::String(crate::vm_lab::sha256_hex_bytes(&bytes)),
            );
        }
        let doc = serde_json::json!({"source_commit": commit, "sha256": sums});
        std::fs::write(dir.join(PREBUILT_DESCRIPTOR_FILENAME), doc.to_string()).unwrap();
    }

    /// A valid prebuilt dir: three x86_64 ELF64 binaries needing glibc <= 2.34.
    fn valid_prebuilt_dir(dir: &Path) {
        for name in NODE_BINARY_NAMES {
            std::fs::write(
                dir.join(name),
                synth_elf(2, 0x3E, name, &["2.2.5", "2.34", "2.17"]),
            )
            .unwrap();
        }
        write_descriptor(dir, COMMIT);
    }

    #[test]
    fn prebuilt_dir_happy_path_reports_hashes_and_glibc_max() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let v = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap();
        assert_eq!(v.binaries.len(), 3);
        assert!(v.binaries[0].ends_with("rustynetd"));
        assert_eq!(v.glibc_max.as_ref().unwrap().to_string(), "2.34");
        assert_eq!(v.source_commit, COMMIT);
        for name in NODE_BINARY_NAMES {
            let bytes = std::fs::read(tmp.path().join(name)).unwrap();
            assert_eq!(v.sha256[*name], crate::vm_lab::sha256_hex_bytes(&bytes));
        }
    }

    #[test]
    fn prebuilt_dir_rejects_missing_and_empty_binary() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        std::fs::remove_file(tmp.path().join("rustynet-relay")).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(
            err.contains("rustynet-relay") && err.contains("missing"),
            "{err}"
        );

        valid_prebuilt_dir(tmp.path());
        std::fs::write(tmp.path().join("rustynetd"), b"").unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("rustynetd") && err.contains("empty"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn prebuilt_dir_rejects_symlinked_binary_and_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let real = tmp.path().join("real-cli");
        std::fs::rename(tmp.path().join("rustynet-cli"), &real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("rustynet-cli")).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("symlink"), "{err}");

        // The descriptor is held to the same rule.
        valid_prebuilt_dir(tmp.path());
        let real_desc = tmp.path().join("real-desc.json");
        std::fs::rename(tmp.path().join(PREBUILT_DESCRIPTOR_FILENAME), &real_desc).unwrap();
        std::os::unix::fs::symlink(&real_desc, tmp.path().join(PREBUILT_DESCRIPTOR_FILENAME))
            .unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn prebuilt_dir_rejects_wrong_elf_shape() {
        let mut big_endian = synth_elf(2, 0x3E, "x", &["2.17"]);
        big_endian[5] = 2; // EI_DATA = ELFDATA2MSB
        let mut relocatable = synth_elf(2, 0x3E, "x", &["2.17"]);
        relocatable[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        let mut core = synth_elf(2, 0x3E, "x", &["2.17"]);
        core[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
        let mut bad_phdr = synth_elf_interp(b"/lib64/ld-linux-x86-64.so.2");
        bad_phdr[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff off the end
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            // aarch64 machine
            ("machine", synth_elf(2, 0xB7, "x", &["2.17"]), "e_machine"),
            // ELFCLASS32
            ("class", synth_elf(1, 0x3E, "x", &["2.17"]), "64-bit"),
            // big-endian ELF (e_machine would be read byte-swapped)
            ("endian", big_endian, "little-endian"),
            ("e_type rel", relocatable, "e_type"),
            ("e_type core", core, "e_type"),
            // a loader other than the glibc x86_64 one
            (
                "interp musl",
                synth_elf_interp(b"/lib/ld-musl-x86_64.so.1"),
                "interpreter",
            ),
            ("phdr oob", bad_phdr, "malformed"),
            // not an ELF at all
            ("magic", b"#!/bin/sh\necho hi\n".repeat(8), "not an ELF"),
            // truncated header
            ("short", vec![0x7f, b'E', b'L', b'F', 2, 1], "not an ELF"),
        ];
        for (label, bytes, want) in cases {
            let tmp = tempfile::tempdir().unwrap();
            valid_prebuilt_dir(tmp.path());
            std::fs::write(tmp.path().join("rustynet-cli"), bytes).unwrap();
            write_descriptor(tmp.path(), COMMIT);
            let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
            assert!(err.contains(want), "{label}: {err}");
        }
        // The right interpreter, and a static binary (no PT_INTERP), pass.
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        std::fs::write(
            tmp.path().join("rustynet-cli"),
            synth_elf_interp(b"/lib64/ld-linux-x86-64.so.2"),
        )
        .unwrap();
        write_descriptor(tmp.path(), COMMIT);
        validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap();
    }

    fn put_cli_and_validate(bytes: Vec<u8>, floor: &str) -> Result<ValidatedPrebuiltDir, String> {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        std::fs::write(tmp.path().join("rustynet-cli"), bytes).unwrap();
        write_descriptor(tmp.path(), COMMIT);
        validate_prebuilt_dir(tmp.path(), COMMIT, floor)
    }

    fn required(bytes: Vec<u8>) -> Result<Option<GlibcVersion>, String> {
        elf_required_glibc("t", &bytes)
    }

    /// The requirement comes from the Verneed/Vernaux chain the loader reads.
    /// A name that lives only as the tail of another string (`xGLIBC_2.40`, as
    /// GNU ld's .dynstr tail-merging produces) is still found; a NUL-delimited
    /// `GLIBC_2.99` sitting in rodata is not a requirement.
    #[test]
    fn prebuilt_dir_reads_glibc_from_verneed_not_from_text() {
        let mut merged = spec(&["GLIBC_2.17"]);
        merged
            .names
            .push(VerName::TailMerged("GLIBC_2.40".to_owned()));
        let bytes = elf(&merged);
        // No NUL-delimited "GLIBC_2.40" exists anywhere in the file...
        assert!(!bytes.windows(12).any(|w| w == b"\0GLIBC_2.40\0"));
        // ...yet it is caught (a whole-file scan would accept this at 2.35).
        let err = put_cli_and_validate(bytes.clone(), "2.35").unwrap_err();
        assert!(err.contains("2.40"), "{err}");
        let ok = put_cli_and_validate(bytes, "2.40").unwrap();
        assert_eq!(ok.glibc_max.unwrap().to_string(), "2.40");
        // A NUL-delimited literal outside the verneed table is not a need.
        let mut decoy = spec(&["GLIBC_2.17"]);
        decoy.tag = "\0GLIBC_2.99\0".to_owned();
        put_cli_and_validate(elf(&decoy), "2.35").unwrap();
        assert_eq!(required(elf(&decoy)).unwrap().unwrap().to_string(), "2.17");
    }

    #[test]
    fn prebuilt_dir_verneed_takes_the_max_and_ignores_non_version_names() {
        let mut sp = spec(&["GLIBC_2.2.5", "GLIBC_2.34", "GLIBC_PRIVATE", "GLIBC_2.17"]);
        assert_eq!(required(elf(&sp)).unwrap().unwrap().to_string(), "2.34");
        // The same names spread over two Verneed structures (libc + another
        // library): the chain walk must follow vn_next.
        sp.groups = 2;
        assert_eq!(required(elf(&sp)).unwrap().unwrap().to_string(), "2.34");
        let mut late = spec(&["GLIBC_2.17", "GLIBC_2.17", "GLIBC_2.38"]);
        late.groups = 3;
        assert_eq!(required(elf(&late)).unwrap().unwrap().to_string(), "2.38");
    }

    #[test]
    fn prebuilt_dir_unverifiable_dynamic_binaries_are_rejected() {
        // Dynamic (PT_INTERP + PT_DYNAMIC) but no DT_VERNEED.
        let mut no_verneed = spec(&[]);
        no_verneed.interp = Some(GOOD_INTERP.to_vec());
        no_verneed.extra_dyn = vec![(1, 1)];
        let err = required(elf(&no_verneed)).unwrap_err();
        assert!(err.contains("unverifiable"), "{err}");
        // A loader but no PT_DYNAMIC at all.
        let mut no_dynamic = spec(&[]);
        no_dynamic.interp = Some(GOOD_INTERP.to_vec());
        assert!(
            required(elf(&no_dynamic))
                .unwrap_err()
                .contains("unverifiable")
        );
        // A genuinely static binary (no loader, no dynamic) has no needs.
        assert_eq!(required(elf(&spec(&[]))).unwrap(), None);
    }

    /// DT_RELR is read from the dynamic section, never from a string, and only
    /// matters to a dynamically-linked (PT_INTERP) program.
    #[test]
    fn prebuilt_dir_detects_dt_relr_structurally() {
        // The marker text alone (rodata / tail bytes) is not a requirement.
        let mut lit = spec(&["GLIBC_2.17"]);
        lit.tag = "\0GLIBC_ABI_DT_RELR\0".to_owned();
        put_cli_and_validate(elf(&lit), "2.35").unwrap();
        // Unrelated dynamic entries: fine at 2.35.
        let mut plain = spec(&["GLIBC_2.17"]);
        plain.extra_dyn = vec![(1, 0x10), (12, 0x20)];
        put_cli_and_validate(elf(&plain), "2.35").unwrap();
        // DT_RELR (36): needs 2.36.
        let mut relr = spec(&["GLIBC_2.17"]);
        relr.extra_dyn = vec![(36, 0x30)];
        let err = put_cli_and_validate(elf(&relr), "2.35").unwrap_err();
        assert!(err.contains("2.36"), "{err}");
        put_cli_and_validate(elf(&relr), "2.36").unwrap();
        // DT_RELRSZ (35) alone counts too.
        let mut relrsz = spec(&["GLIBC_2.17"]);
        relrsz.extra_dyn = vec![(35, 8)];
        assert!(put_cli_and_validate(elf(&relrsz), "2.35").is_err());
        // Entries after DT_NULL are ignored.
        let mut after_null = spec(&["GLIBC_2.17"]);
        after_null.extra_dyn = vec![(0, 0), (36, 0x30)];
        put_cli_and_validate(elf(&after_null), "2.35").unwrap();
        // More than one PT_DYNAMIC is ambiguous and refused, not "first wins".
        let mut second = spec(&["GLIBC_2.17"]);
        second.second_dynamic = vec![(36, 1)];
        let err = put_cli_and_validate(elf(&second), "2.35").unwrap_err();
        assert!(err.contains("malformed"), "{err}");
        // A static-pie (no PT_INTERP) with DT_RELR needs no glibc loader.
        let mut static_pie = spec(&[]);
        static_pie.extra_dyn = vec![(36, 1)];
        assert_eq!(required(elf(&static_pie)).unwrap(), None);
    }

    #[test]
    fn prebuilt_dir_glibc_abi_dt_relr_name_needs_2_36() {
        let sp = spec(&["GLIBC_2.17", "GLIBC_ABI_DT_RELR"]);
        assert_eq!(required(elf(&sp)).unwrap().unwrap().to_string(), "2.36");
        assert!(put_cli_and_validate(elf(&sp), "2.35").is_err());
        put_cli_and_validate(elf(&sp), "2.36").unwrap();
    }

    /// Two PT_LOADs with different vaddr-to-offset deltas (the string table and
    /// version needs are in the second): the mapping must go through the right
    /// segment, and only when exactly one matches.
    #[test]
    fn prebuilt_dir_maps_addresses_through_the_matching_pt_load() {
        let mut sp = spec(&["GLIBC_2.17", "GLIBC_2.38"]);
        sp.split_load = true;
        assert_eq!(required(elf(&sp)).unwrap().unwrap().to_string(), "2.38");
        assert!(put_cli_and_validate(elf(&sp), "2.35").is_err());
        put_cli_and_validate(elf(&sp), "2.38").unwrap();
        // An overlapping duplicate PT_LOAD makes the mapping ambiguous.
        let mut dup = spec(&["GLIBC_2.17"]);
        dup.dup_load = true;
        assert!(required(elf(&dup)).unwrap_err().contains("malformed"));
    }

    /// The table must agree with its own headers, and be unambiguous: extra
    /// entries hidden behind a short vn_cnt / DT_VERNEEDNUM, repeated dynamic
    /// tags, a second PT_DYNAMIC, or a table that names no GLIBC version are
    /// all refused.
    #[test]
    fn prebuilt_dir_rejects_inconsistent_or_ambiguous_version_tables() {
        type Patch = Box<dyn Fn(&mut Vec<u8>, &Layout)>;
        let mut two_groups = spec(&["GLIBC_2.17", "GLIBC_2.38"]);
        two_groups.groups = 2;
        let mut dup_strtab = spec(&["GLIBC_2.17"]);
        dup_strtab.extra_dyn = vec![(5, BASE + 0x10)];
        let mut dup_strsz = spec(&["GLIBC_2.17"]);
        dup_strsz.extra_dyn = vec![(10, 4)];
        let mut dup_verneed = spec(&["GLIBC_2.17"]);
        dup_verneed.extra_dyn = vec![(0x6fff_fffe, BASE + 0x10)];
        let mut dup_num = spec(&["GLIBC_2.17"]);
        dup_num.extra_dyn = vec![(0x6fff_ffff, 1)];
        let mut second_dyn = spec(&["GLIBC_2.17"]);
        second_dyn.second_dynamic = vec![(1, 1)];
        let cases: Vec<(&str, ElfSpec, Patch)> = vec![
            (
                "vn_cnt smaller than the real chain",
                spec(&["GLIBC_2.17", "GLIBC_2.38"]),
                Box::new(|b, l| put16(b, l.verneed + 2, 1)),
            ),
            (
                "vn_cnt larger than the real chain",
                spec(&["GLIBC_2.17", "GLIBC_2.38"]),
                Box::new(|b, l| put16(b, l.verneed + 2, 3)),
            ),
            (
                "DT_VERNEEDNUM smaller than the real chain",
                two_groups.clone(),
                Box::new(|b, l| put64(b, l.dynamic + 16 * 3 + 8, 1)),
            ),
            (
                "DT_VERNEEDNUM larger than the real chain",
                two_groups,
                Box::new(|b, l| put64(b, l.dynamic + 16 * 3 + 8, 3)),
            ),
            (
                "vn_version not 1",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put16(b, l.verneed, 2)),
            ),
            ("duplicate DT_STRTAB", dup_strtab, Box::new(|_, _| {})),
            ("duplicate DT_STRSZ", dup_strsz, Box::new(|_, _| {})),
            ("duplicate DT_VERNEED", dup_verneed, Box::new(|_, _| {})),
            ("duplicate DT_VERNEEDNUM", dup_num, Box::new(|_, _| {})),
            ("two PT_DYNAMIC", second_dyn, Box::new(|_, _| {})),
            (
                "PT_INTERP not NUL-terminated",
                spec(&["GLIBC_2.17"]),
                // PT_INTERP is the second program header; drop its last byte.
                Box::new(|b, _| {
                    let len = get64(b, 64 + 56 + 32);
                    put64(b, 64 + 56 + 32, len - 1);
                }),
            ),
            (
                "e_phentsize not 56",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, _| put16(b, 54, 64)),
            ),
        ];
        for (label, sp, patch) in cases {
            let (mut bytes, layout) = build_elf(&sp);
            patch(&mut bytes, &layout);
            let err = elf_required_glibc("t", &bytes)
                .and_then(|v| check_elf_x86_64("t", &bytes).map(|()| v))
                .expect_err(label);
            assert!(err.contains("malformed"), "{label}: {err}");
        }
        // A table with no GLIBC_<digit> name at all proves nothing.
        for names in [
            &["GLIBC_PRIVATE"][..],
            &["libc.so.6"][..],
            &["foo", "bar"][..],
        ] {
            let err = required(elf(&spec(names))).unwrap_err();
            assert!(err.contains("unverifiable"), "{names:?}: {err}");
        }
    }

    /// A table whose Vernaux chain overlaps itself (vna_next = 4) is bounded by
    /// the file-size budget rather than followed to the end of the file.
    #[test]
    fn prebuilt_dir_bounds_the_version_chain_by_file_size() {
        let mut sp = spec(&["GLIBC_2.17"]);
        // Every 4-byte word reads as 4: so at any overlapping window the
        // name offset is 4 and vna_next is 4.
        sp.tag = "\u{4}\0\0\0".repeat(4000);
        let (mut bytes, l) = build_elf(&sp);
        let tag_start = bytes.len() - 4 * 4000;
        let aux0 = l.verneed + 16;
        put32(&mut bytes, aux0 + 12, (tag_start - aux0) as u32);
        let err = required(bytes).unwrap_err();
        assert!(err.contains("file-size bound"), "{err}");
    }

    /// A hostile table of many names all pointing into one huge unterminated
    /// string must fail fast (this was quadratic: 60000 x 2 MB ~ 68 s).
    #[test]
    fn prebuilt_dir_long_version_name_scan_is_bounded() {
        let mut names: Vec<VerName> = vec![VerName::Plain("y".repeat(1_000_000))];
        names.extend((0..20_000).map(|_| VerName::Plain("GLIBC_2.17".to_owned())));
        let mut sp = spec(&["GLIBC_2.17"]);
        sp.names = names;
        let (mut bytes, l) = build_elf(&sp);
        let first_name_off = {
            let b: [u8; 4] = bytes[l.verneed + 16 + 8..l.verneed + 16 + 12]
                .try_into()
                .unwrap();
            u32::from_le_bytes(b)
        };
        for k in 0..20_001usize {
            put32(&mut bytes, l.verneed + 16 + 16 * k + 8, first_name_off);
        }
        let start = std::time::Instant::now();
        let err = required(bytes).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "name scan must be bounded, took {:?}",
            start.elapsed()
        );
    }

    /// Hostile version-needs tables and mappings are errors, never panics or
    /// silent accepts.
    #[test]
    fn prebuilt_dir_rejects_hostile_verneed_tables() {
        let two = || {
            let mut sp = spec(&["GLIBC_2.17", "GLIBC_2.34"]);
            sp.groups = 2; // two Verneed structs, one Vernaux each
            sp
        };
        let one_group_two_aux = || spec(&["GLIBC_2.17", "GLIBC_2.34"]);
        type Patch = Box<dyn Fn(&mut Vec<u8>, &Layout)>;
        let cases: Vec<(&str, ElfSpec, Patch)> = vec![
            (
                "vn_next zero before DT_VERNEEDNUM entries were read",
                two(),
                Box::new(|b, l| put32(b, l.verneed + 12, 0)),
            ),
            (
                "vna_next zero before vn_cnt entries were read",
                one_group_two_aux(),
                Box::new(|b, l| put32(b, l.verneed + 16 + 12, 0)),
            ),
            (
                "vna_name beyond DT_STRSZ",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put32(b, l.verneed + 16 + 8, 0x00ff_ffff)),
            ),
            (
                "DT_STRSZ overruns the file",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 16 + 8, 1 << 40)),
            ),
            (
                "DT_STRSZ cuts the name before its NUL",
                spec(&["GLIBC_2.17"]),
                // strtab is "\0libc.so.6\0GLIBC_2.17\0"; 14 ends inside the name.
                Box::new(|b, l| put64(b, l.dynamic + 16 + 8, 14)),
            ),
            (
                "DT_VERNEEDNUM huge",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 16 * 3 + 8, 1 << 40)),
            ),
            (
                "DT_VERNEEDNUM zero",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 16 * 3 + 8, 0)),
            ),
            (
                "vn_cnt 65535 in a tiny file",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put16(b, l.verneed + 2, 0xffff)),
            ),
            (
                "vn_aux off the file",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put32(b, l.verneed + 8, 0x7fff_ffff)),
            ),
            (
                "DT_VERNEED outside every PT_LOAD",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 16 * 2 + 8, 0x10)),
            ),
            (
                "DT_STRTAB outside every PT_LOAD",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 8, 0x10)),
            ),
            (
                "DT_STRTAB past the end of its PT_LOAD",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, l| put64(b, l.dynamic + 8, BASE + 0x10_0000)),
            ),
            (
                // The bytes exist in the file but PT_LOAD does not map them.
                "PT_LOAD does not cover the string table",
                spec(&["GLIBC_2.17"]),
                Box::new(|b, _| put64(b, 64 + 32, 0x40)),
            ),
            (
                "GLIBC_ name that is not a version",
                spec(&["GLIBC_2.4x"]),
                Box::new(|_, _| {}),
            ),
        ];
        for (label, sp, patch) in cases {
            let (mut bytes, layout) = build_elf(&sp);
            patch(&mut bytes, &layout);
            let err = required(bytes).expect_err(label);
            assert!(
                err.contains("malformed") || err.contains("file-size bound"),
                "{label}: {err}"
            );
        }
        // DT_VERNEED without DT_VERNEEDNUM (its tag rewritten to DT_NEEDED): unusable.
        let (mut bytes, l) = build_elf(&spec(&["GLIBC_2.17"]));
        put64(&mut bytes, l.dynamic + 16 * 3, 1);
        assert!(required(bytes).is_err());
    }

    /// A sparse file over the size cap is refused BEFORE it is read into memory.
    #[test]
    fn prebuilt_dir_rejects_an_oversized_binary_without_reading_it() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(tmp.path().join("rustynetd"))
            .unwrap();
        f.set_len(MAX_PREBUILT_FILE_BYTES + 1).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("limit") && err.contains("rustynetd"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn prebuilt_dir_rejects_untrusted_owner_mode_and_symlinked_dir() {
        use std::os::unix::fs::PermissionsExt;
        // Group-writable binary.
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let bin = tmp.path().join("rustynetd");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o664)).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(
            err.contains("writable") && err.contains("chmod go-w"),
            "{err}"
        );
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap();

        // World-writable descriptor.
        let desc = tmp.path().join(PREBUILT_DESCRIPTOR_FILENAME);
        std::fs::set_permissions(&desc, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").is_err());
        std::fs::set_permissions(&desc, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Group-writable directory.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("dir") && err.contains("writable"), "{err}");
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // The directory itself may not be a symlink.
        let holder = tempfile::tempdir().unwrap();
        let link = holder.path().join("link");
        std::os::unix::fs::symlink(tmp.path(), &link).unwrap();
        let err = validate_prebuilt_dir(&link, COMMIT, "2.39").unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn prebuilt_owner_check_rejects_a_foreign_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let meta = std::fs::symlink_metadata(tmp.path()).unwrap();
        let me = running_uid();
        check_owner_and_mode(&meta, "dir", tmp.path(), me).unwrap();
        let err = check_owner_and_mode(&meta, "dir", tmp.path(), me + 1).unwrap_err();
        assert!(err.contains("owned by uid"), "{err}");
    }

    #[test]
    fn prebuilt_dir_enforces_glibc_floor_inclusively() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        // A too-new symbol in ONE binary (numeric 2.40 > 2.39, not lexical).
        std::fs::write(
            tmp.path().join("rustynet-relay"),
            synth_elf(2, 0x3E, "relay", &["2.17", "2.40"]),
        )
        .unwrap();
        write_descriptor(tmp.path(), COMMIT);
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(
            err.contains("rustynet-relay") && err.contains("2.40"),
            "{err}"
        );
        // Exactly at the floor is accepted.
        validate_prebuilt_dir(tmp.path(), COMMIT, "2.40").unwrap();
        // A malformed floor never passes silently.
        assert!(validate_prebuilt_dir(tmp.path(), COMMIT, "two").is_err());
    }

    #[test]
    fn prebuilt_dir_rejects_sha256_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        // Tamper with a binary AFTER the descriptor was written: still a valid
        // ELF within the floor, so only the hash check can catch it.
        std::fs::write(
            tmp.path().join("rustynetd"),
            synth_elf(2, 0x3E, "tampered", &["2.17"]),
        )
        .unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("rustynetd") && err.contains("sha256"), "{err}");
    }

    #[test]
    fn prebuilt_dir_rejects_commit_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let other = "fedcba9876543210fedcba9876543210fedcba98";
        let err = validate_prebuilt_dir(tmp.path(), other, "2.39").unwrap_err();
        assert!(err.contains("commit"), "{err}");
        // A prefix of the right commit is not the right commit.
        assert!(validate_prebuilt_dir(tmp.path(), &COMMIT[..12], "2.39").is_err());
        // Neither is an empty expectation, even against an empty descriptor
        // commit (two empty strings must not "match").
        assert!(validate_prebuilt_dir(tmp.path(), "", "2.39").is_err());
        write_descriptor(tmp.path(), "");
        assert!(validate_prebuilt_dir(tmp.path(), "", "2.39").is_err());
        write_descriptor(tmp.path(), COMMIT);
        // Surrounding whitespace on the orchestrator side (git output) is fine.
        validate_prebuilt_dir(tmp.path(), &format!("{COMMIT}\n"), "2.39").unwrap();
    }

    #[test]
    fn prebuilt_dir_rejects_missing_or_garbled_descriptor() {
        let tmp = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(tmp.path());
        let desc = tmp.path().join(PREBUILT_DESCRIPTOR_FILENAME);

        std::fs::write(&desc, b"{not json").unwrap();
        assert!(validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").is_err());

        // Unknown field (a typo'd check must not be silently ignored).
        std::fs::write(
            &desc,
            format!(r#"{{"source_commit":"{COMMIT}","sha256":{{}},"sha265":{{}}}}"#),
        )
        .unwrap();
        assert!(validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").is_err());

        // A binary without a recorded hash.
        std::fs::write(
            &desc,
            format!(r#"{{"source_commit":"{COMMIT}","sha256":{{}}}}"#),
        )
        .unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("no sha256"), "{err}");

        // A hash that is not 64 lowercase hex digits.
        valid_prebuilt_dir(tmp.path());
        let text = std::fs::read_to_string(&desc).unwrap();
        let upper = text.replace(
            &crate::vm_lab::sha256_hex_bytes(&std::fs::read(tmp.path().join("rustynetd")).unwrap()),
            "ABC",
        );
        std::fs::write(&desc, upper).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("lowercase hex"), "{err}");

        std::fs::remove_file(&desc).unwrap();
        let err = validate_prebuilt_dir(tmp.path(), COMMIT, "2.39").unwrap_err();
        assert!(err.contains("PREBUILT.json"), "{err}");
    }

    #[test]
    fn prebuilt_manifest_covers_only_listed_aliases_and_records_provenance() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(a.path());
        valid_prebuilt_dir(b.path());
        let report = tempfile::tempdir().unwrap();
        let n = prepare_prebuilt_node_binaries(
            report.path(),
            &[
                ("azure-vm-1".to_owned(), a.path().to_path_buf()),
                ("lab-2".to_owned(), b.path().to_path_buf()),
            ],
            COMMIT,
            "2.39",
        )
        .unwrap();
        assert_eq!(n, 2);
        let got = read_host_cross_binaries(report.path(), "azure-vm-1")
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 3);
        assert!(got[0].starts_with(a.path()) && got[0].ends_with("rustynetd"));
        // An alias that was not listed (a node that still guest-builds) has no
        // entry, so the install adapter takes the normal build path for it.
        assert_eq!(
            read_host_cross_binaries(report.path(), "guest-built").unwrap(),
            None
        );
        // Once provenance exists, an alias without an entry is an error, never
        // "nothing to verify" (no silent unverified ship).
        assert!(read_prebuilt_sha256(report.path(), "guest-built").is_err());

        let sums = read_prebuilt_sha256(report.path(), "azure-vm-1")
            .unwrap()
            .unwrap();
        assert_eq!(sums.len(), 3);
        let bytes = std::fs::read(a.path().join("rustynetd")).unwrap();
        assert_eq!(sums["rustynetd"], crate::vm_lab::sha256_hex_bytes(&bytes));
        let prov: serde_json::Value = serde_json::from_slice(
            &std::fs::read(report.path().join(PREBUILT_PROVENANCE_RELATIVE_PATH)).unwrap(),
        )
        .unwrap();
        assert_eq!(prov["orchestrator_commit"], COMMIT);
        // Honest about what the binding is: declared by the dir's author.
        assert_eq!(prov["attestation"], "self-declared");
        assert_eq!(prov["nodes"]["lab-2"]["source_commit"], COMMIT);
        assert_eq!(prov["nodes"]["lab-2"]["glibc_max"], "2.34");
    }

    #[test]
    fn prebuilt_manifest_writes_nothing_when_any_dir_is_invalid() {
        let good = tempfile::tempdir().unwrap();
        let bad = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(good.path());
        valid_prebuilt_dir(bad.path());
        std::fs::remove_file(bad.path().join("rustynetd")).unwrap();
        let report = tempfile::tempdir().unwrap();
        let err = prepare_prebuilt_node_binaries(
            report.path(),
            &[
                ("ok".to_owned(), good.path().to_path_buf()),
                ("broken".to_owned(), bad.path().to_path_buf()),
            ],
            COMMIT,
            "2.39",
        )
        .unwrap_err();
        assert!(err.contains("'broken'"), "{err}");
        assert!(!report.path().join(HOST_CROSS_MANIFEST_FILENAME).exists());
        assert!(
            !report
                .path()
                .join(PREBUILT_PROVENANCE_RELATIVE_PATH)
                .exists()
        );
    }

    #[test]
    fn prebuilt_targets_must_be_linux_node_aliases() {
        let prebuilt = vec![("azure-vm-1".to_owned(), PathBuf::from("/p"))];
        let nodes = vec![
            ("azure-vm-1".to_owned(), VmGuestPlatform::Linux),
            ("mac-1".to_owned(), VmGuestPlatform::Macos),
        ];
        check_prebuilt_targets(&prebuilt, &nodes).unwrap();

        let err = check_prebuilt_targets(&[("ghost".to_owned(), PathBuf::from("/p"))], &nodes)
            .unwrap_err();
        assert!(err.contains("not one of the --node aliases"), "{err}");
        let err = check_prebuilt_targets(&[("mac-1".to_owned(), PathBuf::from("/p"))], &nodes)
            .unwrap_err();
        assert!(err.contains("Linux"), "{err}");
    }

    #[test]
    fn prebuilt_arch_must_be_x86_64() {
        require_prebuilt_arch("n", "x86_64\n").unwrap();
        require_prebuilt_arch("n", "amd64").unwrap();
        let err = require_prebuilt_arch("n", "aarch64").unwrap_err();
        assert!(err.contains("x86_64 only"), "{err}");
        assert!(require_prebuilt_arch("n", "riscv64").is_err());
    }

    #[test]
    fn prebuilt_flags_are_exclusive_with_host_cross_and_fail_closed() {
        let one = vec![("a".to_owned(), PathBuf::from("/p"))];
        check_prebuilt_flags(None, &one, None, false).unwrap();
        check_prebuilt_flags(Some("working-tree"), &one, Some("2.35"), false).unwrap();
        check_prebuilt_flags(None, &[], None, false).unwrap();

        // The exclusion is decided on the PARSED mode, so padding or an alias
        // cannot slip past it.
        for mode in [
            "host-cross-binary",
            " host-cross-binary ",
            "\thost-cross-binary",
        ] {
            let err = check_prebuilt_flags(Some(mode), &one, None, false).unwrap_err();
            assert!(err.contains("mutually exclusive"), "{mode:?}: {err}");
        }
        // An unparseable mode is refused, not treated as "not host-cross".
        assert!(check_prebuilt_flags(Some("host-cross-bin"), &one, None, false).is_err());
        let err = check_prebuilt_flags(None, &[], Some("2.39"), false).unwrap_err();
        assert!(err.contains("requires"), "{err}");
        assert!(check_prebuilt_flags(None, &one, Some("2.x"), false).is_err());
        let dup = vec![
            ("a".to_owned(), PathBuf::from("/p")),
            ("a".to_owned(), PathBuf::from("/q")),
        ];
        let err = check_prebuilt_flags(None, &dup, None, false).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
        // A dirty tree does not match the HEAD label: refused.
        let err = check_prebuilt_flags(None, &one, None, true).unwrap_err();
        assert!(err.contains("--allow-dirty"), "{err}");
        // ...but --allow-dirty without prebuilt binaries is not our business.
        check_prebuilt_flags(None, &[], None, true).unwrap();
    }

    #[test]
    fn prebuilt_resume_refuses_different_binaries_or_a_different_head() {
        let a = tempfile::tempdir().unwrap();
        valid_prebuilt_dir(a.path());
        let report = tempfile::tempdir().unwrap();
        let listed = vec![("n1".to_owned(), a.path().to_path_buf())];
        prepare_prebuilt_node_binaries(report.path(), &listed, COMMIT, "2.39").unwrap();
        // Same binaries again (resume/rerun) is fine.
        prepare_prebuilt_node_binaries(report.path(), &listed, COMMIT, "2.39").unwrap();
        check_prebuilt_provenance_commit(report.path(), COMMIT, false).unwrap();
        // A dirty tree cannot honour the recorded HEAD label (flag-less resume).
        let err = check_prebuilt_provenance_commit(report.path(), COMMIT, true).unwrap_err();
        assert!(err.contains("--allow-dirty"), "{err}");

        // A different binary set for the same report dir is refused, and the
        // recorded provenance is left untouched.
        let before = std::fs::read(report.path().join(PREBUILT_PROVENANCE_RELATIVE_PATH)).unwrap();
        std::fs::write(
            a.path().join("rustynetd"),
            synth_elf(2, 0x3E, "rebuilt", &["2.17"]),
        )
        .unwrap();
        write_descriptor(a.path(), COMMIT);
        let err =
            prepare_prebuilt_node_binaries(report.path(), &listed, COMMIT, "2.39").unwrap_err();
        assert!(err.contains("different prebuilt binaries"), "{err}");
        assert_eq!(
            before,
            std::fs::read(report.path().join(PREBUILT_PROVENANCE_RELATIVE_PATH)).unwrap()
        );
        // Likewise a different alias set.
        let other = vec![("n2".to_owned(), a.path().to_path_buf())];
        assert!(prepare_prebuilt_node_binaries(report.path(), &other, COMMIT, "2.39").is_err());

        // Provenance from another commit blocks an install at this HEAD, with
        // or without the flag; no provenance means nothing to check.
        let head2 = "fedcba9876543210fedcba9876543210fedcba98";
        let err = check_prebuilt_provenance_commit(report.path(), head2, false).unwrap_err();
        assert!(err.contains("refusing to install"), "{err}");
        let empty = tempfile::tempdir().unwrap();
        check_prebuilt_provenance_commit(empty.path(), head2, false).unwrap();
        // No provenance: --allow-dirty is not this feature's business.
        check_prebuilt_provenance_commit(empty.path(), head2, true).unwrap();
    }

    #[test]
    fn prebuilt_arg_parses_alias_equals_absolute_dir() {
        let (alias, dir) = parse_prebuilt_node_binaries_arg("azure-vm-1=/opt/pb/azure").unwrap();
        assert_eq!(alias, "azure-vm-1");
        assert_eq!(dir, PathBuf::from("/opt/pb/azure"));
        for bad in ["azure-vm-1", "=/x", "a=", "a=relative/dir", ""] {
            assert!(parse_prebuilt_node_binaries_arg(bad).is_err(), "{bad}");
        }
        assert_eq!(resolve_prebuilt_glibc_floor(None).unwrap(), "2.39");
        assert_eq!(resolve_prebuilt_glibc_floor(Some("2.31")).unwrap(), "2.31");
        assert!(resolve_prebuilt_glibc_floor(Some("")).is_err());
    }
}

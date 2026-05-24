# start.sh Operator-UX Rust Migration Plan (2026-05-24)

Status: active planning ledger. This document is the implementation guide
for migrating the remaining logic in `start.sh` (4,558 lines, 148 shell
functions) into Rust. It continues the
[ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md),
which already moved every privileged/secret-bearing flow into `rustynet ops`
subcommands. This plan covers what that plan deferred as "Phase D: optional
full Rust operator UX" plus cleanup of the last residual direct privileged
shell operations.

Line numbers reference `start.sh` and `crates/rustynet-cli/src/main.rs` as of
2026-05-24 and must be re-confirmed during implementation.

## 1. Why migrate (motivation)

1. **Cross-platform.** `start.sh` is bash; it does not run natively on
   Windows. Rustynet already ships a Windows daemon + CLI surface, but the
   operator experience is Linux/macOS-only. A Rust operator binary
   (`rustynet operator ...`) is natively cross-platform and removes the
   bash dependency.
2. **Security.** Config handling in shell uses dynamic variable assignment
   (`printf -v "${key}"`), string-templated file writes, and `stat`/`id`
   parsing. Porting to typed Rust removes injection/footgun surface, gives
   fail-closed typed validation, atomic `0600` writes, and reuses the
   hardened `rustynet-local-security` permission checks. It also collapses
   parse-fused-to-IO shell into testable pure functions.
3. **Maintainability and test coverage.** ~4.5k lines of untested bash
   become unit-tested Rust. This dovetails with
   [TestCoverageImprovementPlan_2026-05-24.md](./TestCoverageImprovementPlan_2026-05-24.md).

## 2. Current state (verified inventory)

- **Secret/privileged flows: already migrated.** No shell function
  generates, reads, or writes key/passphrase bytes. All custody, trust,
  membership, assignment, and service-lifecycle operations marshal
  `RUSTYNET_*` env vars and call a `rustynet ops ...` verb under `run_root`.
- **Residual DIRECT privileged shell ops (only two, both non-secret):**
  - `save_config` (L865-922): writes `wizard.env` then `chmod 600` (L921).
  - `ensure_binaries_available` (L1462-1507): `run_root install -m 0755`
    of `rustynetd` and `rustynet` into `/usr/local/bin` (L1495-1507).
- **The bulk of `start.sh` is now:** MENU_UX, CONFIG, ROLE_POLICY,
  validators, ARGS, DEP_BOOTSTRAP, NET_EGRESS, PEER_STORE display, and
  EXIT_SELECT orchestration that dispatches to the CLI.
- **Existing Rust surface to build on:**
  - `rustynet operator menu` — `execute_operator_menu()`
    (`main.rs:5660`): a minimal 6-option stub (status, netcheck, exit-off,
    advertise route, lan on/off). Far smaller than start.sh's role-aware
    multi-submenu UX.
  - 22 `rustynet ops` verbs (custody, trust, membership, service lifecycle,
    peer-store, assignment-refresh, LAN coupling, role coupling).
  - Front-door CLI verbs: `status`, `netcheck`, `exit-node select|off`,
    `lan-access on|off`, `route advertise`, `key rotate|revoke`.

The dispatch glue (SERVICE_DISPATCH, SECRET_PRIV orchestrators) does **not**
need re-migration — it already calls Rust. The operator menu in Rust just
needs to call the same `ops`/front-door verbs directly instead of shelling
through start.sh.

## 3. Target architecture

### 3.1 New library crate: `crates/rustynet-operator`

Add a transport-agnostic library crate holding the portable, pure,
unit-testable logic. Rationale: `rustynet-cli/src/main.rs` is already 23k
lines; piling operator logic into it worsens the maintainability problem. A
focused library crate is independently testable and keeps the binary thin.
It must declare `#![forbid(unsafe_code)]` (workspace lint) and depend on
`rustynet-local-security` for permission checks and `rustynet-control` for
role-capability mapping.

Proposed module layout:

```
crates/rustynet-operator/
  Cargo.toml
  src/
    lib.rs              // re-exports; crate docs
    config/
      model.rs          // OperatorConfig struct + field enums
      keys.rs           // allowlist + key<->field mapping
      parse.rs          // pure parse of wizard.env text -> OperatorConfig
      validate.rs       // fail-closed semantic validation
      persist.rs        // atomic 0600 write + file-security checks
    role.rs             // NodeRole, RolePreset, normalization + policy
    launch.rs           // LaunchProfile, LanMode, ExitChain validators
    args.rs             // StartArgs parser (typed)
    egress.rs           // pure parsers for `ip`/route output + endpoint host
    menu/
      model.rs          // MenuAction enum + role-aware menu trees
      mod.rs            // (render/dispatch lives in CLI; model is here)
```

The **interactive loop and process dispatch** (reading stdin, exec'ing
`rustynet ops`, `run_root`) stay in `rustynet-cli` because they are
binary/OS-bound; the **decisions** they make come from `rustynet-operator`
so they are testable without a TTY or root.

### 3.2 Shell role after migration

- `start.sh` shrinks to a thin bootstrap shim: locate or build the binary,
  then `exec rustynet operator menu`. Target end state ~40 lines.
- Windows users invoke `rustynet operator menu` directly (no shim needed).
- macOS/Linux keep the shim for the `./start.sh` muscle-memory entrypoint
  during transition; retire it after one release.

## 4. Per-area migration (concrete functions)

Ordered by ascending risk / ascending effort. Each item lists the shell
source, the Rust target (crate::module::function), behavior, security
controls, and required tests.

### 4.1 CONFIG model + parse + validate + persist (do first — highest security ROI, pure logic)

Replaces: `is_allowed_config_key` (L338), `normalize_config_value` (L350),
`validate_config_file_security` (L363), `load_config_file` (L404),
`validate_loaded_config_or_die` (L431), `save_config` (L865-922), and the
`enforce_*` policy functions (L485-541).

**`config/model.rs`**
```rust
/// Typed mirror of wizard.env. Every field corresponds to one allowlisted
/// key. Path-typed fields use PathBuf; bounded scalars use the enums below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub backend_mode: BackendMode,
    pub wg_listen_port: u16,
    pub node_role: Option<NodeRole>,
    pub setup_role_preset: Option<RolePreset>,
    pub default_launch_profile: LaunchProfile,
    pub auto_launch_on_start: bool,
    pub auto_launch_lan_mode: LanMode,
    pub exit_chain: ExitChain,
    pub fail_closed_ssh: FailClosedSsh,   // allow flag + required CIDRs
    pub auto_port_forward: AutoPortForward,
    // ... one field per allowlisted key (full list at start.sh L341)
}

impl OperatorConfig {
    /// Built-in defaults (mirrors the top-of-file defaults, start.sh L11-31).
    pub fn defaults_for_host(host: HostProfile) -> Self { /* ... */ }
}
```

**`config/keys.rs`**
```rust
/// The persistable-key allowlist (mirrors is_allowed_config_key, L341).
/// Returns Err for unknown keys so the loader can fail-closed or skip.
pub fn is_allowed_config_key(key: &str) -> bool;

/// Apply a raw KEY=value pair onto a partially-built config, with typed
/// coercion. Unknown keys are rejected (caller decides skip vs fail).
pub fn apply_kv(builder: &mut ConfigBuilder, key: &str, value: &str)
    -> Result<(), ConfigError>;
```

**`config/parse.rs`** (pure — the recurring "split parse from IO" pattern)
```rust
/// Parse wizard.env *text* into an OperatorConfig. No filesystem access.
/// - skips blank/`#` lines (start.sh L414)
/// - rejects malformed lines not matching ^[A-Z0-9_]+=.*$ (L415)
/// - strips surrounding single quotes (normalize_config_value, L350)
/// - drops trailing CR (L426)
/// - ignores unknown allowlisted keys with a collected warning
pub fn parse_wizard_env(text: &str) -> Result<ParsedConfig, ConfigError>;
```

**`config/validate.rs`** (pure, fail-closed — mirrors `validate_loaded_config_or_die` L431 + `enforce_*`)
```rust
/// Semantic validation. Returns the *enforced* config (policy defaults
/// applied) or a hard error. Mirrors:
///  - NODE_ROLE in {admin,client,blind_exit}, blind_exit host support (L434-449)
///  - exit-chain hops 1|2, node-id charset (L451-463)
///  - launch profile / auto-launch bool / lan mode (L465-477)
///  - MANUAL_PEER_OVERRIDE must be 0 (break-glass removed) (L478-482)
///  - backend mode valid for host (enforce_backend_mode, L485)
///  - AUTO_TUNNEL_ENFORCE forced to 1 (enforce_auto_tunnel_policy, L498)
///  - fail-closed SSH requires CIDRs (L505)
///  - wg listen port 1..=65535 (L518)
///  - auto-port-forward role/host gating (L525)
pub fn validate_and_enforce(parsed: ParsedConfig, host: HostProfile)
    -> Result<OperatorConfig, ConfigError>;
```

**`config/persist.rs`**
```rust
/// File-security gate (mirrors validate_config_file_security, L363):
/// reject symlink, reject owner != (current uid | 0), reject group/world
/// writable. Delegates the owner/mode checks to rustynet-local-security
/// so there is ONE hardened permission-check implementation.
pub fn assert_config_file_secure(path: &Path) -> Result<(), ConfigError>;

/// Atomic write of wizard.env at mode 0600 (replaces save_config's
/// string-templated write + chmod 600, L865-921). Write to a temp file in
/// the same dir, fsync, set 0600, then rename. No partial/torn files.
pub fn save_config_atomic(path: &Path, cfg: &OperatorConfig)
    -> Result<(), ConfigError>;

/// Load = assert_config_file_secure + read (bounded) + parse + validate.
pub fn load_config(path: &Path, host: HostProfile)
    -> Result<OperatorConfig, ConfigError>;
```

Security controls: typed fail-closed validation; no dynamic variable
assignment; atomic 0600 write; symlink/owner/mode rejection via
`rustynet-local-security`; bounded read (cap file size before parse).

Tests (all pure, no IO except persist round-trip in tempdir):
- allowlist accept/reject; malformed line rejection; quote-stripping; CR trim.
- every `enforce_*` reject path (bad role, blind_exit on unsupported host,
  bad hops, bad node-id, out-of-range port, missing SSH CIDRs,
  MANUAL_PEER_OVERRIDE != 0).
- `save_config_atomic` produces 0600, round-trips through `load_config`,
  and never leaves a temp file on simulated write failure.
- `assert_config_file_secure` rejects symlink, wrong owner, group/world
  writable (reuse local-security fixtures).

### 4.2 Role policy + validators (pure logic)

Replaces: `normalize_node_role` (L176), `normalize_role_preset` (L212),
`is_*_role` (L268-280), `require_admin_role` (L289),
`enforce_role_policy_defaults` (L299), `is_blind_exit_supported_host`
(L199), and the validators `is_valid_launch_profile` (L724),
`is_valid_lan_mode` (L731), `is_valid_exit_chain_hops` (L738),
`sanitize_exit_chain_defaults` (L745), `sanitize_launch_defaults` (L768),
`is_valid_node_id_value` (L2813).

**`role.rs`**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole { Admin, Client, BlindExit }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolePreset { /* the 6 presets from NodeRoleTaxonomy_2026-05-21.md */ }

impl NodeRole {
    pub fn parse(s: &str) -> Result<Self, RoleError>;          // L176/L434
    pub fn is_blind_exit_supported(host: HostProfile) -> bool; // L199
}

impl RolePreset {
    pub fn parse(s: &str) -> Result<Self, RoleError>;          // L212
    pub fn primary_role(self) -> NodeRole;                     // coercion, L212
    /// Map operator preset -> mesh RoleCapability set, delegating to
    /// rustynet_control::roles to keep one capability source of truth.
    pub fn capabilities(self) -> Vec<rustynet_control::roles::RoleCapability>;
}

/// Force role-appropriate defaults onto a config (mirrors L299): blind_exit
/// locks launch/port/trust posture; admin enables trust refresh; etc.
pub fn enforce_role_policy_defaults(cfg: &mut OperatorConfig);
```

**`launch.rs`**
```rust
pub enum LaunchProfile { Menu, Auto, /* quick-* variants, L724 */ }
pub enum LanMode { Skip, On, Off }                              // L731
pub struct ExitChain { pub hops: ExitChainHops, pub entry: Option<NodeId>, pub final_node: Option<NodeId> }
pub enum ExitChainHops { One, Two }                             // L738

impl LaunchProfile { pub fn parse(s: &str) -> Result<Self, _>; }
impl LanMode       { pub fn parse(s: &str) -> Result<Self, _>; }
impl ExitChain     { pub fn sanitize(self) -> Self; }           // L745
pub fn is_valid_node_id(s: &str) -> bool;                       // L2813
```

Tests: round-trip parse/Display for each enum; reject unknown tokens;
node-id charset boundary; exit-chain sanitize clamps invalid combos;
`enforce_role_policy_defaults` produces the locked posture for blind_exit.

### 4.3 Argument parser (pure logic)

Replaces: `parse_start_arguments` (L805) and `print_start_help` (L784).

**`args.rs`**
```rust
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StartArgs {
    pub requested_profile: Option<LaunchProfile>,
    pub auto_only: bool,
    pub requested_exit_node_id: Option<NodeId>,
    pub requested_lan_mode: Option<LanMode>,
}

/// Mirrors the shell flag set: --profile <v>, --auto, --exit-node-id <v>,
/// --lan <skip|on|off>, --help/-h. Fail-closed on missing values and
/// unknown flags (start.sh L806-862). Returns the typed struct or a usage
/// error carrying the help text.
pub fn parse_start_args<I: IntoIterator<Item = String>>(argv: I)
    -> Result<StartArgs, ArgsError>;

pub fn help_text() -> &'static str;
```

Tests: each flag, missing-value rejection, unknown-flag rejection,
`--auto` sets auto_only, invalid `--profile`/`--lan` rejected, `-h` returns
help.

### 4.4 Egress / endpoint parsing (split parse from IO)

Replaces: `detect_default_egress` (L924), `endpoint_host_from_value`
(L943), `route_interface_for_host` (L956),
`effective_selected_exit_node_for_egress` (L935), and the route-reconcile
helpers (L968-1027).

Pure parsers in **`egress.rs`** (the IO shim that runs `ip`/`route` stays in
the CLI and feeds captured stdout to these):
```rust
/// Parse `ip -o -4 route show to default` first line -> egress iface (L926).
pub fn parse_linux_default_route_iface(ip_output: &str) -> Option<String>;
/// Parse `route -n get default` (macOS) -> iface (L930).
pub fn parse_macos_default_route_iface(route_output: &str) -> Option<String>;
/// Parse `ip route get <host>` -> dev name (L956).
pub fn parse_route_get_dev(ip_output: &str) -> Option<String>;
/// Extract host from `[v6]:port` / `v4:port` endpoint string (L943).
pub fn endpoint_host_from_value(endpoint: &str) -> Option<String>;
```

Cross-platform note: add a Windows variant
(`parse_windows_default_route_iface`) backed by `GetBestRoute`/`netsh`
output; this is the kind of OS divergence that is far cleaner as typed Rust
than as bash `case` blocks.

Tests: golden `ip`/`route` output fixtures incl. IPv6 endpoints, multiple
routes, no-default-route, malformed lines.

### 4.5 Operator menu (the UX port)

Replaces: `main_menu` (L4398), the six `menu_*` submenus (L4116-4380),
`prompt_*` (L701-723), `show_runtime_config` (L3572),
`refresh_menu_runtime_status` (L3162), and label helpers.

Model in **`menu/model.rs`** (pure, testable):
```rust
/// One selectable operator action. Decoupled from rendering so the
/// role-aware tree can be unit-tested without a TTY.
pub enum MenuAction {
    ToggleConnection, SelectExitNode, DisableExit, OfferAsExit,
    ToggleLanAccess, AdvertiseRoute, Status, Netcheck, ShowDevices,
    ShowConfig, Doctor, FirstRunSetup, Reconfigure, SaveConfig,
    StartOrRestart, ShowServiceStatus, RefreshTrust, RotateKey,
    RevokeKey, Disconnect, SwitchRole, ConfigureLaunchDefaults, Quit,
}

/// Build the role-aware menu tree (admin / client / blind_exit variants,
/// and the blind_exit "locked" configuration view). Mirrors the structure
/// at start.sh L4116-4458. Pure function of role + lock state.
pub fn menu_tree(role: NodeRole, blind_exit_locked: bool) -> MenuTree;
```

Dispatch loop in `rustynet-cli` (extends `execute_operator_menu`,
`main.rs:5660`): render `menu_tree`, read stdin, and for each action call
the **existing** `ops`/front-door verbs (e.g. `IpcCommand::Status`,
`exit-node select`, `lan-access on`, the `ops restart-runtime-service`
path). The daemon-status header comes from `IpcCommand::Status` parsed into
typed fields (replaces `refresh_menu_runtime_status` + `extract_status_field`
awk at L3030/L3162).

Security: every privileged action continues to flow through the existing
`run_root` + `rustynet ops` argv-only path; the menu only chooses which verb
to call. No new privileged surface.

Tests: `menu_tree` produces the correct option set per role and hides
admin-only actions for client/blind_exit; locked blind_exit shows only
read-only entries (parity with L4316-4380).

### 4.6 Peer-store + exit-selection display (mostly already dispatched)

`PEER_STORE` (L2656-2789) and `EXIT_SELECT` (L2818-4054) already call
`rustynet ops peer-store-validate|list` and front-door `exit-node`/
`lan-access`/`route` verbs. Migration here is mechanical: move the
interactive prompts and the result formatting into the Rust menu dispatch,
reusing the typed status parser from 4.5. The pure helpers
`peer_endpoint_host` (L2680) and `extract_status_field` (L3030) move to
`egress.rs`/a `status.rs` parser with unit tests. No new `ops` verbs needed
except possibly `ops peer-store-probe` if we want online-probing
(`probe_peer_online_status`, L2696) off the shell `ping`.

### 4.7 Dependency / toolchain bootstrap (largest, most OS-specific — decide scope)

Covers `DEP_BOOTSTRAP` (L1028-1461): `package_manager` (L1028), `map_package`
(L1143), rustup/toolchain ensure (L1228-1371), `install_runtime_dependencies`
(L1372), homebrew/xcode CLT (L1057-1142), and `doctor_preflight` (L1515).

This is install-time glue with low runtime/secret risk but high OS
divergence. Recommended split:
- **Port the decision logic to Rust (pure, testable):** `map_package`
  (command -> distro package name, L1143) and the version/component checks
  become pure functions; the doctor checks (presence + permission audit,
  L1515) become a typed `DoctorReport`. Expose as
  `rustynet ops doctor` (report) and `rustynet setup deps --check`.
- **Keep the actual installer invocations argv-only from Rust**, not shell:
  run `apt-get`/`dnf`/`pacman`/`zypper`/`brew`/`rustup` via
  `std::process::Command` with explicit args (no shell string), matching the
  argv-only-exec mandate. A `PackageManager` enum abstracts the per-distro
  command construction.
- **Defer/keep-as-shim** the macOS Xcode CLT and Homebrew *first-install*
  (interactive `softwareupdate`) — these are genuinely interactive OS flows;
  wrap them but do not reimplement.

Cross-platform payoff: a Rust `rustynet ops doctor` and package abstraction
extends naturally to Windows (winget/choco) where bash cannot go.

Tests: `map_package` table; `PackageManager` argv construction per distro;
`DoctorReport` classification (missing dep, weak perms) with fixtures.

### 4.8 Residual direct privileged ops (close the last shell gaps)

1. **Config write/chmod** (`save_config` L921): handled by
   `config::persist::save_config_atomic` (4.1) — atomic 0600 in Rust.
2. **Binary install** (`ensure_binaries_available` L1495-1507:
   `run_root install -m 0755 .../rustynetd|rustynet`): migrate to a Rust op,
   e.g. `rustynet ops install-binaries --from <release-dir>` (or fold into
   the existing `ops install-systemd`). Enforce: absolute source path,
   source is a regular file owned appropriately, atomic copy to
   `/usr/local/bin`, mode 0755, argv-only. This removes the last direct
   `install` from the active shell path. The `cargo build --release`
   invocation may stay in the bootstrap shim (build-time, non-privileged).

## 5. Phasing and sequencing

- **Phase 1 — pure-logic core (no behavior change, fully unit-tested):**
  4.1 CONFIG, 4.2 role/validators, 4.3 args, 4.4 egress parsers, 4.5
  `menu_tree` model. Land `crates/rustynet-operator` with tests. `start.sh`
  unchanged. This is safe, high-coverage, and reviewable in isolation.
- **Phase 2 — wire the Rust operator menu:** expand `execute_operator_menu`
  to consume `rustynet-operator` (full role-aware menu + typed status). Add
  `rustynet operator menu` parity with start.sh's menus. Keep start.sh as
  the default entrypoint but have it able to `exec rustynet operator menu`.
- **Phase 3 — config + residual privileged ops:** switch start.sh's config
  load/validate/save to call Rust (or have the Rust operator own config
  end-to-end); add `ops install-binaries`; remove the two direct privileged
  shell ops.
- **Phase 4 — dependency bootstrap:** `ops doctor` + `PackageManager`
  abstraction (4.7); convert `install_runtime_dependencies` to argv-only
  Rust exec.
- **Phase 5 — shim reduction / retirement:** reduce `start.sh` to the
  bootstrap shim; document `rustynet operator menu` as the canonical
  entrypoint; add a Windows operator path. Retire start.sh after one release
  (use git history for rollback, per the existing migration plan's rule —
  do not keep a second active implementation in-tree).

## 6. Validation gates (run per phase)

Workspace gates (CLAUDE.md §7):
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Scope-specific:
- New `rustynet-operator` unit tests (target high branch coverage on
  config/validate/role/args/egress — these are the security-relevant pure
  functions).
- `./scripts/ci/phase10_gates.sh`, `./scripts/ci/membership_gates.sh`.
- Linux fresh-install + role-switch smoke (Debian/Mint/Ubuntu/Fedora) for
  Phases 2-4; macOS launchd/keychain sanity for any macOS-touching change.
- A behavior-parity check: drive `rustynet operator menu` through the same
  sequence as the shell menu and diff outcomes (status, exit select, lan
  toggle, config save).
- Add `rustynet-operator` to the coverage-gate floor set
  (`scripts/ci/regression_coverage_gates.sh`) once seeded.

## 7. Security guardrails (must hold at every step)

- No migration step may weaken fail-closed defaults or secret custody.
- All file paths: absolute, symlink-rejected, owner/mode-checked via
  `rustynet-local-security` (one hardened implementation).
- All external-process calls: argv-only `Command` (no shell string
  construction with untrusted values).
- Config writes: atomic, 0600, no torn files; bounded reads before parse.
- No secret material in logs or error strings (the daemon's secret-log
  audit scanner already covers the workspace; new crate is in scope).
- One hardened path per workflow; no dormant shell fallback once the Rust
  path lands.

## 8. Open decisions (confirm before/during implementation)

1. **New crate vs. modules in `rustynet-cli`.** This plan recommends a new
   `rustynet-operator` library crate for testability and to avoid growing
   the 23k-line main.rs. Confirm.
2. **Argument parsing style.** Manual typed parser (consistent with the
   existing `parse_command` in main.rs) vs. adopting `clap`. Recommend
   manual to match the codebase and avoid a new dependency in a
   security-sensitive surface; revisit if the flag set grows.
3. **Dependency-bootstrap scope.** Port decision logic + argv-only installer
   (recommended) vs. keep a thin shell installer for now. The interactive
   macOS first-install flows likely stay shimmed regardless.
4. **start.sh retirement timeline.** One release as a shim, then remove —
   confirm the deprecation window.

## 9. Bottom line

The hard part (secret/privileged custody) is already in Rust. This migration
is mostly porting **pure, testable logic** (config, role, validators, args,
egress) into a new `rustynet-operator` crate, then re-pointing a full
role-aware Rust operator menu at the `ops`/front-door verbs that already
exist. The two residual direct privileged shell ops (config chmod, binary
install) are closed by an atomic Rust config writer and one new
`ops install-binaries` verb. Net result: a cross-platform (incl. Windows)
operator experience, ~4.5k lines of untested bash replaced by unit-tested
Rust, and the last direct shell mutations removed from the active path.

Recommended first slice: **Phase 1, section 4.1 (CONFIG core)** — pure,
high security value, immediately gate-able, and it unblocks the menu wiring.

## Appendix A — Ready-to-paste reference implementations

These are complete, faithful Rust ports of the pure-logic `start.sh`
functions, written for the new `crates/rustynet-operator` crate. They are
`std`-only, `#![forbid(unsafe_code)]`-clean, Rust 2024 edition, and include
unit tests. Behavior mirrors the shell exactly (including its quirks, which
are called out in comments). The `print_warn`/`print_err` side effects are
replaced by returned `Vec<String>` warnings / `Result` errors so the logic
is pure and testable; the CLI layer prints them.

Drop each block at the path in its header comment. Known shell limitations
that are intentionally preserved are flagged with `// NOTE(parity):`.

### A.0 — Crate manifest

```toml
# crates/rustynet-operator/Cargo.toml
[package]
name = "rustynet-operator"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
# Pure-logic core needs no external deps. When wiring config<->capabilities,
# add: rustynet-control = { path = "../rustynet-control" }
# When delegating permission checks, add:
# rustynet-local-security = { path = "../rustynet-local-security" }

[lints]
workspace = true
```

Remember to add `"crates/rustynet-operator"` to the root `Cargo.toml`
`members` list.

### A.1 — `host.rs`

```rust
//! crates/rustynet-operator/src/host.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfile {
    Linux,
    Macos,
    Windows,
    Unsupported,
}

impl HostProfile {
    /// Detect the current host. Mirrors apply_host_profile_defaults (L133):
    /// anything that is not Linux/macOS/Windows is Unsupported.
    pub fn detect() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unsupported
        }
    }
}
```

### A.2 — `role.rs`

```rust
//! crates/rustynet-operator/src/role.rs
use crate::host::HostProfile;
use crate::launch::{ExitChain, ExitChainHops, LanMode, LaunchProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Admin,
    Client,
    BlindExit,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Client => "client",
            Self::BlindExit => "blind_exit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "client" => Some(Self::Client),
            "blind_exit" => Some(Self::BlindExit),
            _ => None,
        }
    }
}

/// The six user-selectable presets (NodeRoleTaxonomy_2026-05-21.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolePreset {
    Anchor,
    Admin,
    Exit,
    Relay,
    Client,
    BlindExit,
}

impl RolePreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anchor => "anchor",
            Self::Admin => "admin",
            Self::Exit => "exit",
            Self::Relay => "relay",
            Self::Client => "client",
            Self::BlindExit => "blind_exit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anchor" => Some(Self::Anchor),
            "admin" => Some(Self::Admin),
            "exit" => Some(Self::Exit),
            "relay" => Some(Self::Relay),
            "client" => Some(Self::Client),
            "blind_exit" => Some(Self::BlindExit),
            _ => None,
        }
    }

    /// Preset -> daemon-side primary role (start.sh L225-229).
    pub fn primary_role(self) -> NodeRole {
        match self {
            Self::Client => NodeRole::Client,
            Self::BlindExit => NodeRole::BlindExit,
            Self::Admin | Self::Exit | Self::Relay | Self::Anchor => NodeRole::Admin,
        }
    }
}

pub fn is_blind_exit_supported_host(host: HostProfile) -> bool {
    matches!(host, HostProfile::Linux | HostProfile::Macos)
}

/// Mirrors normalize_node_role + normalize_role_preset (start.sh L176-235).
/// Pure: returns the normalized role/preset plus operator-facing warnings.
///
/// NOTE(parity): the shell reverts an unsupported-host blind_exit to client
/// BEFORE applying preset coercion, so a `blind_exit` preset can re-assert
/// the blind_exit role on an unsupported host. This port preserves that
/// ordering; tighten it only as a deliberate, documented behavior change.
pub fn normalize_role(
    raw_role: Option<&str>,
    raw_preset: Option<&str>,
    setup_complete: bool,
    host: HostProfile,
) -> (NodeRole, Option<RolePreset>, Vec<String>) {
    let mut warnings = Vec::new();

    // --- normalize_node_role (L176) ---
    let mut role = match raw_role.map(str::trim).filter(|s| !s.is_empty()) {
        None => {
            if setup_complete {
                NodeRole::Admin
            } else {
                NodeRole::Client
            }
        }
        Some(s) => match NodeRole::parse(s) {
            Some(r) => r,
            None => {
                warnings.push(format!("Invalid NODE_ROLE='{s}', defaulting to 'client'."));
                NodeRole::Client
            }
        },
    };
    if role == NodeRole::BlindExit && !is_blind_exit_supported_host(host) {
        warnings.push(
            "blind_exit role is supported only on Linux/macOS hosts. Reverting to client role."
                .to_owned(),
        );
        role = NodeRole::Client;
    }

    // --- normalize_role_preset (L212) ---
    let preset = match raw_preset.map(str::trim).filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => match RolePreset::parse(s) {
            Some(p) => Some(p),
            None => {
                warnings.push(format!("Invalid SETUP_ROLE_PRESET='{s}', clearing."));
                None
            }
        },
    };
    if let Some(p) = preset {
        let expected = p.primary_role();
        if role != expected {
            warnings.push(format!(
                "NODE_ROLE='{}' does not match SETUP_ROLE_PRESET='{}'; coercing to '{}'.",
                role.as_str(),
                p.as_str(),
                expected.as_str()
            ));
            role = expected;
        }
    }

    (role, preset, warnings)
}

/// The role-policy fields enforce_role_policy_defaults mutates. In the full
/// crate these are fields of OperatorConfig (see plan §4.1); this focused
/// struct keeps the reference impl self-contained and unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePolicyState {
    pub node_role: NodeRole,
    pub manual_peer_override: bool,
    pub auto_refresh_trust: bool,
    pub default_launch_profile: LaunchProfile,
    pub auto_port_forward_exit: bool,
    pub exit_chain: ExitChain,
    pub auto_launch_on_start: bool,
    pub auto_launch_exit_node_id: Option<String>,
    pub auto_launch_lan_mode: LanMode,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_cidrs: Vec<String>,
}

/// Mirrors enforce_role_policy_defaults (start.sh L299). Pure: the caller
/// passes whether the trust signer key file exists (the shell does a `-f`
/// test, L306) so this stays IO-free. Assumes `node_role` is already
/// normalized via [`normalize_role`].
pub fn enforce_role_policy_defaults(
    state: &mut RolePolicyState,
    trust_signer_key_present: bool,
    trust_signer_key_path: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if state.node_role == NodeRole::Admin {
        return warnings;
    }

    // Break-glass manual peer override is removed; force off (L305).
    state.manual_peer_override = false;

    if state.auto_refresh_trust && !trust_signer_key_present {
        warnings.push(format!(
            "Trust signer key {trust_signer_key_path} is unavailable; disabling \
             AUTO_REFRESH_TRUST for role '{}'.",
            state.node_role.as_str()
        ));
        state.auto_refresh_trust = false;
    }

    match state.node_role {
        NodeRole::Client => {
            if matches!(
                state.default_launch_profile,
                LaunchProfile::QuickExitNode | LaunchProfile::QuickHybrid
            ) {
                warnings.push(format!(
                    "Launch profile '{}' is admin-only; forcing 'quick-connect' for client role.",
                    state.default_launch_profile.as_str()
                ));
                state.default_launch_profile = LaunchProfile::QuickConnect;
            }
            state.auto_port_forward_exit = false;
        }
        NodeRole::BlindExit => {
            if state.default_launch_profile != LaunchProfile::QuickExitNode {
                warnings.push(
                    "blind_exit role enforces default launch profile 'quick-exit-node'."
                        .to_owned(),
                );
                state.default_launch_profile = LaunchProfile::QuickExitNode;
            }
            state.exit_chain = ExitChain {
                hops: ExitChainHops::One,
                entry: None,
                final_node: None,
            };
            state.auto_launch_on_start = true;
            state.auto_launch_exit_node_id = None;
            state.auto_launch_lan_mode = LanMode::Off;
            state.fail_closed_ssh_allow = false;
            state.fail_closed_ssh_cidrs.clear();
        }
        NodeRole::Admin => {}
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_role_defaults_by_setup_state() {
        let (r, _, _) = normalize_role(None, None, true, HostProfile::Linux);
        assert_eq!(r, NodeRole::Admin);
        let (r, _, _) = normalize_role(None, None, false, HostProfile::Linux);
        assert_eq!(r, NodeRole::Client);
    }

    #[test]
    fn invalid_role_falls_back_to_client_with_warning() {
        let (r, _, w) = normalize_role(Some("wizard"), None, true, HostProfile::Linux);
        assert_eq!(r, NodeRole::Client);
        assert!(w.iter().any(|m| m.contains("Invalid NODE_ROLE")));
    }

    #[test]
    fn blind_exit_reverts_on_unsupported_host() {
        let (r, _, w) = normalize_role(Some("blind_exit"), None, true, HostProfile::Windows);
        assert_eq!(r, NodeRole::Client);
        assert!(w.iter().any(|m| m.contains("Reverting to client")));
    }

    #[test]
    fn preset_coerces_node_role() {
        let (r, p, w) = normalize_role(Some("client"), Some("exit"), true, HostProfile::Linux);
        assert_eq!(r, NodeRole::Admin); // exit preset -> admin primary
        assert_eq!(p, Some(RolePreset::Exit));
        assert!(w.iter().any(|m| m.contains("coercing")));
    }

    #[test]
    fn blind_exit_enforces_locked_posture() {
        let mut state = RolePolicyState {
            node_role: NodeRole::BlindExit,
            manual_peer_override: true,
            auto_refresh_trust: true,
            default_launch_profile: LaunchProfile::Menu,
            auto_port_forward_exit: true,
            exit_chain: ExitChain {
                hops: ExitChainHops::Two,
                entry: Some("a".to_owned()),
                final_node: Some("b".to_owned()),
            },
            auto_launch_on_start: false,
            auto_launch_exit_node_id: Some("x".to_owned()),
            auto_launch_lan_mode: LanMode::On,
            fail_closed_ssh_allow: true,
            fail_closed_ssh_cidrs: vec!["10.0.0.0/8".to_owned()],
        };
        let _ = enforce_role_policy_defaults(&mut state, true, "/etc/rustynet/trust.key");
        assert_eq!(state.default_launch_profile, LaunchProfile::QuickExitNode);
        assert_eq!(state.exit_chain.hops, ExitChainHops::One);
        assert!(state.exit_chain.entry.is_none());
        assert!(state.auto_launch_on_start);
        assert_eq!(state.auto_launch_lan_mode, LanMode::Off);
        assert!(!state.fail_closed_ssh_allow);
        assert!(state.fail_closed_ssh_cidrs.is_empty());
        assert!(!state.manual_peer_override);
    }

    #[test]
    fn client_downgrades_admin_only_profile_and_disables_port_forward() {
        let mut state = RolePolicyState {
            node_role: NodeRole::Client,
            manual_peer_override: false,
            auto_refresh_trust: false,
            default_launch_profile: LaunchProfile::QuickHybrid,
            auto_port_forward_exit: true,
            exit_chain: ExitChain { hops: ExitChainHops::One, entry: None, final_node: None },
            auto_launch_on_start: false,
            auto_launch_exit_node_id: None,
            auto_launch_lan_mode: LanMode::Skip,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_cidrs: Vec::new(),
        };
        let w = enforce_role_policy_defaults(&mut state, true, "/etc/rustynet/trust.key");
        assert_eq!(state.default_launch_profile, LaunchProfile::QuickConnect);
        assert!(!state.auto_port_forward_exit);
        assert!(w.iter().any(|m| m.contains("admin-only")));
    }

    #[test]
    fn missing_trust_signer_disables_auto_refresh_for_non_admin() {
        let mut state = RolePolicyState {
            node_role: NodeRole::Client,
            manual_peer_override: false,
            auto_refresh_trust: true,
            default_launch_profile: LaunchProfile::QuickConnect,
            auto_port_forward_exit: false,
            exit_chain: ExitChain { hops: ExitChainHops::One, entry: None, final_node: None },
            auto_launch_on_start: false,
            auto_launch_exit_node_id: None,
            auto_launch_lan_mode: LanMode::Skip,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_cidrs: Vec::new(),
        };
        let _ = enforce_role_policy_defaults(&mut state, false, "/etc/rustynet/trust.key");
        assert!(!state.auto_refresh_trust);
    }
}
```

### A.3 — `launch.rs`

```rust
//! crates/rustynet-operator/src/launch.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchProfile {
    Menu,
    QuickConnect,
    QuickExitNode,
    QuickHybrid,
}

impl LaunchProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Menu => "menu",
            Self::QuickConnect => "quick-connect",
            Self::QuickExitNode => "quick-exit-node",
            Self::QuickHybrid => "quick-hybrid",
        }
    }

    /// Mirrors is_valid_launch_profile (start.sh L724).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "menu" => Some(Self::Menu),
            "quick-connect" => Some(Self::QuickConnect),
            "quick-exit-node" => Some(Self::QuickExitNode),
            "quick-hybrid" => Some(Self::QuickHybrid),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanMode {
    Skip,
    On,
    Off,
}

impl LanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::On => "on",
            Self::Off => "off",
        }
    }

    /// Mirrors is_valid_lan_mode (start.sh L731).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skip" => Some(Self::Skip),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitChainHops {
    One,
    Two,
}

impl ExitChainHops {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::One => "1",
            Self::Two => "2",
        }
    }

    /// Mirrors is_valid_exit_chain_hops (start.sh L738).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "1" => Some(Self::One),
            "2" => Some(Self::Two),
            _ => None,
        }
    }
}

/// Mirrors is_valid_node_id_value (start.sh L2813): ^[A-Za-z0-9._-]+$.
pub fn is_valid_node_id(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitChain {
    pub hops: ExitChainHops,
    pub entry: Option<String>,
    pub final_node: Option<String>,
}

impl ExitChain {
    /// Mirrors sanitize_exit_chain_defaults (start.sh L745). Invalid node ids
    /// are cleared with a warning; a non-2-hop chain drops the final node;
    /// blind_exit forces a bare 1-hop chain.
    ///
    /// NOTE(parity): the shell also coerces an unparseable EXIT_CHAIN_HOPS
    /// string to "1" with a warning (L746-749). In the typed model that
    /// happens at parse time (see config/validate.rs), so `hops` is already
    /// valid here.
    pub fn sanitize(mut self, is_blind_exit: bool) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();

        if let Some(id) = &self.entry {
            if !is_valid_node_id(id) {
                warnings.push(format!(
                    "Invalid EXIT_CHAIN_ENTRY_NODE_ID='{id}', clearing."
                ));
                self.entry = None;
            }
        }
        if let Some(id) = &self.final_node {
            if !is_valid_node_id(id) {
                warnings.push(format!(
                    "Invalid EXIT_CHAIN_FINAL_NODE_ID='{id}', clearing."
                ));
                self.final_node = None;
            }
        }
        if self.hops != ExitChainHops::Two {
            self.final_node = None;
        }
        if is_blind_exit {
            self.hops = ExitChainHops::One;
            self.entry = None;
            self.final_node = None;
        }

        (self, warnings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_lan_round_trip() {
        for p in [
            LaunchProfile::Menu,
            LaunchProfile::QuickConnect,
            LaunchProfile::QuickExitNode,
            LaunchProfile::QuickHybrid,
        ] {
            assert_eq!(LaunchProfile::parse(p.as_str()), Some(p));
        }
        assert_eq!(LaunchProfile::parse("bogus"), None);
        for m in [LanMode::Skip, LanMode::On, LanMode::Off] {
            assert_eq!(LanMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(LanMode::parse("maybe"), None);
    }

    #[test]
    fn node_id_charset() {
        assert!(is_valid_node_id("node-1.host_A"));
        assert!(!is_valid_node_id(""));
        assert!(!is_valid_node_id("bad id"));
        assert!(!is_valid_node_id("slash/here"));
    }

    #[test]
    fn sanitize_clears_invalid_and_couples_hops() {
        let chain = ExitChain {
            hops: ExitChainHops::One,
            entry: Some("ok-id".to_owned()),
            final_node: Some("also-ok".to_owned()),
        };
        let (c, _) = chain.sanitize(false);
        // 1-hop drops the final node.
        assert!(c.final_node.is_none());
        assert_eq!(c.entry.as_deref(), Some("ok-id"));

        let chain = ExitChain {
            hops: ExitChainHops::Two,
            entry: Some("bad id".to_owned()),
            final_node: Some("good".to_owned()),
        };
        let (c, w) = chain.sanitize(false);
        assert!(c.entry.is_none());
        assert_eq!(c.final_node.as_deref(), Some("good"));
        assert!(w.iter().any(|m| m.contains("ENTRY_NODE_ID")));
    }

    #[test]
    fn blind_exit_forces_bare_single_hop() {
        let chain = ExitChain {
            hops: ExitChainHops::Two,
            entry: Some("a".to_owned()),
            final_node: Some("b".to_owned()),
        };
        let (c, _) = chain.sanitize(true);
        assert_eq!(c.hops, ExitChainHops::One);
        assert!(c.entry.is_none() && c.final_node.is_none());
    }
}
```

### A.4 — `args.rs`

```rust
//! crates/rustynet-operator/src/args.rs
use crate::launch::{LanMode, LaunchProfile};

/// `--auto` / `--profile auto` request the saved default; `--profile <p>`
/// requests a specific profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedLaunch {
    SavedDefault,
    Profile(LaunchProfile),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StartArgs {
    pub requested_profile: Option<RequestedLaunch>,
    pub auto_only: bool,
    pub requested_exit_node_id: Option<String>,
    pub requested_lan_mode: Option<LanMode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgsOutcome {
    Run(StartArgs),
    ShowHelp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgsError(pub String);

/// Mirrors parse_start_arguments (start.sh L805) + the post-parse validation
/// at L849-862. Fail-closed on missing values and unknown flags.
pub fn parse_start_args<I>(argv: I) -> Result<ArgsOutcome, ArgsError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = StartArgs::default();
    let mut requested_profile_raw: Option<String> = None;
    let mut it = argv.into_iter();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--profile" => {
                let v = it
                    .next()
                    .ok_or_else(|| ArgsError("--profile requires a value.".to_owned()))?;
                requested_profile_raw = Some(v);
            }
            "--auto" => {
                args.requested_profile = Some(RequestedLaunch::SavedDefault);
                args.auto_only = true;
            }
            "--exit-node-id" => {
                let v = it
                    .next()
                    .ok_or_else(|| ArgsError("--exit-node-id requires a value.".to_owned()))?;
                args.requested_exit_node_id = Some(v);
            }
            "--lan" => {
                let v = it
                    .next()
                    .ok_or_else(|| ArgsError("--lan requires a value (skip|on|off).".to_owned()))?;
                let mode = LanMode::parse(&v).ok_or_else(|| {
                    ArgsError(format!("Invalid --lan value '{v}'. Expected skip|on|off."))
                })?;
                args.requested_lan_mode = Some(mode);
            }
            "--help" | "-h" => return Ok(ArgsOutcome::ShowHelp),
            other => return Err(ArgsError(format!("Unknown argument: {other}"))),
        }
    }

    // Post-parse profile handling (start.sh L849-857). "auto" is a pseudo
    // profile meaning "use saved default"; it skips profile validation.
    if let Some(raw) = requested_profile_raw {
        if raw == "auto" {
            args.requested_profile = Some(RequestedLaunch::SavedDefault);
            args.auto_only = true;
        } else {
            let profile = LaunchProfile::parse(&raw)
                .ok_or_else(|| ArgsError(format!("Invalid --profile value '{raw}'.")))?;
            args.requested_profile = Some(RequestedLaunch::Profile(profile));
            // Any non-menu profile applies once and exits.
            if profile != LaunchProfile::Menu {
                args.auto_only = true;
            }
        }
    }

    Ok(ArgsOutcome::Run(args))
}

pub fn help_text() -> &'static str {
    "Rustynet startup options:\n  \
     ./start.sh\n    Interactive menu mode.\n    \
     Exit-node selection supports 1-hop and 2-hop chain prompts.\n\n  \
     ./start.sh --profile <menu|quick-connect|quick-exit-node|quick-hybrid>\n    \
     Apply a launch profile once. Non-menu profiles apply and exit.\n    \
     blind_exit role accepts only 'menu' or 'quick-exit-node'.\n\n  \
     ./start.sh --auto\n    Apply saved default launch profile once and exit.\n\n  \
     Optional modifiers:\n    \
     --exit-node-id <node-id>   Override configured exit node id for this run.\n    \
     --lan <skip|on|off>        Override configured LAN mode for this run.\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_explicit_profile_and_sets_auto_only() {
        let out = parse_start_args(argv(&["--profile", "quick-connect"])).unwrap();
        let ArgsOutcome::Run(a) = out else { panic!("expected run") };
        assert_eq!(
            a.requested_profile,
            Some(RequestedLaunch::Profile(LaunchProfile::QuickConnect))
        );
        assert!(a.auto_only);
    }

    #[test]
    fn menu_profile_stays_interactive() {
        let ArgsOutcome::Run(a) = parse_start_args(argv(&["--profile", "menu"])).unwrap() else {
            panic!()
        };
        assert!(!a.auto_only);
    }

    #[test]
    fn auto_flag_requests_saved_default() {
        let ArgsOutcome::Run(a) = parse_start_args(argv(&["--auto"])).unwrap() else { panic!() };
        assert_eq!(a.requested_profile, Some(RequestedLaunch::SavedDefault));
        assert!(a.auto_only);
    }

    #[test]
    fn missing_values_are_rejected() {
        assert!(parse_start_args(argv(&["--profile"])).is_err());
        assert!(parse_start_args(argv(&["--exit-node-id"])).is_err());
        assert!(parse_start_args(argv(&["--lan"])).is_err());
    }

    #[test]
    fn invalid_values_and_unknown_flags_are_rejected() {
        assert!(parse_start_args(argv(&["--profile", "turbo"])).is_err());
        assert!(parse_start_args(argv(&["--lan", "perhaps"])).is_err());
        assert!(parse_start_args(argv(&["--frobnicate"])).is_err());
    }

    #[test]
    fn help_short_circuits() {
        assert_eq!(parse_start_args(argv(&["--help"])).unwrap(), ArgsOutcome::ShowHelp);
        assert_eq!(parse_start_args(argv(&["-h"])).unwrap(), ArgsOutcome::ShowHelp);
    }
}
```

### A.5 — `egress.rs`

```rust
//! crates/rustynet-operator/src/egress.rs
use crate::launch::ExitChainHops;

/// Extract the host from a `[v6]:port` or `v4:port` endpoint string.
/// Mirrors endpoint_host_from_value (start.sh L943).
///
/// NOTE(parity): like the shell regex, the IPv4 form is not octet-range
/// checked (it accepts e.g. `999.1.1.1:51820`). Add range validation only as
/// a deliberate change.
pub fn endpoint_host_from_value(endpoint: &str) -> Option<String> {
    // Bracketed IPv6: [<hex/colon/dot>]:<digits>
    if let Some(rest) = endpoint.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after.strip_prefix(':')?;
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        let port_ok = !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
        return (host_ok && port_ok).then(|| host.to_owned());
    }

    // IPv4: a.b.c.d:port
    let (host, port) = endpoint.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let octets: Vec<&str> = host.split('.').collect();
    let ipv4_shaped = octets.len() == 4
        && octets
            .iter()
            .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
    ipv4_shaped.then(|| host.to_owned())
}

/// Parse `ip -o -4 route show to default` -> egress iface.
/// Mirrors detect_default_egress Linux branch (awk NR==1 {print $5}, L926).
///
/// NOTE(parity): assumes the `default via <gw> dev <iface> ...` shape, where
/// the iface is the 5th whitespace field. A `default dev <iface>` line (no
/// gateway) would mis-index, exactly as the shell awk does.
pub fn parse_linux_default_route_iface(ip_output: &str) -> Option<String> {
    let line = ip_output.lines().next()?;
    line.split_whitespace().nth(4).map(str::to_owned)
}

/// Parse macOS `route -n get default` -> iface.
/// Mirrors detect_default_egress macOS branch (awk /interface:/{print $2}, L930).
pub fn parse_macos_default_route_iface(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find(|line| line.contains("interface:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
}

/// Parse `ip -o -{4,6} route get <host>` -> dev name.
/// Mirrors route_interface_for_host (awk find "dev" then next token, L956).
pub fn parse_route_get_dev(ip_output: &str) -> Option<String> {
    let line = ip_output.lines().next()?;
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.iter()
        .position(|&t| t == "dev")
        .and_then(|i| toks.get(i + 1))
        .map(|s| (*s).to_owned())
}

/// Mirrors effective_selected_exit_node_for_egress (start.sh L935): on a
/// 2-hop chain where this device is the entry, the egress-relevant node is
/// the final hop; otherwise it is the entry.
pub fn effective_selected_exit_node_for_egress(
    hops: ExitChainHops,
    entry: Option<&str>,
    final_node: Option<&str>,
    device_node_id: &str,
) -> Option<String> {
    if hops == ExitChainHops::Two && entry == Some(device_node_id) {
        return final_node.map(str::to_owned);
    }
    entry.map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_host_ipv4_and_ipv6() {
        assert_eq!(endpoint_host_from_value("192.168.1.5:51820").as_deref(), Some("192.168.1.5"));
        assert_eq!(endpoint_host_from_value("[fd00::1]:51820").as_deref(), Some("fd00::1"));
        assert_eq!(endpoint_host_from_value("[::ffff:1.2.3.4]:1").as_deref(), Some("::ffff:1.2.3.4"));
        assert_eq!(endpoint_host_from_value("not-an-endpoint"), None);
        assert_eq!(endpoint_host_from_value("192.168.1.5"), None); // no port
        assert_eq!(endpoint_host_from_value("[fd00::1]:notaport"), None);
    }

    #[test]
    fn linux_default_route_field_five() {
        let out = "default via 10.0.0.1 dev eth0 proto dhcp metric 100";
        assert_eq!(parse_linux_default_route_iface(out).as_deref(), Some("eth0"));
        assert_eq!(parse_linux_default_route_iface(""), None);
    }

    #[test]
    fn macos_default_route_interface_line() {
        let out = "   route to: default\n   gateway: 10.0.0.1\n   interface: en0\n";
        assert_eq!(parse_macos_default_route_iface(out).as_deref(), Some("en0"));
    }

    #[test]
    fn route_get_dev_token() {
        let out = "10.0.0.1 dev wlan0 src 10.0.0.5 uid 1000";
        assert_eq!(parse_route_get_dev(out).as_deref(), Some("wlan0"));
        assert_eq!(parse_route_get_dev("blackhole 10.0.0.1"), None);
    }

    #[test]
    fn effective_exit_selects_final_on_two_hop_self_entry() {
        assert_eq!(
            effective_selected_exit_node_for_egress(ExitChainHops::Two, Some("me"), Some("dst"), "me")
                .as_deref(),
            Some("dst")
        );
        assert_eq!(
            effective_selected_exit_node_for_egress(ExitChainHops::Two, Some("other"), Some("dst"), "me")
                .as_deref(),
            Some("other")
        );
        assert_eq!(
            effective_selected_exit_node_for_egress(ExitChainHops::One, Some("entry"), None, "me")
                .as_deref(),
            Some("entry")
        );
    }
}
```

### A.6 — `config/keys.rs`

```rust
//! crates/rustynet-operator/src/config/keys.rs

/// The persistable-key allowlist. Mirrors is_allowed_config_key (start.sh
/// L341) exactly — keep this in sync with OperatorConfig's fields and with
/// save_config's emitted keys (L867-919).
pub fn is_allowed_config_key(key: &str) -> bool {
    matches!(
        key,
        "SOCKET_PATH"
            | "STATE_PATH"
            | "TRUST_EVIDENCE_PATH"
            | "TRUST_VERIFIER_KEY_PATH"
            | "TRUST_WATERMARK_PATH"
            | "AUTO_TUNNEL_ENFORCE"
            | "AUTO_TUNNEL_BUNDLE_PATH"
            | "AUTO_TUNNEL_VERIFIER_KEY_PATH"
            | "AUTO_TUNNEL_WATERMARK_PATH"
            | "AUTO_TUNNEL_MAX_AGE_SECS"
            | "TRAVERSAL_BUNDLE_PATH"
            | "TRAVERSAL_VERIFIER_KEY_PATH"
            | "TRAVERSAL_WATERMARK_PATH"
            | "TRAVERSAL_MAX_AGE_SECS"
            | "WG_INTERFACE"
            | "WG_LISTEN_PORT"
            | "AUTO_PORT_FORWARD_EXIT"
            | "AUTO_PORT_FORWARD_LEASE_SECS"
            | "WG_PRIVATE_KEY_PATH"
            | "WG_ENCRYPTED_PRIVATE_KEY_PATH"
            | "WG_KEY_PASSPHRASE_PATH"
            | "WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH"
            | "SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH"
            | "WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT"
            | "WG_PUBLIC_KEY_PATH"
            | "EGRESS_INTERFACE"
            | "MEMBERSHIP_SNAPSHOT_PATH"
            | "MEMBERSHIP_LOG_PATH"
            | "MEMBERSHIP_WATERMARK_PATH"
            | "MEMBERSHIP_OWNER_SIGNING_KEY_PATH"
            | "BACKEND_MODE"
            | "DATAPLANE_MODE"
            | "PRIVILEGED_HELPER_SOCKET_PATH"
            | "PRIVILEGED_HELPER_TIMEOUT_MS"
            | "RECONCILE_INTERVAL_MS"
            | "MAX_RECONCILE_FAILURES"
            | "FAIL_CLOSED_SSH_ALLOW"
            | "FAIL_CLOSED_SSH_ALLOW_CIDRS"
            | "TRUST_SIGNER_KEY_PATH"
            | "AUTO_REFRESH_TRUST"
            | "DEVICE_NODE_ID"
            | "SETUP_COMPLETE"
            | "NODE_ROLE"
            | "SETUP_ROLE_PRESET"
            | "MANUAL_PEER_OVERRIDE"
            | "MANUAL_PEER_AUDIT_LOG"
            | "DEFAULT_LAUNCH_PROFILE"
            | "AUTO_LAUNCH_ON_START"
            | "AUTO_LAUNCH_EXIT_NODE_ID"
            | "AUTO_LAUNCH_LAN_MODE"
            | "EXIT_CHAIN_HOPS"
            | "EXIT_CHAIN_ENTRY_NODE_ID"
            | "EXIT_CHAIN_FINAL_NODE_ID"
            | "HOST_PROFILE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_known_keys_and_rejects_unknown() {
        assert!(is_allowed_config_key("NODE_ROLE"));
        assert!(is_allowed_config_key("WG_LISTEN_PORT"));
        assert!(!is_allowed_config_key("DROP_ALL_TABLES"));
        assert!(!is_allowed_config_key("node_role")); // case-sensitive
        assert!(!is_allowed_config_key(""));
    }
}
```

### A.7 — `config/parse.rs`

```rust
//! crates/rustynet-operator/src/config/parse.rs
use crate::config::keys::is_allowed_config_key;
use std::collections::BTreeMap;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedConfig {
    pub values: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

/// Strip a single layer of surrounding single quotes.
/// Mirrors normalize_config_value (start.sh L350).
pub fn normalize_config_value(value: &str) -> String {
    if value == "''" {
        return String::new();
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        return value[1..value.len() - 1].to_owned();
    }
    value.to_owned()
}

/// Parse wizard.env *text* into an allowlisted key/value map plus warnings.
/// No filesystem access. Mirrors load_config_file's line loop (start.sh
/// L413-428):
///   * skip blank lines and lines whose first non-space char is '#'
///   * a line must match `^[A-Z0-9_]+=.*$`, else warn "malformed" and skip
///   * unknown (non-allowlisted) keys warn and are skipped
///   * the value has one layer of surrounding quotes stripped
///
/// NOTE(parity): `str::lines()` already strips a trailing `\r`, so the shell's
/// explicit CR trim (L426) is unnecessary here.
pub fn parse_wizard_env(text: &str) -> ParsedConfig {
    let mut out = ParsedConfig::default();

    for line in text.lines() {
        let lead_trimmed = line.trim_start();
        if lead_trimmed.is_empty() || lead_trimmed.starts_with('#') {
            continue;
        }

        let Some(eq) = line.find('=') else {
            out.warnings.push("Ignoring malformed config line.".to_owned());
            continue;
        };
        let key = &line[..eq];
        let raw_value = &line[eq + 1..];

        let key_shaped = !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !key_shaped {
            out.warnings.push("Ignoring malformed config line.".to_owned());
            continue;
        }

        if !is_allowed_config_key(key) {
            out.warnings
                .push(format!("Ignoring unknown config key '{key}'."));
            continue;
        }

        out.values
            .insert(key.to_owned(), normalize_config_value(raw_value));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_one_quote_layer() {
        assert_eq!(normalize_config_value("''"), "");
        assert_eq!(normalize_config_value("'abc'"), "abc");
        assert_eq!(normalize_config_value("plain"), "plain");
        assert_eq!(normalize_config_value("'a'b'"), "a'b"); // greedy outer strip
    }

    #[test]
    fn parses_allowlisted_keys_only() {
        let text = "\
# comment line
   # indented comment

NODE_ROLE=admin
WG_LISTEN_PORT='51820'
UNKNOWN_KEY=whatever
not a config line
lowercase=skip
";
        let parsed = parse_wizard_env(text);
        assert_eq!(parsed.values.get("NODE_ROLE").map(String::as_str), Some("admin"));
        assert_eq!(parsed.values.get("WG_LISTEN_PORT").map(String::as_str), Some("51820"));
        assert!(!parsed.values.contains_key("UNKNOWN_KEY"));
        assert!(!parsed.values.contains_key("lowercase"));
        // one "unknown key" warning + two "malformed line" warnings
        assert!(parsed.warnings.iter().any(|w| w.contains("unknown config key 'UNKNOWN_KEY'")));
        assert_eq!(parsed.warnings.iter().filter(|w| w.contains("malformed")).count(), 2);
    }
}
```

### A.8 — `config/persist.rs` (Unix)

```rust
//! crates/rustynet-operator/src/config/persist.rs
use std::fs::{self, OpenOptions, Permissions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Insecure(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "config io error: {m}"),
            Self::Insecure(m) => write!(f, "config security error: {m}"),
        }
    }
}
impl std::error::Error for ConfigError {}

/// Atomic 0600 write. Replaces save_config's templated write + chmod
/// (start.sh L865-921): write to a sibling temp file created mode-0600,
/// fsync, then rename over the target so readers never see a torn file.
/// Consider delegating the final owner/mode assertion to
/// `rustynet-local-security` to keep one hardened permission path.
#[cfg(unix)]
pub fn save_config_atomic(path: &Path, serialized: &str) -> Result<(), ConfigError> {
    let dir = path
        .parent()
        .ok_or_else(|| ConfigError::Io("config path has no parent directory".to_owned()))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ConfigError::Io("config path has no file name".to_owned()))?;
    let tmp = dir.join(format!(".{file_name}.tmp"));

    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| ConfigError::Io(format!("open temp {}: {e}", tmp.display())))?;
        f.write_all(serialized.as_bytes())
            .map_err(|e| ConfigError::Io(format!("write temp: {e}")))?;
        // Re-assert mode in case a permissive umask altered create().
        f.set_permissions(Permissions::from_mode(0o600))
            .map_err(|e| ConfigError::Io(format!("chmod temp: {e}")))?;
        f.sync_all()
            .map_err(|e| ConfigError::Io(format!("fsync temp: {e}")))?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        ConfigError::Io(format!("rename temp into place: {e}"))
    })
}

/// File-security gate. Mirrors validate_config_file_security (start.sh L363):
/// a missing file is OK; reject symlinks, owners other than the current uid
/// or root, and group/world-writable modes.
#[cfg(unix)]
pub fn assert_config_file_secure(path: &Path, current_uid: u32) -> Result<(), ConfigError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ConfigError::Io(format!("stat config: {e}"))),
    };

    if meta.file_type().is_symlink() {
        return Err(ConfigError::Insecure(format!(
            "Refusing to load symlink config file: {}",
            path.display()
        )));
    }

    let owner = meta.uid();
    if owner != current_uid && owner != 0 {
        return Err(ConfigError::Insecure(format!(
            "Config file owner is not trusted ({}, uid={owner}).",
            path.display()
        )));
    }

    let mode = meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(ConfigError::Insecure(format!(
            "Config file must not be group/world writable: {} (mode {:03o}).",
            path.display(),
            mode & 0o777
        )));
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn atomic_write_sets_0600_and_round_trips() {
        let dir = std::env::temp_dir().join(format!("rustynet-op-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wizard.env");
        save_config_atomic(&path, "NODE_ROLE=admin\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "NODE_ROLE=admin\n");

        // no leftover temp file
        assert!(!dir.join(".wizard.env.tmp").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_secure() {
        let path = std::env::temp_dir().join("rustynet-nonexistent-cfg-xyz.env");
        let _ = fs::remove_file(&path);
        assert!(assert_config_file_secure(&path, 1000).is_ok());
    }

    #[test]
    fn group_writable_is_rejected() {
        let dir = std::env::temp_dir().join(format!("rustynet-op-gw-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wizard.env");
        fs::write(&path, "x").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o660)).unwrap();
        let current = nix_uid();
        let res = assert_config_file_secure(&path, current);
        assert!(matches!(res, Err(ConfigError::Insecure(_))));
        fs::remove_dir_all(&dir).ok();
    }

    // Minimal uid fetch without adding a dependency: read from metadata of a
    // file we just created (owned by us).
    fn nix_uid() -> u32 {
        let probe = std::env::temp_dir().join(format!("rustynet-uid-probe-{}", std::process::id()));
        fs::write(&probe, "").unwrap();
        let uid = fs::metadata(&probe).unwrap().uid();
        let _ = fs::remove_file(&probe);
        uid
    }
}
```

### A.9 — Wiring notes for the implementer

- **`lib.rs`** should declare `#![forbid(unsafe_code)]` and the module tree:
  `pub mod host; pub mod role; pub mod launch; pub mod args; pub mod egress;
  pub mod config { pub mod keys; pub mod parse; pub mod persist; }`.
- **Load pipeline** (replaces the shell startup sequence at L4502+):
  `assert_config_file_secure` → read (bounded) → `parse_wizard_env` →
  build a typed config → `normalize_role` → per-field validators →
  `enforce_role_policy_defaults` → `ExitChain::sanitize`. Each step collects
  warnings; the CLI prints them and hard-errors on the `Result::Err` cases
  that the shell `*_or_die` functions exit on.
- **`config/validate.rs`** (the one module left as signatures in §4.1) maps
  the parsed string map onto the typed `OperatorConfig`, turning
  `EXIT_CHAIN_HOPS`/`WG_LISTEN_PORT`/booleans into typed values with the
  fail-closed errors from §4.1; reuse `ExitChainHops::parse`,
  `LaunchProfile::parse`, `LanMode::parse`, and `is_valid_node_id` above.
- **Serializer** for `save_config_atomic`: emit `KEY=value\n` in the exact
  order of `save_config` (L867-919) so diffs against the shell output stay
  empty during the parity phase.
- **Windows**: `config/persist.rs` is `#[cfg(unix)]`; add a `#[cfg(windows)]`
  sibling that enforces an ACL granting only the owner + SYSTEM (mirror the
  approach in `rustynetd`'s `windows_paths`/`windows_key_custody` modules),
  and an atomic `ReplaceFileW`/rename. Track this as the Windows slice of
  Phase 3.
- **Tests gate**: once these modules land, add `rustynet-operator` module
  names to `scripts/ci/regression_coverage_gates.sh` floors so the coverage
  cannot silently regress.

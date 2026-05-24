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

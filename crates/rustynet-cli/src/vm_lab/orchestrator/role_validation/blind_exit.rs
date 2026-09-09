#![allow(dead_code)]
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::VmGuestPlatform;

pub fn blind_exit_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Macos)
}

/// The `rustynet` CLI by absolute install path per OS. The POSIX backend runs
/// `status` under `sudo -n`, and RHEL-family `sudo` (Rocky) ships a
/// `secure_path` that omits `/usr/local/bin`, so a bare `rustynet` name fails
/// "command not found". Name it absolutely (mirrors anchor.rs). Windows uses
/// the `.exe` on PATH; blind_exit is blocked on Windows in production, but the
/// code path stays correct.
pub(crate) fn rustynet_program(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Windows => "rustynet.exe",
        _ => "/usr/local/bin/rustynet",
    }
}

/// The daemon's local control-socket path per OS, passed to `rustynet status`
/// via the `RUSTYNET_DAEMON_SOCKET` env var (mirrors
/// `capture_daemon_status_for_platform` in live_lab_bin_support). `status` is a
/// top-level command, not an `ops` subcommand, and it connects to a socket
/// path that differs by OS: macOS runs the daemon under `/private/var/run`
/// (the bare `/var/run` symlink resolves there on macOS hosts; the
/// `/usr/local/var/rustynet` state root is a different, wrong path).
pub(crate) fn daemon_socket_path(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Macos => "/private/var/run/rustynet/rustynetd.sock",
        // Linux path is the production default; Windows is unreachable here in
        // production (blind_exit_runtime_implemented is false) but the match
        // must stay exhaustive and sensible.
        _ => "/run/rustynet/rustynetd.sock",
    }
}

pub fn validate_blind_exit_runtime(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
    alias: &str,
) -> Result<(), String> {
    let status_out = shell
        .run_argv(
            &[rustynet_program(platform), "status"],
            &[("RUSTYNET_DAEMON_SOCKET", daemon_socket_path(platform))],
            &[],
        )
        .map_err(|e| format!("{alias}: failed to run rustynet status: {e}"))?;
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    if !status_out.is_success() {
        return Err(format!(
            "{alias}: rustynet status exited non-zero: {}",
            status_str.trim()
        ));
    }
    let has_blind_exit_role = status_str
        .split_whitespace()
        .any(|token| token == "node_role=blind_exit");
    if !has_blind_exit_role {
        return Err(format!(
            "{alias}: daemon does not report blind_exit role; status={}",
            status_str.trim()
        ));
    }

    match platform {
        VmGuestPlatform::Linux => {
            // B3 (NodeEngineAuditConsolidation_2026-09-08 §2-A): the old probe
            // was "any non-empty stdout", which `iptables -t nat -L` satisfies
            // with its chain header on a node that installed NOTHING. Read the
            // full ruleset and judge the blind_exit-specific shape.
            let out = shell
                .run_argv(&["sh", "-c", LINUX_BLIND_EXIT_PROBE], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe forwarding rules: {e}"))?;
            if !out.is_success() {
                return Err(format!(
                    "{alias}: nft list ruleset exited non-zero: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            linux_blind_exit_ruleset_verdict(&stdout)
                .map_err(|reason| format!("{alias}: {reason}"))?;
        }
        VmGuestPlatform::Macos => {
            let out = shell
                .run_argv(&["sh", "-c", MACOS_BLIND_EXIT_ANCHOR_PROBE], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe pf blind_exit anchor: {e}"))?;
            if !out.is_success() {
                return Err(format!(
                    "{alias}: pfctl blind_exit anchor query exited non-zero: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            let rules = String::from_utf8_lossy(&out.stdout);
            macos_blind_exit_rules_verdict(&rules)
                .map_err(|reason| format!("{alias}: {reason}"))?;
            // A blind_exit translates nothing: the regular-exit NAT anchor must
            // be empty, or the node is a NATing exit wearing the blind_exit role.
            let nat = shell
                .run_argv(&["sh", "-c", MACOS_EXIT_NAT_ANCHOR_PROBE], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe pf NAT anchor: {e}"))?;
            if !nat.is_success() {
                return Err(format!(
                    "{alias}: pfctl NAT anchor query exited non-zero: {}",
                    String::from_utf8_lossy(&nat.stderr).trim()
                ));
            }
            let nat_rules = String::from_utf8_lossy(&nat.stdout);
            if nat_rules
                .lines()
                .any(|line| line.trim_start().starts_with("nat "))
            {
                return Err(format!(
                    "{alias}: blind_exit must not translate, but the exit NAT anchor holds: {}",
                    nat_rules.trim()
                ));
            }
        }
        VmGuestPlatform::Windows => {
            // H3 (MultiAgentSecurityReview_2026-09-08): Windows downgrades
            // blind_exit to full NAT and this probe blesses it. Tracked there;
            // the NetNat presence check is kept until the daemon-side fix lands.
            let out = shell
                .run_argv(&["powershell", "-Command", "Get-NetNat 2>$null"], &[], &[])
                .map_err(|e| format!("{alias}: failed to probe Windows NAT: {e}"))?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.trim().is_empty() {
                return Err(format!(
                    "{alias}: no Windows NAT rules found for blind_exit"
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

/// `nft list ruleset` with stderr folded in so a permission error is visible
/// in the failure message rather than silently producing empty stdout.
pub(crate) const LINUX_BLIND_EXIT_PROBE: &str = "nft list ruleset 2>&1";
/// The blind_exit pf anchor the daemon loads (`macos_blind_exit.rs`).
pub(crate) const MACOS_BLIND_EXIT_ANCHOR_PROBE: &str =
    "sudo pfctl -a com.rustynet/blind_exit -s rules 2>&1";
/// The regular-exit translation anchor; must be empty on a blind_exit.
pub(crate) const MACOS_EXIT_NAT_ANCHOR_PROBE: &str = "sudo pfctl -a com.rustynet/nat -s nat 2>&1";

/// Judge a full `nft list ruleset` dump for the blind_exit shape the daemon
/// installs (`linux_blind_exit::build_linux_blind_exit_forward_commands`): a
/// `rustynet*` table whose `forward` chain carries the
/// `iifname <tun> oifname <egress> <family> saddr <mesh> accept` rule, and NO
/// `masquerade` in any rustynet table (a blind_exit forwards without
/// translating; a masquerade means a regular exit is wearing the role).
///
/// Only rustynet-owned tables are judged, so a host's own docker/libvirt
/// masquerade cannot fail a correct node, and a foreign table cannot pass a
/// node that installed nothing.
///
/// F7 (NodeEngineValidatorFalseGreenReview_2026-09-09): the forward and
/// established rules only count inside a chain whose header declares
/// `hook forward`. A rule parked in an unrelated chain of a rustynet table
/// (say the killswitch's `hook output` chain) does not forward anything, so
/// blessing it would green-light a node that cannot actually pass mesh
/// traffic; entering a new chain resets the context, and only the chain
/// header's `hook forward` declaration re-arms it.
pub(crate) fn linux_blind_exit_ruleset_verdict(ruleset: &str) -> Result<(), String> {
    let mut in_rustynet_table = false;
    let mut in_forward_chain = false;
    let mut depth = 0usize;
    let mut forward_rule = false;
    let mut established_rule = false;
    let mut masquerade = false;
    for raw in ruleset.lines() {
        let line = raw.trim();
        if depth == 0 {
            if let Some(rest) = line.strip_prefix("table ") {
                let name = rest.split_whitespace().nth(1).unwrap_or_default();
                in_rustynet_table = name.starts_with("rustynet");
            }
        }
        if in_rustynet_table {
            // A `chain <name>` header starts a new chain context; `hook
            // forward` (on the header itself or on the following `type …
            // hook forward …` line) is what re-arms rule detection. The
            // masquerade scan intentionally stays chain-agnostic: any
            // translation inside a rustynet table disqualifies the node.
            if line.starts_with("chain ") {
                in_forward_chain = false;
            }
            if line.contains("hook forward") {
                in_forward_chain = true;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.contains(&"masquerade") {
                masquerade = true;
            }
            if in_forward_chain {
                if tokens.contains(&"iifname")
                    && tokens.contains(&"oifname")
                    && tokens.contains(&"saddr")
                    && tokens.last() == Some(&"accept")
                {
                    forward_rule = true;
                }
                if line.contains("ct state established,related accept") {
                    established_rule = true;
                }
            }
        }
        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
        if depth == 0 && line.contains('}') {
            in_rustynet_table = false;
            in_forward_chain = false;
        }
    }
    if masquerade {
        return Err(
            "blind_exit must not translate, but a rustynet table holds a masquerade rule"
                .to_owned(),
        );
    }
    if !forward_rule || !established_rule {
        return Err(
            "no blind_exit forward rules (rustynet table forward chain with \
             `iifname … oifname … saddr … accept` and `ct state established,related accept`) \
             found in nft ruleset"
                .to_owned(),
        );
    }
    Ok(())
}

/// Judge `pfctl -a com.rustynet/blind_exit -s rules` output for the shape
/// `macos_blind_exit::render` emits: a mesh-sourced inbound pass on the tunnel
/// and a mesh-sourced outbound pass on the egress interface.
pub(crate) fn macos_blind_exit_rules_verdict(rules: &str) -> Result<(), String> {
    let has_inbound = rules
        .lines()
        .any(|line| line.trim_start().starts_with("pass in quick on ") && line.contains(" from "));
    let has_outbound = rules
        .lines()
        .any(|line| line.trim_start().starts_with("pass out quick on ") && line.contains(" from "));
    if !has_inbound || !has_outbound {
        return Err(format!(
            "no blind_exit pf rules (mesh-sourced `pass in quick on <tun> … from <mesh>` and \
             `pass out quick on <egress> … from <mesh>`) in the blind_exit anchor; got: {}",
            rules.trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn program_status(shell: &MockShellHost, role_line: &str, code: i32) {
        // Register the status response under every per-OS program name so the
        // helper stays platform-agnostic — validate_blind_exit_runtime resolves
        // the program from the platform under test (absolute path on POSIX,
        // .exe on Windows) and will match whichever key it uses.
        for program in ["/usr/local/bin/rustynet", "rustynet.exe"] {
            shell.program_run_response(
                &[program, "status"],
                RemoteExitStatus {
                    code,
                    stdout: role_line.as_bytes().to_vec(),
                    stderr: Vec::new(),
                },
            );
        }
    }

    #[test]
    fn runtime_implemented_linux_and_macos_not_windows() {
        assert!(blind_exit_runtime_implemented(VmGuestPlatform::Linux));
        assert!(blind_exit_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!blind_exit_runtime_implemented(VmGuestPlatform::Windows));
    }

    #[test]
    fn fails_closed_when_status_command_errors() {
        let shell = MockShellHost::new();
        program_status(&shell, "error: daemon unreachable", 1);
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("non-zero status exit should fail closed");
        assert!(err.contains("exited non-zero"), "{err}");
    }

    #[test]
    fn fails_closed_when_role_not_reported() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=exit state=ExitActive",
            0,
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("missing blind_exit role should fail closed");
        assert!(err.contains("does not report blind_exit role"), "{err}");
    }

    const LINUX_BLIND_EXIT_RULESET: &str = "table inet rustynet_ks_g3 {\n\
\tchain killswitch {\n\
\t\ttype filter hook output priority filter; policy drop;\n\
\t\toifname \"lo\" accept\n\
\t}\n\
\tchain forward {\n\
\t\ttype filter hook forward priority filter; policy drop;\n\
\t\tct state established,related accept\n\
\t\tiifname \"rustynet0\" oifname \"enp0s1\" ip saddr 100.64.0.0/10 accept\n\
\t}\n\
}\n";

    fn linux_probe(shell: &MockShellHost, code: i32, stdout: &str) {
        shell.program_run_response(
            &["sh", "-c", LINUX_BLIND_EXIT_PROBE],
            RemoteExitStatus {
                code,
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            },
        );
    }

    #[test]
    fn linux_passes_when_forwarding_rules_present() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        linux_probe(&shell, 0, LINUX_BLIND_EXIT_RULESET);
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect("blind_exit forward rules present should pass");
    }

    #[test]
    fn linux_fails_closed_when_no_forwarding_rules() {
        // B3: the REAL producer output on a node that installed nothing —
        // a killswitch table with no forward rule, and (for the legacy
        // iptables probe) a bare chain header. Mutation caught: reverting the
        // verdict to `stdout.trim().is_empty()` passes both fixtures.
        for fixture in [
            "table inet rustynet_ks_g3 {\n\tchain killswitch {\n\t\ttype filter hook output priority filter; policy drop;\n\t}\n}\n",
            "Chain POSTROUTING (policy ACCEPT)\ntarget     prot opt source               destination\n",
            "",
        ] {
            let shell = MockShellHost::new();
            program_status(
                &shell,
                "node_id=test-node node_role=blind_exit state=ExitActive",
                0,
            );
            linux_probe(&shell, 0, fixture);
            let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
                .expect_err("ruleset without blind_exit forward rules must fail closed");
            assert!(err.contains("no blind_exit forward rules"), "{err}");
        }
    }

    #[test]
    fn linux_fails_closed_when_rustynet_table_masquerades() {
        // A regular NATing exit wearing the blind_exit role. Mutation caught:
        // dropping the masquerade check.
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        let ruleset = format!(
            "{LINUX_BLIND_EXIT_RULESET}table ip rustynet_nat_g3 {{\n\tchain postrouting {{\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"enp0s1\" ip saddr 100.64.0.0/10 masquerade\n\t}}\n}}\n"
        );
        linux_probe(&shell, 0, &ruleset);
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("masquerade on a blind_exit must fail closed");
        assert!(err.contains("must not translate"), "{err}");
    }

    #[test]
    fn linux_ignores_foreign_tables_in_both_directions() {
        // A docker masquerade must not fail a correct node, and a foreign
        // forward rule must not pass a node that installed nothing.
        // Mutation caught: judging every table instead of rustynet* tables.
        let docker = "table ip nat {\n\tchain POSTROUTING {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\toifname \"eth0\" masquerade\n\t}\n}\n";
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        linux_probe(&shell, 0, &format!("{docker}{LINUX_BLIND_EXIT_RULESET}"));
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect("foreign masquerade must not fail a correct blind_exit");

        let foreign_forward = "table inet filter {\n\tchain forward {\n\t\tct state established,related accept\n\t\tiifname \"br0\" oifname \"eth0\" ip saddr 10.0.0.0/8 accept\n\t}\n}\n";
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        linux_probe(&shell, 0, foreign_forward);
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("a foreign forward rule must not pass a blind_exit that installed nothing");
    }

    #[test]
    fn linux_fails_closed_when_nft_exits_non_zero() {
        // Mutation caught: dropping the `is_success()` check (an unprivileged
        // `nft` prints an error and exits 1 with empty stdout).
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        linux_probe(&shell, 1, LINUX_BLIND_EXIT_RULESET);
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Linux, "node1")
            .expect_err("nft failure must fail closed");
        assert!(err.contains("exited non-zero"), "{err}");
    }

    #[test]
    fn linux_accepts_ruleset_rendered_from_daemon_producer_commands() {
        // F7 producer-shape pin: the verdict must accept exactly what the
        // daemon installs (`build_linux_blind_exit_forward_commands`),
        // rendered back into `nft list ruleset` shape. Mutation caught: any
        // drift between the producer's rule shape and the validator's
        // accepted shape (producer and validator can only stay honest
        // together).
        let config = rustynetd::linux_blind_exit::LinuxBlindExitConfig::new(
            "rustynet0",
            "enp0s1",
            "100.64.0.0/10",
        )
        .expect("valid blind_exit config");
        let commands = rustynetd::linux_blind_exit::build_linux_blind_exit_forward_commands(
            &config,
            "rustynet_g3",
        )
        .expect("valid nft command sequences");
        let mut rendered: Vec<String> = Vec::new();
        for argv in &commands {
            // Skip the `flush chain` sequence; only `add rule` sequences
            // correspond to ruleset lines.
            if argv.first().map(String::as_str) != Some("add") {
                continue;
            }
            assert_eq!(
                argv.get(4).map(String::as_str),
                Some("forward"),
                "producer must target the forward chain"
            );
            let mut line = String::new();
            let mut quote_next = false;
            for token in argv.iter().skip(5) {
                if !line.is_empty() {
                    line.push(' ');
                }
                if quote_next {
                    line.push('"');
                    line.push_str(token);
                    line.push('"');
                } else {
                    line.push_str(token);
                }
                // nft ruleset output quotes interface-match values.
                quote_next = token == "iifname" || token == "oifname";
            }
            rendered.push(line);
        }
        assert_eq!(
            rendered.len(),
            2,
            "producer emits the established and mesh-forward accepts: {rendered:?}"
        );
        let ruleset = format!(
            "table inet rustynet_g3 {{\n\tchain forward {{\n\t\ttype filter hook forward \
             priority filter; policy drop;\n\t\t{}\n\t}}\n}}\n",
            rendered.join("\n\t\t")
        );
        linux_blind_exit_ruleset_verdict(&ruleset)
            .expect("verdict must accept the daemon producer's own rule shape");
    }

    #[test]
    fn linux_fails_closed_when_forward_rules_sit_outside_a_forward_chain() {
        // F7 mutation caught: counting the accept rules anywhere inside a
        // rustynet table. The exact producer-shaped rules parked in the
        // killswitch's `hook output` chain forward nothing, so blessing them
        // would green-light a node that cannot pass mesh traffic.
        let misplaced = "table inet rustynet_ks_g3 {\n\
         \tchain killswitch {\n\
         \t\ttype filter hook output priority filter; policy drop;\n\
         \t\tct state established,related accept\n\
         \t\tiifname \"rustynet0\" oifname \"enp0s1\" ip saddr 100.64.0.0/10 accept\n\
         \t}\n\
         }\n";
        let err = linux_blind_exit_ruleset_verdict(misplaced)
            .expect_err("forward rules outside a `hook forward` chain must fail closed");
        assert!(err.contains("no blind_exit forward rules"), "{err}");
    }

    const MACOS_BLIND_EXIT_RULES: &str = "pass quick on lo0 all\n\
pass out quick on utun9 inet all keep state\n\
pass in quick on utun9 inet from 100.64.0.0/10 to any keep state\n\
pass out quick on en0 inet from 100.64.0.0/10 to any keep state\n\
block drop out quick all\n";

    fn macos_probes(shell: &MockShellHost, anchor_code: i32, anchor: &str, nat: &str) {
        shell.program_run_response(
            &["sh", "-c", MACOS_BLIND_EXIT_ANCHOR_PROBE],
            RemoteExitStatus {
                code: anchor_code,
                stdout: anchor.as_bytes().to_vec(),
                stderr: Vec::new(),
            },
        );
        shell.program_run_response(
            &["sh", "-c", MACOS_EXIT_NAT_ANCHOR_PROBE],
            RemoteExitStatus {
                code: 0,
                stdout: nat.as_bytes().to_vec(),
                stderr: Vec::new(),
            },
        );
    }

    #[test]
    fn macos_passes_when_blind_exit_anchor_rules_present_and_nat_anchor_empty() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        macos_probes(&shell, 0, MACOS_BLIND_EXIT_RULES, "");
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "mac1")
            .expect("blind_exit anchor rules present should pass");
    }

    #[test]
    fn macos_fails_closed_on_empty_or_foreign_anchor_output() {
        // B3: `pfctl -s nat` always prints SOMETHING on a host with any NAT;
        // the anchor-scoped probe must see the blind_exit rule shape itself.
        // Mutation caught: reverting to a non-empty-stdout check.
        for fixture in [
            "",
            "nat on en0 inet from 192.168.64.0/24 to any -> (en0) round-robin\n",
        ] {
            let shell = MockShellHost::new();
            program_status(
                &shell,
                "node_id=test-node node_role=blind_exit state=ExitActive",
                0,
            );
            macos_probes(&shell, 0, fixture, "");
            let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "mac1")
                .expect_err("anchor without blind_exit rules must fail closed");
            assert!(err.contains("no blind_exit pf rules"), "{err}");
        }
    }

    #[test]
    fn macos_fails_closed_when_exit_nat_anchor_translates() {
        // Mutation caught: dropping the NAT-anchor emptiness check.
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        macos_probes(
            &shell,
            0,
            MACOS_BLIND_EXIT_RULES,
            "nat on en0 inet from 100.64.0.0/10 to any -> (en0) round-robin\n",
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "mac1")
            .expect_err("a translating blind_exit must fail closed");
        assert!(err.contains("must not translate"), "{err}");
    }

    #[test]
    fn macos_fails_closed_when_pfctl_exits_non_zero() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        macos_probes(&shell, 1, MACOS_BLIND_EXIT_RULES, "");
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Macos, "mac1")
            .expect_err("pfctl failure must fail closed");
        assert!(err.contains("exited non-zero"), "{err}");
    }

    #[test]
    fn windows_passes_when_netnat_present() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        shell.program_run_response(
            &["powershell", "-Command", "Get-NetNat 2>$null"],
            RemoteExitStatus {
                code: 0,
                stdout: b"Name : RustyNetNat".to_vec(),
                stderr: Vec::new(),
            },
        );
        validate_blind_exit_runtime(&shell, VmGuestPlatform::Windows, "win-node")
            .expect("netnat present should pass");
    }

    #[test]
    fn windows_fails_closed_when_no_netnat() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            "node_id=test-node node_role=blind_exit state=ExitActive",
            0,
        );
        shell.program_run_response(
            &["powershell", "-Command", "Get-NetNat 2>$null"],
            RemoteExitStatus {
                code: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
        let err = validate_blind_exit_runtime(&shell, VmGuestPlatform::Windows, "win-node")
            .expect_err("no NetNat output should fail closed");
        assert!(err.contains("no Windows NAT rules found"), "{err}");
    }
}

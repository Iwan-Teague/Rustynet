//! Tests for `remote_shell.rs`. Wired in via `#[path] mod tests` so
//! the tests live in the same `cfg(test)` module as the impls under
//! test and can reach `pub(crate)` items directly via `super::`.

use super::*;

// ── Mock backend: programmed responses round-trip ────────────────────────────

#[test]
fn mock_backend_read_file_returns_bytes_written() {
    let host = MockShellHost::new();
    host.write_file("/tmp/probe", b"hello world", 0o600)
        .unwrap();
    let bytes = host.read_file("/tmp/probe").unwrap();
    assert_eq!(bytes, b"hello world");
}

#[test]
fn mock_backend_write_file_preserves_mode_on_stat() {
    let host = MockShellHost::new();
    host.write_file("/var/lib/rustynet/key", b"secret", 0o600)
        .unwrap();
    let stat = host.stat("/var/lib/rustynet/key").unwrap();
    assert_eq!(stat.mode_octal, 0o600);
    assert_eq!(stat.size, b"secret".len() as u64);
}

#[test]
fn mock_backend_run_argv_propagates_exit_code() {
    let host = MockShellHost::new();
    host.program_run_response(
        &["rustynet", "status"],
        RemoteExitStatus {
            code: 42,
            stdout: b"node_id=abc".to_vec(),
            stderr: Vec::new(),
        },
    );
    let result = host
        .run_argv(&["rustynet", "status"], &[], &[])
        .expect("programmed response");
    assert_eq!(result.code, 42);
    assert_eq!(result.stdout, b"node_id=abc");
    assert!(!result.is_success());
}

#[test]
fn mock_backend_run_argv_logs_invocation_for_assertion() {
    let host = MockShellHost::new();
    host.program_run_response(
        &["echo", "hi"],
        RemoteExitStatus {
            code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    );
    host.run_argv(&["echo", "hi"], &[("FOO", "bar")], b"input")
        .unwrap();
    let log = host.run_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].argv, vec!["echo".to_string(), "hi".to_string()]);
    assert_eq!(log[0].env, vec![("FOO".to_string(), "bar".to_string())]);
    assert_eq!(log[0].stdin, b"input");
}

#[test]
fn mock_backend_tcp_send_recv_returns_programmed_response() {
    let host = MockShellHost::new();
    host.program_tcp_response("127.0.0.1:51822", b"pong".to_vec());
    let response = host
        .tcp_send_recv("127.0.0.1:51822", b"ping", Duration::from_secs(1))
        .unwrap();
    assert_eq!(response, b"pong");
    let log = host.tcp_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].addr, "127.0.0.1:51822");
    assert_eq!(log[0].payload, b"ping");
    assert_eq!(log[0].timeout, Duration::from_secs(1));
}

#[test]
fn mock_backend_run_argv_returns_error_when_no_response_programmed() {
    let host = MockShellHost::new();
    let err = host
        .run_argv(&["rustynet", "missing"], &[], &[])
        .expect_err("no programmed response");
    match err {
        RemoteShellError::Transport { message } => {
            assert!(message.contains("no programmed response"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn mock_backend_tcp_returns_network_error_when_addr_unknown() {
    let host = MockShellHost::new();
    let err = host
        .tcp_send_recv("127.0.0.1:9999", b"x", Duration::from_millis(100))
        .expect_err("closed addr");
    match err {
        RemoteShellError::Network { message } => {
            assert!(message.contains("no programmed tcp"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn mock_backend_read_file_returns_transport_error_for_missing_path() {
    let host = MockShellHost::new();
    let err = host.read_file("/missing").expect_err("missing");
    match err {
        RemoteShellError::Transport { message } => {
            assert!(message.contains("no file at"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn mock_backend_stat_override_wins_over_synthetic_stat() {
    let host = MockShellHost::new();
    host.write_file("/tmp/file", b"abc", 0o644).unwrap();
    host.set_stat_override(
        "/tmp/file",
        RemoteStat {
            size: 999,
            mode_octal: 0o755,
            owner_uid_or_sid: "1000".to_owned(),
            group_gid_or_sid: "1000".to_owned(),
        },
    );
    let stat = host.stat("/tmp/file").unwrap();
    assert_eq!(stat.size, 999);
    assert_eq!(stat.mode_octal, 0o755);
    assert_eq!(stat.owner_uid_or_sid, "1000");
}

// ── Input validation contracts ───────────────────────────────────────────────

#[test]
fn read_file_rejects_empty_path_fail_closed() {
    let host = MockShellHost::new();
    let err = host.read_file("").expect_err("empty path");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn write_file_rejects_nul_bearing_path_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .write_file("/tmp/nul\0path", b"x", 0o600)
        .expect_err("NUL path");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn write_file_rejects_disallowed_mode_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .write_file("/tmp/file", b"x", 0o777)
        .expect_err("disallowed mode");
    match err {
        RemoteShellError::InvalidInput { message } => {
            assert!(message.contains("allow-list"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn run_argv_rejects_empty_argv_fail_closed() {
    let host = MockShellHost::new();
    let err = host.run_argv(&[], &[], &[]).expect_err("empty argv");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn run_argv_rejects_empty_program_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .run_argv(&["", "arg"], &[], &[])
        .expect_err("empty argv[0]");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn run_argv_rejects_nul_in_any_argv_element_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .run_argv(&["echo", "good", "nul\0arg"], &[], &[])
        .expect_err("NUL argv");
    match err {
        RemoteShellError::InvalidInput { message } => {
            assert!(message.contains("argv element 2"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn run_argv_rejects_env_with_equals_in_key_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .run_argv(&["echo"], &[("FOO=BAD", "value")], &[])
        .expect_err("equals in key");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn run_argv_rejects_env_with_nul_in_value_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .run_argv(&["echo"], &[("FOO", "value\0bad")], &[])
        .expect_err("NUL value");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn tcp_send_recv_rejects_addr_without_port_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .tcp_send_recv("hostonly", b"x", Duration::from_secs(1))
        .expect_err("no port");
    match err {
        RemoteShellError::InvalidInput { message } => {
            assert!(message.contains("':'"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn tcp_send_recv_rejects_port_zero_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .tcp_send_recv("127.0.0.1:0", b"x", Duration::from_secs(1))
        .expect_err("port zero");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn tcp_send_recv_rejects_empty_host_fail_closed() {
    let host = MockShellHost::new();
    let err = host
        .tcp_send_recv(":1234", b"x", Duration::from_secs(1))
        .expect_err("empty host");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn validate_remote_path_rejects_empty_path() {
    let err = validate_remote_path("").expect_err("empty");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn validate_remote_path_rejects_nul() {
    let err = validate_remote_path("/etc/foo\0bar").expect_err("nul");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn validate_mode_octal_accepts_allow_list_modes() {
    for mode in [0o600u16, 0o700, 0o644, 0o755] {
        validate_mode_octal(mode).unwrap_or_else(|err| panic!("mode {mode:o} rejected: {err}"));
    }
}

#[test]
fn validate_mode_octal_rejects_outside_allow_list() {
    for mode in [0u16, 0o400, 0o777, 0o666] {
        validate_mode_octal(mode).expect_err(&format!("mode {mode:o} should have been rejected"));
    }
}

#[test]
fn validate_tcp_addr_extracts_host_and_port() {
    let (host, port) = validate_tcp_addr("127.0.0.1:51822").unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 51822);
}

#[test]
fn tcp_send_recv_body_prefers_nc_and_falls_back_to_bash_dev_tcp() {
    let body = build_tcp_send_recv_body("127.0.0.1", 51822, "cGF5bG9hZA==", 5);
    // The nc primary path is preserved verbatim for guests that ship it.
    assert!(
        body.contains("command -v nc") && body.contains("nc -w 5 -- '127.0.0.1' 51822"),
        "nc path missing or altered: {body}"
    );
    // Minimal guests (Rocky/RHEL — no nc, no egress to install one) fall back
    // to bash's /dev/tcp, bounded by `timeout` exactly as `nc -w` was.
    assert!(
        body.contains("command -v bash")
            && body.contains("/dev/tcp/")
            && body.contains("timeout 5 bash -c"),
        "bash /dev/tcp fallback missing: {body}"
    );
    // The validated port is present and the base64 payload is single-quoted.
    assert!(body.contains("51822"), "port missing: {body}");
    assert!(
        body.contains("'cGF5bG9hZA=='"),
        "payload not single-quote-escaped: {body}"
    );
}

#[test]
fn validate_tcp_addr_supports_ipv6_bracket_form_rsplit() {
    // We rsplit on ':' so the last segment is the port — IPv6
    // bracketed addresses round-trip correctly.
    let (host, port) = validate_tcp_addr("[::1]:443").unwrap();
    assert_eq!(host, "[::1]");
    assert_eq!(port, 443);
}

// ── Argv construction: shell-escaping is leak-proof on POSIX ────────────────

#[test]
fn shell_quote_round_trips_apostrophes_safely() {
    // The crate-level shell_quote is re-used by the POSIX backends;
    // confirm it stays leak-proof for the obnoxious cases live-lab
    // substages will actually feed it.
    assert_eq!(super::shell_quote("plain"), "'plain'");
    assert_eq!(super::shell_quote("with 'quote'"), "'with '\\''quote'\\'''");
    assert_eq!(
        super::shell_quote("$INJECT; rm -rf /"),
        "'$INJECT; rm -rf /'"
    );
    assert_eq!(super::shell_quote("` ;|& > <"), "'` ;|& > <'");
}

// ── Argv construction: PowerShell EncodedCommand carries arbitrary bytes ─────

#[test]
fn powershell_single_quote_escape_doubles_apostrophes() {
    assert_eq!(powershell_single_quote_escape("simple"), "simple");
    assert_eq!(
        powershell_single_quote_escape("with 'quote'"),
        "with ''quote''"
    );
    assert_eq!(powershell_single_quote_escape(""), "");
}

#[test]
fn utf16le_bytes_matches_powershell_encodedcommand_input() {
    // PowerShell's `-EncodedCommand` decodes its argument as
    // base64(UTF-16LE(script)). Verify the local helper produces the
    // same bytes the remote PowerShell will accept. For ASCII the
    // pattern is a NUL between every byte.
    assert_eq!(utf16le_bytes("hi"), vec![b'h', 0, b'i', 0]);
    // Non-ASCII: U+00E9 (é) is 0xE9 0x00 in UTF-16LE.
    assert_eq!(utf16le_bytes("é"), vec![0xE9, 0x00]);
}

#[test]
fn encode_base64_decodes_round_trip_with_strict_decoder() {
    let cases: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"abc",
        b"abcd",
        &[0u8, 1, 2, 3, 0xff, 0xfe, 0xfd],
    ];
    for original in cases {
        let encoded = encode_base64_standard(original);
        let decoded = decode_base64_strict(&encoded).expect("round-trip");
        assert_eq!(decoded.as_slice(), *original);
    }
}

#[test]
fn decode_base64_strict_rejects_garbage_input() {
    let err = decode_base64_strict("not_base64!@#").expect_err("garbage rejected");
    match err {
        RemoteShellError::Protocol { message } => {
            assert!(message.contains("base64 decode"), "got: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

// ── POSIX stat parser ───────────────────────────────────────────────────────

#[test]
fn parse_posix_stat_round_trips_gnu_format() {
    // GNU stat -c '%s %a %u %g' output for a 1024-byte 0644 root-owned file.
    let stat = parse_posix_stat("1024 644 0 0").expect("gnu stat parse");
    assert_eq!(stat.size, 1024);
    assert_eq!(stat.mode_octal, 0o644);
    assert_eq!(stat.owner_uid_or_sid, "0");
    assert_eq!(stat.group_gid_or_sid, "0");
}

#[test]
fn parse_posix_stat_round_trips_bsd_format_after_mode_normalisation() {
    // BSD `%Lp` already prints the lower 9 bits as octal without
    // leading zeros, matching GNU `%a`. Verify the parser treats
    // them identically.
    let stat = parse_posix_stat("4096 700 501 20").expect("bsd stat parse");
    assert_eq!(stat.size, 4096);
    assert_eq!(stat.mode_octal, 0o700);
    assert_eq!(stat.owner_uid_or_sid, "501");
    assert_eq!(stat.group_gid_or_sid, "20");
}

#[test]
fn parse_posix_stat_rejects_short_line_fail_closed() {
    let err = parse_posix_stat("1024 644 0").expect_err("missing field");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

#[test]
fn parse_posix_stat_rejects_non_numeric_mode_fail_closed() {
    let err = parse_posix_stat("1024 rwx 0 0").expect_err("non-numeric mode");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

// ── Windows stat parser ─────────────────────────────────────────────────────

#[test]
fn parse_windows_stat_parses_canonical_envelope() {
    let envelope = "SIZE:42\nOWNER:S-1-5-32-544\nGROUP:S-1-5-32-545\nSDDL:O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)\n";
    let stat = parse_windows_stat(envelope).expect("parse");
    assert_eq!(stat.size, 42);
    assert_eq!(stat.owner_uid_or_sid, "S-1-5-32-544");
    assert_eq!(stat.group_gid_or_sid, "S-1-5-32-545");
    // SYSTEM + Admins full control, no Everyone/Users entries → 0o600.
    assert_eq!(stat.mode_octal, 0o600);
}

#[test]
fn parse_windows_stat_maps_users_or_everyone_to_world_readable_mode() {
    let envelope = "SIZE:0\nOWNER:S-1-5-32-544\nGROUP:S-1-5-32-545\nSDDL:O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)\n";
    let stat = parse_windows_stat(envelope).expect("parse");
    assert_eq!(stat.mode_octal, 0o644);
}

#[test]
fn parse_windows_stat_passes_through_empty_group_value() {
    // Envelope has a `GROUP:` line with no value (whitespace-trimmed
    // to empty). The parser treats this as a present-but-empty value
    // and propagates the empty string verbatim — the
    // owner-fallback branch only fires when the GROUP line is
    // absent entirely (see the next test).
    let envelope = "SIZE:7\nOWNER:S-1-5-18\nGROUP:\nSDDL:O:SYG:SYD:(A;;FA;;;SY)\n";
    let stat = parse_windows_stat(envelope).expect("parse");
    assert_eq!(stat.owner_uid_or_sid, "S-1-5-18");
    assert_eq!(stat.group_gid_or_sid, "");
}

#[test]
fn parse_windows_stat_defaults_group_to_owner_when_group_line_missing() {
    // No `GROUP:` line in the envelope at all — exercises the
    // `group.unwrap_or_else(|| owner.clone())` branch in
    // `parse_windows_stat`. Without this test the owner-fallback
    // code path has zero coverage.
    let envelope = "SIZE:7\nOWNER:S-1-5-18\nSDDL:O:SYG:SYD:(A;;FA;;;SY)\n";
    let stat = parse_windows_stat(envelope).expect("parse");
    assert_eq!(stat.owner_uid_or_sid, "S-1-5-18");
    assert_eq!(stat.group_gid_or_sid, "S-1-5-18");
}

#[test]
fn parse_windows_stat_rejects_missing_size_fail_closed() {
    let err = parse_windows_stat("OWNER:S-1\nGROUP:S-2\nSDDL:O:BA\n").expect_err("missing SIZE");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

#[test]
fn parse_windows_stat_rejects_missing_owner_fail_closed() {
    let err = parse_windows_stat("SIZE:1\nGROUP:S-2\nSDDL:O:BA\n").expect_err("missing OWNER");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

#[test]
fn parse_windows_stat_rejects_missing_sddl_fail_closed() {
    let err = parse_windows_stat("SIZE:1\nOWNER:S-1\nGROUP:S-2\n").expect_err("missing SDDL");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

#[test]
fn synthetic_mode_from_sddl_owner_only_is_0o600() {
    let sddl = "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)";
    assert_eq!(synthetic_mode_from_sddl(sddl), 0o600);
}

#[test]
fn synthetic_mode_from_sddl_with_users_is_0o644() {
    let sddl = "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
    assert_eq!(synthetic_mode_from_sddl(sddl), 0o644);
}

#[test]
fn synthetic_mode_from_sddl_with_everyone_is_0o644() {
    let sddl = "O:BAG:BAD:(A;;FA;;;SY)(A;;FR;;;WD)";
    assert_eq!(synthetic_mode_from_sddl(sddl), 0o644);
}

// ── Run-argv envelope parser ────────────────────────────────────────────────

#[test]
fn parse_run_argv_envelope_extracts_code_and_streams() {
    let stdout_b64 = encode_base64_standard(b"hello");
    let stderr_b64 = encode_base64_standard(b"warn");
    let envelope = format!("CODE:0\nSTDOUT:{stdout_b64}\nSTDERR:{stderr_b64}\n");
    let result = parse_run_argv_envelope(&envelope).expect("parse");
    assert_eq!(result.code, 0);
    assert_eq!(result.stdout, b"hello");
    assert_eq!(result.stderr, b"warn");
    assert!(result.is_success());
}

#[test]
fn parse_run_argv_envelope_handles_non_zero_exit() {
    let stdout_b64 = encode_base64_standard(b"");
    let stderr_b64 = encode_base64_standard(b"oops");
    let envelope = format!("CODE:127\nSTDOUT:{stdout_b64}\nSTDERR:{stderr_b64}\n");
    let result = parse_run_argv_envelope(&envelope).expect("parse");
    assert_eq!(result.code, 127);
    assert_eq!(result.stderr, b"oops");
    assert!(!result.is_success());
}

#[test]
fn parse_run_argv_envelope_handles_binary_stdout_round_trip() {
    let payload: Vec<u8> = (0u8..=255u8).collect();
    let stdout_b64 = encode_base64_standard(&payload);
    let stderr_b64 = encode_base64_standard(&[]);
    let envelope = format!("CODE:0\nSTDOUT:{stdout_b64}\nSTDERR:{stderr_b64}\n");
    let result = parse_run_argv_envelope(&envelope).expect("parse");
    assert_eq!(result.stdout, payload);
}

#[test]
fn parse_run_argv_envelope_rejects_missing_code_fail_closed() {
    let envelope = format!(
        "STDOUT:{}\nSTDERR:{}\n",
        encode_base64_standard(b"x"),
        encode_base64_standard(b""),
    );
    let err = parse_run_argv_envelope(&envelope).expect_err("missing CODE");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

#[test]
fn parse_run_argv_envelope_rejects_unparseable_code_fail_closed() {
    let envelope = format!(
        "CODE:not_a_number\nSTDOUT:{}\nSTDERR:{}\n",
        encode_base64_standard(b""),
        encode_base64_standard(b""),
    );
    let err = parse_run_argv_envelope(&envelope).expect_err("bad CODE");
    assert!(matches!(err, RemoteShellError::Protocol { .. }));
}

// ── Error type plumbing ─────────────────────────────────────────────────────

#[test]
fn remote_shell_error_string_conversion_keeps_variant_label() {
    let err = RemoteShellError::InvalidInput {
        message: "test".to_owned(),
    };
    let as_string: String = err.into();
    assert!(as_string.contains("invalid input"));
    assert!(as_string.contains("test"));
}

#[test]
fn remote_shell_error_display_formats_each_variant() {
    let variants = [
        (
            RemoteShellError::InvalidInput {
                message: "a".to_owned(),
            },
            "invalid input: a",
        ),
        (
            RemoteShellError::Transport {
                message: "b".to_owned(),
            },
            "transport error: b",
        ),
        (
            RemoteShellError::Protocol {
                message: "c".to_owned(),
            },
            "protocol error: c",
        ),
        (
            RemoteShellError::Network {
                message: "d".to_owned(),
            },
            "network error: d",
        ),
        (
            RemoteShellError::Unsupported {
                message: "e".to_owned(),
            },
            "unsupported: e",
        ),
    ];
    for (err, expected) in variants {
        assert_eq!(err.to_string(), expected);
    }
}

// ── Backend selection ───────────────────────────────────────────────────────

/// Build a throwaway SSH `NodeConnection` for the factory tests. The
/// backend it produces is never driven over SSH — every factory test
/// exercises an input-validation path that fails before any transport —
/// so a tempfile-backed known_hosts (alive only for construction) is
/// sufficient.
fn throwaway_conn(host: &str) -> crate::vm_lab::orchestrator::connection::NodeConnection {
    use std::io::Write;
    let mut kh = tempfile::NamedTempFile::new().expect("tempfile");
    writeln!(kh, "# placeholder").expect("write kh");
    crate::vm_lab::orchestrator::connection::NodeConnection::ssh(
        host,
        22,
        Some("debian".to_owned()),
        std::path::PathBuf::from("/tmp/id"),
        kh.path().to_path_buf(),
        None,
    )
    .expect("conn")
}

#[test]
fn new_remote_shell_host_returns_a_linux_backend_for_linux_platform() {
    let host = new_remote_shell_host(
        crate::vm_lab::VmGuestPlatform::Linux,
        throwaway_conn("host"),
    )
    .expect("linux backend");
    // We cannot downcast through Arc<dyn>, but we can confirm input
    // validation is wired up by exercising one primitive's argv
    // validation path. The validator is shared, so all three backends
    // reject the same invalid input the same way.
    let err = host.read_file("").expect_err("empty path");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn new_remote_shell_host_returns_a_macos_backend_for_macos_platform() {
    let host = new_remote_shell_host(
        crate::vm_lab::VmGuestPlatform::Macos,
        throwaway_conn("host"),
    )
    .expect("macos backend");
    let err = host
        .run_argv(&[], &[], &[])
        .expect_err("empty argv on macos backend");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn new_remote_shell_host_returns_a_windows_backend_for_windows_platform() {
    let host = new_remote_shell_host(
        crate::vm_lab::VmGuestPlatform::Windows,
        throwaway_conn("host"),
    )
    .expect("windows backend");
    let err = host
        .tcp_send_recv("no-port", b"x", Duration::from_secs(1))
        .expect_err("bad addr on windows backend");
    assert!(matches!(err, RemoteShellError::InvalidInput { .. }));
}

#[test]
fn new_remote_shell_host_rejects_non_desktop_platforms_fail_closed() {
    // iOS / Android have no SSH shell backend; the factory must fail
    // closed rather than hand back a backend that silently no-ops.
    for platform in [
        crate::vm_lab::VmGuestPlatform::Ios,
        crate::vm_lab::VmGuestPlatform::Android,
    ] {
        // `Arc<dyn RemoteShellHost>` is not `Debug`, so `expect_err` is
        // unavailable; match on the result directly instead.
        let result = new_remote_shell_host(platform, throwaway_conn("host"));
        assert!(matches!(
            result,
            Err(crate::vm_lab::orchestrator::error::AdapterError::UnsupportedPlatform { .. })
        ));
    }
}

// ── Windows ACL mapping ─────────────────────────────────────────────────────

#[test]
fn windows_mode_to_acl_script_owner_only_drops_inherited_aces() {
    let script = windows_mode_to_acl_script("C:\\ProgramData\\file", 0o600);
    assert!(script.contains("/inheritance:r"));
    assert!(script.contains("SYSTEM:(F)"));
    assert!(script.contains("Administrators:(F)"));
    assert!(!script.contains("BUILTIN\\Users"));
}

#[test]
fn windows_mode_to_acl_script_world_readable_grants_users_read() {
    let script = windows_mode_to_acl_script("C:\\ProgramData\\file", 0o644);
    assert!(script.contains("/inheritance:r"));
    assert!(script.contains("SYSTEM:(F)"));
    assert!(script.contains("BUILTIN\\Users:(R)"));
}

#[test]
fn windows_mode_to_acl_script_escapes_embedded_apostrophe_in_path() {
    let script = windows_mode_to_acl_script("C:\\ProgramData\\it's_fine\\file", 0o600);
    // The escape doubles the apostrophe so the surrounding single
    // quotes around the path literal stay balanced inside the
    // PowerShell script body.
    assert!(script.contains("it''s_fine"));
}

// ── Windows write_file: ACL-before-bytes contract (HIGH-1 fold-in) ───────────

#[test]
fn windows_write_file_script_applies_acl_before_writing_payload_bytes() {
    // The hardened contract is "tighten DACL on the tmpfile BEFORE
    // any secret bytes are written, then atomic-rename onto the
    // final path". Verify the script body orders the operations
    // correctly: icacls on $tmp must precede WriteAllBytes on $tmp.
    let script = windows_write_file_script(
        "C:\\ProgramData\\RustyNet\\secrets\\anchor.dpapi",
        b"secret-bytes-payload",
        0o600,
    );
    let acl_at = script
        .find("icacls $tmp /inheritance:r")
        .expect("icacls $tmp call must appear in script");
    let write_at = script
        .find("[System.IO.File]::WriteAllBytes($tmp")
        .expect("WriteAllBytes on $tmp must appear in script");
    assert!(
        acl_at < write_at,
        "icacls must run BEFORE WriteAllBytes so secret bytes never land in a world-readable tmpfile (acl_at={acl_at}, write_at={write_at})",
    );
}

#[test]
fn windows_write_file_script_atomically_renames_tmpfile_onto_target() {
    // After the tmpfile is ACL'd and filled, Move-Item replaces the
    // final path atomically. Asserting the script contains the
    // Move-Item step locks in the rename-onto-target step of the
    // contract.
    let script = windows_write_file_script(
        "C:\\ProgramData\\RustyNet\\trust\\membership.owner.key.pub",
        b"public-key-bytes",
        0o644,
    );
    assert!(
        script.contains("Move-Item -LiteralPath $tmp -Destination $path -Force"),
        "tmpfile must be atomic-renamed onto the final path"
    );
    let write_at = script
        .find("[System.IO.File]::WriteAllBytes($tmp")
        .expect("WriteAllBytes must precede Move-Item");
    let move_at = script
        .find("Move-Item -LiteralPath $tmp -Destination $path -Force")
        .expect("Move-Item must appear");
    assert!(
        write_at < move_at,
        "bytes must land in the ACL'd tmpfile before the rename"
    );
}

#[test]
fn windows_write_file_script_verifies_post_move_acl_for_owner_only_mode() {
    // The post-move DACL verifier runs Get-Acl on the final path and
    // throws if the DACL drifted from the owner-only shape. The
    // verifier MUST run after the Move-Item — otherwise it inspects
    // the tmpfile's DACL, not the renamed target's, and a hostile
    // rename could move a different ACL onto $path.
    let script = windows_write_file_script(
        "C:\\ProgramData\\RustyNet\\secrets\\token.dpapi",
        b"x",
        0o600,
    );
    let move_at = script
        .find("Move-Item -LiteralPath $tmp -Destination $path -Force")
        .expect("Move-Item must appear");
    let verify_at = script
        .find("$verifyAcl = (Get-Acl -LiteralPath $path).Sddl")
        .expect("post-move ACL verify must appear");
    assert!(
        move_at < verify_at,
        "post-move ACL verify must run AFTER Move-Item so it inspects the final path's DACL"
    );
    assert!(
        script.contains("post-move ACL drift on owner-only mode"),
        "owner-only verify must emit the canonical drift message"
    );
    assert!(
        script.contains("Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue"),
        "ACL drift recovery must remove the offending file fail-closed"
    );
}

#[test]
fn windows_write_file_script_cleans_up_tmpfile_on_exception() {
    // The script's catch arm removes the tmpfile if any step throws.
    // Without this, a partial write (or an ACL verify drift) would
    // leave a partial file with potentially incorrect DACL on disk.
    let script = windows_write_file_script("C:\\ProgramData\\RustyNet\\file", b"x", 0o600);
    assert!(
        script.contains("Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue"),
        "tmpfile cleanup must appear in the catch handler"
    );
    assert!(
        script.contains("throw"),
        "catch handler must re-throw to surface the failure to the caller"
    );
}

#[test]
fn windows_write_file_script_creates_parent_directory_if_missing() {
    // The script ensures the parent dir exists before staging the
    // tmpfile — otherwise the very first New-Item call against a
    // path under a non-existent parent would fail with an opaque
    // "Could not find a part of the path" error.
    let script = windows_write_file_script("C:\\ProgramData\\RustyNet\\subdir\\file", b"x", 0o600);
    assert!(
        script.contains("New-Item -ItemType Directory -Force -Path $parent"),
        "script must ensure parent dir exists before staging tmpfile"
    );
}

#[test]
fn windows_write_file_script_rejects_disallowed_mode_via_acl_helper() {
    // Modes outside the cross-platform allow-list make the ACL
    // helpers emit a `Write-Error` stanza. The validate_mode_octal
    // wall already rejects them in the calling impl, but if the
    // raw helpers are wired anywhere else (e.g. from a future
    // substage), the script-level guard is the last fail-closed line.
    let bad = windows_write_file_script("C:\\ProgramData\\RustyNet\\f", b"x", 0o777);
    assert!(
        bad.contains("not in cross-platform allow-list"),
        "disallowed mode must trip the script-level guard"
    );
}

#[test]
fn windows_post_move_acl_verify_script_world_readable_rejects_everyone_sid() {
    // World-readable modes allow BUILTIN\\Users but NEVER allow
    // Everyone (WD). The verify script's regex MUST reject any DACL
    // that grants Everyone an ACE, even on a 0o644 target.
    let verify = windows_post_move_acl_verify_script(0o644);
    assert!(verify.contains(";WD\\)"), "WD (Everyone) check must appear");
    assert!(
        verify.contains("post-move ACL drift on world-readable mode (Everyone present)"),
        "Everyone-rejection message must appear"
    );
    // The verifier still requires SYSTEM and Administrators on
    // world-readable mode — those entries provide the privileged
    // admin path even when the file is widely readable.
    assert!(verify.contains(";FA;;;SY\\)"));
    assert!(verify.contains(";FA;;;BA\\)"));
}

// ── Windows TCP read loop: timeout-based, not first-segment-based (MED-3) ────

#[test]
fn windows_tcp_send_recv_script_loop_is_timeout_based_not_first_segment_based() {
    // The hardened read-loop contract: keep reading until either
    // the peer half-closes (Read returns 0) or the caller's deadline
    // fires. The legacy implementation exited on first idle poll
    // once any byte had arrived (`elseif ($ms.Length -gt 0) { break; }`),
    // which truncated multi-segment responses with >50ms inter-
    // segment gaps. Verify the script body does NOT contain that
    // first-segment-exit shape.
    let script = windows_tcp_send_recv_script("127.0.0.1", 51822, "AAAA", 30_000);
    assert!(
        !script.contains("elseif ($ms.Length -gt 0) { break; }"),
        "first-segment-arrival exit MUST NOT appear in the read loop"
    );
    assert!(
        !script.contains("$client.Available -gt 0"),
        "Available-poll loop is the truncating shape; new loop blocks on BeginRead instead"
    );
    // The new loop drives BeginRead with the remaining-deadline
    // WaitHandle so each iteration waits up to the remaining timeout
    // for data and only exits on EOF or deadline.
    assert!(
        script.contains("BeginRead"),
        "loop must use BeginRead so each iteration blocks on the remaining timeout"
    );
    assert!(
        script.contains("WaitOne($remainingMs"),
        "BeginRead must be awaited with the remaining-deadline timeout, not a fixed sleep"
    );
    assert!(
        script.contains("if ($read -le 0) {"),
        "loop must exit on peer half-close (Read returns 0)"
    );
}

#[test]
fn windows_tcp_send_recv_script_uses_deadline_not_fixed_sleep() {
    // The loop's deadline anchor is a UtcNow timestamp + the
    // operator's timeout. Each iteration recomputes the remaining
    // millis so we never block past the deadline even if the peer
    // sends a slow trickle of bytes.
    let script = windows_tcp_send_recv_script("127.0.0.1", 51822, "", 5_000);
    assert!(script.contains("[DateTime]::UtcNow.AddMilliseconds(5000)"));
    assert!(script.contains("$remainingMs"));
    // The truncating sleep loop should be gone — Start-Sleep was
    // the polling delay between Available checks in the old impl.
    assert!(
        !script.contains("Start-Sleep -Milliseconds 50"),
        "old polling delay must be removed; loop now blocks on BeginRead+WaitHandle"
    );
}

#[test]
fn windows_tcp_send_recv_script_aborts_connect_on_deadline() {
    // The connect path uses BeginConnect + AsyncWaitHandle.WaitOne
    // with the caller's timeout, so a hung peer never blocks forever
    // even if SO_RCVTIMEO is somehow ignored.
    let script = windows_tcp_send_recv_script("203.0.113.1", 8443, "", 1_500);
    assert!(script.contains("BeginConnect"));
    assert!(script.contains("WaitOne(1500"));
    assert!(script.contains("tcp connect timed out"));
}

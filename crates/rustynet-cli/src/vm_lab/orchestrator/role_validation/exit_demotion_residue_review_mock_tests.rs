//! REVIEWER-PROPOSED additional unit tests (not part of the implementer's patch):
//! drive `restore_pre_demotion_role` through the scripted mock so the verify branch has
//! more than one independent witness.
use super::*;
use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

fn ok(stdout: &str) -> RemoteExitStatus {
    RemoteExitStatus {
        code: 0,
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

fn status_argv() -> [&'static str; 6] {
    [
        "sudo",
        "-n",
        "env",
        "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
        "/usr/local/bin/rustynet",
        "status",
    ]
}

fn role_set_admin_argv() -> [&'static str; 8] {
    [
        "sudo",
        "-n",
        "env",
        "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
        "/usr/local/bin/rustynet",
        "role",
        "set",
        "admin",
    ]
}

fn grep_argv() -> [&'static str; 6] {
    [
        "sudo",
        "-n",
        "grep",
        "-E",
        "^(RUSTYNET_)?NODE_ROLE=",
        "/etc/default/rustynetd",
    ]
}

fn sed_argv(program: &str) -> Vec<String> {
    [
        "sudo",
        "-n",
        "sed",
        "-i",
        "-E",
        program,
        "/etc/default/rustynetd",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn program_restore(mock: &MockShellHost, verify_readback: &str) {
    mock.program_run_response(&role_set_admin_argv(), ok(""));
    let program = "s/^RUSTYNET_NODE_ROLE=.*$/RUSTYNET_NODE_ROLE=admin/";
    let sed = sed_argv(program);
    let sed_refs: Vec<&str> = sed.iter().map(String::as_str).collect();
    mock.program_run_response(&sed_refs, ok(""));
    mock.program_run_response(&grep_argv(), ok(verify_readback));
    mock.program_run_response(
        &status_argv(),
        ok("node_id=n node_role=admin state=Ready\n"),
    );
}

fn recorded() -> PreDemotionRoles {
    PreDemotionRoles {
        live: "admin".to_owned(),
        persisted: PersistedRoleRecord {
            key: PersistedRoleKey::RustynetNodeRole,
            value: "admin".to_owned(),
        },
    }
}

#[test]
fn rrs_verify_value_mismatch_is_an_error_through_the_mock() {
    let mock = MockShellHost::new();
    program_restore(&mock, "RUSTYNET_NODE_ROLE=client\n");
    let err = restore_pre_demotion_role(&mock, &recorded()).expect_err("value mismatch must fail");
    assert!(err.contains("persisted role verify mismatch"), "{err}");
    assert!(err.contains("left behind: persisted role client"), "{err}");
}

#[test]
fn rrs_verify_key_mismatch_is_an_error_through_the_mock() {
    let mock = MockShellHost::new();
    program_restore(&mock, "NODE_ROLE=admin\n");
    let err = restore_pre_demotion_role(&mock, &recorded()).expect_err("key mismatch must fail");
    assert!(err.contains("persisted role verify mismatch"), "{err}");
}

#[test]
fn rrs_verify_read_failure_is_an_error_through_the_mock() {
    let mock = MockShellHost::new();
    mock.program_run_response(&role_set_admin_argv(), ok(""));
    let sed = sed_argv("s/^RUSTYNET_NODE_ROLE=.*$/RUSTYNET_NODE_ROLE=admin/");
    let sed_refs: Vec<&str> = sed.iter().map(String::as_str).collect();
    mock.program_run_response(&sed_refs, ok(""));
    mock.program_run_response(
        &grep_argv(),
        RemoteExitStatus {
            code: 2,
            stdout: Vec::new(),
            stderr: b"grep: /etc/default/rustynetd: Permission denied\n".to_vec(),
        },
    );
    mock.program_run_response(
        &status_argv(),
        ok("node_id=n node_role=admin state=Ready\n"),
    );
    let err =
        restore_pre_demotion_role(&mock, &recorded()).expect_err("unreadable verify must fail");
    assert!(err.contains("persisted role verify read failed"), "{err}");
    assert!(err.contains("persisted role unreadable"), "{err}");
}

#[test]
fn rrs_clean_restore_is_ok_through_the_mock() {
    let mock = MockShellHost::new();
    program_restore(&mock, "RUSTYNET_NODE_ROLE=admin\n");
    restore_pre_demotion_role(&mock, &recorded()).expect("clean restore");
}

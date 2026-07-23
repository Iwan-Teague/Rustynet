# Antares scan — `ALL` — CWE-862

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-862 — Missing authorization: no authorization check when an actor accesses a resource or performs an action (default-deny ACL bypass).  
**Verdict:** `vulnerable_files`  
**Budget:** 30/30 terminal cmds, 39 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/linux_runtime_acls.rs` | inspected |

## Model reasoning

The Linux runtime ACL verifier implements ACL verification logic (collect_linux_runtime_acl_report and evaluate_linux_runtime_acl_metadata) that checks filesystem ownership, group ownership, and permissions. This is the implementation area where authorization checks would be performed; if the verification logic contains missing checks (e.g., failing to validate ownership/group or allowing unauthorized access), it would be the CWE-862 location.

## Commands run
```
$ ls
$ grep -RIn "acl\.|access control\.|is_authorized\.|authorize\.|authorized\.|denylist\.|allowlist\.|role\.|permission\.|admin\.|authz" .
$ find . -maxdepth 2 | grep -E "(acl|access|control|authz|role|permission|admin)"
$ find . -maxdepth 2 | grep -E "acl|access|control|authz|role|permission|admin"
$ find mcp -maxdepth 2 | grep -E "acl|access|control|authz|role|permission|admin"
$ grep -RIn "acl" .
$ grep -RIn "verify_acl\|verify_runtime_acl\|check_acl\|check_runtime_acl\|acl_check\|acl_verify" crates/rustynetd/src
$ grep -RIn "verify_acl" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ find crates/rustynetd/src -name '*.rs' | xargs grep -n "linux_runtime_acls"
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "linux_runtime_acls" crates/rustynetd/src
$ grep -RIn "verify_acl\|verify_runtime_acl\|check_acl\|check_runtime_acl\|acl_check\|acl_verify" crates/rustynetd/src
$ grep -RIn "verify_acl" crates/rustynetd/src
$ grep -RIn "verify_acl" crates/rustynetd/src
$ find crates/rustynetd/src -name '*.rs' | xargs grep -n "linux_runtime_acls"
$ find crates/rustynetd/src -name '*.rs' | grep -E "linux_runtime_acls"
$ cat crates/rustynetd/src/linux_runtime_acls.rs
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
$ grep -RIn "inspect_runtime_root_status" crates/rustynetd/src
```

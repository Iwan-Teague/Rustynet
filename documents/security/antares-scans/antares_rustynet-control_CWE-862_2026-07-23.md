# Antares scan — `rustynet-control` — CWE-862

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-862 — Missing authorization: no authorization check when an actor accesses a resource or performs an action (default-deny ACL bypass).  
**Verdict:** `vulnerable_files`  
**Budget:** 11/22 terminal cmds, 16 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The PolicyGuard implementation defaults to deny (PolicyGuard::default() in tests) and is responsible for evaluating access decisions. The default-allow-list pattern is implemented in PolicyGuard::allow_list(set) which adds all members of a set to the allow list. If the default-allow-list is misconfigured (e.g., includes wildcard or overly broad identities/tags) or if authorization checks are bypassed, an actor may be able to access resources or perform actions without proper authorization (CWE-862). The code in src/lib.rs contains the PolicyGuard implementation and related default-allow-list logic, making it the primary location to inspect for missing authorization checks.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "authorize\|authorization\|authorized\|deny-\|is_authorized\|has_role\|check_acl\|acl" /workspace/repo/src | head -n 200
$ grep -RIn "authorize" /workspace/repo/src | head -n 200
$ sed -n '4400,4480p' /workspace/repo/src/lib.rs
$ grep -RIn "authorize_attempt\(|authorize\(|authorize_attempt" /workspace/repo/src | head -n 200
$ grep -RIn "authorize_attempt" /workspace/repo/src | head -n 200
$ cat /workspace/repo/src/lib.rs
$ grep -RIn "authorize" /workspace/repo/src | grep -v "lib.rs" | head -n 200
$ grep -RIn "deny-\(|deny(" /workspace/repo/src | head -n 200
$ grep -RIn "deny(" /workspace/repo/src | head -n 200
$ sed -n '4600,4680p' /workspace/repo/src/lib.rs
$ grep -RIn "PolicyGuard" /workspace/repo/src | head -n 200
$ grep -RIn "default_allow_list\|default_allow_list\b\|deny_by_default\|deny_by_default\b" /workspace/repo/ | head -n 200
$ grep -RIn "default_allow_list" /workspace/repo/src | head -n 200
```

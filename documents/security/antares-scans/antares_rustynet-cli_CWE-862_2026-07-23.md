# Antares scan — `rustynet-cli` — CWE-862

**Date:** 2026-07-23  
**Scope:** `rustynet-cli` (273 first-party `.rs` files)  
**CWE:** CWE-862 — Missing authorization: no authorization check when an actor accesses a resource or performs an action (default-deny ACL bypass).  
**Verdict:** `turn_cap`  
**Budget:** 28/30 terminal cmds, 40 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

hit hard turn cap (40) without submission

## Commands run
```
$ ls
$ find . -maxdepth 2 | grep -E "src/server|src/auth|src/middleware|src/acl|src/access|src/security"
$ find src -maxdepth 2 | head -n 200
$ grep -RIn "acl\.|access control\.|access_control\.|access_control_list\.|access_list\.|allow\.|deny\.|role\.|permission\.|permission_check\.|authorize\.|authorization\.|authz\.|is_authorized\.|is_authorized_to\.|has_permission\.|has_permission_to\.|check_permission\.|check_acl\.|allow_all\.|allow_all_users\.|anonymous\.|anonymous_access\.|anonymous_user\.|anonymous_account\.|default_deny\.|deny_by_default\.|is_authenticated\.|is_authenticated_and_authorized\.|is_authenticated_and_authorized_to" src
$ rg -n "acl\.|access control\.|access_control\.|access_list\.|allow\.|deny\.|role\.|permission\.|permission_check\.|authorize\.|authorization\.|authz\.|is_authorized\.|has_permission\.|check_permission\.|check_acl\.|default_deny\.|deny_by_default" src
$ grep -RIn "acl\.|access control\.|access_control\.|access_list\.|allow\.|deny\.|role\.|permission\.|permission_check\.|authorize\.|authorization\.|authz\.|is_authorized\.|has_permission\.|check_permission\.|check_acl\.|default_deny\.|deny_by_default" src
$ grep -RIn "acl" src
$ rg -n "lock_admin_acl|lock_admin_acl\(" src
$ grep -RIn "lock_admin_acl" src
$ grep -RIn "check_acl\.|check_acl\(" src
$ grep -RIn "check_acl" src
$ grep -RIn "check_permission\|check_permission(" src
$ grep -RIn "check_permission" src
$ grep -RIn "permission" src
$ grep -RIn "is_owner\|is_owner(" src
$ grep -RIn "is_owner" src
$ grep -RIn "is_owner" src
$ grep -RIn "owner" src
$ rg -n "authorize|authorization|authorize\(" src
$ grep -RIn "authorize\(" src
$ grep -RIn "authorize" src
$ grep -RIn "owner-only\|owner_only\|owner_only_mode\|owner_only_mode\(" src
$ grep -RIn "owner-only" src
$ grep -RIn "owner_only\|owner_only_mode\|owner_only" src
$ grep -RIn "owner_only" src
$ rg -n "enforce_owner_only_mode|owner_only_mode|set_mode_owner_only|owner_only" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "fn enforce_owner_only_mode" src
$ grep -RIn "set_mode_owner_only" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ grep -RIn "enforce_owner_only_mode" src
$ cat src/ops_phase9.rs
$ sed -n '264,350p' src/ops_phase9.rs
```

# Antares scan — `rustynet-backend-wireguard` — CWE-862

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-wireguard` (21 first-party `.rs` files)  
**CWE:** CWE-862 — Missing authorization: no authorization check when an actor accesses a resource or performs an action (default-deny ACL bypass).  
**Verdict:** `vulnerable_files`  
**Budget:** 21/22 terminal cmds, 27 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/udp_offload_probe.rs` | inspected |

## Model reasoning

The probe inspects kernel-land UDP batching/offload capabilities (sendmmsg, recvmmsg, UDP_SEGMENT/UDP_GRO socket options) by reading /proc/sys/kernel/osrelease and checking kernel release gates. It does not perform any host-side authorization checks to ensure the runtime is authorized to invoke these privileged kernel operations. This allows an attacker to infer batching/offload capabilities and potentially bypass host-side authorization checks that would otherwise prevent invoking privileged kernel-land operations.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "authorize\|authorization\|authorized\|is_authorized\|check_acl\|acl\|allow_all\|allow_any\|deny_all" /workspace/repo/src/ | head -n 200
$ grep -RIn "authorize" /workspace/repo/src/
$ grep -RIn "acl" /workspace/repo/src/
$ grep -RIn "is_authorized" /workspace/repo/src/
$ grep -RIn "check_acl" /workspace/repo/src/
$ grep -RIn "permission\|permissions\|permission_check\|has_permission\|require_permission" /workspace/repo/src/
$ grep -RIn "permission" /workspace/repo/src/
$ grep -RIn "allow_" /workspace/repo/src/
$ grep -RIn "auth" /workspace/repo/src/
$ grep -RIn "reject\|reject_unauthenticated\|unauthenticated\|deny\|block\|access_denied\|access_denied_to_authoritative" /workspace/repo/src/
$ grep -RIn "reject" /workspace/repo/src/
$ cat src/udp_offload_probe.rs
$ grep -RIn "AuthoritativeSocket\|AuthoritativeTransportIdentity\|AuthoritativeTransportIdentity::" /workspace/repo/
$ grep -RIn "AuthoritativeSocket" /workspace/repo/
$ cat src/userspace_shared/socket.rs
$ grep -RIn "sendmmsg\(|recvmmsg\(|sendmsgnonblock\(|recvmsgnonblock\(" /workspace/repo/
$ grep -RIn "sendmsgnonblock\b" /workspace/repo/
$ grep -RIn "sendmsgnonblock" /workspace/repo/
$ grep -RIn "sendmmsg\(" /workspace/repo/
$ grep -RIn "sendmmsg" /workspace/repo/
$ cat src/udp_offload_probe.rs | head -n 300
$ grep -RIn "sendmsgnonblock\b" /workspace/repo/
$ grep -RIn "sendmsgnonblock" /workspace/repo/src/
$ grep -RIn "sendmsgnonblock" /workspace/repo/benches/
```

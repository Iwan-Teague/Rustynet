# Antares scan — `ALL` — CWE-502

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-502 — Deserialization of untrusted data leading to unsafe object/state construction.  
**Verdict:** `vulnerable_files`  
**Budget:** 20/30 terminal cmds, 26 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/macos_runtime_acls.rs` | inspected |

## Model reasoning

The file contains direct serde_json::from_str(...) calls that deserialize attacker-controlled JSON (e.g., lines 424, 500, 515, 524). These call sites expect successful deserialization and do not validate the deserialized structure, which can lead to unsafe object/state construction (CWE-502).

## Commands run
```
$ ls
$ grep -RIn "pickle\.|unsafe_load\.|deserialize\.|deserialize_object\.|deserialize\(" .
$ grep -RIn "pickle" .
$ grep -RIn "unsafe_load\|deserialize_object\|deserialize\(" .
$ grep -RIn "java\.deserialize\|deserialize\(" .
$ grep -RIn "deserialize" .
$ grep -RIn "deserialize_from_str\(" .
$ grep -RIn "deserialize_from_str" .
$ grep -RIn "deserialize" crates/rustynetd/src .
$ grep -RIn "deserialize_from_value" .
$ grep -RIn "serde_json::Deserializer" .
$ grep -RIn "from_str\(" .
$ grep -RIn "serde_json" .
$ grep -RIn "from_str\(" crates/rustynetd/src .
$ grep -RIn "from_str" crates/rustynetd/src .
$ find . -name '*.rs' | xargs grep -n "from_str"
$ grep -RIn "from_str" crates/rustynetd/src
$ cat crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str\|deserialize\|serde_json" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -n "from_str" crates/rustynetd/src/macos_runtime_acls.rs
$ grep -RIn "from_str" crates/rustynetd/src
```

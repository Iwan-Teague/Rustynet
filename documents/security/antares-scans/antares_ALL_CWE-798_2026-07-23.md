# Antares scan — `ALL` — CWE-798

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-798 — Use of hard-coded credentials or keys.  
**Verdict:** `vulnerable_files`  
**Budget:** 7/30 terminal cmds, 29 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/key_material.rs` | inspected |

## Model reasoning

The macOS implementation in crates/rustynetd/src/key_material.rs uses MACOS_PASSPHRASE_KEYCHAIN_SERVICE (net.rustynet.wg-key-passphrase) and resolves an account from an environment variable PASSPHRASE_KEYCHAIN_ACCOUNT_ENV. This embeds a hardcoded keychain service/account identifier in the code, which is a hard-coded credential/key value pattern (CWE-798).

## Commands run
```
$ grep -RIn "password\|passwd\|secret\|apikey\|token\|PRIVATE_KEY\|SSH_KEY" /workspace/repo/ | head -n 200
$ ls -la
$ grep -RIn "password\|passwd\|secret\|apikey\|token\|PRIVATE_KEY\|SSH_KEY" /workspace/repo/ | head -n 300
$ find . -maxdepth 2 | grep -E "(crates|src|gui|mcp|tools)"
$ find . -name Cargo.toml | head -n 20
$ grep -RIn "password" /workspace/repo/crates | head -n 200
$ grep -RIn "password" /workspace/repo/crates | grep -E "(src|Cargo.toml)"
$ grep -RIn "password" /workspace/repo/crates | grep -E "src|Cargo\.toml"
$ grep -RIn "password" /workspace/repo/crates | grep -E "src|Cargo\.toml"
$ grep -RIn "password" /workspace/repo/crates | grep -E "src|Cargo\.toml"
$ grep -RIn "password" /workspace/repo/crates | head -n 200
$ grep -RIn "secret" /workspace/repo/crates | head -n 200
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" .
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd/src
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd/src
$ grep -RIn "store_macos_generic_password_system_keychain_owned\|store_macos_generic_password_allow_any_app" /workspace/repo/crates/rustynetd/src | head -n 50
$ cat /workspace/repo/crates/rustynetd/src/key_material.rs
$ cat /workspace/repo/crates/rustynetd/src/key_material.rs | head -n 200
```

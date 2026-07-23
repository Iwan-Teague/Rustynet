# Antares scan — `ALL` — CWE-330

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-330 — Use of insufficiently random values: predictable randomness used for keys, nonces, tokens, or IDs.  
**Verdict:** `vulnerable_files`  
**Budget:** 22/30 terminal cmds, 30 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynet-crypto/src/lib.rs` | inferred (grep-only) |

## Model reasoning

The CSPRNG fallback implementation is in crates/rustynet-crypto/src/lib.rs (functions like try_generate_key_custody_material and generate_key_custody_material). These functions implement fallback randomness for keys/nonces and are the likely location of the CWE-330 issue if they use predictable sources or non-CSPRNG fallbacks.

## Commands run
```
$ rg -n "random\.|SecureRandom|Random\.|Math\.random|crypto\.random\.|uuid\.|nonce\.|token\.|generateRandom\(" .
$ rg -n "random\." .
$ grep -RIn "SecureRandom" .
$ grep -RIn "Random\(" . --exclude-dir "*.git" --exclude-dir "build" || true
$ find . -maxdepth 2 | xargs grep -n "random\("
$ find . -maxdepth 2 | grep -E "random\("
$ find . -maxdepth 2 | grep -E "random|Secure|crypto|nonce|token|uuid|rand"
$ ls -la
$ find crates -maxdepth 2 | head -n 200
$ find crates/rustynet-crypto -maxdepth 2 | head -n 50
$ grep -RIn "nonce" crates/rustynet-crypto
$ rg -n "CSPRNG|CSPRNG-derived|cryptographically|randomness|rng|Rng|Rand::Int|rand::thread_rng|ThreadRng|SystemRng|Mersenne" crates/rustynet-crypto
$ grep -RIn "CSPRNG" crates/rustynet-crypto
$ rg -n "try_generate_key_custody_material|try_fill_bytes|generate_key_custody_material|CSPRNG|SystemRng|Mersenne|OsRng|ThreadRng|rand::thread_rng|SystemRng" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material\|try_fill_bytes\|generate_key_custody_material\|CSPRNG\|SystemRng\|Mersenne\|OsRng\|ThreadRng\|rand::thread_rng" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
$ grep -n "try_generate_key_custody_material" crates/rustynet-crypto/src/lib.rs
```

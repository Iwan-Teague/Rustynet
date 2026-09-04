# Windows SDDL Broad-Principal Validator — Reachability Analysis of F2.c (2026-09-04)

**Status:** UNTRUSTED — machine-generated docs-only analysis. No code changed. Every repo claim is
cited to file:line read at analysis time on branch `ai-edit/edit-1788560936778-26537-25`; Windows API
behavior is described from the named Microsoft documentation pages (page titles only — this
environment has no web access, so no verbatim quotations are reproduced and none should be treated
as quoted). A human must verify each claim before acting on the recommendation.

**Scope:** Analyze finding F2.c in
[WindowsFixesSecurityReview_2026-09-04.md](./WindowsFixesSecurityReview_2026-09-04.md): whether
`validate_windows_dpapi_root` / `validate_windows_dpapi_file`
(`crates/rustynet-crypto/src/lib.rs:1048-1080`) can be bypassed by a raw-SID trustee spelling such
as `(A;;FA;;;S-1-1-0)`, given that they reject only the SDDL acronym substrings `;;;WD)`,
`;;;AU)`, `;;;BU)` (`crates/rustynet-crypto/src/lib.rs:1056-1058` and `1073-1075`).

---

## 1) The real implementation of `inspect_file_sddl`

`rustynet-crypto` imports it from the Windows-native crate, behind a `target_os = "windows"` gate:

- `crates/rustynet-crypto/src/lib.rs:16-19` —
  `#[cfg(target_os = "windows")] use rustynet_windows_native::{ WindowsDpapiScope, dpapi_protect, dpapi_unprotect, inspect_file_sddl, };`
- Call sites: `crates/rustynet-crypto/src/lib.rs:1054` (root) and `:1071` (file), both
  `.map_err(|_| CryptoError::PermissionValidationUnavailable)?` — the read error path fails closed.

The real Windows implementation (the crate's `cfg(windows)` module; the `#[cfg(not(windows))]`
stub that returns a platform-blocker error is at
`crates/rustynet-windows-native/src/lib.rs:105-108`):

1. `inspect_file_sddl` — `crates/rustynet-windows-native/src/lib.rs:413-450`. Calls
   **`GetFileSecurityW`** twice (sizing call expecting `ERROR_INSUFFICIENT_BUFFER`, then the real
   read) requesting `OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION`
   (`src/lib.rs:416-439`), then hands the raw `SECURITY_DESCRIPTOR` buffer to:
2. `security_descriptor_to_sddl` — `crates/rustynet-windows-native/src/lib.rs:1205-1230`. Calls
   **`ConvertSecurityDescriptorToStringSecurityDescriptorW`** with `SDDL_REVISION_1` and exactly
   the components that were read (owner + DACL), then converts the returned `PWSTR` to a Rust
   `String`.

So the string the validators substring-match is produced entirely by
`ConvertSecurityDescriptorToStringSecurityDescriptorW` from a binary descriptor fetched by
`GetFileSecurityW`. Nothing in the repo constructs or post-processes the SDDL string for these two
validators; there is no other implementation path (`crates/rustynet-windows-native/src/lib.rs:107`
is the only other definition, non-Windows stub, unreachable on Windows).

## 2) What the Windows API emits: alias vs raw SID

Documented behavior of the two APIs (Microsoft Learn: *"Security Descriptor String Format"* — the
SDDL grammar and the SID-alias table; *"ConvertSecurityDescriptorToStringSecurityDescriptor"* —
rendering rules; same contract for the `W` variant):

- In a binary `SECURITY_DESCRIPTOR` there is **no such thing as a "spelling"**: every trustee
  (ACE trust fields, owner, group) is a `SID` structure. The raw-`S-1-…`-vs-acronym distinction
  exists **only in the string rendering**, and the renderer — not the ACL author — chooses it.
- The SDDL grammar permits a trustee field to be either an SID alias (e.g. `WD`) or a literal SID
  string (e.g. `S-1-1-0`). That flexibility is an *input* (parsing) property; it does not mean the
  renderer preserves whatever spelling someone "wrote".
- `ConvertSecurityDescriptorToStringSecurityDescriptor` replaces SIDs that have entries in the
  documented well-known-SID alias table with their acronyms. For machine-independent well-known
  SIDs — Everyone `S-1-1-0`→`WD`, Authenticated Users `S-1-5-11`→`AU`, Builtin Users
  `S-1-5-32-545`→`BU`, Anonymous Logon `S-1-5-7`→`AN`, Network `S-1-5-2`→`NU`, Interactive
  `S-1-5-4`→`IU`, Local System `S-1-5-18`→`SY`, Creator Owner `S-1-3-0`→`CO`, Creator Group
  `S-1-3-1`→`CG`, Owner Rights `S-1-3-4`→`OW`, and the rest of the alias table — the mapping is
  deterministic and requires no domain lookup. For **domain-relative** aliases (`DA`, `DU`, `DD`,
  `DG`, `DC`, `EA`, `PA`, …) the acronym is used only when the SID's domain is recognizable;
  otherwise the SID is emitted as a raw `S-1-…` string. Principals with **no alias-table entry at
  all** — machine-local accounts/groups (`S-1-5-21-…`), domain principals, per-service SIDs
  (`S-1-5-80-…`), capability SIDs — are always emitted raw.

**Consequence for F2.c's headline scenario:** an ACE granting Everyone can only *contain* the SID
value `S-1-1-0` — whatever tool authored it, including `icacls` with an explicit SID argument,
because that is what a descriptor stores. `GetFileSecurityW` returns that binary SID and
`ConvertSecurityDescriptorToStringSecurityDescriptorW` renders it as `WD`, producing the exact
substring `;;;WD)` the validator rejects. **The literal raw-SID bypass `(A;;FA;;;S-1-1-0)` is not
reachable through this implementation**: the API normalizes S-1-1-0, S-1-5-11 and S-1-5-32-545 back
to WD/AU/BU before the string ever reaches `sddl.contains(...)`. The same normalization argument
applies to any spelling variant of the three rejected principals, because only one binary SID value
exists for each.

## 3) Broad principals the check does NOT catch

The deny-list covers three of roughly forty documented aliases. Still-passing forms:

**a. Aliased but not rejected (render as acronyms, so no substring matches):**

- `AN` — Anonymous Logon (`S-1-5-7`): network access without authentication. Real exposure class.
- `NU` — Network logon (`S-1-5-2`): any remote network logon.
- `IU` — Interactive (`S-1-5-4`): any locally logged-on user.
- `CO`/`CG` — Creator Owner / Creator Group (`S-1-3-0`/`S-1-3-1`): resolve to whoever created or
  owns; meaningful mainly on inheritable ACEs, but a `CI`/`OI` ACE for `CO` grants the *file's*
  owner rights in child objects.
- `OW` — Owner Rights (`S-1-3-4`): grants to the object owner, overriding-by-precedence for the
  owner; combined with `O:WD` an `OW` ACE grants Everyone-as-owner.
- `PS` — Principal Self (`S-1-5-10`), `ED` — Enterprise Domain Controllers (`S-1-5-9`),
  `RC` — Restricted Code (`S-1-5-12`), `SU` — Service logon (`S-1-5-6`), `NS`/`LS` — NetworkService/
  LocalService (`S-1-5-20`/`S-1-5-19`): progressively narrower, but none is the owning user.
- Domain-relative aliases when the domain resolves: `DU` (Domain Users), `DD` (Domain
  Controllers), `DG` (Domain Guests), `DC` (Domain Computers) — `DU` in particular is broad
  (every authenticated domain user) on a domain-joined host.
- (`BA` — Builtin Administrators, and `SY` — Local System, are *accepted by design*: the
  implementing arm's comment at `crates/rustynet-crypto/src/lib.rs:1893-1900` states access is
  "confined to SYSTEM, Administrators and specific user SIDs, never a broad group".)

Repo evidence that non-rejected aliases appear in real ACL verdicts the project already reasons
about: `crates/rustynetd/src/windows_registry_acls.rs:408` uses the fixture
`"O:BAD:P(A;;KA;;;SY)(A;;KR;;;AN)"` — `AN` grants are an anticipated real-world shape.

**b. Raw-SID renderable principals (no alias exists, so `S-1-…` appears verbatim):**

- `S-1-1-0`, `S-1-5-11`, `S-1-5-32-545` as *literal strings in a rendered DACL are unreachable*
  (§2 normalization) — listing them here because F2.c asked: they bypass the substring check only
  in a hypothetical code path that feeds validator strings not produced by
  `ConvertSecurityDescriptorToStringSecurityDescriptorW`. No such path exists for these validators.
- What *is* reachable raw: any trustee outside the alias table — machine-local groups and accounts
  (`S-1-5-21-<machine>-…`), domain groups when the domain is unrecognized
  (`S-1-5-21-<domain>-513` = Domain Users, unaliased), per-service SIDs (`S-1-5-80-…`). A
  broadly-populated local/domain group granted here is invisible to the deny-list. Raw-SID trustees
  are a real, already-fixture'd shape in this repo: `crates/rustynetd/src/windows_paths.rs:734`
  (`O:S-1-5-80-9999D:P(...)`) and `crates/rustynetd/src/windows_key_custody.rs:590`
  (`O:S-1-5-80-1234567890D:...`).

**c. F2.c's second aspect (unanchored substring): effectively dead.** The renderer emits ACEs as
`(<type>;<flags>;<rights>;;;<trustee>)`; the trustee field is either an alias or a digits-only
`S-1-…` string, so the substring `;;;WD)` can only materialize as an ACE whose trustee is exactly
`WD`. The `O:`/`G:` owner/group fields are bare trustees (e.g. `O:WDG:BA`) and never produce the
`;;;…)` wrapper. A non-trustee occurrence would require non-canonical SDDL that
`ConvertSecurityDescriptorToStringSecurityDescriptorW` does not emit.

## 4) Verdict: theoretical-only as stated; real as a coverage gap

**F2.c's literal scenario — an ACE spelled `(A;;FA;;;S-1-1-0)` defeats the validator — is
theoretical-only** for this implementation. The descriptor stores SIDs as binary values;
`ConvertSecurityDescriptorToStringSecurityDescriptorW` re-renders S-1-1-0/S-1-5-11/S-1-5-32-545 as
WD/AU/BU, and the validator rejects them. The attacker does not choose the spelling; the API does.

**The generalized finding is real but narrow (defense-in-depth, moderate):** the deny-list of three
acronyms does not cover (i) other broad-ish aliases — concretely `AN`, `NU`, `IU`, and in domain
contexts `DU` — and (ii) alias-less principals rendered raw (domain/machine groups, service SIDs).
Reachability requires an actor that can already write the object's DACL (owner, administrator, or
WRITE_DAC holder), who could equally replace the file; the check's value is catching
misconfiguration/exposure, and misconfiguration tooling also authors binary SIDs, so the residual
risk is a deliberately ACL'd exposure via a group outside the deny-list. This does not break the
fail-closed posture (F2.a) — read errors, symlinks, missing `D:P`/`D:` all still fail closed
(`crates/rustynet-crypto/src/lib.rs:1050-1061`, `1067-1078`) — it narrows what "no broad access"
means, relative to what the arm's own comment promises (`crates/rustynet-crypto/src/lib.rs:1896-1899`).

## 5) Proposed hardening (PROPOSAL ONLY — not implemented)

1. **Normalize trustees, then evaluate, instead of substring-matching spellings.** Split the DACL
   string into ACEs, split each ACE on `;`, take the 6th field (trustee), and classify it:
   - alias → map to its well-known SID (the alias table is a fixed documented set; embed the
     mapping of the broad subset: `WD`→`S-1-1-0`, `AU`→`S-1-5-11`, `BU`→`S-1-5-32-545`,
     `AN`→`S-1-5-7`, `NU`→`S-1-5-2`, `IU`→`S-1-5-4`, `CO`/`CG`/`OW`/`PS`/`RC`/`SU`/`NS`/`LS`,
     `DU`/`DD`/`DG`/`ED`);
   - `S-1-…` string → keep as SID. (`ConvertSidToStringSidW` already exists in the crate at
     `crates/rustynet-windows-native/src/lib.rs:1232` for the reverse direction; `windows-sys`
     exposes `ConvertStringSidToSidW` if canonicalization through a binary SID is preferred.)
2. **Prefer an allow-list to a longer deny-list.** The arm's design comment
   (`crates/rustynet-crypto/src/lib.rs:1896-1899`) already promises "SYSTEM, Administrators and
   specific user SIDs, never a broad group"; enforce exactly that: reject any trustee that is not
   `SY`/`BA`/the current user's SID (and, if policy accepts them, `NS`/`LS`/`LA`). This closes
   every alias gap *and* every raw-SID group in one rule, and also subsumes F2.b's missing
   owner-SID assertion if the check is extended to the `O:`/`G:` fields.
3. **Fail closed on unparseable ACEs** (`CryptoError::PermissionValidationUnavailable`), keeping
   the current posture: an SDDL shape the classifier does not understand must never read as a pass.
4. Scope note: the same deny-list shape exists in other Windows ACL consumers
   (`crates/rustynetd/src/windows_paths.rs:1087-1117`, `windows_key_custody.rs`,
   `crates/rustynet-relay/src/main.rs:4265+`); if hardening lands in `rustynet-crypto`, audit those
   call sites for the identical alias-coverage gap in a follow-up (out of scope here — this
   analysis changes no code).

## 6) Evidence trail

- Validators + deny-list: `crates/rustynet-crypto/src/lib.rs:1048-1063` (root), `1065-1080` (file),
  deny-list substrings at `1056-1058` and `1073-1075`; import at `16-19`; arm comment at
  `1893-1909` (validator calls at `1907-1908`).
- `inspect_file_sddl`: real `crates/rustynet-windows-native/src/lib.rs:413-450`
  (`GetFileSecurityW`, `OWNER|DACL`); stub `:105-108`; renderer
  `security_descriptor_to_sddl` `:1205-1230` (`ConvertSecurityDescriptorToStringSecurityDescriptorW`,
  `SDDL_REVISION_1`); `ConvertSidToStringSidW` helper `:1232+`.
- Microsoft documentation (titles only; behavior summarized in §2, not quoted): *"Security
  Descriptor String Format"*, *"SID Strings"*, *"ConvertSecurityDescriptorToStringSecurityDescriptor"*,
  the well-known-SID/alias tables under *"Well-known security identifiers"* and the SDDL SID-alias
  table. Offline environment — verify exact wording against learn.microsoft.com before merging.
- Finding under analysis: `documents/operations/active/WindowsFixesSecurityReview_2026-09-04.md`
  §F2.c (`:63-67`), summary table `:87`.

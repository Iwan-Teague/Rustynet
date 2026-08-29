//! The one audited boundary between a Rust value and a shell script that runs on
//! a lab host (QH-01).
//!
//! # Why this module exists
//!
//! Host scripts used to be rendered by ordered `str::replace` chains at the call
//! site. That shape carried three independent command-injection breakouts on
//! `HOST_PROVISION_GUEST_SCRIPT` alone:
//!
//! 1. **Substitution order.** `__AUTH_KEY__` was substituted *last* and its value
//!    carried single quotes by construction (`format!("'{path}'")`). A guest name
//!    of `__AUTH_KEY__` passed `ensure_provision_guest_name`, landed inside
//!    `NAME='…'`, and the final `replace` then rewrote *that* text — injecting
//!    quotes into the name's own quoting context.
//! 2. **`pool` was not validated at all**, and landed in `POOL='__POOL__'`.
//! 3. **`image` was validated for path shape only** (no metacharacter rule), and
//!    landed in `IMAGE='__IMAGE__'`.
//!
//! Legs 2 and 3 needed no ordering trick, so making substitution
//! order-independent is *necessary but not sufficient*. The fix has to be
//! escape-first.
//!
//! # QH-19 — "the renderer owns the quoting" is necessary but NOT sufficient
//!
//! **Read this before assuming a value is safe because it went through a
//! `Binding`.** The lesson people take from QH-01 is "escape at interpolation",
//! and that is only correct for sinks that parse the script *once*. Six distinct
//! sink contexts turned up while fixing this class, each needing a **different**
//! control, and escaping is the right answer in only two of them:
//!
//! | Sink context | The control that actually applies |
//! |---|---|
//! | Single-quoted position | reject `'` (nothing else can end the word) |
//! | Double-quoted position | reject `$`, backtick, `\` (`'` is inert here) |
//! | **Heredoc body** | reject **newline** — quoting the heredoc protects nothing, because a body that emits a line equal to the terminator closes it early and the remainder runs in the OUTER script |
//! | **Nested command string** (`script -qec`, `sh -c`, `ssh host 'cmd'`) | quote for **two** levels: single-quote the inner string so the outer shell expands nothing into it, and pass the value through the environment so the inner shell expands it as one quoted word |
//! | **SSH post-host argv** | quote for the **remote login shell** — `ssh(1)` joins post-host arguments with spaces and `sshd` hands the result to a shell, so client-side argv is not remote argv (QH-13) |
//! | **Path composition** (`"$POOL/$IMAGE"`) | **confinement**, which is orthogonal to quoting — `shell_quote("../../etc/passwd")` is a perfectly safe shell *word* that still traverses out of the pool |
//!
//! Two rules generalise from that table:
//!
//! 1. **Escaping and validation are complementary layers, not competing answers.**
//!    An escaper makes a value inert *as syntax*; it cannot make it *semantically*
//!    acceptable. Path confinement, length, and identifier shape are validator
//!    jobs and no renderer subsumes them — which is why the `ensure_*` validators
//!    are still called on values this module also escapes. Deleting one because
//!    "the renderer handles quoting now" reopens a different hole than the one
//!    QH-01 closed.
//! 2. **A renderer cannot be safe context-free.** Which control applies is a
//!    property of *where the value lands*, so the spelling decision has to be
//!    carried in the type. That is precisely what [`Binding`]'s variants buy over
//!    plain string substitution, and why adding a value means choosing a variant
//!    rather than reaching for `Literal` by default.
//!
//! The known exception is documented at [`HOST_GUEST_CONSOLE_SCRIPT`]: it is the
//! one template where a `Literal`'s escaping is not by itself the control, because
//! `script -qec` re-parses in a nested shell.
//!
//! # The contract
//!
//! **The renderer owns the quoting; the caller never does.** A caller hands over
//! a typed [`Binding`] and the renderer decides how it is spelled:
//!
//! - [`Binding::Literal`] — arbitrary caller data. Emitted `shell_quote`d, so it
//!   is one shell word no matter what it contains. **The template must NOT wrap
//!   the token in quotes** (`POOL=__POOL__`, never `POOL='__POOL__'`) — the
//!   quoting comes from the renderer. Enforced by
//!   `no_literal_token_is_adjacent_to_a_quote_in_its_template`.
//! - [`Binding::Bare`] — a value that must appear *unquoted* (a numeric, a
//!   toolchain channel, a filename stem inside a longer quoted path). Restricted
//!   to `[A-Za-z0-9._-]+`, which cannot end a quoted word, start an expansion, or
//!   introduce a word boundary.
//! - [`Binding::QuotedWords`] — a list that becomes several shell words. Each
//!   element is `shell_quote`d by the renderer and joined with a space, so the
//!   caller never assembles quotes itself.
//! - [`Binding::RawFragment`] — verbatim shell syntax, and therefore the one
//!   binding with **no validation at all**. It is not made safe by its
//!   `&'static str` type: `&'static str` is not the same as a literal
//!   (`String::leak` produces one from arbitrary runtime data), so an earlier
//!   version of this claim ("it can only ever be a compile-time literal") was
//!   false. What confines it is that the only values reaching it are the three
//!   associated constants of [`DefaultHostSshPath`], a type with a private field
//!   and no constructor. That is what makes the `$HOME`-bearing defaults safe, and
//!   it is checked by the compiler (verified: constructing one from another module
//!   fails with `E0603`).
//!
//!   The distinction is concrete, not hypothetical: `vm_lab::image_catalog`'s
//!   `leak_host_id` is a live `String::leak` → `&'static str` factory over
//!   **inventory data**, one module away. It cannot reach `RawFragment` — `Binding`
//!   is private to this module and `RawFragment` is constructed at exactly one site
//!   (`HostSshPath::binding`) — but it is precisely the thing a `&'static str`
//!   parameter would NOT have excluded. If `Binding` is ever made more visible, that
//!   function is the first place to check.
//! - [`Binding::HeredocBody`] — a multi-line body interpolated into a quoted
//!   heredoc. Neither escaping nor a metacharacter rule is the right control
//!   there; the rule is "the body must not contain a line equal to the
//!   terminator", which this variant enforces.
//! - [`Binding::PowerShellLiteral`] — the same idea for the one PowerShell
//!   template on this path: emitted `powershell_quote`d.
//!
//! # The boundary
//!
//! [`ScriptTemplate`]'s field is private to this module and there is no
//! constructor, so **no code outside this file can produce one** — and
//! [`render_script_template`] is the only thing that consumes one. Every script
//! template is a private const here, reachable only through the named
//! `render_*` functions below. A new render site therefore cannot compile a
//! bypass: it has nothing to render and no way to build a template.
//! `no_script_template_is_declared_outside_this_module` is the backstop for a
//! template smuggled in as a plain `&str` const elsewhere in the tree.

use super::{powershell_quote, shell_quote};

/// A shell-script template with `__TOKEN__` placeholders.
///
/// The field is private and there is no public constructor: a `ScriptTemplate`
/// can only be written in *this* module, which is what confines rendering to
/// [`render_script_template`].
struct ScriptTemplate(&'static str);

/// How the renderer spells one substituted value.
///
/// The variant *is* the safety argument for the value — see the module docs.
enum Binding<'a> {
    /// Arbitrary caller data, emitted `shell_quote`d. Empty is legal (`''`).
    Literal(&'a str),
    /// A value that must appear unquoted; restricted to `[A-Za-z0-9._-]+`.
    Bare(&'a str),
    /// A list that becomes several shell words; each is `shell_quote`d here.
    QuotedWords(&'a [String]),
    /// Verbatim shell syntax. `&'static str` so caller data cannot reach it.
    RawFragment(&'static str),
    /// A body written into a quoted heredoc whose terminator is `terminator`.
    HeredocBody {
        value: &'a str,
        terminator: &'static str,
    },
    /// Arbitrary caller data for a PowerShell template, `powershell_quote`d.
    PowerShellLiteral(&'a str),
}

impl Binding<'_> {
    fn kind(&self) -> &'static str {
        match self {
            Binding::Literal(_) => "Literal",
            Binding::Bare(_) => "Bare",
            Binding::QuotedWords(_) => "QuotedWords",
            Binding::RawFragment(_) => "RawFragment",
            Binding::HeredocBody { .. } => "HeredocBody",
            Binding::PowerShellLiteral(_) => "PowerShellLiteral",
        }
    }

    /// The exact bytes this binding contributes to the rendered script.
    fn render(&self, token: &str) -> Result<String, String> {
        match self {
            Binding::Literal(value) => {
                ensure_literal_binding_value(token, value)?;
                Ok(shell_quote(value))
            }
            Binding::Bare(value) => {
                ensure_bare_binding_value(token, value)?;
                Ok((*value).to_owned())
            }
            Binding::QuotedWords(words) => {
                let mut out = String::new();
                for word in words.iter() {
                    ensure_literal_binding_value(token, word)?;
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(&shell_quote(word));
                }
                Ok(out)
            }
            Binding::RawFragment(value) => Ok((*value).to_owned()),
            Binding::HeredocBody { value, terminator } => {
                ensure_heredoc_body(token, value, terminator)?;
                Ok((*value).to_owned())
            }
            Binding::PowerShellLiteral(value) => powershell_quote(value),
        }
    }
}

/// A `Literal` is `shell_quote`d, so a quote, `$`, backtick, `;`, `|`, `&`, a
/// redirection or a glob inside it cannot escape the word it becomes. What
/// escaping does **not** contain is a newline, and a newline is load-bearing
/// here: `HOST_LAUNCH_SCRIPT` writes a *second* script inside a
/// `<<'RUNNER_EOF'` heredoc that `bash` then re-parses, so a `repo_dir` or
/// `report_dir` carrying `\n` followed by a line reading `RUNNER_EOF` would
/// close the heredoc early and run the remainder in the **outer** script.
/// Refusing `\0`, `\n` and `\r` at interpolation is that control.
///
/// Empty is deliberately legal: `__SHA256__` ("unpinned"), `__EXPECT_MODEL__`
/// ("host declares no pool disk") and `__TARGETS__` ("every domain") all render
/// as `''`, and the script branches on emptiness to mean exactly that.
///
/// Enforced here for every `Literal`/`QuotedWords` value; proven by
/// `a_newline_bearing_literal_cannot_close_the_runner_heredoc` and
/// `an_empty_literal_renders_as_an_empty_shell_word`.
fn ensure_literal_binding_value(token: &str, value: &str) -> Result<(), String> {
    if let Some(bad) = value
        .chars()
        .find(|ch| *ch == '\0' || *ch == '\n' || *ch == '\r')
    {
        return Err(format!(
            "{token} contains the control character {bad:?} and is refused \
             (a newline could close a heredoc a host script re-parses): {value:?}"
        ));
    }
    Ok(())
}

/// A `Bare` value is emitted **unquoted**, so its alphabet is the whole control:
/// `[A-Za-z0-9._-]` cannot close a quoted word, start an expansion or a command
/// substitution, introduce a word boundary, or glob. Empty is refused because an
/// empty bare word silently vanishes from the rendered command.
///
/// Enforced here; proven by `a_bare_binding_refuses_everything_outside_its_alphabet`.
fn ensure_bare_binding_value(token: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!(
            "{token} is a bare (unquoted) token and must not be empty"
        ));
    }
    if let Some(bad) = value
        .chars()
        .find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')))
    {
        return Err(format!(
            "{token} is a bare (unquoted) token and must match [A-Za-z0-9._-]+, \
             but contains {bad:?}: {value:?}"
        ));
    }
    Ok(())
}

/// A heredoc body is written verbatim, so quoting is not the control and a
/// metacharacter rule would be wrong (the body is YAML, which legitimately
/// contains `:` and newlines). The one thing that ends a quoted heredoc is a
/// line equal to its terminator, so that is what is refused — together with the
/// requirement that the body end in `\n`, because the template places the
/// terminator immediately after the token and it must start at column 0.
///
/// Enforced here; proven by `a_heredoc_body_cannot_smuggle_its_own_terminator`.
fn ensure_heredoc_body(token: &str, value: &str, terminator: &str) -> Result<(), String> {
    if value.contains('\0') || value.contains('\r') {
        return Err(format!("{token} heredoc body contains a control character"));
    }
    if !value.ends_with('\n') {
        return Err(format!(
            "{token} heredoc body must end in a newline so the terminator starts at column 0"
        ));
    }
    if value.lines().any(|line| line.trim_end() == terminator) {
        return Err(format!(
            "{token} heredoc body contains a line equal to the terminator {terminator:?}, \
             which would close the heredoc early"
        ));
    }
    Ok(())
}

/// Substitute every declared binding into `template` in a **single pass**.
///
/// Order-independence is structural, not a convention: the walk copies template
/// bytes forward and appends rendered values, and **never re-scans a byte it has
/// already emitted**. A value that happens to spell another binding's token is
/// therefore inert data — which is the QH-01 breakout.
///
/// Fails closed on a **declared binding that the template does not contain**
/// (a rename or a typo would otherwise silently drop a value). It deliberately
/// does *not* fail on an unknown `__TOKEN__` found in the template:
/// `__PLACEHOLDERS__` occurs in a comment in `HOST_LAUNCH_SCRIPT`, and
/// `__VM_LAB_SECTION__` / `__RUSTYNET_CAPTURE_*` are protocol sentinels — that
/// rule would refuse every launch.
///
/// Proven by `rendering_is_single_pass_so_a_placeholder_valued_binding_is_inert`
/// and `an_unconsumed_declared_binding_is_refused`.
fn render_script_template(
    template: ScriptTemplate,
    bindings: &[(&'static str, Binding<'_>)],
) -> Result<String, String> {
    let body = template.0;
    let mut rendered: Vec<String> = Vec::with_capacity(bindings.len());
    for (token, binding) in bindings {
        rendered.push(binding.render(token)?);
    }

    let mut out = String::with_capacity(body.len() + 128);
    let mut consumed = vec![false; bindings.len()];
    let mut cursor = 0usize;
    while cursor < body.len() {
        // The earliest declared token starting at or after `cursor` wins. Ties
        // (one token a prefix of another) go to the longer token.
        let mut best: Option<(usize, usize)> = None;
        for (index, (token, _)) in bindings.iter().enumerate() {
            if let Some(offset) = body[cursor..].find(token) {
                let at = cursor + offset;
                let better = match best {
                    None => true,
                    Some((best_at, best_index)) => {
                        at < best_at
                            || (at == best_at && token.len() > bindings[best_index].0.len())
                    }
                };
                if better {
                    best = Some((at, index));
                }
            }
        }
        let Some((at, index)) = best else {
            out.push_str(&body[cursor..]);
            break;
        };
        out.push_str(&body[cursor..at]);
        out.push_str(rendered[index].as_str());
        consumed[index] = true;
        // Advance PAST the substituted text: emitted bytes are never re-scanned.
        cursor = at + bindings[index].0.len();
    }

    for (index, (token, binding)) in bindings.iter().enumerate() {
        if !consumed[index] {
            return Err(format!(
                "script template does not contain {token} (declared as {}); \
                 refusing to ship a script with a dropped value",
                binding.kind()
            ));
        }
    }
    Ok(out)
}

// --- the script templates: private to this module ---------------------------

/// Fetch a base image into a libvirt host's pool, resumably.
///
/// Runs ON the host (the pool is there, and the bytes should not transit the
/// orchestrator). Shipped over stdin, and every interpolated value is a `Literal`
/// the renderer `shell_quote`s — see [`render_host_fetch_image_script`]. The
/// digest and disk model are bound to a variable once, at the top, rather than
/// substituted at each of their seven use sites: a token that appears inside both
/// `'…'` and `"…"` on different lines cannot be correctly spelled by one value.
///
/// Every choice here is a lesson from a failure that actually happened:
/// - **No sudo inside the retry loop.** Caching sudo once and calling `sudo curl`
///   per image meant the 15-minute timestamp expired mid-download, so every later
///   call hit a passwordless prompt and exited 1 — burning all retries in seconds
///   and looking exactly like a network failure. Download as the user; one
///   privileged `install` at the end.
/// - **`-C -` resume + retry.** Sources are verified to send `Accept-Ranges`, so a
///   drop resumes at the byte it stopped rather than restarting.
/// - **`--proto-redir =https`.** A mirror redirector bounced curl to a non-HTTPS
///   mirror, which curl refuses with rc=1 — indistinguishable from other failures.
/// - **A stall detector** (`--speed-time`), so a hung transfer dies and resumes
///   instead of hanging until the outer timeout.
const HOST_FETCH_IMAGE_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
POOL=__POOL__
NAME=__NAME__
URL=__URL__
SHA256=__SHA256__
EXPECT_MODEL=__EXPECT_MODEL__
STAGE="$HOME/.rustynet-image-staging"
mkdir -p "$STAGE"

if [ -f "$POOL/$NAME" ] && [ -f "$POOL/$NAME.done" ]; then
  # A pinned digest re-verifies what is already there. The .done marker only
  # records that some past run finished; it is not evidence the bytes on disk are
  # still the bytes that were fetched.
  if [ -n "$SHA256" ]; then
    POOL_ACTUAL="$(sha256sum "$POOL/$NAME" | cut -d' ' -f1)"
    if [ "$POOL_ACTUAL" != "$SHA256" ]; then
      echo "[image] REFUSING: $NAME is in the pool but its sha256 does not match" >&2
      echo "[image]   expected $SHA256" >&2
      echo "[image]   actual   $POOL_ACTUAL" >&2
      echo "[image] Not overwriting. Remove $POOL/$NAME and re-run to refetch." >&2
      exit 1
    fi
    echo "[image] $NAME already complete in the pool (sha256 verified)"
    exit 0
  fi
  echo "[image] $NAME already complete in the pool"
  exit 0
fi

# Guard BEFORE writing: the pool must sit on the declared disk, matched by MODEL.
# Device letters are not stable across boots, so a letter is not a guard.
if [ -n "$EXPECT_MODEL" ]; then
  DEV="$(findmnt -n -o SOURCE --target "$POOL" | sed 's/[0-9]*$//')"
  MODEL="$(lsblk -no MODEL "$DEV" | head -1 | xargs)"
  if [ "$MODEL" != "$EXPECT_MODEL" ]; then
    echo "[image] REFUSING: $POOL is on '$MODEL' ($DEV), not '$EXPECT_MODEL'. Nothing written." >&2
    exit 1
  fi
  echo "[image] guard: $POOL -> $DEV = $MODEL (ok)"
fi

# A COMPLETE staged file must skip the transfer entirely.
#
# `curl -C -` on an already-complete file asks for `Range: <size>-`, the server
# answers 416, and curl exits 33/36 — which the loop below reads as "resume
# rejected" and responds to by DELETING the file and re-downloading from zero.
# So an interrupted-then-completed run (download succeeded, install failed) would
# throw away a finished multi-GB transfer on the retry. Compare the staged size
# against Content-Length up front and jump straight to install when they match.
# NOTE: no `awk BEGIN{IGNORECASE=1}` here. IGNORECASE is a GAWK extension and the
# hosts run mawk, which silently ignores it — so /^content-length:/ never matched
# the real `Content-Length:` header and this probe returned empty, defeating
# itself without a word. tr+grep -i is portable across both awks.
REMOTE_SIZE="$(curl -4 -sIL --proto-redir =https --connect-timeout 30 "$URL" 2>/dev/null \
  | tr -d '\r' | grep -i '^content-length:' | tail -1 | awk '{print $2}')"
if [ -f "$STAGE/$NAME" ] && [ -n "${REMOTE_SIZE:-}" ]; then
  LOCAL_SIZE="$(stat -c %s "$STAGE/$NAME" 2>/dev/null || echo 0)"
  if [ "$LOCAL_SIZE" = "$REMOTE_SIZE" ]; then
    echo "[image] staged $NAME is already complete ($LOCAL_SIZE bytes) — skipping download"
    SKIP_DOWNLOAD=1
  fi
fi

for attempt in 1 2 3 4 5; do
  if [ "${SKIP_DOWNLOAD:-0}" = "1" ]; then rc=0; else
  # NO sudo in this loop, deliberately.
  curl -4 -L -C - --proto-redir =https \
       --retry 10 --retry-delay 10 --retry-all-errors --retry-max-time 0 \
       --connect-timeout 30 --speed-limit 1024 --speed-time 180 \
       -o "$STAGE/$NAME" "$URL" >/dev/null 2>&1
  rc=$?
  fi
  if [ $rc -eq 0 ]; then
    echo "[image] downloaded $NAME ($(du -h "$STAGE/$NAME" | cut -f1))"
    # Integrity gate BEFORE the image is placed where libvirt will boot guests from.
    # TLS authenticates the transport, not the artifact: these URLs are redirectors
    # onto mirrors/archives, and this file is a driver ISO that gets injected into
    # guests. Verify against the caller's pinned digest, and refuse+delete on a
    # mismatch rather than leave a bad image staged for a later retry to install.
    if [ -n "$SHA256" ]; then
      ACTUAL="$(sha256sum "$STAGE/$NAME" | cut -d' ' -f1)"
      if [ "$ACTUAL" != "$SHA256" ]; then
        echo "[image] REFUSING: sha256 mismatch for $NAME" >&2
        echo "[image]   expected $SHA256" >&2
        echo "[image]   actual   $ACTUAL" >&2
        rm -f "$STAGE/$NAME"
        exit 1
      fi
      echo "[image] sha256 verified: $ACTUAL"
    else
      echo "[image] WARNING: no --sha256 pinned; integrity rests on TLS alone" >&2
    fi
    # Unprivileged install first. A pool that is group-writable to kvm with the
    # setgid bit set (see the remediation below) needs no root at all: the new
    # file inherits group kvm, and libvirt-qemu is a member, so qemu can read it.
    # Preferring this path keeps image staging out of the sudo blast radius.
    if install -m 0644 "$STAGE/$NAME" "$POOL/$NAME" 2>/dev/null; then
      touch "$POOL/$NAME.done" 2>/dev/null
      rm -f "$STAGE/$NAME"
      echo "[image] installed into $POOL/$NAME (unprivileged)"
      exit 0
    fi
    # Root-owned pool: only works where sudo is already passwordless.
    if sudo -n install -o libvirt-qemu -g kvm -m 0644 "$STAGE/$NAME" "$POOL/$NAME" 2>/dev/null; then
      sudo -n touch "$POOL/$NAME.done" 2>/dev/null
      rm -f "$STAGE/$NAME"
      echo "[image] installed into $POOL/$NAME (via sudo)"
      exit 0
    fi
    echo "[image] downloaded OK but $POOL is not writable by $(id -un)." >&2
    echo "[image] The download is kept at $STAGE/$NAME — re-run to install, no re-download." >&2
    echo "[image] Grant write access ONCE on the host (no stored credential, world perms unchanged):" >&2
    echo "[image]   sudo chgrp kvm $POOL && sudo chmod 2771 $POOL" >&2
    echo "[image] Requires $(id -un) in group kvm; verify with: id -nG" >&2
    exit 1
  fi
  # 33/36: the server refused the range -> the partial is unusable, restart clean
  if [ $rc -eq 33 ] || [ $rc -eq 36 ]; then
    echo "[image] resume rejected (rc=$rc), restarting from zero"
    rm -f "$STAGE/$NAME"
  fi
  echo "[image] attempt $attempt failed rc=$rc, re-resuming"
  sleep 10
done
echo "[image] FAILED after 5 attempts: $NAME" >&2
exit 1
"#,
);

/// Capture a guest's serial console during a fresh boot.
///
/// The tool for "the VM will not boot and nothing says why". It is what surfaced
/// the `--graphics none` GRUB loop: the console showed GRUB re-printing
/// ``Booting `Debian GNU/Linux'`` forever with no kernel output at all, which no
/// other signal revealed — `domstate` cheerfully said `running` throughout.
///
/// Destructive to the guest's uptime: it force-stops the domain to catch the boot
/// from the start, because attaching afterwards shows nothing on a hung guest.
///
/// # Enforcement point for `__DOMAIN__` (S1 — read before editing the template)
///
/// This is the **only** template where `Binding::Literal`'s escaping is not by
/// itself the control, because `script -qec` re-parses its argument as a command
/// string in a nested shell (see the inline comment at that line). Two controls
/// carry it, and neither is visible from the token site:
///
/// 1. **In the template:** the nested command string is single-quoted and `DOM` is
///    exported, so the value is expanded by the inner shell as one quoted word.
///    Proven by `guest_console_nested_command_string_is_single_quoted`.
/// 2. **At the caller:** `execute_ops_vm_lab_guest_console` validates the domain
///    with [`super::ensure_provision_guest_name`] (`[A-Za-z0-9_-]`, `1..=60`),
///    which admits nothing a shell would treat as syntax in the first place.
///
/// **Honest gap (S6):** `guest_console` has no `dry_run` path, so no test goes red
/// if that caller-side validation call is deleted — unlike the nine calls covered
/// by `provision_guest_enforcement_tests`. Control 1 is therefore the one that is
/// mechanically proven; control 2 is defence in depth that a reader must preserve
/// deliberately. If a `dry_run` is ever added to this command, add the negative
/// test that binds it.
const HOST_GUEST_CONSOLE_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
DOM=__DOMAIN__
SECS=__SECONDS__
virsh -c qemu:///system destroy "$DOM" >/dev/null 2>&1 || true
sleep 2
# `script` supplies the pty that `virsh console` requires over a non-tty ssh session.
#
# THE ONE PLACE ESCAPING AT INTERPOLATION IS NOT SUFFICIENT (S1).
# `script -qec <string>` hands <string> to `$SHELL -c`, so it is re-parsed as a
# COMMAND STRING by a nested shell. `shell_quote`ing the `DOM=` assignment above
# protects that assignment and nothing else: with the command string
# double-quoted, the OUTER shell would expand `$DOM` into it and the INNER shell
# would then re-parse the expanded value, so a `;` in the value would run.
#
# Two changes make the nested parse safe, and both are load-bearing:
#   1. the command string is SINGLE-quoted, so the outer shell does not expand
#      anything into it;
#   2. `DOM` is exported for this command, so the INNER shell expands `"$DOM"`
#      itself, as one already-quoted word.
# Do not "simplify" this back to interpolating $DOM into a double-quoted string.
DOM="$DOM" timeout "$SECS" script -qec 'virsh -c qemu:///system start --console "$DOM"' /dev/null 2>&1 | head -120
echo
echo "--- capture ended ---"
echo "domstate: $(virsh -c qemu:///system domstate "$DOM" 2>&1)"
"#,
);

/// The toolchain a Debian-family lab guest needs before `rn_bootstrap.sh` will run.
///
/// `rn_bootstrap` **verifies** prerequisites and fails when they are missing — it
/// does not install them — so a fresh cloud image needs this first. Shipped over
/// SSH on **stdin**, never argv, and it interpolates exactly one value (the pinned
/// toolchain channel, validated before use).
///
/// Every non-obvious line here is a lesson that cost real time; see the inline
/// comments before "simplifying" any of them.
const GUEST_TOOLCHAIN_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
echo "[toolchain] $(. /etc/os-release; echo "$PRETTY_NAME") on $(uname -m)"

# rn_bootstrap runs `sudo -n`, so passwordless sudo is a hard prerequisite, not a
# nicety. Fail here with the reason rather than deep inside a build.
if ! sudo -n true 2>/dev/null; then
  echo "[toolchain] FATAL: passwordless sudo is required (rn_bootstrap uses 'sudo -n')" >&2
  exit 1
fi
echo "[toolchain] passwordless sudo: ok"

export DEBIAN_FRONTEND=noninteractive

# Retry apt rather than pinning a mirror. An update was observed to stall on a
# connection that never delivered, while EVERY mirror edge served a full payload
# in <0.25s when probed directly — including the exact IP apt was stuck on. That
# is a transient stall on a flaky link, not a broken mirror. The last attempt is
# verbose because `-qq` is what hid the explanation the first time.
apt_update() {
  for attempt in 1 2 3; do
    if sudo -n timeout 180 apt-get update -qq >/dev/null 2>&1; then
      echo "[toolchain] apt-get update ok (attempt $attempt)"; return 0
    fi
    echo "[toolchain] apt-get update stalled/failed (attempt $attempt), retrying"
  done
  echo "[toolchain] apt-get update failing — verbose attempt:" >&2
  sudo -n timeout 180 apt-get update 2>&1 | tail -5 >&2
  return 1
}
if [ "${VERIFY_ONLY:-0}" != "1" ]; then
  apt_update || exit 1
  # nft=nftables, wg=wireguard-tools, ping=iputils-ping; clang+llvm for bindgen;
  # dnsutils=dig, required by the exit_dns_failclosed_validation live-lab stage
  # (Debian cloud images ship no dnsutils, so dig is absent without this).
  sudo -n timeout 1200 apt-get install -y -qq \
    curl git make pkg-config clang llvm libclang-dev \
    build-essential \
    nftables wireguard-tools iproute2 \
    tar gzip tcpdump iputils-ping dnsutils \
    libssl-dev libsqlite3-dev ca-certificates \
    >/dev/null 2>&1
  echo "[toolchain] apt packages installed"

  # rustup pinned to the repo's rust-toolchain.toml channel, so the guest builds
  # with the same compiler as CI instead of whatever is newest.
  if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
    sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain __CHANNEL__ \
      -c rustfmt -c clippy >/dev/null 2>&1
    echo "[toolchain] rustup installed (__CHANNEL__)"
  else
    echo "[toolchain] rustup already present"
  fi

  # Put the rustup shims on the DEFAULT PATH.
  #
  # rustup installs into ~/.cargo/bin and only adds it via ~/.profile, which a
  # NON-LOGIN ssh shell never sources — and that is exactly the shell the
  # orchestrator drives guests over. So `ssh guest cargo build` dies with 127
  # (command not found) while cargo is sitting there installed. The working UTM
  # fleet has its shims on /usr/bin for this reason. /usr/local/bin is already on
  # the default PATH, so link there — keeping rustup, and therefore
  # rust-toolchain.toml's pin, rather than a distro cargo that would ignore it.
  for shim in cargo rustc rustup rustfmt cargo-clippy clippy-driver rustdoc; do
    if [ -x "$HOME/.cargo/bin/$shim" ]; then
      sudo -n ln -sf "$HOME/.cargo/bin/$shim" "/usr/local/bin/$shim"
    fi
  done
  echo "[toolchain] rustup shims linked into /usr/local/bin (non-login PATH)"
fi

# Verify with rn_bootstrap's OWN path. A non-login ssh shell has
# PATH=/usr/local/bin:/usr/bin:/bin:/usr/games — no /usr/sbin — so `command -v nft`
# reports MISSING for a binary sitting at /usr/sbin/nft. That is this repo's
# documented "sbin PATH fail-open": checking with a narrower PATH than the consumer
# uses yields a confident false negative. rn_bootstrap prepends the sbin dirs, so a
# checker that does not is stricter AND wronger than the thing it checks for.
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

echo "--- rn_bootstrap prerequisite check (its list, its PATH) ---"
missing=0
for cmd in curl git make pkg-config clang nft wg rustup tar gzip tcpdump ping dig; do
  if command -v "$cmd" >/dev/null 2>&1; then printf "  %-12s ok\n" "$cmd"
  else printf "  %-12s MISSING\n" "$cmd"; missing=1; fi
done
if command -v gcc >/dev/null 2>&1 || command -v cc >/dev/null 2>&1; then echo "  C compiler   ok"; else echo "  C compiler   MISSING"; missing=1; fi
if command -v g++ >/dev/null 2>&1 || command -v c++ >/dev/null 2>&1; then echo "  C++ compiler ok"; else echo "  C++ compiler MISSING"; missing=1; fi
if command -v llvm-config >/dev/null 2>&1 || ls /usr/bin/llvm-config-* >/dev/null 2>&1; then echo "  llvm-config  ok"; else echo "  llvm-config  MISSING"; missing=1; fi
if pkg-config --exists openssl; then echo "  pkgcfg openssl  ok"; else echo "  pkgcfg openssl  MISSING"; missing=1; fi
if pkg-config --exists sqlite3; then echo "  pkgcfg sqlite3  ok"; else echo "  pkgcfg sqlite3  MISSING"; missing=1; fi
echo "  rust:        $(rustc --version 2>/dev/null || echo MISSING)"
echo "  cargo:       $(cargo --version 2>/dev/null || echo MISSING)"
if [ "$missing" -eq 0 ]; then
  echo "[toolchain] ALL PREREQUISITES SATISFIED"
  exit 0
fi
echo "[toolchain] PREREQUISITES MISSING — rn_bootstrap would fail" >&2
exit 1
"#,
);

/// Launcher shipped to a host to start a live-lab run **detached**.
///
/// The problem it solves: `vm-lab-orchestrate-live-lab` runs for 30–45 minutes,
/// but an SSH invocation that waited for it would die the moment the connection
/// dropped — and this is the one action the whole multi-host program exists to
/// remove from manual SSH. So the run must outlive the launching connection.
///
/// How it stays alive and stays killable:
/// - A tiny **runner** script writes its own `$$` to a pidfile and then `exec`s
///   the orchestrator, so the pid we record IS the orchestrator's pid (an `exec`
///   keeps the pid). `$!` cannot be used because `setsid` forks and the parent
///   exits immediately, leaving `$!` pointing at a corpse.
/// - `setsid` puts the orchestrator in a **new session/process group**, so it is
///   not killed when this SSH session closes AND `vm-lab-stop-host-run` can signal
///   the whole group by the recorded pid.
/// - `nohup` + redirecting all three fds off the SSH channel means the launcher
///   returns in ~1s (it only waits for the pidfile, written before the slow
///   `cargo` compile/exec) instead of blocking for the whole run.
///
/// **Quoting (QH-01/QH-05).** This comment used to read "every interpolated value
/// is single-quoted here and the caller forbids a literal single quote in any of
/// them, so the quoting cannot be escaped". That was false — it silently omitted
/// the three values (`__ORCH_IDENTITY__`, `__ORCH_KNOWN_HOSTS__`, `__ORCH_ARGS__`)
/// that carried quotes *by construction*, which is the gap QH-01 exploited.
///
/// The truth now: the template holds **bare** tokens and
/// [`render_host_launch_script`] decides how each is spelled. `__REPO_DIR__` and
/// `__REPORT_DIR__` are `Literal`s the renderer `shell_quote`s; `__LAUNCH_ID__` is
/// `Bare` because it sits inside longer quoted paths; the two SSH paths are a
/// compile-time `RawFragment` default or a renderer-quoted `Literal` override; and
/// `__ORCH_ARGS__` is `QuotedWords`, so the caller no longer joins `'a' 'b'`
/// itself.
///
/// **Double parse.** The `<<'RUNNER_EOF'` heredoc below writes a *second* script
/// that `bash` re-parses, so a value carrying `\n` plus a line reading
/// `RUNNER_EOF` would close the heredoc early and run the remainder in this,
/// the OUTER, script. `ensure_literal_binding_value` is that control; proven by
/// `a_newline_bearing_literal_cannot_close_the_runner_heredoc`.
const HOST_LAUNCH_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
REPO_DIR=__REPO_DIR__
cd "$REPO_DIR" || { echo "LAUNCH-ERROR: repo_dir not found: $REPO_DIR" >&2; exit 1; }

# NO concurrency gate here. Mutual exclusion is taken by the orchestrator itself
# (QH-18): a per-GUEST flock at the ops dispatch chokepoint, which every invocation
# form reaches — including the one this script launches and the bare
# `ops vm-lab-orchestrate-live-lab` the runbooks document.
#
# The argv-pattern gate that used to sit here could not be repaired in place.
# Driven inline over ssh the whole script text lands in the remote `bash -c` argv,
# so the pattern matched its own launcher and refused on an idle host; and no
# rewriting of the pattern removes that, because the script must contain the
# subcommand string it is about to run. It was also the wrong unit — per-HOST, so
# it refused the disjoint-guest concurrency the project deliberately supports
# (MAX_CONCURRENT_LAB_RUNS = 3).

# Only the run-handle dir is created here. The report dir is left for the
# orchestrator, which refuses to start into a NON-EMPTY one — so the launcher must
# not seed it (an earlier version put the log inside it and the run refused itself).
mkdir -p 'state/host-lab-runs' || { echo "LAUNCH-ERROR: cannot create state/host-lab-runs" >&2; exit 1; }

# Retire leftover pidfiles so they do not accumulate across a session and a later
# stop never has a dead pid to consider. Each one is checked for liveness first:
# with the old per-host gate gone, a run on DISJOINT guests may legitimately be in
# flight, and deleting its pidfile would strip the stop path of its handle. A pid is
# kept only while it is still the orchestrator, verified by argv (`-ww` so a leaked
# COLUMNS cannot truncate the marker away and divert a live run to deletion); dead
# and recycled pids are removed.
for stale_pidfile in state/host-lab-runs/*.pid; do
  [ -f "$stale_pidfile" ] || continue
  stale_pid="$(cat "$stale_pidfile" 2>/dev/null || true)"
  if [ -n "$stale_pid" ] && ps -ww -o args= -p "$stale_pid" 2>/dev/null | grep -q 'vm-lab-orchestrate-live-lab'; then
    continue
  fi
  rm -f "$stale_pidfile" 2>/dev/null || true
done

RUNNER='state/host-lab-runs/__LAUNCH_ID__.run.sh'
PIDFILE='state/host-lab-runs/__LAUNCH_ID__.pid'
LOG='state/host-lab-runs/__LAUNCH_ID__.log'

# Quoted heredoc: the shell writes this verbatim, so $$ and $HOME survive to
# runtime rather than expanding now. The __PLACEHOLDERS__ were already substituted
# in Rust before the script was sent.
cat > "$RUNNER" <<'RUNNER_EOF'
#!/bin/bash
cd __REPO_DIR__ || exit 1
echo $$ > 'state/host-lab-runs/__LAUNCH_ID__.pid'
exec cargo run --quiet -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab --report-dir __REPORT_DIR__ --ssh-identity-file __ORCH_IDENTITY__ --known-hosts-file __ORCH_KNOWN_HOSTS__ __ORCH_ARGS__
RUNNER_EOF

setsid nohup bash "$RUNNER" > "$LOG" 2>&1 < /dev/null &

# The runner writes its pid before exec'ing cargo, so this appears within a moment
# even though the compile/run that follows takes far longer.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  [ -s "$PIDFILE" ] && break
  sleep 0.3
done
PID="$(cat "$PIDFILE" 2>/dev/null || true)"
if [ -z "${PID:-}" ]; then
  echo "LAUNCH-ERROR: runner did not report a pid within ~4.5s (see $LOG)" >&2
  exit 3
fi
echo "LAUNCHED launch_id=__LAUNCH_ID__ pid=$PID log=$LOG"
"#,
);

/// Recover stuck libvirt guests on a host — the counterpart to the UTM
/// `probe_and_recover_local_utm.sh` for the libvirt/KVM backend.
///
/// "Stuck" for a libvirt guest means: **running but with no DHCP lease** (the
/// network wedged and it never got an address), **paused**, or **shut off** when it
/// should be up. The fix is a hard `destroy` + `start`, which forces a clean boot
/// and a fresh lease. A **healthy** guest — running with an IP — is left alone
/// unless `--force`, so running this against a host with healthy guests is a safe
/// no-op that reports "skip (healthy)" rather than needlessly bouncing them.
///
/// QH-03 fail-closed contract: the caller accepts a run only as
/// **exit 0 AND `RECOVER-END` present** (`run_guest_script` rejects a non-zero
/// status, and `execute_ops_vm_lab_recover_host_vms` requires the sentinel). The
/// two halves must therefore agree:
///
/// - **Required steps** (domain enumeration, every recovery action, and the
///   post-action "is it actually running" verification) print
///   `RECOVER-ERROR: ...` to stderr and `exit 1` — no `RECOVER-END` is printed, so
///   a wholly failed run can never read as success.
/// - **Tolerated steps** are *visibly* tolerated, never silently `|| true`: a
///   named domain absent from the host prints `NOT FOUND ... (skipped)` and a
///   healthy guest prints `skip (healthy: ...)`, and the run still succeeds.
const HOST_RECOVER_VMS_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
FORCE=__FORCE__
TARGETS=__TARGETS__

recover_error() {
  echo "RECOVER-ERROR: $*" >&2
  exit 1
}

echo "RECOVER-BEGIN"
if [ -z "$TARGETS" ]; then
  # REQUIRED: enumerating the host's domains is the operation's input. A failing
  # virsh is not "no guests" (an empty-but-valid list is) — it is "cannot run the
  # recovery at all".
  list_out="$(virsh -c qemu:///system list --name --all 2>/dev/null)" \
    || recover_error "cannot enumerate domains on this host: 'virsh list' failed (is libvirtd reachable?)"
  TARGETS="$(printf '%s\n' "$list_out" | grep -v '^$' | tr '\n' ' ')"
fi

for d in $TARGETS; do
  # TOLERATED (visible): a named domain that is not on this host is an operator
  # listing mistake, not a recovery failure — report it and continue.
  st="$(virsh -c qemu:///system domstate "$d" 2>/dev/null)" || st=""
  if [ -z "$st" ]; then echo "  $d: NOT FOUND on this host (skipped)"; continue; fi
  ip="$(virsh -c qemu:///system domifaddr "$d" 2>/dev/null | grep -oE '([0-9]+\.){3}[0-9]+' | grep -v '^127\.' | head -1)"
  case "$st" in
    running)
      if [ "$FORCE" = "1" ] || [ -z "$ip" ]; then
        # REQUIRED: the reset must actually take effect. `destroy || true` here is
        # exactly the QH-03 defect — a failed start after a successful destroy
        # leaves the guest SHUT OFF while the script printed success.
        virsh -c qemu:///system destroy "$d" >/dev/null 2>&1 \
          || recover_error "domain $d: destroy failed during reset (guest left as-is)"
        virsh -c qemu:///system start "$d" >/dev/null 2>&1 \
          || recover_error "domain $d: start failed after destroy — GUEST LEFT SHUT OFF"
        st_now="$(virsh -c qemu:///system domstate "$d" 2>/dev/null)" || st_now=""
        [ "$st_now" = "running" ] \
          || recover_error "domain $d: reset did not take effect (state now: ${st_now:-unknown})"
        echo "  $d: RESET (was running${ip:+, ip=$ip}${ip:+, forced}${ip:-, no lease})"
      else
        echo "  $d: skip (healthy: running, ip=$ip)"
      fi
      ;;
    paused)
      # REQUIRED: resume first; if that fails, fall back to a full reset — but
      # every fallback leg is itself checked, and the end state is verified.
      if ! virsh -c qemu:///system resume "$d" >/dev/null 2>&1; then
        virsh -c qemu:///system destroy "$d" >/dev/null 2>&1 \
          || recover_error "domain $d: resume failed and destroy fallback failed"
        virsh -c qemu:///system start "$d" >/dev/null 2>&1 \
          || recover_error "domain $d: start failed after destroy fallback — GUEST LEFT SHUT OFF"
      fi
      st_now="$(virsh -c qemu:///system domstate "$d" 2>/dev/null)" || st_now=""
      [ "$st_now" = "running" ] \
        || recover_error "domain $d: paused recovery did not take effect (state now: ${st_now:-unknown})"
      echo "  $d: RECOVERED (was paused)"
      ;;
    *)
      # REQUIRED: starting a shut-off guest is the whole action; a failed start
      # must not print STARTED.
      virsh -c qemu:///system start "$d" >/dev/null 2>&1 \
        || recover_error "domain $d: start failed (was $st)"
      st_now="$(virsh -c qemu:///system domstate "$d" 2>/dev/null)" || st_now=""
      [ "$st_now" = "running" ] \
        || recover_error "domain $d: start did not take effect (state now: ${st_now:-unknown})"
      echo "  $d: STARTED (was $st)"
      ;;
  esac
done
# Sentinel printed ONLY on success: every required step above either succeeded or
# the script already exited 1 through recover_error without reaching this line.
echo "RECOVER-END"
"#,
);

/// Report a remote host's disk: filesystem headroom on the image pool, plus what
/// is consuming it (base images + per-guest qcow2 overlays accrue there).
///
/// The `du` is capped to one directory level (`--max-depth=1`) and to the pool, so
/// it stays fast and cannot wander the whole disk. Sizes are listed largest-first
/// because "what do I delete to reclaim space?" is the question this answers.
///
/// QH-03 fail-closed contract: the caller accepts a run only as **exit 0 AND
/// `DISK-END` present** (`run_guest_script` rejects a non-zero status, and
/// `execute_ops_vm_lab_host_disk_status` requires the sentinel — a truncated run
/// is an error, not a short report).
///
/// - **Required steps** (the pool directory must exist and be measurable — it is
///   the *subject* of the report; the `df` headroom line and the `du` pool total
///   are the two headline numbers) print `DISK-ERROR: ...` to stderr and `exit 1`
///   with no `DISK-END`, so a failed report can never read as success.
/// - **Tolerated steps** are *visibly* tolerated: the advisory largest-files
///   listing prints `(largest-files listing unavailable: ...)` when it cannot be
///   produced and `(size unavailable)` next to any file whose individual `du`
///   fails, and the run still succeeds — the headline numbers above are the
///   answer the caller asked for.
const HOST_DISK_STATUS_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
POOL=__POOL__
disk_error() {
  echo "DISK-ERROR: $*" >&2
  exit 1
}

# REQUIRED: the pool is the subject of the report. A missing pool is not an empty
# report — it is "the thing you asked about is not here".
if [ ! -d "$POOL" ]; then
  disk_error "pool directory $POOL does not exist on this host"
fi
echo "DISK-BEGIN"
echo "-- filesystem holding the pool --"
df -h "$POOL" 2>/dev/null || disk_error "df failed for $POOL (cannot report headroom)"
echo "-- pool total --"
du -sh "$POOL" 2>/dev/null || disk_error "du failed for $POOL (cannot report pool usage)"
echo "-- largest files in the pool (base images + guest overlays) --"
# TOLERATED (visible): this section is advisory; if it cannot be produced the
# run still succeeds because the two headline numbers above are the answer.
if ! listing="$(ls -1S "$POOL" 2>/dev/null)"; then
  echo "  (largest-files listing unavailable: ls failed for $POOL)"
else
  printf '%s\n' "$listing" | head -20 | while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -e "$POOL/$f" ] || continue
    sz="$(du -h "$POOL/$f" 2>/dev/null | cut -f1)"
    if [ -n "$sz" ]; then
      printf '  %s\t%s\n' "$sz" "$f"
    else
      printf '  (size unavailable)\t%s\n' "$f"
    fi
  done
fi
# Sentinel printed ONLY on success: every required step above either succeeded or
# the script already exited 1 through disk_error without reaching this line.
echo "DISK-END"
"#,
);

/// Renumber a host's libvirt `default` network off the shared libvirt default
/// (`192.168.122.0/24`) onto the host's declared `guest_subnet`, so several KVM
/// hosts can each advertise their guest subnet to the tailnet without colliding.
///
/// Two deliberate improvements over the scratchpad it replaces:
/// - **No sudo.** The scratchpad piped a password into `sudo -S`; a libvirt-group
///   member can drive `net-define`/`destroy`/`start` on `qemu:///system` directly
///   (verified on `ubuntu-kvm-1`), so no credential is needed or embedded.
/// - **Idempotent.** It reads the network's CURRENT prefix and no-ops if it already
///   matches the target — so re-running it does NOT needlessly destroy the network
///   and restart every guest. The restart (guests must re-lease) only happens on an
///   actual change.
const HOST_RENUMBER_NET_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
NET=default
TARGET_PREFIX=__TARGET_PREFIX__

XML="$(virsh -c qemu:///system net-dumpxml "$NET" 2>/dev/null)" || {
  echo "RENUMBER-ERROR: cannot read libvirt network '$NET' (is $(id -un) in the libvirt group?)" >&2
  exit 1
}
CUR_IP="$(printf '%s' "$XML" | grep -oE "<ip address='[0-9.]+'" | head -1 | grep -oE '[0-9.]+' | head -1)"
if [ -z "$CUR_IP" ]; then
  echo "RENUMBER-ERROR: could not find the current IPv4 in the '$NET' network XML" >&2
  exit 1
fi
CUR_PREFIX="${CUR_IP%.*}."

if [ "$CUR_PREFIX" = "$TARGET_PREFIX" ]; then
  echo "RENUMBER-RESULT: already on ${TARGET_PREFIX}0/24 — no change, guests untouched"
  exit 0
fi

echo "RENUMBER-RESULT: renumbering ${CUR_PREFIX}0/24 -> ${TARGET_PREFIX}0/24"
TMP="$(mktemp)"
printf '%s' "$XML" | sed "s/${CUR_PREFIX//./\\.}/${TARGET_PREFIX}/g" > "$TMP"
virsh -c qemu:///system net-destroy "$NET" >/dev/null 2>&1 || true
virsh -c qemu:///system net-undefine "$NET" >/dev/null 2>&1 || true
virsh -c qemu:///system net-define "$TMP" || { echo "RENUMBER-ERROR: net-define failed" >&2; rm -f "$TMP"; exit 1; }
virsh -c qemu:///system net-start "$NET" || { echo "RENUMBER-ERROR: net-start failed" >&2; rm -f "$TMP"; exit 1; }
virsh -c qemu:///system net-autostart "$NET" >/dev/null 2>&1 || true
rm -f "$TMP"

# Running guests must be bounced to pick up a lease on the new subnet.
for d in $(virsh -c qemu:///system list --name --all | grep -v '^$'); do
  st="$(virsh -c qemu:///system domstate "$d" 2>/dev/null || echo unknown)"
  if [ "$st" = "running" ]; then
    virsh -c qemu:///system destroy "$d" >/dev/null 2>&1 || true
  fi
  virsh -c qemu:///system start "$d" >/dev/null 2>&1 || true
  echo "  restarted: $d"
done
echo "RENUMBER-RESULT: done"
"#,
);

/// Read one file out of a host's checkout — the missing half of `host_run_status`,
/// which hands back a `report_dir` nothing could then read.
///
/// Read-only and bounded: a size cap keeps a stray path (a multi-GB capture, a core
/// dump) from being streamed into a tool response. The path is confined to the
/// host's repo_dir by the caller (relative, no traversal), so this cannot exfiltrate
/// arbitrary host files.
const HOST_FETCH_ARTIFACT_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
REPO_DIR=__REPO_DIR__
cd "$REPO_DIR" || { echo "FETCH-ERROR: repo_dir not found: $REPO_DIR" >&2; exit 1; }
P=__PATH__
if [ ! -f "$P" ]; then echo "FETCH-ERROR: not a regular file: $P" >&2; exit 2; fi
SIZE="$(stat -c %s "$P" 2>/dev/null || echo 0)"
CAP=__CAP__
if [ "$SIZE" -gt "$CAP" ]; then
  echo "FETCH-ERROR: $P is $SIZE bytes, over the $CAP-byte cap; narrow the path or raise --max-bytes" >&2
  exit 3
fi
echo "FETCH-META path=$P size=$SIZE"
echo "FETCH-BODY-BEGIN"
cat "$P"
"#,
);

/// Script shipped to a host to stop an in-flight live-lab run.
///
/// Signals the run's **process group**, not just the leader, so the whole tree
/// (`cargo` → `rustynet-cli` → the guest-SSH children) goes down together — a plain
/// `kill <pid>` would orphan the children to keep running against the guests. The
/// recorded pid IS the session-leader/pgid (the runner wrote it before `exec`), so
/// `kill -- -<pid>` reaches the group. TERM first, then KILL after a grace period.
///
/// **The recorded pidfiles are the ONLY source of candidate pids (STOP-PGREP).** A
/// `pgrep -f 'vm-lab-orchestrate-live-lab'` fallback used to be unioned in for a run
/// whose handle file was lost. It could not be repaired in place, for the same reason
/// the launch-side gate could not (QH-18): this script is driven **inline** over SSH,
/// so its whole text lands in the remote `bash -c` argv — and the text necessarily
/// contains the subcommand string it searches for. `pgrep -f` therefore matched the
/// script's own launcher, and this script's very next act is
/// `kill -TERM -- -<pid>` on the matched pid's **process group** — its own. A stop on
/// an idle host could signal itself, and on a busy host could take down an unrelated
/// shell that merely had the string in its argv.
///
/// What replaces it is not a better pattern but a better handle. The launch script
/// prunes `state/host-lab-runs/*.pid` under an argv liveness check (QH-18), keeping
/// any pidfile whose pid is still the orchestrator, so a live run always has a
/// trustworthy recorded handle. Reading only those pidfiles removes pattern matching
/// from the stop path entirely: the marker string is still used, but only via
/// `ps -p <pid>` against one specific recorded pid, never as a scan over every
/// command line on the box.
///
/// Two guards on each recorded pid, both of which must pass before it is signaled:
///
/// 1. **Ancestor exclusion.** The pid must not be this script's own shell or any of
///    its ancestors. That is the structural half of the self-match fix: even if a
///    pidfile were somehow to name the ssh/bash process carrying this script's text,
///    it could not be signaled.
/// 2. **Pid-recycling guard.** Pidfiles are retired at the next launch, not on
///    natural completion (the runner `exec`s cargo, leaving no shell to clean up), so
///    a stale pidfile can linger between a run finishing and the next launch — and
///    the OS may recycle its dead pid to an unrelated live process. So a pid is
///    signaled ONLY if its argv still contains `vm-lab-orchestrate-live-lab`; a dead
///    or recycled pid is skipped, never killed.
///
/// With no live recorded pid the script signals nothing, prunes the stale handles and
/// says so — the honest answer, and the one that cannot kill a bystander.
const HOST_STOP_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
REPO_DIR=__REPO_DIR__
cd "$REPO_DIR" 2>/dev/null || true

# The recorded handles are the ONLY source of candidate pids. There is deliberately
# NO whole-process-table argv pattern scan anywhere in this script:
# this script is driven inline over ssh, so its own text sits in an ancestor's argv
# and contains the very subcommand string such a scan would search for. The scan
# matched its own launcher, and the next thing this script does is signal the matched
# pid's PROCESS GROUP — its own. The launcher keeps live pidfiles under an argv
# liveness check, so a running orchestrator always has a recorded handle.

# Ancestor chain of this shell (self first). Nothing in it may ever be signaled —
# the structural half of the self-match fix. Bounded so a bogus ppid cannot loop.
ancestors=" "
anc="$$"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
  case "$anc" in ''|0|1) break ;; esac
  ancestors="$ancestors$anc "
  anc="$(ps -o ppid= -p "$anc" 2>/dev/null | tr -d '[:space:]')"
done

# CRITICAL — pid recycling: a recorded pidfile can be stale (its run completed or
# was killed without a stop, so the pid is dead) and the OS may have recycled that
# pid to an UNRELATED live process. Signaling it would kill an innocent process. So
# a recorded pid is signaled ONLY if it is still the orchestrator, verified by its
# argv.
pids=""
skipped=""
for f in state/host-lab-runs/*.pid; do
  [ -f "$f" ] || continue
  p="$(cat "$f" 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$p" ] || continue
  case "$p" in *[!0-9]*) skipped="$skipped $p"; continue ;; esac
  # Never signal ourselves or an ancestor, whatever a pidfile claims.
  case "$ancestors" in *" $p "*) skipped="$skipped $p"; continue ;; esac
  # The recorded pid IS the runner's pid, which exec'd cargo, so a live one's argv
  # still contains 'vm-lab-orchestrate-live-lab'. A dead or recycled pid does not.
  # `-ww` disables ps's COLUMNS width truncation (procps-ng truncates to COLUMNS
  # even down a pipe): the marker sits ~60 cols into the argv, so a leaked COLUMNS
  # would otherwise sever it and divert a LIVE run's pid to `skipped`. This is a
  # lookup of ONE named pid, not a scan — it cannot match anything but that pid.
  if ps -ww -o args= -p "$p" 2>/dev/null | grep -q 'vm-lab-orchestrate-live-lab'; then
    pids="$pids $p"
  else
    skipped="$skipped $p"
  fi
done

# de-dup + drop blanks
pids="$(printf '%s\n' $pids | sort -u | tr '\n' ' ')"
pids="$(echo $pids)"
skipped="$(echo $skipped)"

[ -n "$skipped" ] && echo "STOP-RESULT: ignoring stale/recycled recorded pid(s): $skipped"

if [ -z "$pids" ]; then
  # Nothing live to signal; clear any stale handle files so status stays honest.
  rm -f state/host-lab-runs/*.pid 2>/dev/null || true
  echo "STOP-RESULT: no run in flight (no live recorded pid in state/host-lab-runs)"
  exit 0
fi

echo "STOP-RESULT: signaling: $pids"
for p in $pids; do kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true; done

# grace period, then escalate any survivor
for _ in 1 2 3 4 5 6 7 8 9 10; do
  alive=""
  for p in $pids; do kill -0 "$p" 2>/dev/null && alive="$alive $p"; done
  [ -z "$alive" ] && break
  sleep 0.5
done
survivors=""
for p in $pids; do kill -0 "$p" 2>/dev/null && survivors="$survivors $p"; done
if [ -n "$survivors" ]; then
  echo "STOP-RESULT: escalating to KILL:$survivors"
  for p in $survivors; do kill -KILL -- "-$p" 2>/dev/null || kill -KILL "$p" 2>/dev/null || true; done
fi

# retire the handle files so a later status does not report a dead pid as live
rm -f state/host-lab-runs/*.pid 2>/dev/null || true
echo "STOP-RESULT: stopped"
"#,
);

/// Answer "is a live-lab run in flight on this host?" without a process-table scan.
///
/// **Why this is not `pgrep -f 'vm-lab-orchestrate-live-lab'` (QH-18 class).** The
/// status path drives its probe over SSH, and sshd hands the command to the login
/// shell — so whatever we send arrives as the argument of a remote `bash -c`, and
/// its whole text sits in that shell's argv. A `pgrep -f` for the orchestrator
/// subcommand therefore matched the parent shell that was carrying the pattern,
/// and an idle host reported a run in flight. It is the same defect, and the same
/// unfixable shape, as the launch-side gate and the stop-side fallback: no pattern
/// can be made correct while the probe must contain the string it searches for.
///
/// What replaces it is a better handle, not a better pattern. The launch script
/// keeps `state/host-lab-runs/*.pid` under an argv liveness check, so a genuinely
/// running orchestrator always leaves a trustworthy recorded pid. Reading only
/// those removes pattern matching from the status path entirely: the marker string
/// is still used, but only via `ps -p <pid>` against one specific recorded pid,
/// never as a scan over every command line on the box.
///
/// Each recorded pid clears two guards before it is reported live:
///
/// 1. **Ancestor exclusion.** The pid must not be this shell or any of its
///    ancestors. Structural, and it holds even against a corrupted or forged
///    pidfile — the ssh/bash process carrying this probe's text can never be
///    reported as a run.
/// 2. **Pid-recycling guard.** Pidfiles are retired at the next launch, not on
///    natural completion, so a stale handle can name a pid the OS has since
///    recycled to an unrelated process. A pid counts only if its own argv still
///    contains the orchestrator marker. `-ww` disables ps's COLUMNS truncation,
///    which would otherwise sever the marker and report a live run as absent.
///
/// Read-only: it inspects pidfiles and `ps`, and mutates nothing. A stale handle is
/// left alone here — retiring it belongs to the launch and stop paths, and a status
/// command that silently deleted the stop path's handle would be worse than a
/// slightly untidy directory.
///
/// Output is one `RUN-IN-FLIGHT: <pid> <argv>` line per live recorded pid, and
/// nothing at all when the host is idle.
const HOST_RUN_STATUS_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"#!/bin/bash
set -uo pipefail
REPO_DIR=__REPO_DIR__
cd "$REPO_DIR" 2>/dev/null || true

# Ancestor chain of this shell (self first). Nothing in it may ever be reported as
# a run: this probe is driven inline over ssh, so an ancestor's argv contains this
# text — including the orchestrator marker below. Bounded so a bogus ppid cannot
# loop forever.
ancestors=" "
anc="$$"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
  case "$anc" in ''|0|1) break ;; esac
  ancestors="$ancestors$anc "
  anc="$(ps -o ppid= -p "$anc" 2>/dev/null | tr -d '[:space:]')"
done

# The recorded handles are the ONLY source of candidate pids. There is deliberately
# no whole-process-table argv pattern scan anywhere in this script.
for f in state/host-lab-runs/*.pid; do
  [ -f "$f" ] || continue
  p="$(cat "$f" 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$p" ] || continue
  case "$p" in *[!0-9]*) continue ;; esac
  case "$ancestors" in *" $p "*) continue ;; esac
  args="$(ps -ww -o args= -p "$p" 2>/dev/null || true)"
  case "$args" in *vm-lab-orchestrate-live-lab*) echo "RUN-IN-FLIGHT: $p $args" ;; esac
done
"#,
);

/// Create a libvirt guest on a host: qemu-img overlay + cloud-init seed +
/// virt-install --import. Runs entirely unprivileged — the pool is group-writable
/// to `kvm` and the host user is in `libvirt` (see the pool remediation in the
/// LinuxVmHostPlan).
///
/// **Quoting (QH-01/QH-05).** This comment used to read "each interpolated value is
/// single-quoted and the caller forbids a literal single quote, so the quoting
/// cannot be escaped". All three clauses were wrong: `__AUTH_KEY__`'s value was
/// built as `format!("'{path}'")` and so carried quotes *by construction*; `pool`
/// had no validator at all; and `image` was checked for path shape only. The
/// template now holds **bare** tokens and
/// [`render_host_provision_guest_script`] decides the spelling — see that function
/// for the per-token argument. Enforced by the renderer; proven by
/// `the_provision_script_renders_byte_for_byte` and the
/// `provision_guest_refuses_hostile_*_on_the_real_call_path` tests.
const HOST_PROVISION_GUEST_SCRIPT: ScriptTemplate = ScriptTemplate(
    r##"#!/bin/bash
set -uo pipefail
POOL=__POOL__
NAME=__NAME__
IMAGE=__IMAGE__
DISK_GB=__DISK_GB__
RAM_MB=__RAM_MB__
VCPUS=__VCPUS__
BASE="$POOL/$IMAGE"
OVERLAY="$POOL/$NAME.qcow2"
SEED="$POOL/$NAME-seed.iso"

# TOCTOU re-checks on the box, which is the source of truth for what exists.
[ -f "$BASE" ] || { echo "PROVISION-ERROR: base image not found: $BASE" >&2; exit 1; }
if virsh -c qemu:///system dominfo "$NAME" >/dev/null 2>&1; then
  echo "PROVISION-ERROR: domain $NAME already exists — refusing to overwrite" >&2; exit 2
fi
[ -e "$OVERLAY" ] && { echo "PROVISION-ERROR: overlay already exists: $OVERLAY" >&2; exit 3; }
PUBKEY_SRC=__AUTH_KEY__
PUBKEY="$(cat "$PUBKEY_SRC" 2>/dev/null || true)"
[ -n "$PUBKEY" ] || { echo "PROVISION-ERROR: no readable public key at $PUBKEY_SRC" >&2; exit 4; }

# Copy-on-write overlay on the base image (pool group-writable — no sudo).
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "${DISK_GB}G" >/dev/null 2>&1 \
  || { echo "PROVISION-ERROR: qemu-img create failed" >&2; exit 5; }

# cloud-init seed: hostname + the provisioning host's key on the image's default
# user, so the host can SSH in immediately with no follow-up authorize step.
WORK="$(mktemp -d)"
{
  echo "#cloud-config"
  echo "hostname: $NAME"
  echo "ssh_authorized_keys:"
  echo "  - $PUBKEY"
} > "$WORK/user-data"
{
  echo "instance-id: $NAME"
  echo "local-hostname: $NAME"
} > "$WORK/meta-data"
if ! cloud-localds "$SEED" "$WORK/user-data" "$WORK/meta-data" >/dev/null 2>&1; then
  echo "PROVISION-ERROR: cloud-localds failed (is cloud-image-utils installed?)" >&2
  rm -rf "$WORK"; rm -f "$OVERLAY"; exit 6
fi
rm -rf "$WORK"

# Create + boot. --noautoconsole so virt-install returns instead of attaching a
# console; --video vga because a headless Debian cloud image's GRUB needs a
# framebuffer (a documented lab gotcha).
# --osinfo is mandatory in modern virt-install; detect=on,require=off auto-detects
# from the image and falls back to a generic profile (a perf warning, not a fatal
# error) rather than requiring a per-image OS name.
if ! virt-install --connect qemu:///system --name "$NAME" \
     --memory "$RAM_MB" --vcpus "$VCPUS" --cpu host-passthrough \
     --disk "$OVERLAY" --disk "$SEED",device=cdrom \
     --network network=default,model=virtio --video vga --graphics none \
     --osinfo detect=on,require=off --import --noautoconsole >/dev/null 2>&1; then
  echo "PROVISION-ERROR: virt-install failed (re-run the virt-install by hand for the reason)" >&2
  virsh -c qemu:///system undefine "$NAME" >/dev/null 2>&1 || true
  rm -f "$OVERLAY" "$SEED"; exit 7
fi
virsh -c qemu:///system autostart "$NAME" >/dev/null 2>&1 || true

st="$(virsh -c qemu:///system domstate "$NAME" 2>/dev/null || echo unknown)"
echo "PROVISION-RESULT: created domain $NAME (state=$st, overlay=$OVERLAY, seed=$SEED)"
"##,
);

/// Netplan repair applied to a guest whose NIC went unmanaged after a MAC
/// regen — the documented failure mode. Piped to `sudo bash -s` on the guest, so
/// it runs as **root**: everything interpolated here crosses a privileged
/// boundary.
const NETPLAN_REPAIR_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"set -eu
ts="$(date +%Y%m%dT%H%M%S)"
mkdir -p /etc/netplan
for f in /etc/netplan/*.yaml; do
  [ -e "$f" ] || continue
  cp -a "$f" "$f.rustynet-recover.$ts.bak"
  case "$f" in
    /etc/netplan/00-rustynet-recovery.yaml) ;;
    *) mv "$f" "$f.rustynet-disabled.$ts" ;;
  esac
done
cat > /etc/netplan/00-rustynet-recovery.yaml <<'RN_NETPLAN_EOF'
__RN_NETPLAN__RN_NETPLAN_EOF
chmod 600 /etc/netplan/00-rustynet-recovery.yaml
netplan apply
"#,
);

/// NetworkManager repair for the same failure mode. Also `sudo bash -s`.
const NETWORK_MANAGER_REPAIR_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"set -eu
iface=__RN_IFACE__
con="$(nmcli -t -f NAME,DEVICE con show 2>/dev/null | awk -F: -v i="$iface" '$2==i{print $1; exit}')"
if [ -n "${con:-}" ]; then
  nmcli con mod "$con" 802-3-ethernet.mac-address "" 2>/dev/null || true
  nmcli con mod "$con" ipv4.method auto ipv6.method auto || true
  nmcli con up "$con"
else
  nmcli con add type ethernet ifname "$iface" con-name "rustynet-recover-$iface" ipv4.method auto ipv6.method auto
  nmcli con up "rustynet-recover-$iface"
fi
"#,
);

/// systemd-networkd repair for the same failure mode. Also `sudo bash -s`.
const NETWORKD_REPAIR_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"set -eu
mkdir -p /etc/systemd/network
cat > /etc/systemd/network/10-rustynet-recover.network <<'RN_NETWORKD_EOF'
[Match]
Name=__RN_IFACE__
[Network]
DHCP=yes
RN_NETWORKD_EOF
chmod 644 /etc/systemd/network/10-rustynet-recover.network
systemctl enable --now systemd-networkd 2>/dev/null || true
networkctl reload
networkctl reconfigure __RN_IFACE__
"#,
);

/// Windows Exit evidence capture. PowerShell, not bash: its values are spelled
/// by `powershell_quote` via [`Binding::PowerShellLiteral`].
const WINDOWS_EXIT_EVIDENCE_CAPTURE_SCRIPT: ScriptTemplate = ScriptTemplate(
    r#"
Set-StrictMode -Version Latest;
$ErrorActionPreference = 'Stop';
$ProgressPreference = 'SilentlyContinue';
$ArtifactRoot = __ROOT__;
$DnsDir = Join-Path -Path $ArtifactRoot -ChildPath 'dns_leak_proof';
$DaemonPath = __DAEMON__;
$KillswitchProbeMarker = __MARKER__;
$TunnelAlias = 'rustynet0';
$MeshCidr = '100.64.0.0/10';
$NatName = 'RustyNetExit-rustynet0';
$ServiceName = 'RustyNet';
$script:WrittenLabels = @();
$script:SkippedReasons = @();
function Add-WrittenLabel {
    param([string]$Label)
    $script:WrittenLabels += $Label
}
function Add-SkippedReason {
    param([string]$Reason)
    $script:SkippedReasons += $Reason
}
function Write-JsonFile {
    param([string]$Path, [object]$Value)
    $parent = Split-Path -Parent $Path;
    New-Item -ItemType Directory -Force -Path $parent | Out-Null;
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8;
}
function Get-ForwardingState {
    param([string]$Alias)
    try {
        return [string]((Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction Stop).Forwarding)
    } catch {
        return ('Error: ' + $_.Exception.Message)
    }
}
function Get-DefaultEgressAlias {
    try {
        return [string](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -ne $TunnelAlias } |
            Sort-Object -Property RouteMetric,InterfaceMetric |
            Select-Object -First 1 -ExpandProperty InterfaceAlias)
    } catch {
        return ''
    }
}
function Test-NetNatAbsent {
    # Fail-closed NAT presence (mirrors the RSA-0031 daemon merge in
    # crates/rustynetd/src/windows_exit_nat_lifecycle.rs): only a query that
    # SUCCEEDS and returns no matching NetNat proves the NAT was torn down.
    # `Get-NetNat -ErrorAction SilentlyContinue` conflates "absent" with
    # "provider/WMI query failed" — both return $null — which would let a query
    # error be read as a successful teardown (fail-open). The MSFT_NetNat
    # provider throws a CimException "No MSFT_NetNat objects found ..." for a
    # genuinely-absent named NAT; that single message is the only error that
    # counts as absent. Any other failure is indeterminate → treated as PRESENT
    # (not torn down) so teardown can never be claimed from an error.
    param([string]$Name)
    try {
        $existing = Get-NetNat -Name $Name -ErrorAction Stop;
        return ($null -eq $existing);
    } catch {
        if ($_.Exception.Message -match 'No MSFT_NetNat') {
            return $true;
        }
        return $false;
    }
}

New-Item -ItemType Directory -Force -Path $ArtifactRoot | Out-Null;

$egressAlias = Get-DefaultEgressAlias;
$nat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue;
if ($null -eq $nat) {
    Add-SkippedReason 'NAT lifecycle proof skipped: reviewed NetNat was not present; Windows host is not currently serving exit traffic';
} elseif ([string]::IsNullOrWhiteSpace($egressAlias)) {
    Add-SkippedReason 'NAT lifecycle proof skipped: no non-tunnel default egress interface was detected';
} else {
    $duringTunnelForwarding = Get-ForwardingState -Alias $TunnelAlias;
    $duringEgressForwarding = Get-ForwardingState -Alias $egressAlias;
    $stopError = '';
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop;
        Start-Sleep -Seconds 4;
    } catch {
        $stopError = $_.Exception.Message;
    }
    # Fail-closed teardown evaluation (mirror of the RSA-0031 daemon merge):
    # restoration is proven ONLY when the NAT query succeeds and shows it gone
    # AND both interfaces report the literal 'Disabled'. A NetNat query error
    # counts as still-present; a forwarding query error ('Error: ...') is not
    # 'Disabled' and so cannot be read as restored.
    $afterNatAbsent = Test-NetNatAbsent -Name $NatName;
    $afterTunnelForwarding = Get-ForwardingState -Alias $TunnelAlias;
    $afterEgressForwarding = Get-ForwardingState -Alias $egressAlias;
    $forwardingRestored = $afterNatAbsent -and
        ($afterTunnelForwarding -eq 'Disabled') -and
        ($afterEgressForwarding -eq 'Disabled');
    # The host WAS serving exit (NAT present during run), so a clean teardown is
    # MANDATORY. Always emit the lifecycle artifact with the real measured
    # after-stop state — never skip on a non-restoration. Writing the artifact
    # only on success would let a genuine residual NAT (a release-blocking open
    # relay) be masked as a Skip, because the validate stage maps an ABSENT
    # artifact to Skipped. With the artifact always present, the validator
    # FAILS on netnat_present=true or forwarding_restored=false.
    Write-JsonFile -Path (Join-Path -Path $ArtifactRoot -ChildPath 'scm_context_nat_lifecycle.json') -Value ([pscustomobject]@{
        schema_version = 1;
        nat_name = $NatName;
        mesh_cidr = $MeshCidr;
        during_run = [pscustomobject]@{
            netnat_present = $true;
            internal_prefix = [string]$nat.InternalIPInterfaceAddressPrefix;
            tunnel_forwarding = $duringTunnelForwarding;
            egress_forwarding = $duringEgressForwarding;
            egress_alias = $egressAlias;
        };
        after_stop = [pscustomobject]@{
            netnat_present = (-not $afterNatAbsent);
            forwarding_restored = $forwardingRestored;
            tunnel_forwarding = $afterTunnelForwarding;
            egress_forwarding = $afterEgressForwarding;
            stop_error = $stopError;
        };
    });
    Add-WrittenLabel 'scm_context_nat_lifecycle';
    if (-not $forwardingRestored) {
        Add-SkippedReason ('NAT lifecycle teardown did NOT prove restoration (artifact emitted for fail-closed validation); stop_error=' + $stopError + '; after_nat_absent=' + $afterNatAbsent + '; after_tunnel=' + $afterTunnelForwarding + '; after_egress=' + $afterEgressForwarding);
    }
    try {
        Start-Service -Name $ServiceName -ErrorAction Stop;
        Start-Sleep -Seconds 8;
    } catch {
        Add-SkippedReason ('service restart after NAT lifecycle probe failed: ' + $_.Exception.Message);
    }
}

$dnsRuleNames = @('RustyNetDNS-BlockLanUdp', 'RustyNetDNS-BlockLanTcp');
$dnsRules = @();
foreach ($ruleName in $dnsRuleNames) {
    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue;
    if ($null -ne $rule) {
        $dnsRules += [pscustomobject]@{
            name = [string]$rule.Name;
            action = [string]$rule.Action;
            direction = [string]$rule.Direction;
            enabled = [string]$rule.Enabled;
            profile = [string]$rule.Profile;
        };
    }
}
# `@(...)` around the pipeline is load-bearing under `Set-StrictMode -Version
# Latest` (set at the top of this script): a `Where-Object` that matches nothing
# yields `$null`, and reading `.Count` on `$null` throws PropertyNotFoundStrict.
# `$dnsRules.Count` on the line above needs no wrap — it is initialised `@()` and
# only ever appended to, so it is always an array.
#
# The reachable state is "exactly two DNS rules exist but none is
# Block/Outbound/Enabled": `-and` short-circuits otherwise. It threw rather than
# reporting a false pass, so this was never a bypass — but it threw INSTEAD of
# reporting "rules present but not blocking", and `firewall_block_rules.json` was
# then never written, so the cost was the diagnosability of a security-relevant
# DNS misconfiguration.
$dnsRulesOk = ($dnsRules.Count -eq 2) -and
    (@($dnsRules | Where-Object { $_.action -eq 'Block' -and $_.direction -eq 'Outbound' -and $_.enabled -eq 'True' }).Count -eq 2);
if ($dnsRulesOk) {
    New-Item -ItemType Directory -Force -Path $DnsDir | Out-Null;
    Write-JsonFile -Path (Join-Path -Path $DnsDir -ChildPath 'firewall_block_rules.json') -Value ([pscustomobject]@{
        schema_version = 1;
        overall_ok = $true;
        rules = $dnsRules;
    });
    Add-WrittenLabel 'dns_firewall_block_rules';
    $dnsCheckRaw = (& $DaemonPath windows-dns-failclosed-check --no-fail-on-drift 2>&1) -join [Environment]::NewLine;
    if ($LASTEXITCODE -eq 0) {
        Set-Content -LiteralPath (Join-Path -Path $DnsDir -ChildPath 'windows_dns_failclosed_check.json') -Value $dnsCheckRaw -Encoding UTF8;
        Add-WrittenLabel 'dns_failclosed_check';
    } else {
        Add-SkippedReason ('windows-dns-failclosed-check did not exit cleanly: ' + $dnsCheckRaw);
    }
} else {
    Add-SkippedReason 'DNS packet proof precheck skipped: reviewed RustyNet DNS block firewall rules were not both present/enforced';
}

if (Test-Path -LiteralPath $KillswitchProbeMarker -PathType Leaf) {
    $baselineRaw = (& $DaemonPath windows-killswitch-assert --no-fail-on-drift 2>&1) -join [Environment]::NewLine;
    $baselineCode = [int]$LASTEXITCODE;
    $baselineOk = $false;
    try {
        $baselineJson = $baselineRaw | ConvertFrom-Json -ErrorAction Stop;
        $baselineOk = [bool]$baselineJson.overall_ok;
    } catch {
        Add-SkippedReason ('killswitch precedence proof skipped: baseline JSON parse failed: ' + $_.Exception.Message);
    }
    if ($baselineCode -eq 0 -and $baselineOk) {
        $tamperedRaw = '';
        $tamperedCode = 0;
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction Stop;
            $tamperedRaw = (& $DaemonPath windows-killswitch-assert 2>&1) -join [Environment]::NewLine;
            $tamperedCode = [int]$LASTEXITCODE;
        } finally {
            try {
                Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block -ErrorAction SilentlyContinue;
            } catch {
            }
            try {
                Start-Service -Name $ServiceName -ErrorAction SilentlyContinue;
                Start-Sleep -Seconds 8;
            } catch {
            }
        }
        if ($tamperedCode -ne 0) {
            Write-JsonFile -Path (Join-Path -Path $ArtifactRoot -ChildPath 'killswitch_precedence.json') -Value ([pscustomobject]@{
                schema_version = 1;
                baseline_assert = [pscustomobject]@{
                    overall_ok = $true;
                };
                tampered_assert = [pscustomobject]@{
                    overall_ok = $false;
                    exit_code = $tamperedCode;
                    reason = $tamperedRaw.Trim();
                };
            });
            Add-WrittenLabel 'killswitch_precedence';
        } else {
            Add-SkippedReason 'killswitch precedence proof skipped: tampered assertion exited zero';
        }
    } elseif ($baselineCode -ne 0) {
        Add-SkippedReason ('killswitch precedence proof skipped: baseline assertion failed: ' + $baselineRaw);
    }
} else {
    Add-SkippedReason ('killswitch precedence proof skipped: marker file not present at ' + $KillswitchProbeMarker);
}

[pscustomobject]@{
    schema_version = 1;
    artifact_root = $ArtifactRoot;
    written_labels = $script:WrittenLabels;
    skipped_reasons = $script:SkippedReasons;
} | ConvertTo-Json -Depth 12
"#,
);

// --- named render functions: the module's ONLY exported surface -------------
//
// Every function below is the single place a given host script can be produced.
// Callers hand over plain values; the binding kinds here are the safety
// argument, and they are asserted against the templates by
// `no_literal_token_is_adjacent_to_a_quote_in_its_template`.

/// Render the image-fetch script. `sha256` empty means "unpinned" and
/// `expect_model` empty means "the host declares no pool disk" — both render as
/// `''` and the script branches on emptiness, so `Literal` must (and does) allow
/// empty. Proven by `an_empty_literal_renders_as_an_empty_shell_word`.
pub(crate) fn render_host_fetch_image_script(
    pool: &str,
    name: &str,
    url: &str,
    sha256: &str,
    expect_model: &str,
) -> Result<String, String> {
    render_script_template(
        HOST_FETCH_IMAGE_SCRIPT,
        &[
            ("__POOL__", Binding::Literal(pool)),
            ("__NAME__", Binding::Literal(name)),
            ("__URL__", Binding::Literal(url)),
            ("__SHA256__", Binding::Literal(sha256)),
            ("__EXPECT_MODEL__", Binding::Literal(expect_model)),
        ],
    )
}

/// Render the guest boot-console capture. `seconds` is a clamped `u32`, so it is
/// rendered `Bare` (unquoted) — `timeout "$SECS"` wants a number.
pub(crate) fn render_host_guest_console_script(
    domain: &str,
    seconds: u32,
) -> Result<String, String> {
    render_script_template(
        HOST_GUEST_CONSOLE_SCRIPT,
        &[
            ("__DOMAIN__", Binding::Literal(domain)),
            ("__SECONDS__", Binding::Bare(&seconds.to_string())),
        ],
    )
}

/// Render the guest toolchain installer. The channel is a `rustup` argument and
/// a bare word inside `--default-toolchain __CHANNEL__`, so it is `Bare`.
pub(crate) fn render_guest_toolchain_script(channel: &str) -> Result<String, String> {
    render_script_template(
        GUEST_TOOLCHAIN_SCRIPT,
        &[("__CHANNEL__", Binding::Bare(channel))],
    )
}

/// Render the stuck-guest recovery script. `targets` is a space-joined domain
/// list and is legitimately empty ("every domain on the host"), so it is a
/// `Literal`; `force` is a rendered `0`/`1` and is `Bare`.
pub(crate) fn render_host_recover_vms_script(force: bool, targets: &str) -> Result<String, String> {
    render_script_template(
        HOST_RECOVER_VMS_SCRIPT,
        &[
            ("__FORCE__", Binding::Bare(if force { "1" } else { "0" })),
            ("__TARGETS__", Binding::Literal(targets)),
        ],
    )
}

/// Render the pool disk-usage report.
pub(crate) fn render_host_disk_status_script(pool: &str) -> Result<String, String> {
    render_script_template(
        HOST_DISK_STATUS_SCRIPT,
        &[("__POOL__", Binding::Literal(pool))],
    )
}

/// Render the libvirt-network renumber script. The prefix comes from
/// `guest_subnet_prefix`, which admits only digits and dots, and it is
/// substituted into a `sed` expression as well as a variable — `Bare` is the
/// binding that matches that shape.
pub(crate) fn render_host_renumber_net_script(target_prefix: &str) -> Result<String, String> {
    render_script_template(
        HOST_RENUMBER_NET_SCRIPT,
        &[("__TARGET_PREFIX__", Binding::Bare(target_prefix))],
    )
}

/// Render the single-artifact read. `cap` is a `u64` byte count compared with
/// `-gt`, so it is `Bare`.
pub(crate) fn render_host_fetch_artifact_script(
    repo_dir: &str,
    path: &str,
    cap: u64,
) -> Result<String, String> {
    render_script_template(
        HOST_FETCH_ARTIFACT_SCRIPT,
        &[
            ("__REPO_DIR__", Binding::Literal(repo_dir)),
            ("__PATH__", Binding::Literal(path)),
            ("__CAP__", Binding::Bare(&cap.to_string())),
        ],
    )
}

/// Render the stop-in-flight-run script.
pub(crate) fn render_host_stop_script(repo_dir: &str) -> Result<String, String> {
    render_script_template(
        HOST_STOP_SCRIPT,
        &[("__REPO_DIR__", Binding::Literal(repo_dir))],
    )
}

/// Render the read-only "is a run in flight?" probe. See [`HOST_RUN_STATUS_SCRIPT`].
pub(crate) fn render_host_run_status_script(repo_dir: &str) -> Result<String, String> {
    render_script_template(
        HOST_RUN_STATUS_SCRIPT,
        &[("__REPO_DIR__", Binding::Literal(repo_dir))],
    )
}

/// A sanctioned unquoted shell fragment for an SSH-path default.
///
/// Exists to close S3. The field is private and there is **no constructor**, so the
/// only values that exist anywhere in the crate are the three associated constants
/// below. That is what actually confines [`Binding::RawFragment`] — the one binding
/// with zero validation — rather than the type `&'static str`, which does not mean
/// "literal" (`String::leak` yields `&'static str` from arbitrary runtime data, so
/// a `pub(crate)` variant taking `&'static str` was constructible crate-wide with
/// unvalidated content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DefaultHostSshPath(&'static str);

impl DefaultHostSshPath {
    /// The orchestrator's guest SSH key, expanded on the host.
    pub(crate) const ORCH_IDENTITY: Self = Self("\"$HOME/.ssh/id_ed25519\"");
    /// The orchestrator's known_hosts file, expanded on the host.
    pub(crate) const ORCH_KNOWN_HOSTS: Self = Self("\"$HOME/.ssh/known_hosts\"");
    /// The public key seeded into a provisioned guest, expanded on the host.
    pub(crate) const GUEST_AUTHORIZED_KEY: Self = Self("\"$HOME/.ssh/id_ed25519.pub\"");

    fn fragment(self) -> &'static str {
        self.0
    }
}

/// Which SSH file the launched orchestrator should use on the host.
///
/// The `Default` arm is a [`Binding::RawFragment`] because it is deliberately shell
/// syntax: a **double-quoted `$HOME` expansion that must expand on the host**, not
/// on the launcher. So it cannot be escaped, and it is the only binding with no
/// validation at all.
///
/// **Corrected claim (S3).** This previously read "the fragment is a compile-time
/// literal, which `RawFragment(&'static str)` enforces at the type level". That was
/// false twice over: `&'static str` is not the same as a literal (`String::leak`),
/// and this variant was `pub(crate)`, so any code in the crate could put arbitrary
/// unvalidated content into a `RawFragment`. The enforcement is now real but comes
/// from a different place — [`DefaultHostSshPath`] has a private field and no
/// constructor, so the only inhabitants are its three constants.
///
/// An `Override` is caller data and is quoted by the renderer. Proven by
/// `the_default_orchestrator_paths_expand_home_on_the_host` and
/// `an_overridden_orchestrator_path_is_quoted_by_the_renderer`.
pub(crate) enum HostSshPath<'a> {
    Default(DefaultHostSshPath),
    Override(&'a str),
}

impl<'a> HostSshPath<'a> {
    fn binding(&self) -> Binding<'a> {
        match self {
            HostSshPath::Default(default) => Binding::RawFragment(default.fragment()),
            HostSshPath::Override(path) => Binding::Literal(path),
        }
    }
}

// The former `DefaultHostSshPath::ORCH_IDENTITY` / `DefaultHostSshPath::ORCH_KNOWN_HOSTS`
// `pub(crate) const &str`s are gone: a loose `&'static str` constant invites a
// caller to pass some OTHER `&'static str` to `HostSshPath::Default`, which is
// exactly the S3 hole. The values now live as `DefaultHostSshPath` associated
// constants, which are the only inhabitants of that type.

/// Render the detached live-lab launcher.
///
/// `orchestrator_args` are `QuotedWords`: the **renderer** quotes each one, so
/// the pre-joined `'a' 'b'` string that used to be built at the call site (and
/// was the value that carried quotes by construction into the QH-01 breakout) no
/// longer exists.
///
/// `launch_id` is `Bare` because it is substituted *inside* longer quoted paths
/// (`'state/host-lab-runs/__LAUNCH_ID__.pid'`); its `[A-Za-z0-9._-]+` alphabet
/// is what makes that position safe. `repo_dir` and `report_dir` are `Literal`
/// and land inside the `<<'RUNNER_EOF'` heredoc that `bash` re-parses — see
/// `ensure_literal_binding_value` for that control.
pub(crate) fn render_host_launch_script(
    repo_dir: &str,
    report_dir: &str,
    launch_id: &str,
    orch_identity: &HostSshPath<'_>,
    orch_known_hosts: &HostSshPath<'_>,
    orchestrator_args: &[String],
) -> Result<String, String> {
    render_script_template(
        HOST_LAUNCH_SCRIPT,
        &[
            ("__REPO_DIR__", Binding::Literal(repo_dir)),
            ("__REPORT_DIR__", Binding::Literal(report_dir)),
            ("__LAUNCH_ID__", Binding::Bare(launch_id)),
            ("__ORCH_IDENTITY__", orch_identity.binding()),
            ("__ORCH_KNOWN_HOSTS__", orch_known_hosts.binding()),
            ("__ORCH_ARGS__", Binding::QuotedWords(orchestrator_args)),
        ],
    )
}

// The default host path for the key seeded into a provisioned guest was a loose
// `pub(crate) const &str` here. It is now `DefaultHostSshPath::GUEST_AUTHORIZED_KEY`
// — see the note on the retired orchestrator path constants above for why a loose
// `&'static str` constant next to a `&'static str`-taking variant was the S3 hole.

/// Render the guest-provisioning script — the QH-01 site.
///
/// The three historical breakouts are all closed here: `pool`, `name` and
/// `image` are `Literal` (so the renderer quotes them, and the template no
/// longer wraps the token in quotes), the numerics are `Bare`, and
/// `authorized_key` is either a compile-time `RawFragment` default or a
/// renderer-quoted `Literal` override — it can no longer carry a `'` by
/// construction. Substitution is a single pass, so a value spelling
/// `__AUTH_KEY__` is inert data. Proven by
/// `the_provision_script_renders_byte_for_byte`,
/// `a_guest_name_spelling_another_token_stays_data`,
/// `a_hostile_pool_or_image_stays_one_shell_word`, and the real-call-path
/// `provision_guest_refuses_hostile_pool_on_the_real_call_path` /
/// `provision_guest_refuses_hostile_image_on_the_real_call_path` /
/// `provision_guest_refuses_hostile_name_on_the_real_call_path` /
/// `provision_guest_refuses_hostile_authorized_key_on_the_real_call_path`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_host_provision_guest_script(
    pool: &str,
    name: &str,
    image: &str,
    disk_gb: u64,
    ram_mb: u64,
    vcpus: u32,
    authorized_key: &HostSshPath<'_>,
) -> Result<String, String> {
    render_script_template(
        HOST_PROVISION_GUEST_SCRIPT,
        &[
            ("__POOL__", Binding::Literal(pool)),
            ("__NAME__", Binding::Literal(name)),
            ("__IMAGE__", Binding::Literal(image)),
            ("__DISK_GB__", Binding::Bare(&disk_gb.to_string())),
            ("__RAM_MB__", Binding::Bare(&ram_mb.to_string())),
            ("__VCPUS__", Binding::Bare(&vcpus.to_string())),
            ("__AUTH_KEY__", authorized_key.binding()),
        ],
    )
}

/// Render the netplan repair body written to a guest by `sudo bash -s`.
///
/// The YAML body goes into a `<<'RN_NETPLAN_EOF'` heredoc, so quoting is not the
/// control and a metacharacter rule would be wrong (YAML needs `:` and
/// newlines). `HeredocBody` enforces the rule that actually applies: the body
/// must end in a newline and must not contain a line equal to the terminator.
pub(crate) fn render_netplan_repair_script(netplan_yaml: &str) -> Result<String, String> {
    render_script_template(
        NETPLAN_REPAIR_SCRIPT,
        &[(
            "__RN_NETPLAN__",
            Binding::HeredocBody {
                value: netplan_yaml,
                terminator: "RN_NETPLAN_EOF",
            },
        )],
    )
}

/// Render the NetworkManager repair script. The interface name is a bare word.
pub(crate) fn render_network_manager_repair_script(interface: &str) -> Result<String, String> {
    render_script_template(
        NETWORK_MANAGER_REPAIR_SCRIPT,
        &[("__RN_IFACE__", Binding::Bare(interface))],
    )
}

/// Render the systemd-networkd repair script. The interface name lands in a
/// `.network` unit key (`Name=__RN_IFACE__`) as well as an argv word, so `Bare`
/// is the binding that matches both.
pub(crate) fn render_networkd_repair_script(interface: &str) -> Result<String, String> {
    render_script_template(
        NETWORKD_REPAIR_SCRIPT,
        &[("__RN_IFACE__", Binding::Bare(interface))],
    )
}

/// Render the Windows Exit evidence capture — the one PowerShell template on
/// this path. All three values are crate constants today; `PowerShellLiteral`
/// keeps the renderer in charge of quoting so that stays true if a caller ever
/// passes something else.
pub(crate) fn render_windows_exit_evidence_capture_script(
    artifact_root: &str,
    daemon_path: &str,
    killswitch_probe_marker: &str,
) -> Result<String, String> {
    render_script_template(
        WINDOWS_EXIT_EVIDENCE_CAPTURE_SCRIPT,
        &[
            ("__ROOT__", Binding::PowerShellLiteral(artifact_root)),
            ("__DAEMON__", Binding::PowerShellLiteral(daemon_path)),
            (
                "__MARKER__",
                Binding::PowerShellLiteral(killswitch_probe_marker),
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    // --- a minimal POSIX word splitter, for the tokenizer-level assertions ----
    //
    // `bash -n` is near-worthless as an inertness check: `IMAGE='d.qcow2';id;''`
    // is *syntactically valid*, so a parse test would pass a live breakout. What
    // actually distinguishes "data" from "syntax" is the word/operator split, so
    // that is what these tests assert on.

    /// Split one script line into shell words and operators.
    ///
    /// Words are unquoted; operators (`;` `|` `&` `<` `>`) come back as their own
    /// tokens, so "the payload became syntax" is directly observable.
    fn shell_split(line: &str) -> Result<Vec<String>, String> {
        let mut tokens: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut have_word = false;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                ' ' | '\t' => {
                    if have_word {
                        tokens.push(std::mem::take(&mut current));
                        have_word = false;
                    }
                }
                ';' | '|' | '&' | '<' | '>' => {
                    if have_word {
                        tokens.push(std::mem::take(&mut current));
                        have_word = false;
                    }
                    tokens.push(ch.to_string());
                }
                '\'' => {
                    have_word = true;
                    let mut closed = false;
                    for inner in chars.by_ref() {
                        if inner == '\'' {
                            closed = true;
                            break;
                        }
                        current.push(inner);
                    }
                    if !closed {
                        return Err(format!("unterminated single quote in {line:?}"));
                    }
                }
                '"' => {
                    have_word = true;
                    let mut closed = false;
                    while let Some(inner) = chars.next() {
                        if inner == '"' {
                            closed = true;
                            break;
                        }
                        if inner == '\\' {
                            if let Some(escaped) = chars.next() {
                                current.push(escaped);
                            }
                            continue;
                        }
                        current.push(inner);
                    }
                    if !closed {
                        return Err(format!("unterminated double quote in {line:?}"));
                    }
                }
                '\\' => {
                    have_word = true;
                    if let Some(escaped) = chars.next() {
                        current.push(escaped);
                    }
                }
                other => {
                    have_word = true;
                    current.push(other);
                }
            }
        }
        if have_word {
            tokens.push(current);
        }
        Ok(tokens)
    }

    fn line_starting_with<'a>(script: &'a str, prefix: &str) -> &'a str {
        script
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{script}"))
    }

    // --- the structural table over the consts themselves ---------------------
    //
    // This is what catches a NEW render site or a template edit: it is asserted
    // against a scan of each const, so no call site can bypass it.

    /// Tokens that appear in a template but are NOT bindings, with why.
    ///
    /// `__PLACEHOLDERS__` is prose in a comment; the rest are wire sentinels the
    /// parsers on this side match on. This is why the renderer refuses an
    /// *unconsumed binding* but deliberately does NOT refuse an unknown token —
    /// that rule would break every launch.
    const NON_BINDING_TOKENS: &[&str] = &["__PLACEHOLDERS__"];

    struct TemplateRow {
        name: &'static str,
        template: ScriptTemplate,
        /// (token, binding kind) exactly as the production render function declares.
        bindings: &'static [(&'static str, &'static str)],
    }

    fn template_table() -> Vec<TemplateRow> {
        vec![
            TemplateRow {
                name: "HOST_FETCH_IMAGE_SCRIPT",
                template: HOST_FETCH_IMAGE_SCRIPT,
                bindings: &[
                    ("__POOL__", "Literal"),
                    ("__NAME__", "Literal"),
                    ("__URL__", "Literal"),
                    ("__SHA256__", "Literal"),
                    ("__EXPECT_MODEL__", "Literal"),
                ],
            },
            TemplateRow {
                name: "HOST_GUEST_CONSOLE_SCRIPT",
                template: HOST_GUEST_CONSOLE_SCRIPT,
                bindings: &[("__DOMAIN__", "Literal"), ("__SECONDS__", "Bare")],
            },
            TemplateRow {
                name: "GUEST_TOOLCHAIN_SCRIPT",
                template: GUEST_TOOLCHAIN_SCRIPT,
                bindings: &[("__CHANNEL__", "Bare")],
            },
            TemplateRow {
                name: "HOST_LAUNCH_SCRIPT",
                template: HOST_LAUNCH_SCRIPT,
                bindings: &[
                    ("__REPO_DIR__", "Literal"),
                    ("__REPORT_DIR__", "Literal"),
                    ("__LAUNCH_ID__", "Bare"),
                    ("__ORCH_IDENTITY__", "RawFragment|Literal"),
                    ("__ORCH_KNOWN_HOSTS__", "RawFragment|Literal"),
                    ("__ORCH_ARGS__", "QuotedWords"),
                ],
            },
            TemplateRow {
                name: "HOST_RECOVER_VMS_SCRIPT",
                template: HOST_RECOVER_VMS_SCRIPT,
                bindings: &[("__FORCE__", "Bare"), ("__TARGETS__", "Literal")],
            },
            TemplateRow {
                name: "HOST_DISK_STATUS_SCRIPT",
                template: HOST_DISK_STATUS_SCRIPT,
                bindings: &[("__POOL__", "Literal")],
            },
            TemplateRow {
                name: "HOST_RENUMBER_NET_SCRIPT",
                template: HOST_RENUMBER_NET_SCRIPT,
                bindings: &[("__TARGET_PREFIX__", "Bare")],
            },
            TemplateRow {
                name: "HOST_FETCH_ARTIFACT_SCRIPT",
                template: HOST_FETCH_ARTIFACT_SCRIPT,
                bindings: &[
                    ("__REPO_DIR__", "Literal"),
                    ("__PATH__", "Literal"),
                    ("__CAP__", "Bare"),
                ],
            },
            TemplateRow {
                name: "HOST_STOP_SCRIPT",
                template: HOST_STOP_SCRIPT,
                bindings: &[("__REPO_DIR__", "Literal")],
            },
            TemplateRow {
                name: "HOST_PROVISION_GUEST_SCRIPT",
                template: HOST_PROVISION_GUEST_SCRIPT,
                bindings: &[
                    ("__POOL__", "Literal"),
                    ("__NAME__", "Literal"),
                    ("__IMAGE__", "Literal"),
                    ("__DISK_GB__", "Bare"),
                    ("__RAM_MB__", "Bare"),
                    ("__VCPUS__", "Bare"),
                    ("__AUTH_KEY__", "RawFragment|Literal"),
                ],
            },
            TemplateRow {
                name: "NETPLAN_REPAIR_SCRIPT",
                template: NETPLAN_REPAIR_SCRIPT,
                bindings: &[("__RN_NETPLAN__", "HeredocBody")],
            },
            TemplateRow {
                name: "NETWORK_MANAGER_REPAIR_SCRIPT",
                template: NETWORK_MANAGER_REPAIR_SCRIPT,
                bindings: &[("__RN_IFACE__", "Bare")],
            },
            TemplateRow {
                name: "NETWORKD_REPAIR_SCRIPT",
                template: NETWORKD_REPAIR_SCRIPT,
                bindings: &[("__RN_IFACE__", "Bare")],
            },
            TemplateRow {
                name: "WINDOWS_EXIT_EVIDENCE_CAPTURE_SCRIPT",
                template: WINDOWS_EXIT_EVIDENCE_CAPTURE_SCRIPT,
                bindings: &[
                    ("__ROOT__", "PowerShellLiteral"),
                    ("__DAEMON__", "PowerShellLiteral"),
                    ("__MARKER__", "PowerShellLiteral"),
                ],
            },
        ]
    }

    /// Every `__TOKEN__` in a template is a declared binding (or an explicitly
    /// listed non-binding sentinel), and every declared binding is in its
    /// template. Exhaustive in both directions, so adding a placeholder to a
    /// template without binding it — or binding a token that no longer exists —
    /// turns this red.
    #[test]
    fn the_template_binding_table_is_exhaustive_in_both_directions() {
        for row in template_table() {
            let found = scan_tokens(row.template.0);
            let declared: Vec<&str> = row.bindings.iter().map(|(token, _)| *token).collect();
            for token in &found {
                assert!(
                    declared.contains(&token.as_str())
                        || NON_BINDING_TOKENS.contains(&token.as_str()),
                    "{}: template contains {token} but nothing binds it (add a binding, or list it \
                     in NON_BINDING_TOKENS with a reason)",
                    row.name
                );
            }
            for token in &declared {
                assert!(
                    found.contains(&(*token).to_owned()),
                    "{}: {token} is declared but no longer appears in the template",
                    row.name
                );
            }
        }
    }

    /// **The v1 bug class, asserted structurally.** A `Literal` is emitted
    /// `shell_quote`d, so the template must NOT put a quote next to the token: a
    /// template reading `POOL='__POOL__'` would render `POOL=''/pool''`, and worse,
    /// it is exactly the shape that let a substituted value inject into another
    /// value's quoting context. `Bare` tokens ARE allowed next to a quote — their
    /// alphabet cannot close a quoted word, which is the whole point of the variant.
    #[test]
    fn no_literal_token_is_adjacent_to_a_quote_in_its_template() {
        for row in template_table() {
            let body = row.template.0;
            for (token, kind) in row.bindings {
                if !(kind.contains("Literal") || *kind == "QuotedWords") {
                    continue;
                }
                if *kind == "PowerShellLiteral" {
                    continue;
                }
                let mut from = 0usize;
                while let Some(offset) = body[from..].find(token) {
                    let at = from + offset;
                    let before = body[..at].chars().next_back();
                    let after = body[at + token.len()..].chars().next();
                    for (side, ch) in [("before", before), ("after", after)] {
                        if let Some(ch) = ch {
                            assert!(
                                ch != '\'' && ch != '"',
                                "{}: {token} is a {kind} but has a {ch:?} immediately {side} it — \
                                 the RENDERER owns the quoting, so the template must not add any",
                                row.name
                            );
                        }
                    }
                    from = at + token.len();
                }
            }
        }
    }

    /// Every row renders with the kinds the table declares. Not a semantic check,
    /// but it keeps the table from drifting into something unrenderable.
    #[test]
    fn every_template_renders_with_the_kinds_the_table_declares() {
        for row in template_table() {
            let bindings: Vec<(&'static str, Binding<'_>)> = row
                .bindings
                .iter()
                .map(|(token, kind)| {
                    let binding = match *kind {
                        "Literal" | "QuotedWords" => Binding::Literal("benign-value"),
                        "Bare" => Binding::Bare("benign.value-1"),
                        "RawFragment|Literal" => Binding::Literal("/home/u/key"),
                        "HeredocBody" => Binding::HeredocBody {
                            value: "benign: true\n",
                            terminator: "RN_NETPLAN_EOF",
                        },
                        "PowerShellLiteral" => Binding::PowerShellLiteral("C:\\benign"),
                        other => panic!("{}: unknown kind {other}", row.name),
                    };
                    (*token, binding)
                })
                .collect();
            let rendered = render_script_template(row.template, bindings.as_slice())
                .unwrap_or_else(|err| panic!("{} must render: {err}", row.name));
            for (token, _) in row.bindings {
                assert!(
                    !rendered.contains(token),
                    "{}: {token} survived rendering",
                    row.name
                );
            }
        }
    }

    /// Every `__TOKEN__` in `body`, matched **shortest-first**.
    ///
    /// Shortest-first matters: `NETPLAN_REPAIR_SCRIPT` reads
    /// `__RN_NETPLAN__RN_NETPLAN_EOF`, so a greedy scan would swallow the heredoc
    /// terminator and report no token at all — silently making the exhaustiveness
    /// check vacuous for exactly the template that needs it most.
    fn scan_tokens(body: &str) -> Vec<String> {
        let bytes = body.as_bytes();
        let mut found: Vec<String> = Vec::new();
        let mut index = 0usize;
        while index + 5 <= bytes.len() {
            if !(bytes[index] == b'_' && bytes[index + 1] == b'_') {
                index += 1;
                continue;
            }
            let mut matched = None;
            let mut end = index + 3;
            while end + 2 <= bytes.len() {
                // `&body[a..b]` panics unless both ends sit on char boundaries, so a
                // `__` followed by a multi-byte character used to abort the scan with
                // a panic instead of reporting no token. Token names are ASCII, so a
                // non-boundary index cannot be part of one — skip it.
                if !body.is_char_boundary(index + 2) || !body.is_char_boundary(end) {
                    end += 1;
                    continue;
                }
                let middle = &body[index + 2..end];
                if !middle
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                {
                    break;
                }
                if bytes[end] == b'_' && bytes[end + 1] == b'_' {
                    // `__A__` only; an interior `__` is a boundary, not part of a name.
                    if !middle.starts_with('_') && !middle.ends_with('_') {
                        matched = Some(end + 2);
                    }
                    break;
                }
                end += 1;
            }
            match matched {
                Some(stop) => {
                    let token = body[index..stop].to_owned();
                    if !found.contains(&token) {
                        found.push(token);
                    }
                    index = stop;
                }
                None => index += 1,
            }
        }
        found
    }

    /// **Byte-for-byte**, not `contains(...)`. A full expected string is the only
    /// assertion a still-vulnerable renderer cannot satisfy, and it doubles as the
    /// fails-on-revert test: reinstating the ordered `.replace` chain, or
    /// re-wrapping a `Literal` token in quotes in the template, changes these bytes.
    #[test]
    fn the_provision_script_renders_byte_for_byte() {
        const EXPECTED: &str = r##"#!/bin/bash
set -uo pipefail
POOL='/var/lib/libvirt/images'
NAME='provtest'
IMAGE='debian-13.qcow2'
DISK_GB=6
RAM_MB=1024
VCPUS=1
BASE="$POOL/$IMAGE"
OVERLAY="$POOL/$NAME.qcow2"
SEED="$POOL/$NAME-seed.iso"

# TOCTOU re-checks on the box, which is the source of truth for what exists.
[ -f "$BASE" ] || { echo "PROVISION-ERROR: base image not found: $BASE" >&2; exit 1; }
if virsh -c qemu:///system dominfo "$NAME" >/dev/null 2>&1; then
  echo "PROVISION-ERROR: domain $NAME already exists — refusing to overwrite" >&2; exit 2
fi
[ -e "$OVERLAY" ] && { echo "PROVISION-ERROR: overlay already exists: $OVERLAY" >&2; exit 3; }
PUBKEY_SRC="$HOME/.ssh/id_ed25519.pub"
PUBKEY="$(cat "$PUBKEY_SRC" 2>/dev/null || true)"
[ -n "$PUBKEY" ] || { echo "PROVISION-ERROR: no readable public key at $PUBKEY_SRC" >&2; exit 4; }

# Copy-on-write overlay on the base image (pool group-writable — no sudo).
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" "${DISK_GB}G" >/dev/null 2>&1 \
  || { echo "PROVISION-ERROR: qemu-img create failed" >&2; exit 5; }

# cloud-init seed: hostname + the provisioning host's key on the image's default
# user, so the host can SSH in immediately with no follow-up authorize step.
WORK="$(mktemp -d)"
{
  echo "#cloud-config"
  echo "hostname: $NAME"
  echo "ssh_authorized_keys:"
  echo "  - $PUBKEY"
} > "$WORK/user-data"
{
  echo "instance-id: $NAME"
  echo "local-hostname: $NAME"
} > "$WORK/meta-data"
if ! cloud-localds "$SEED" "$WORK/user-data" "$WORK/meta-data" >/dev/null 2>&1; then
  echo "PROVISION-ERROR: cloud-localds failed (is cloud-image-utils installed?)" >&2
  rm -rf "$WORK"; rm -f "$OVERLAY"; exit 6
fi
rm -rf "$WORK"

# Create + boot. --noautoconsole so virt-install returns instead of attaching a
# console; --video vga because a headless Debian cloud image's GRUB needs a
# framebuffer (a documented lab gotcha).
# --osinfo is mandatory in modern virt-install; detect=on,require=off auto-detects
# from the image and falls back to a generic profile (a perf warning, not a fatal
# error) rather than requiring a per-image OS name.
if ! virt-install --connect qemu:///system --name "$NAME" \
     --memory "$RAM_MB" --vcpus "$VCPUS" --cpu host-passthrough \
     --disk "$OVERLAY" --disk "$SEED",device=cdrom \
     --network network=default,model=virtio --video vga --graphics none \
     --osinfo detect=on,require=off --import --noautoconsole >/dev/null 2>&1; then
  echo "PROVISION-ERROR: virt-install failed (re-run the virt-install by hand for the reason)" >&2
  virsh -c qemu:///system undefine "$NAME" >/dev/null 2>&1 || true
  rm -f "$OVERLAY" "$SEED"; exit 7
fi
virsh -c qemu:///system autostart "$NAME" >/dev/null 2>&1 || true

st="$(virsh -c qemu:///system domstate "$NAME" 2>/dev/null || echo unknown)"
echo "PROVISION-RESULT: created domain $NAME (state=$st, overlay=$OVERLAY, seed=$SEED)"
"##;
        let rendered = render_host_provision_guest_script(
            "/var/lib/libvirt/images",
            "provtest",
            "debian-13.qcow2",
            6,
            1024,
            1,
            &HostSshPath::Default(DefaultHostSshPath::GUEST_AUTHORIZED_KEY),
        )
        .expect("renders");
        assert_eq!(rendered, EXPECTED);
    }

    /// Byte-for-byte for the launcher, including the `<<'RUNNER_EOF'` heredoc that
    /// `bash` re-parses and the renderer-quoted orchestrator args.
    #[test]
    fn the_launcher_script_renders_byte_for_byte() {
        const EXPECTED: &str = r#"#!/bin/bash
set -uo pipefail
REPO_DIR='/home/u/Rustynet'
cd "$REPO_DIR" || { echo "LAUNCH-ERROR: repo_dir not found: $REPO_DIR" >&2; exit 1; }

# NO concurrency gate here. Mutual exclusion is taken by the orchestrator itself
# (QH-18): a per-GUEST flock at the ops dispatch chokepoint, which every invocation
# form reaches — including the one this script launches and the bare
# `ops vm-lab-orchestrate-live-lab` the runbooks document.
#
# The argv-pattern gate that used to sit here could not be repaired in place.
# Driven inline over ssh the whole script text lands in the remote `bash -c` argv,
# so the pattern matched its own launcher and refused on an idle host; and no
# rewriting of the pattern removes that, because the script must contain the
# subcommand string it is about to run. It was also the wrong unit — per-HOST, so
# it refused the disjoint-guest concurrency the project deliberately supports
# (MAX_CONCURRENT_LAB_RUNS = 3).

# Only the run-handle dir is created here. The report dir is left for the
# orchestrator, which refuses to start into a NON-EMPTY one — so the launcher must
# not seed it (an earlier version put the log inside it and the run refused itself).
mkdir -p 'state/host-lab-runs' || { echo "LAUNCH-ERROR: cannot create state/host-lab-runs" >&2; exit 1; }

# Retire leftover pidfiles so they do not accumulate across a session and a later
# stop never has a dead pid to consider. Each one is checked for liveness first:
# with the old per-host gate gone, a run on DISJOINT guests may legitimately be in
# flight, and deleting its pidfile would strip the stop path of its handle. A pid is
# kept only while it is still the orchestrator, verified by argv (`-ww` so a leaked
# COLUMNS cannot truncate the marker away and divert a live run to deletion); dead
# and recycled pids are removed.
for stale_pidfile in state/host-lab-runs/*.pid; do
  [ -f "$stale_pidfile" ] || continue
  stale_pid="$(cat "$stale_pidfile" 2>/dev/null || true)"
  if [ -n "$stale_pid" ] && ps -ww -o args= -p "$stale_pid" 2>/dev/null | grep -q 'vm-lab-orchestrate-live-lab'; then
    continue
  fi
  rm -f "$stale_pidfile" 2>/dev/null || true
done

RUNNER='state/host-lab-runs/launch-1-2.run.sh'
PIDFILE='state/host-lab-runs/launch-1-2.pid'
LOG='state/host-lab-runs/launch-1-2.log'

# Quoted heredoc: the shell writes this verbatim, so $$ and $HOME survive to
# runtime rather than expanding now. The __PLACEHOLDERS__ were already substituted
# in Rust before the script was sent.
cat > "$RUNNER" <<'RUNNER_EOF'
#!/bin/bash
cd '/home/u/Rustynet' || exit 1
echo $$ > 'state/host-lab-runs/launch-1-2.pid'
exec cargo run --quiet -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab --report-dir 'artifacts/live_lab/x' --ssh-identity-file "$HOME/.ssh/id_ed25519" --known-hosts-file "$HOME/.ssh/known_hosts" '--node' 'linux-x86-client-1:client'
RUNNER_EOF

setsid nohup bash "$RUNNER" > "$LOG" 2>&1 < /dev/null &

# The runner writes its pid before exec'ing cargo, so this appears within a moment
# even though the compile/run that follows takes far longer.
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  [ -s "$PIDFILE" ] && break
  sleep 0.3
done
PID="$(cat "$PIDFILE" 2>/dev/null || true)"
if [ -z "${PID:-}" ]; then
  echo "LAUNCH-ERROR: runner did not report a pid within ~4.5s (see $LOG)" >&2
  exit 3
fi
echo "LAUNCHED launch_id=launch-1-2 pid=$PID log=$LOG"
"#;
        let rendered = render_host_launch_script(
            "/home/u/Rustynet",
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Default(DefaultHostSshPath::ORCH_IDENTITY),
            &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
            &["--node".to_owned(), "linux-x86-client-1:client".to_owned()],
        )
        .expect("renders");
        assert_eq!(rendered, EXPECTED);
    }

    #[test]
    fn the_token_scanner_matches_shortest_first() {
        assert_eq!(
            scan_tokens("cat > f <<'RN_NETPLAN_EOF'\n__RN_NETPLAN__RN_NETPLAN_EOF\n"),
            vec!["__RN_NETPLAN__".to_owned()]
        );
        assert_eq!(
            scan_tokens("A=__ONE__ B=__TWO__ A=__ONE__"),
            vec!["__ONE__".to_owned(), "__TWO__".to_owned()]
        );
        assert!(scan_tokens("no tokens here __ __").is_empty());
    }

    // --- renderer invariants -------------------------------------------------

    /// **The QH-01 breakout, as a test.** `--name __AUTH_KEY__` passes
    /// `ensure_provision_guest_name` (uppercase and `_` are both legal in a
    /// libvirt domain name), and under the old ordered `.replace` chain the LAST
    /// substitution rewrote the name that had already been placed — injecting the
    /// key path's quotes into the name's own quoting context. A single-pass walk
    /// never re-scans emitted bytes, so the token stays data.
    #[test]
    fn rendering_is_single_pass_so_a_placeholder_valued_binding_is_inert() {
        let script = render_host_provision_guest_script(
            "/var/lib/libvirt/images",
            "__AUTH_KEY__",
            "debian-13.qcow2",
            6,
            1024,
            1,
            &HostSshPath::Override("/home/u/.ssh/id_ed25519.pub"),
        )
        .expect("a placeholder-shaped name is data, not an error");
        assert!(script.contains("NAME='__AUTH_KEY__'"), "script:\n{script}");
        assert_eq!(
            script.matches("PUBKEY_SRC=").count(),
            1,
            "the key path must be substituted exactly once"
        );
        assert!(script.contains("PUBKEY_SRC='/home/u/.ssh/id_ed25519.pub'"));
    }

    /// The tokenizer-level form of the same claim: the rendered `NAME=` line is
    /// exactly one shell word whose value is the literal token text, and the
    /// rendered script contains no `;`/`|`/`&` operator on that line.
    #[test]
    fn a_guest_name_spelling_another_token_stays_data() {
        let script = render_host_provision_guest_script(
            "/var/lib/libvirt/images",
            "__AUTH_KEY__",
            "debian-13.qcow2",
            6,
            1024,
            1,
            &HostSshPath::Override("/home/u/k.pub"),
        )
        .expect("renders");
        assert_eq!(
            shell_split(line_starting_with(&script, "NAME=")).expect("parses"),
            vec!["NAME=__AUTH_KEY__".to_owned()]
        );
        assert_eq!(
            shell_split(line_starting_with(&script, "PUBKEY_SRC=")).expect("parses"),
            vec!["PUBKEY_SRC=/home/u/k.pub".to_owned()]
        );
    }

    /// `pool` and `image` broke out with **no ordering trick at all** — they were
    /// unvalidated / path-shape-only and landed inside `POOL='…'` / `IMAGE='…'`.
    /// Escaping is what closes that, so assert it at the tokenizer level: the
    /// payload must remain a single word with no operator.
    #[test]
    fn a_hostile_pool_or_image_stays_one_shell_word() {
        let script = render_host_provision_guest_script(
            "/var/lib/libvirt/images';touch /tmp/pwned;'",
            "provtest",
            "d.qcow2';id;'",
            6,
            1024,
            1,
            &HostSshPath::Default(DefaultHostSshPath::GUEST_AUTHORIZED_KEY),
        )
        .expect("the renderer escapes rather than refuses");
        assert_eq!(
            shell_split(line_starting_with(&script, "POOL=")).expect("parses"),
            vec!["POOL=/var/lib/libvirt/images';touch /tmp/pwned;'".to_owned()]
        );
        assert_eq!(
            shell_split(line_starting_with(&script, "IMAGE=")).expect("parses"),
            vec!["IMAGE=d.qcow2';id;'".to_owned()]
        );
    }

    /// A declared binding the template no longer contains is a dropped value, so
    /// the renderer fails closed rather than shipping a script with a hole in it.
    #[test]
    fn an_unconsumed_declared_binding_is_refused() {
        let template = ScriptTemplate("A=__ONE__\n");
        let err = render_script_template(
            template,
            &[
                ("__ONE__", Binding::Literal("1")),
                ("__MISSING__", Binding::Literal("2")),
            ],
        )
        .expect_err("an unconsumed binding must fail closed");
        assert!(err.contains("__MISSING__"), "got: {err}");
    }

    /// An unknown token in the template is NOT an error: `__PLACEHOLDERS__` is
    /// prose in `HOST_LAUNCH_SCRIPT`'s comments and the capture sentinels are
    /// protocol. Erroring on it would refuse every launch.
    #[test]
    fn an_unknown_token_in_the_template_is_left_alone() {
        let rendered = render_script_template(
            ScriptTemplate("A=__ONE__ # see the __PLACEHOLDERS__ note\n"),
            &[("__ONE__", Binding::Literal("1"))],
        )
        .expect("an unbound token in prose must not fail the render");
        assert_eq!(rendered, "A='1' # see the __PLACEHOLDERS__ note\n");
    }

    /// **The heredoc double-parse control, named.** `HOST_LAUNCH_SCRIPT` writes a
    /// second script inside `<<'RUNNER_EOF'` that `bash` then re-parses. A
    /// `repo_dir`/`report_dir` carrying `\n` + a line reading `RUNNER_EOF` would
    /// close the heredoc early and run the remainder in the OUTER script. Before
    /// QH-01 the only thing preventing that was `ensure_no_control_chars` at one
    /// caller — unnamed and untested. It is now enforced at interpolation.
    #[test]
    fn a_newline_bearing_literal_cannot_close_the_runner_heredoc() {
        let hostile = "/home/u/Rustynet\nRUNNER_EOF\ntouch /tmp/pwned\n";
        let err = render_host_launch_script(
            hostile,
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Default(DefaultHostSshPath::ORCH_IDENTITY),
            &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
            &[],
        )
        .expect_err("a newline in a heredoc-embedded value must be refused");
        assert!(err.contains("__REPO_DIR__"), "got: {err}");
        // Same for the report dir, which also lands inside the heredoc.
        assert!(
            render_host_launch_script(
                "/home/u/Rustynet",
                "artifacts\nRUNNER_EOF\nid",
                "launch-1-2",
                &HostSshPath::Default(DefaultHostSshPath::ORCH_IDENTITY),
                &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
                &[],
            )
            .is_err()
        );
        // And the runner heredoc must still be well-formed for benign input.
        let ok = render_host_launch_script(
            "/home/u/Rustynet",
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Default(DefaultHostSshPath::ORCH_IDENTITY),
            &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
            &[],
        )
        .expect("renders");
        assert_eq!(ok.matches("RUNNER_EOF").count(), 2, "open + close only");
    }

    /// Empty is a legal `Literal`: three bindings mean something by being empty.
    #[test]
    fn an_empty_literal_renders_as_an_empty_shell_word() {
        let rendered = render_script_template(
            ScriptTemplate("SHA=__SHA__\n"),
            &[("__SHA__", Binding::Literal(""))],
        )
        .expect("empty must be legal");
        assert_eq!(rendered, "SHA=''\n");
    }

    /// `dig` must be installed AND verified, or `exit_dns_failclosed_validation`
    /// fails on a guest that never had it.
    ///
    /// Debian cloud images ship no `dnsutils`, so `dig` is absent unless the
    /// toolchain installs it — and installing without verifying is how this went
    /// unnoticed: the stage fails much later, on a guest, with a missing-binary
    /// error that reads like a lab fault rather than a provisioning gap. Both
    /// halves are asserted because either one alone is silently insufficient.
    #[test]
    fn the_guest_toolchain_installs_and_verifies_dig_for_the_dns_failclosed_stage() {
        let script = render_guest_toolchain_script("1.88.0")
            .expect("the toolchain script should render for a valid channel");

        // Slice the apt-get install command, NOT the whole script. A bare
        // `script.contains("dnsutils")` is satisfied by the COMMENT above the
        // install list that explains why dnsutils is there — verified: deleting
        // the package from the list left that assertion green. The comment is
        // the thing most likely to survive a careless edit that drops the
        // package, so it is exactly the wrong witness.
        let install_start = script
            .find("apt-get install")
            .expect("the toolchain must install packages");
        let install_end = install_start
            + script[install_start..]
                .find(">/dev/null")
                .expect("the install command must terminate");
        let install_cmd = &script[install_start..install_end];
        assert!(
            install_cmd.contains("dnsutils"),
            "dnsutils (dig) must be in the apt INSTALL LIST, or \
             exit_dns_failclosed_validation fails on a missing dig; \
             install command was: {install_cmd}"
        );
        assert!(
            script.contains(" ping dig; do"),
            "dig must be in the command verification loop, or a failed install \
             is not detected until the stage that needs it"
        );
    }

    /// A `Bare` value is emitted unquoted, so its alphabet is the whole control.
    /// Cases are attack classes, not a mirror of the implementation's rule.
    #[test]
    fn a_bare_binding_refuses_everything_outside_its_alphabet() {
        assert!(render_guest_toolchain_script("1.88.0").is_ok());
        assert!(render_guest_toolchain_script("nightly-2026-01-01").is_ok());
        for hostile in [
            "1.88.0'",                 // quote breakout
            "1.88.0\"",                //
            "1.88.0;id",               // command separator
            "1.88.0|id",               //
            "1.88.0&",                 //
            "1.88.0>x",                // redirection
            "1.88.0 --allow-anything", // word split
            "*",                       // glob
            "$(id)",                   // command substitution
            "`id`",                    //
            "${HOME}",                 // expansion
            "1.88.0\nid",              // newline
            "1.88.о",                  // Cyrillic 'о' homoglyph
            "",                        // empty word vanishes
        ] {
            assert!(
                render_guest_toolchain_script(hostile).is_err(),
                "Bare must refuse {hostile:?}"
            );
        }
    }

    /// The heredoc rule, at the renderer.
    #[test]
    fn a_heredoc_body_cannot_smuggle_its_own_terminator() {
        assert!(render_netplan_repair_script("network:\n  version: 2\n").is_ok());
        // A line equal to the terminator would close the heredoc early.
        assert!(render_netplan_repair_script("a\nRN_NETPLAN_EOF\nrm -rf /\n").is_err());
        // Trailing blanks do not save it: bash strips nothing, but a reader might.
        assert!(render_netplan_repair_script("a\nRN_NETPLAN_EOF  \nid\n").is_err());
        // A body that does not end in a newline puts the terminator mid-line.
        assert!(render_netplan_repair_script("network: 2").is_err());
    }

    /// S1: `script -qec` re-parses its argument as a command string in a nested
    /// shell, so `shell_quote`ing the `DOM=` assignment is not the control here.
    ///
    /// The two properties that make the nested parse safe are asserted directly,
    /// because neither is visible from the token site and the adjacency invariant
    /// cannot see them: the nested command string must be SINGLE-quoted (so the
    /// outer shell expands nothing into it) and `DOM` must be exported for the
    /// command (so the inner shell expands `"$DOM"` itself as one quoted word).
    #[test]
    fn guest_console_nested_command_string_is_single_quoted() {
        let script = render_host_guest_console_script("alpha", 30).expect("renders");

        assert!(
            script.contains(
                "DOM=\"$DOM\" timeout \"$SECS\" script -qec \
                 'virsh -c qemu:///system start --console \"$DOM\"'"
            ),
            "the nested command string must be single-quoted with DOM exported:\n{script}"
        );
        // The pre-fix form interpolated $DOM into a DOUBLE-quoted command string, so
        // the outer shell expanded the value into text the inner shell then re-parsed.
        assert!(
            !script.contains("script -qec \"virsh"),
            "the nested command string must not be double-quoted:\n{script}"
        );
        // The value still reaches the script as a quoted assignment.
        assert!(script.contains("DOM='alpha'"), "{script}");
    }

    /// The `$HOME`-bearing defaults are the reason `RawFragment` exists: they must
    /// expand ON THE HOST, so they cannot be escaped — which makes `RawFragment` the
    /// one binding with no validation at all.
    ///
    /// **Corrected claim (S3):** this used to say `RawFragment(&'static str)` is what
    /// keeps that from becoming a hole because caller data cannot reach it. That was
    /// false — `&'static str` is not a literal (`String::leak`), and the variant
    /// feeding it was `pub(crate)`. The control is [`DefaultHostSshPath`], which has
    /// a private field and no constructor, so its three associated constants are the
    /// only values in existence.
    #[test]
    fn the_default_orchestrator_paths_expand_home_on_the_host() {
        let script = render_host_launch_script(
            "/home/u/Rustynet",
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Default(DefaultHostSshPath::ORCH_IDENTITY),
            &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
            &[],
        )
        .expect("renders");
        assert!(script.contains("--ssh-identity-file \"$HOME/.ssh/id_ed25519\""));
        assert!(script.contains("--known-hosts-file \"$HOME/.ssh/known_hosts\""));
    }

    /// An override is caller data, so the RENDERER quotes it — the call site no
    /// longer builds `format!("'{path}'")`, which is the value that carried quotes
    /// by construction into the QH-01 breakout.
    #[test]
    fn an_overridden_orchestrator_path_is_quoted_by_the_renderer() {
        let script = render_host_launch_script(
            "/home/u/Rustynet",
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Override("/home/u/.ssh/lab_key"),
            &HostSshPath::Override("/home/u/.ssh/lab_known_hosts"),
            &[],
        )
        .expect("renders");
        assert!(script.contains("--ssh-identity-file '/home/u/.ssh/lab_key'"));
        assert!(script.contains("--known-hosts-file '/home/u/.ssh/lab_known_hosts'"));
        // Even a quote-bearing override cannot escape its word.
        let escaped = render_host_launch_script(
            "/home/u/Rustynet",
            "artifacts/live_lab/x",
            "launch-1-2",
            &HostSshPath::Override("/home/u/k';id;'"),
            &HostSshPath::Default(DefaultHostSshPath::ORCH_KNOWN_HOSTS),
            &[],
        )
        .expect("renders");
        let runner = line_starting_with(&escaped, "exec cargo run");
        let words = shell_split(runner).expect("parses");
        assert!(
            words.contains(&"/home/u/k';id;'".to_owned()),
            "the payload must be one argv word; got {words:?}"
        );
        assert!(
            !words.contains(&";".to_owned()),
            "no operator may appear; got {words:?}"
        );
    }

    // --- the backstop ---------------------------------------------------------

    /// The enforcement boundary is the newtype: `ScriptTemplate`'s field is private
    /// and it has no constructor, so no other module can build one, and
    /// `render_script_template` is its only consumer. This test is the backstop for
    /// the two things the type system cannot see:
    ///
    /// 1. a **script template** written somewhere else — any raw string literal in
    ///    the `vm_lab` tree that carries a `__TOKEN__` placeholder. (A raw string
    ///    with no placeholder is a *fixed* script and needs no renderer, which is
    ///    why `KILL_WINDOW_SCRIPT` is correctly not flagged; and matching on
    ///    placeholders rather than on the name `…SCRIPT…` avoids the several
    ///    `const …SCRIPT…: &str` values that are just remote *paths*.)
    /// 2. a new ordered `.replace("__` / `.replacen("__` chain — **including in a
    ///    test**, which is how the original defect stayed green: six test modules
    ///    re-implemented the render chain locally, so production could change
    ///    underneath them.
    ///
    /// # What this backstop does NOT catch (S5) — read before trusting it
    ///
    /// The type boundary is the control; this is a net with known holes, and they
    /// are enumerated rather than implied so nobody mistakes a green run for proof:
    ///
    /// - **Only `r#"…"#`-style raw strings are scanned.** A plain `r"…"` (no hash)
    ///   and an ordinary `"…"` literal are both missed. Widening naively is worse
    ///   than the gap: scanning for `r` + `"` would treat any ordinary string ending
    ///   in `r"` as a raw-string opener and fail spuriously, so a correct fix needs
    ///   real lexing (`proc-macro2`/`syn`) rather than a byte scan.
    /// - **Only UPPERCASE `__TOKEN__` names are recognised** by `scan_tokens`; a
    ///   lowercase or mixed-case placeholder is invisible to it.
    /// - **Only literal `.replace("__` text is matched.** A variable token
    ///   (`.replace(tok, v)`), a `format!`-assembled script, or any other string
    ///   assembly is not detected — `build_section_capture_script` and
    ///   `privileged_rustynet_cli_script` in `mod.rs` are exactly that shape and are
    ///   deliberately outside this boundary (see their doc comments).
    ///
    /// So this test proves "no *obvious* second renderer appeared", not "rendering
    /// cannot happen elsewhere". The latter is held by `ScriptTemplate`'s private
    /// field, which is checked by the compiler.
    #[test]
    fn no_script_template_is_declared_outside_this_module() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vm_lab");
        let mut offenders: Vec<String> = Vec::new();
        for path in rust_sources(&root) {
            if path.file_name().and_then(|name| name.to_str()) == Some("script_template.rs") {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("readable source");
            let display = path
                .strip_prefix(&root)
                .unwrap_or(path.as_path())
                .display()
                .to_string();
            for (index, line) in body.lines().enumerate() {
                // `replacen` too: it is the same ordered-substitution defect with a
                // different name, and a deny-list that names only one spelling is the
                // kind of control that looks green while the pattern walks past it.
                if line.contains(".replace(\"__") || line.contains(".replacen(\"__") {
                    offenders.push(format!(
                        "{display}:{}: an ordered `.replace(\"__`/`.replacen(\"__` chain \
                         outside script_template.rs — add a render_* function there instead",
                        index + 1
                    ));
                }
            }
            for (offset, literal) in raw_string_literals(&body) {
                let tokens = scan_tokens(literal);
                if !tokens.is_empty() {
                    offenders.push(format!(
                        "{display}:{}: a raw string carrying placeholder(s) {tokens:?} — a script \
                         template must be a `ScriptTemplate` const inside script_template.rs",
                        body[..offset].lines().count()
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "script rendering must stay inside vm_lab::script_template:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// Under `Set-StrictMode -Version Latest`, reading a property on a `$null`
    /// pipeline result throws `PropertyNotFoundStrict`. A `Where-Object` that
    /// matches nothing yields `$null`, so `(… | Where-Object {…}).Count` throws
    /// exactly when the filter matches nothing — which is usually the branch the
    /// check exists to detect.
    ///
    /// This scans the CLASS rather than asserting one fixed string, because the
    /// same shape has now appeared in two files written by two different lines, and
    /// a text assertion on one call site would not have caught either of them. The
    /// discriminator is deliberately narrow: only scripts that actually set
    /// StrictMode, and only parenthesised expressions that contain a pipeline. A
    /// script using `-ErrorAction SilentlyContinue` instead of StrictMode is not
    /// affected, and `(Get-Thing -ErrorAction Stop).Prop` throws by design rather
    /// than reading through a `$null`.
    ///
    /// Cannot be a behavioural test: these are PowerShell bodies rendered by Rust,
    /// and no PowerShell runtime is available here. A machine-checked invariant over
    /// the text is the strongest available control, and unlike a per-site assertion
    /// it also covers scripts nobody has written yet.
    #[test]
    fn strictmode_scripts_never_read_a_property_off_an_unwrapped_pipeline() {
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vm_lab/script_template.rs"),
        )
        .expect("readable source");

        let mut offenders: Vec<String> = Vec::new();
        for (offset, body) in raw_string_literals(&source) {
            if !body.contains("Set-StrictMode") {
                continue;
            }
            let bytes = body.as_bytes();
            for (index, window) in bytes.windows(2).enumerate() {
                // A property read on a parenthesised expression: `).Identifier`
                if window != b")." {
                    continue;
                }
                if !bytes
                    .get(index + 2)
                    .is_some_and(|ch| ch.is_ascii_alphabetic())
                {
                    continue;
                }
                // Walk back to the matching `(`.
                let mut depth = 0i32;
                let mut open = None;
                for back in (0..=index).rev() {
                    match bytes[back] {
                        b')' => depth += 1,
                        b'(' => {
                            depth -= 1;
                            if depth == 0 {
                                open = Some(back);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let Some(open) = open else { continue };
                let inner = &body[open + 1..index];
                // Only a pipeline can yield `$null` here; `(Get-X -EA Stop).Prop`
                // throws by design and is not this defect.
                if !inner.contains('|') {
                    continue;
                }
                // `@( … )` makes the result always an array, so the property is valid.
                if open > 0 && bytes[open - 1] == b'@' {
                    continue;
                }
                let property: String = body[index + 2..]
                    .chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric())
                    .collect();
                offenders.push(format!(
                    "script at byte {offset}: `.{property}` read off an unwrapped \
                     pipeline — wrap it as `@( … ).{property}`, or StrictMode throws \
                     PropertyNotFoundStrict when the pipeline yields nothing"
                ));
            }
        }
        assert!(
            offenders.is_empty(),
            "StrictMode scripts must not read a property off an unwrapped pipeline:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The scanner above must actually detect the shape it claims to — otherwise it
    /// is a green test that proves nothing, which is the QH-02 failure mode.
    #[test]
    fn the_strictmode_scanner_detects_the_shape_it_claims_to() {
        // Mirrors the real defect: StrictMode set, pipeline result, unwrapped.
        let bad = "Set-StrictMode -Version Latest;\n$ok = ($x | Where-Object { $_ }).Count;\n";
        let good = "Set-StrictMode -Version Latest;\n$ok = @($x | Where-Object { $_ }).Count;\n";
        // A non-pipeline property read must NOT be flagged.
        let unrelated =
            "Set-StrictMode -Version Latest;\n$f = (Get-Thing -ErrorAction Stop).Prop;\n";
        // Nor a pipeline read in a script without StrictMode.
        let no_strict = "$ok = ($x | Where-Object { $_ }).Count;\n";

        assert!(
            unwrapped_pipeline_property_reads(bad) > 0,
            "must flag: {bad}"
        );
        assert_eq!(
            unwrapped_pipeline_property_reads(good),
            0,
            "must not flag the wrapped form"
        );
        assert_eq!(
            unwrapped_pipeline_property_reads(unrelated),
            0,
            "must not flag a non-pipeline property read"
        );
        assert_eq!(
            unwrapped_pipeline_property_reads(no_strict),
            0,
            "must not flag a script that does not set StrictMode"
        );
    }

    /// Extracted so the scanner's logic is exercisable on synthetic input by
    /// `the_strictmode_scanner_detects_the_shape_it_claims_to`. The whole-file test
    /// above answers "is the repo clean"; this answers "does the check work".
    fn unwrapped_pipeline_property_reads(body: &str) -> usize {
        if !body.contains("Set-StrictMode") {
            return 0;
        }
        let bytes = body.as_bytes();
        let mut count = 0usize;
        for (index, window) in bytes.windows(2).enumerate() {
            if window != b")." {
                continue;
            }
            if !bytes
                .get(index + 2)
                .is_some_and(|ch| ch.is_ascii_alphabetic())
            {
                continue;
            }
            let mut depth = 0i32;
            let mut open = None;
            for back in (0..=index).rev() {
                match bytes[back] {
                    b')' => depth += 1,
                    b'(' => {
                        depth -= 1;
                        if depth == 0 {
                            open = Some(back);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(open) = open else { continue };
            if !body[open + 1..index].contains('|') {
                continue;
            }
            if open > 0 && bytes[open - 1] == b'@' {
                continue;
            }
            count += 1;
        }
        count
    }

    /// Every `r#"…"#` / `r##"…"##` body in `source`, with its byte offset.
    fn raw_string_literals(source: &str) -> Vec<(usize, &str)> {
        let bytes = source.as_bytes();
        let mut out = Vec::new();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] != b'r' {
                index += 1;
                continue;
            }
            let mut hashes = 0usize;
            let mut cursor = index + 1;
            while cursor < bytes.len() && bytes[cursor] == b'#' {
                hashes += 1;
                cursor += 1;
            }
            if hashes == 0 || cursor >= bytes.len() || bytes[cursor] != b'"' {
                index += 1;
                continue;
            }
            let start = cursor + 1;
            let terminator = format!("\"{}", "#".repeat(hashes));
            match source[start..].find(terminator.as_str()) {
                Some(offset) => {
                    out.push((start, &source[start..start + offset]));
                    index = start + offset + terminator.len();
                }
                None => index += 1,
            }
        }
        out
    }

    fn rust_sources(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }
}

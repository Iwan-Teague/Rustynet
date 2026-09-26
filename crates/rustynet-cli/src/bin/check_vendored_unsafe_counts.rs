#![forbid(unsafe_code)]

//! Vendored unsafe-code census drift gate (AQ-248 follow-up).
//!
//! Pins, per `.rs` file under `third_party/`, the counts of `unsafe`
//! blocks, `unsafe fn`s, `unsafe impl`s and `unsafe extern` blocks, and
//! FAILS on any difference between the tree and the checked-in pin file
//! `third_party/UNSAFE_COUNTS.pinned` — in either direction. An increase
//! is new unreviewed unsafe code; a decrease means the pin is stale and
//! no longer documents what ships.
//!
//! This is the option-(a) companion to T2 control C9 recommended by the
//! AQ-248 review (`charter/reviews/REVIEW-aq248-2026-09-25.md` §3): the
//! security bar itself routes vendored code away from the OI-20
//! SAFETY-comment scanner — B1 ends "vendored `third_party/` stays under
//! C9, not this bar" (`charter/security-bar/T2-security-bar.md:34`) and
//! C9 is the quarterly diff of vendored crypto against a pinned upstream
//! tag (`charter/security-bar/T2-security-bar.md:56`). This gate does not
//! replace C9's semantic diff review; it makes the unsafe-token census of
//! the vendored tree an enforced invariant so any drift surfaces at the
//! next gate run and must be reviewed against the upstream tag before it
//! lands.
//!
//! Counts are TOKEN counts, not text counts: line comments (including
//! doc comments), nested block comments and the contents of string,
//! char, byte-string and raw-string literals are stripped before
//! matching, so the word `unsafe` in prose or data never counts. The
//! literal/comment stripping mirrors the AQ-248/D1 lexer in
//! `crates/rustynet-cli/src/ops_phase1.rs`
//! (`strip_string_and_char_literal_contents`, suite commit d948b707e),
//! extended here with block-comment removal, which the SAFETY-adjacency
//! lexer deliberately does not do (a block comment is a real comment
//! there; here it is prose to ignore).
//!
//! Category mapping: `fns` counts `unsafe fn`; `externs` counts
//! `unsafe extern` blocks, whose items are implicitly unsafe fns — the
//! AQ-248 review's "21 unsafe fns" for boringtun is `fns + externs`
//! (2 + 19) here. Any other `unsafe` shape (`unsafe trait`,
//! `#[unsafe(..)]` attributes, `unsafe` followed by nothing
//! recognizable) FAILS the gate as an unrecognized shape: the pin format
//! must be extended and the delta human-reviewed; the gate never
//! silently ignores an unsafe keyword it does not know.
//!
//! Coverage is per FILE, not per `.rs` FILE: rustc can splice tokens from
//! any UTF-8 file via `include!("…")` or `#[path = "…"] mod`, so every
//! UTF-8 file under third_party/ is censused (prose files that merely
//! mention `unsafe` can need a pin line). Files that are not valid UTF-8
//! cannot be spliced as Rust tokens and are skipped — unless they are
//! `.rs` (case-insensitive), which must stay readable and fail the gate.
//! Splice SITES are pinned structurally, not parsed: parsing a splice's
//! target literal is fragile (a non-leading `..` segment, a computed
//! `concat!`/`env!` target, a raw-string target or a macro alias that
//! expands to `include!` all defeat it). Instead the census counts, per
//! file and with the same literal-stripping lexer (so comments and
//! string contents never count), (a) `include!` invocations — the token
//! `include` followed by `!`, whitespace-tolerant, under any path
//! qualifier such as `core::` or `::std::` — and (b) `#[path]`
//! attributes, including `#![path]` and whitespace variants — and (c)
//! every `cfg_attr` token (a `#[cfg_attr(cond, path = "...")]`
//! attribute never spells `#[path`, so its token is the pinned site) —
//! and pins those counts alongside the unsafe counts. Any added, removed
//! or moved splice therefore changes the census and fails the gate until
//! a human reviews it and updates the pin, whatever its target spells.
//! An `include!` whose argument is not a string literal is REFUSED
//! outright: its target is computed at build time (e.g. OUT_DIR content
//! written by build.rs) and no source census can see what it splices. A
//! secondary raw-source check still refuses absolute/`..`-escaping
//! targets outright (defense in depth only; the gate does not depend on
//! it). `include_str!`/`include_bytes!` are deliberately NOT counted:
//! they splice a `&str`/`&[u8]` VALUE, never tokens, so they cannot
//! introduce unsafe code; counting them would pin data plumbing for no
//! security gain.
//! The pin file itself is excluded from its own census: it is data, its
//! line structure is parse-checked, and every path it names is cross-
//! checked against the tree (StalePin/Unpinned), so its content is
//! policed without being counted.
//!
//! Regenerate the pin after a reviewed vendored refresh:
//! `cargo run -p rustynet-cli --bin check_vendored_unsafe_counts -- --generate`
//! (redirect into `third_party/UNSAFE_COUNTS.pinned` in the same commit
//! as the vendored change).

use rustynetd::exit_codes::ExitCode;
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// Scan root, relative to the rustynet repo root.
const SCAN_ROOT: &str = "third_party";
/// Checked-in pin file, relative to the rustynet repo root.
const PIN_PATH: &str = "third_party/UNSAFE_COUNTS.pinned";
/// The pin file's path relative to `SCAN_ROOT`; excluded from the census
/// of its own tree (see module docs).
const PIN_FILE_IN_ROOT: &str = "UNSAFE_COUNTS.pinned";
const PIN_HEADER: &str = "\
# Vendored unsafe-code census pin (AQ-248).
# Per-file token counts of `unsafe` usage under third_party/. Maintained
# by scripts/ci/vendored_unsafe_drift_gate.sh (bin
# crates/rustynet-cli/src/bin/check_vendored_unsafe_counts.rs): the gate fails
# on ANY difference in EITHER direction - an increase is new unreviewed
# unsafe code, a decrease means this pin is stale. Review the delta against
# the pinned upstream tag (the vendor-refresh diff) and update this file in the
# SAME commit as the vendored change.
# Every file is censused, not only *.rs: rustc can splice tokens from any
# UTF-8 file via `include!` or `#[path = \"...\"]`, so prose files that
# merely mention `unsafe` can also need a pin line. Files that are not
# valid UTF-8 cannot be spliced as Rust tokens and are skipped (a
# non-UTF-8 *.rs is a hard error).
# Splice SITES are pinned, not their targets: per file, `includes` counts
# `include!` invocations (any path qualifier, whitespace-tolerant) and
# `path_attrs` counts `#[path]`/`#![path]` attributes, both outside
# comments and strings. `cfg_attrs` counts `cfg_attr` occurrences: a
# `#[cfg_attr(cond, path = \"...\")]` attribute never spells `#[path`, so
# the cfg_attr itself is the pinned site. An added, removed or moved
# splice changes these counts and fails the gate until a human reviews it
# and updates this pin - whatever the target literal spells (`../…`,
# raw strings, macro aliases). An `include!` whose argument is not a
# string literal (concat!/env!/any expression) is REFUSED outright: its
# target is computed at build time (e.g. OUT_DIR content) and no source
# census can see what it splices. A secondary raw-source check refuses
# absolute/`..`-escaping targets outright (defense in depth).
# This pin is DATA, not code: editing it to match a drift silently
# re-baselines the gate. A pin change must be human-reviewed in the SAME
# commit as the change it documents; the gate cannot verify that review.
# Nothing in this census can enforce that review: it has to come from
# the repository's own review rules (a required reviewer for this file).
# Residuals no textual census can see (they need a semantic vendor
# diff against the pinned upstream tag, not this gate): (1) tokens
# EMITTED at build time by proc-macro attribute/derive macros - an
# invocation's own token is visible (it counts as a cfg_attr or plain
# attribute token only when it spells one), what the macro expands to
# never is; (2) an in-place rewrite of an existing `unsafe` block that
# keeps every count equal (e.g. swapping the callee body) drifts nothing.
# Columns: blocks = `unsafe {`; fns = `unsafe fn`; impls = `unsafe impl`;
# externs = `unsafe extern` (its items are unsafe fns; the AQ-248 review's
# boringtun \"21 unsafe fns\" = fns + externs); includes = `include!`
# invocations; path_attrs = `#[path]` attributes; cfg_attrs = `cfg_attr`
# occurrences (all splice-site carriers; `include_str!`/`include_bytes!`
# splice VALUES not tokens and are not counted). Paths are relative to
# third_party/ (e.g. `boringtun/src/lib.rs`). Zero-count files are not
# pinned. Regenerate with: check_vendored_unsafe_counts --generate
";

/// Per-file census of `unsafe` keyword usage shapes plus splice sites.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct UnsafeCounts {
    /// `unsafe { ... }` blocks.
    blocks: u64,
    /// `unsafe fn` items.
    fns: u64,
    /// `unsafe impl` blocks.
    impls: u64,
    /// `unsafe extern` blocks (items inside are implicitly unsafe fns).
    externs: u64,
    /// `include!` invocations (token splice sites; any path qualifier,
    /// whitespace-tolerant). Comments and string contents never count.
    includes: u64,
    /// `#[path]`/`#![path]` attributes (mod splice sites; whitespace
    /// tolerant). Comments and string contents never count.
    path_attrs: u64,
    /// `cfg_attr` occurrences. `#[cfg_attr(cond, path = "...")]` never
    /// spells `#[path`, so the cfg_attr token itself is the pinned site:
    /// when `cond` is true the wrapped `path` attribute takes effect and
    /// splices a module file. Comments and string contents never count.
    cfg_attrs: u64,
}

impl UnsafeCounts {
    fn total(self) -> u64 {
        self.blocks
            + self.fns
            + self.impls
            + self.externs
            + self.includes
            + self.path_attrs
            + self.cfg_attrs
    }

    fn field_name(field: usize) -> &'static str {
        match field {
            0 => "blocks",
            1 => "fns",
            2 => "impls",
            3 => "externs",
            4 => "includes",
            5 => "path_attrs",
            _ => "cfg_attrs",
        }
    }

    fn field_value(self, field: usize) -> u64 {
        match field {
            0 => self.blocks,
            1 => self.fns,
            2 => self.impls,
            3 => self.externs,
            4 => self.includes,
            5 => self.path_attrs,
            _ => self.cfg_attrs,
        }
    }

    /// Rendered as `blocks=N fns=N impls=N externs=N includes=N
    /// path_attrs=N cfg_attrs=N` (pin line body and drift messages).
    fn render(self) -> String {
        format!(
            "blocks={} fns={} impls={} externs={} includes={} path_attrs={} cfg_attrs={}",
            self.blocks,
            self.fns,
            self.impls,
            self.externs,
            self.includes,
            self.path_attrs,
            self.cfg_attrs
        )
    }
}

/// A `unsafe` keyword followed by a shape this gate does not model.
/// Fail-closed: the pin format must be extended after human review.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnrecognizedShape {
    line: usize,
    after: String,
}

impl fmt::Display for UnrecognizedShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}: `unsafe` followed by unrecognized token `{}`",
            self.line, self.after
        )
    }
}

fn count_unsafe_tokens(source: &str) -> Result<UnsafeCounts, UnrecognizedShape> {
    // Secondary defense in depth; the gate's primary mechanism is the
    // structural splice-site pin below (it does not depend on this).
    reject_out_of_root_splices(source)?;
    let code = strip_comments_and_literal_contents(source);
    let chars: Vec<char> = code.chars().collect();
    let mut counts = UnsafeCounts::default();
    count_splice_sites(&chars, &mut counts);
    let mut index = 0;
    while index < chars.len() {
        if !is_unsafe_keyword(&chars, index) {
            index += 1;
            continue;
        }
        let after =
            next_nonspace(&chars, index + "unsafe".len()).ok_or_else(|| UnrecognizedShape {
                line: line_of(&chars, index),
                after: "<end of file>".to_string(),
            })?;
        let rest: String = chars[after..]
            .iter()
            .take_while(|c| c.is_alphanumeric() || **c == '_')
            .collect();
        match (chars[after], rest.as_str()) {
            ('{', _) => counts.blocks += 1,
            (_, "fn") => counts.fns += 1,
            (_, "impl") => counts.impls += 1,
            (_, "extern") => counts.externs += 1,
            (open, "") => {
                return Err(UnrecognizedShape {
                    line: line_of(&chars, after),
                    after: open.to_string(),
                });
            }
            (_, other) => {
                return Err(UnrecognizedShape {
                    line: line_of(&chars, after),
                    after: other.to_string(),
                });
            }
        }
        index = after;
    }
    Ok(counts)
}

/// Count splice sites structurally in already-stripped code: every
/// `include!` invocation (the token `include` then `!`, whitespace
/// tolerated between them, under any path qualifier such as
/// `core::include!` or `::std::include!`) and every `#[path]`
/// attribute (`#`, optional whitespace, optional `!`, optional
/// whitespace, `[`, optional whitespace, the token `path` — so
/// `#![path]`, `# [path]` and `# ! [ path ]` all count). The target is
/// never parsed: whatever it spells (a non-leading `..` segment, a
/// `concat!`/`env!` computation, a raw string, a macro argument), the
/// SITE itself is what drifts the census. A macro body that expands to
/// `include!` contains the real `include` `!` tokens and counts here,
/// so a macro alias cannot smuggle a splice past the pin, and every
/// `cfg_attr` token counts (a `#[cfg_attr(cond, path = "...")]`
/// attribute never spells `#[path`, so its token is the pinned site).
/// Runs on stripped code, so a comment or string mentioning `include!`,
/// `#[path` or `cfg_attr` never counts.
fn count_splice_sites(chars: &[char], counts: &mut UnsafeCounts) {
    let mut index = 0;
    while index < chars.len() {
        if is_word_at(chars, index, &['i', 'n', 'c', 'l', 'u', 'd', 'e']) {
            if let Some(bang) = next_nonspace_index(chars, index + 7) {
                if chars[bang] == '!' {
                    counts.includes += 1;
                    index += 7;
                    continue;
                }
            }
        }
        if chars[index] == '#' {
            if let Some(at) = path_attr_at(chars, index) {
                counts.path_attrs += 1;
                index = at;
                continue;
            }
        }
        if is_word_at(chars, index, &['c', 'f', 'g', '_', 'a', 't', 't', 'r']) {
            // A `cfg_attr` never spells `#[path` itself: the wrapped
            // `path` attribute only materializes when the condition is
            // true, so the cfg_attr TOKEN is the pinned site. Counting
            // every occurrence (not just `#[cfg_attr(`) is deliberate —
            // over-counting is the safe direction for a drift pin.
            counts.cfg_attrs += 1;
            index += 8;
            continue;
        }
        index += 1;
    }
}

/// If the `#` at `start` opens a `#[path]`/`#![path]` attribute (with
/// whitespace variants), return the index just after the `path` token.
fn path_attr_at(chars: &[char], start: usize) -> Option<usize> {
    let mut probe = next_nonspace_index(chars, start + 1)?;
    if chars[probe] == '!' {
        probe = next_nonspace_index(chars, probe + 1)?;
    }
    if chars[probe] != '[' {
        return None;
    }
    let word = next_nonspace_index(chars, probe + 1)?;
    if !is_word_at(chars, word, &['p', 'a', 't', 'h']) {
        return None;
    }
    Some(word + 4)
}

fn next_nonspace_index(chars: &[char], from: usize) -> Option<usize> {
    chars[from..]
        .iter()
        .position(|c| !c.is_whitespace())
        .map(|offset| from + offset)
}

/// True when `start` begins a standalone `unsafe` keyword: the six chars
/// match, the preceding char does not continue an identifier (or is the
/// `#` of a raw identifier like `r#unsafe`), and the following char does
/// not extend it.
fn is_unsafe_keyword(chars: &[char], start: usize) -> bool {
    is_word_at(chars, start, &['u', 'n', 's', 'a', 'f', 'e'])
}

fn is_word_at(chars: &[char], start: usize, word: &[char]) -> bool {
    if chars.len() < start + word.len() {
        return false;
    }
    if chars[start..start + word.len()] != *word {
        return false;
    }
    if let Some(prev) = start.checked_sub(1).map(|i| chars[i]) {
        if is_word_char(prev) || prev == '#' {
            return false;
        }
    }
    match chars.get(start + word.len()) {
        Some(next) => !is_word_char(*next),
        None => true,
    }
}

/// Refuse `include!`/`#[path]` splices whose target is absolute or
/// escapes the scan root with a LEADING `..` segment, and refuse any
/// `include!` whose argument is not a string literal: such a splice pulls
/// Rust tokens from a place this census never walks (outside the tree,
/// or build-time-generated OUT_DIR content), so a zero-token edit to an
/// already-pinned file could smuggle unreviewed unsafe code past the
/// pin. Scanned on the RAW source, because the literal stripper blanks
/// string contents and would erase the target path; a comment or string
/// containing the same sequence also fails, which is the safe direction
/// (it blocks the gate until the prose is reworded).
///
/// This check is BEST-EFFORT defense in depth and deliberately kept
/// simple: it reads only the first characters of the target literal, so
/// a non-leading `..` segment slips past it. The gate does not depend on
/// it — the structural splice-site pin (see `count_splice_sites`) catches
/// those by counting the sites themselves. A COMPUTED `include!` target
/// (`concat!`/`env!`/`$param`/any expression), by contrast, is refused
/// outright here: its content is resolved at build time and NO source
/// census can see it, so pinning the site is not enough.
fn reject_out_of_root_splices(source: &str) -> Result<(), UnrecognizedShape> {
    let chars: Vec<char> = source.chars().collect();
    for index in 0..chars.len() {
        let after_value_quote = splice_target_start(&chars, index)?;
        if let Some(at) = after_value_quote {
            if chars.get(at) == Some(&'/') || starts_with_parent_segment(&chars, at) {
                return Err(UnrecognizedShape {
                    line: line_of(&chars, index),
                    after: "splice target outside third_party/ (`#[path]`/`include!` \
                            may not point at an absolute or `..`-escaping path)"
                        .to_string(),
                });
            }
        }
    }
    Ok(())
}

/// If the token at `start` opens a `#[path = "` / `include!("` splice,
/// return the index of the target literal's FIRST CONTENT character
/// (after the opening quote, or after an `r###` raw-string prefix).
/// A computed `include!` argument (not a `"` / `r"..."` literal) is an
/// error: see `reject_out_of_root_splices`. `None` = no splice shape at
/// `start` (the site is still pinned structurally by the census).
fn splice_target_start(chars: &[char], start: usize) -> Result<Option<usize>, UnrecognizedShape> {
    if is_word_at(chars, start, &['#', '[', 'p', 'a', 't', 'h']) {
        // A `#[path]` value is grammatically always a literal; only the
        // absolute/`..` first-char check applies.
        return Ok(expect_sequence(chars, start + 6, &['=', '"']));
    }
    if is_word_at(chars, start, &['i', 'n', 'c', 'l', 'u', 'd', 'e']) {
        let Some(after_paren) = expect_sequence(chars, start + 7, &['!', '(']) else {
            return Ok(None);
        };
        let Some(at) = next_nonspace(chars, after_paren) else {
            return Ok(None);
        };
        let at = at + raw_string_prefix_len(chars, at);
        if chars.get(at) != Some(&'"') {
            return Err(UnrecognizedShape {
                line: line_of(chars, start),
                after: "computed `include!` target - `include!` must take a string \
                        literal (a computed target is resolved at build time and \
                        no source census can see what it splices)"
                    .to_string(),
            });
        }
        return Ok(Some(at + 1));
    }
    Ok(None)
}

/// Length of the `r` + hashes prefix (quote NOT included) when the char
/// at `at` opens a raw string literal (`r"`, `r#"`, `r##"`, ...); 0 for
/// anything else.
fn raw_string_prefix_len(chars: &[char], at: usize) -> usize {
    if chars.get(at) != Some(&'r') {
        return 0;
    }
    let mut probe = at + 1;
    while chars.get(probe) == Some(&'#') {
        probe += 1;
    }
    if probe > at + 1 && chars.get(probe) != Some(&'"') {
        return 0;
    }
    if chars.get(probe) == Some(&'"') {
        probe - at
    } else {
        0
    }
}

/// True when `at` begins a `..` path segment (`..`/`../…`), the form a
/// `#[path]`/`include!` target needs to escape the scan root.
fn starts_with_parent_segment(chars: &[char], at: usize) -> bool {
    chars.get(at) == Some(&'.')
        && chars.get(at + 1) == Some(&'.')
        && matches!(chars.get(at + 2), None | Some('/') | Some('"'))
}

/// Skip whitespace from `from`, then require exactly the `keys` chars in
/// order, whitespace allowed between them; returns the index of the first
/// char after the last key (for a `"` key: the first content char).
fn expect_sequence(chars: &[char], mut from: usize, keys: &[char]) -> Option<usize> {
    for key in keys {
        from = next_nonspace(chars, from)?;
        if chars[from] != *key {
            return None;
        }
        from += 1;
    }
    Some(from)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn next_nonspace(chars: &[char], from: usize) -> Option<usize> {
    chars[from..]
        .iter()
        .position(|c| !c.is_whitespace())
        .map(|offset| from + offset)
}

fn line_of(chars: &[char], pos: usize) -> usize {
    1 + chars[..pos.min(chars.len())]
        .iter()
        .filter(|c| **c == '\n')
        .count()
}

/// Return the code text with every comment (line, doc, nested block) and
/// every literal (string, byte-string, char, byte-char, raw string of any
/// hash count, including the `b`/`c` prefixed forms) replaced by spaces —
/// newlines preserved so error messages keep real line numbers. A token
/// spanning stripped regions is impossible: stripping only ever inserts
/// whitespace. Mirrors the AQ-248/D1 literal stripping in
/// `ops_phase1.rs::strip_string_and_char_literal_contents` and adds
/// comment removal.
fn strip_comments_and_literal_contents(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        if c == '/' && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                out.push(' ');
                index += 1;
            }
            continue;
        }
        if c == '/' && chars.get(index + 1) == Some(&'*') {
            push_block_comment(&chars, &mut index, &mut out);
            continue;
        }
        if c == '"' {
            push_escaped_literal(&chars, &mut index, &mut out, '"');
            continue;
        }
        if c == '\'' && is_char_literal_open(&chars, index) {
            push_escaped_literal(&chars, &mut index, &mut out, '\'');
            continue;
        }
        if c == 'r' && is_raw_string_open(&chars, index) {
            push_raw_string(&chars, &mut index, &mut out);
            continue;
        }
        out.push(c);
        index += 1;
    }
    out
}

/// Consume a nested block comment (`/* .. /* .. */ .. */`), blanking all
/// of it. If the comment is never closed the rest of the input is blanked
/// (degrade to more stripping, never less).
fn push_block_comment(chars: &[char], index: &mut usize, out: &mut String) {
    out.push(' ');
    out.push(' ');
    *index += 2;
    let mut depth = 1usize;
    while *index < chars.len() && depth > 0 {
        if chars[*index] == '/' && chars.get(*index + 1) == Some(&'*') {
            depth += 1;
            out.push(' ');
            out.push(' ');
            *index += 2;
        } else if chars[*index] == '*' && chars.get(*index + 1) == Some(&'/') {
            depth -= 1;
            out.push(' ');
            out.push(' ');
            *index += 2;
        } else {
            out.push(if chars[*index] == '\n' { '\n' } else { ' ' });
            *index += 1;
        }
    }
}

/// Consume a `"`- or `'`-delimited literal honoring `\` escapes, blanking
/// the whole thing including delimiters. Unterminated input degrades to
/// blanking the rest of the line (literals cannot span lines unescaped).
fn push_escaped_literal(chars: &[char], index: &mut usize, out: &mut String, close: char) {
    out.push(' ');
    *index += 1;
    while *index < chars.len() {
        let c = chars[*index];
        if c == '\\' {
            out.push(' ');
            if let Some(next) = chars.get(*index + 1) {
                out.push(if *next == '\n' { '\n' } else { ' ' });
                *index += 2;
            } else {
                *index += 1;
            }
            continue;
        }
        out.push(if c == '\n' { '\n' } else { ' ' });
        *index += 1;
        if c == close {
            return;
        }
    }
}

/// Consume a raw string `r"..."` / `r#"..."#` (any hash count), blanking
/// all of it; raw strings honor no escapes and may span lines, so only
/// newlines survive. If never closed the rest of the input is blanked.
fn push_raw_string(chars: &[char], index: &mut usize, out: &mut String) {
    let mut hashes = 0usize;
    let mut probe = *index + 1;
    while chars.get(probe) == Some(&'#') {
        hashes += 1;
        probe += 1;
    }
    // Blank `r` + hashes + opening quote.
    for _ in 0..=1 + hashes {
        out.push(' ');
    }
    *index = probe + 1;
    while *index < chars.len() {
        if chars[*index] == '"' {
            let mut seen = 0usize;
            while seen < hashes && chars.get(*index + 1 + seen) == Some(&'#') {
                seen += 1;
            }
            if seen == hashes {
                for _ in 0..=hashes {
                    out.push(' ');
                }
                *index += 1 + hashes;
                return;
            }
        }
        out.push(if chars[*index] == '\n' { '\n' } else { ' ' });
        *index += 1;
    }
}

/// True when the `'` at `quote` opens a char literal: either the escape
/// form `'\n'`, `'\u{...}'` (a closing quote exists before end of line,
/// backslash pairs skipped) or the plain one-char form `'x'`. Lifetime
/// apostrophes (`'a`, `'static`) have no same-line closing quote after
/// one character and are not char literals. Mirrors
/// `ops_phase1.rs::is_char_literal_open`.
fn is_char_literal_open(chars: &[char], quote: usize) -> bool {
    match chars.get(quote + 1) {
        Some('\\') => {
            let mut probe = quote + 2;
            while probe < chars.len() {
                if chars[probe] == '\\' {
                    probe += 2;
                    continue;
                }
                if chars[probe] == '\'' {
                    return true;
                }
                probe += 1;
            }
            false
        }
        Some(_) => chars.get(quote + 2) == Some(&'\''),
        None => false,
    }
}

/// True when the `r` at `index` opens a raw string literal (`r"`, `r#"`,
/// `r##"`, ...). The `r` must start a token: not preceded by an
/// identifier character, except the byte/C-string prefixes `br` and `cr`
/// whose own preceding character must also be a token boundary. Mirrors
/// `ops_phase1.rs::is_raw_string_open`.
fn is_raw_string_open(chars: &[char], index: usize) -> bool {
    if index > 0 {
        let prev = chars[index - 1];
        let in_identifier = is_word_char(prev);
        let prefix = (prev == 'b' || prev == 'c') && (index < 2 || !is_word_char(chars[index - 2]));
        if in_identifier && !prefix {
            return false;
        }
    }
    match chars.get(index + 1) {
        Some('"') => true,
        Some('#') => {
            let mut probe = index + 1;
            while chars.get(probe) == Some(&'#') {
                probe += 1;
            }
            probe > index + 1 && chars.get(probe) == Some(&'"')
        }
        _ => false,
    }
}

/// One line of the pin file: a path relative to `third_party/`
/// (e.g. `boringtun/src/lib.rs`) plus its four pinned counts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PinEntry {
    path: String,
    counts: UnsafeCounts,
}

fn parse_pin(text: &str) -> Result<Vec<PinEntry>, String> {
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (number, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let path = tokens
            .next()
            .ok_or_else(|| format!("pin line {}: empty", number + 1))?;
        if path.starts_with('/') || path.contains("..") {
            return Err(format!(
                "pin line {}: path `{}` must be a relative path under {}/",
                number + 1,
                path,
                SCAN_ROOT
            ));
        }
        if !seen.insert(path.to_string()) {
            return Err(format!(
                "pin line {}: duplicate path `{}`",
                number + 1,
                path
            ));
        }
        let mut counts = UnsafeCounts::default();
        let mut assigned = [false; 7];
        for token in tokens {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                format!(
                    "pin line {}: token `{}` is not key=value",
                    number + 1,
                    token
                )
            })?;
            let field = match key {
                "blocks" => 0,
                "fns" => 1,
                "impls" => 2,
                "externs" => 3,
                "includes" => 4,
                "path_attrs" => 5,
                "cfg_attrs" => 6,
                other => {
                    return Err(format!(
                        "pin line {}: unknown count key `{}` (expected \
                         blocks/fns/impls/externs/includes/path_attrs/cfg_attrs)",
                        number + 1,
                        other
                    ));
                }
            };
            if assigned[field] {
                return Err(format!(
                    "pin line {}: key `{}` given twice",
                    number + 1,
                    key
                ));
            }
            assigned[field] = true;
            let value: u64 = value.parse().map_err(|_| {
                format!(
                    "pin line {}: key `{}` value `{}` is not a non-negative integer",
                    number + 1,
                    key,
                    value
                )
            })?;
            counts.field_value_set(field, value);
        }
        if !assigned.iter().all(|set| *set) {
            return Err(format!(
                "pin line {}: all seven keys \
                 blocks/fns/impls/externs/includes/path_attrs/cfg_attrs are required",
                number + 1
            ));
        }
        if counts.total() == 0 {
            return Err(format!(
                "pin line {}: zero-count entry for `{}` — zero-count files are not pinned, delete the line",
                number + 1,
                path
            ));
        }
        entries.push(PinEntry {
            path: path.to_string(),
            counts,
        });
    }
    Ok(entries)
}

impl UnsafeCounts {
    fn field_value_set(&mut self, field: usize, value: u64) {
        match field {
            0 => self.blocks = value,
            1 => self.fns = value,
            2 => self.impls = value,
            3 => self.externs = value,
            4 => self.includes = value,
            5 => self.path_attrs = value,
            _ => self.cfg_attrs = value,
        }
    }
}

/// One difference between the pin and the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Problem {
    /// Pinned file's counts differ from the tree. The message names the
    /// direction(s): an increase is new unreviewed unsafe, a decrease is
    /// a stale pin.
    Drift {
        path: String,
        pin: UnsafeCounts,
        actual: UnsafeCounts,
    },
    /// A `.rs` file under `third_party/` carries unsafe code but has no
    /// pin entry.
    Unpinned { path: String, actual: UnsafeCounts },
    /// A pin entry names a file that no longer exists under
    /// `third_party/`.
    StalePin { path: String, pin: UnsafeCounts },
    /// An `unsafe` keyword shape this gate does not model.
    UnrecognizedShape {
        path: String,
        shape: UnrecognizedShape,
    },
}

impl Problem {
    fn describe(&self) -> String {
        match self {
            Problem::Drift { path, pin, actual } => {
                let mut directions = Vec::new();
                let mut increased = false;
                let mut decreased = false;
                for field in 0..7 {
                    let pinned = pin.field_value(field);
                    let found = actual.field_value(field);
                    let name = UnsafeCounts::field_name(field);
                    if found > pinned {
                        increased = true;
                        directions.push(format!("+{} {name}", found - pinned));
                    } else if found < pinned {
                        decreased = true;
                        directions.push(format!("-{} {name}", pinned - found));
                    }
                }
                if increased {
                    directions
                        .push("INCREASE = new unreviewed unsafe code or splice site".to_string());
                }
                if decreased {
                    directions.push("DECREASE = stale pin".to_string());
                }
                format!(
                    "DRIFT      {path}: pin {}, tree {} ({})",
                    pin.render(),
                    actual.render(),
                    directions.join(", ")
                )
            }
            Problem::Unpinned { path, actual } => format!(
                "UNPINNED   {path}: unsafe code present ({}), no pin entry",
                actual.render(),
            ),
            Problem::StalePin { path, pin } => format!(
                "STALE PIN  {path}: pinned ({}) but the file no longer exists under {SCAN_ROOT}/",
                pin.render(),
            ),
            Problem::UnrecognizedShape { path, shape } => {
                format!("UNMODELED  {path}: {shape}")
            }
        }
    }
}

/// Compare the pin entries against a recount of the tree under
/// `scan_root`. Pure given the pin text and the tree; the binary wires
/// the filesystem around it.
fn check_tree(scan_root: &Path, pin_text: &str) -> Result<Vec<Problem>, String> {
    let pin_entries = parse_pin(pin_text)?;
    let mut pinned: BTreeMap<String, UnsafeCounts> = pin_entries
        .into_iter()
        .map(|entry| (entry.path, entry.counts))
        .collect();
    let mut problems = Vec::new();
    for rel_path in collect_rs_files(scan_root)
        .map_err(|err| format!("failed to walk {}: {err}", scan_root.display()))?
    {
        let source = match read_census_source(scan_root, &rel_path)? {
            Some(source) => source,
            None => continue,
        };
        match count_unsafe_tokens(&source) {
            Err(shape) => problems.push(Problem::UnrecognizedShape {
                path: rel_path.clone(),
                shape,
            }),
            Ok(actual) => {
                if actual.total() == 0 {
                    if let Some(pin) = pinned.remove(&rel_path) {
                        problems.push(Problem::Drift {
                            path: rel_path,
                            pin,
                            actual,
                        });
                    }
                    continue;
                }
                match pinned.remove(&rel_path) {
                    Some(pin) if pin != actual => problems.push(Problem::Drift {
                        path: rel_path,
                        pin,
                        actual,
                    }),
                    Some(_) => {}
                    None => problems.push(Problem::Unpinned {
                        path: rel_path,
                        actual,
                    }),
                }
            }
        }
    }
    for (path, pin) in pinned {
        problems.push(Problem::StalePin { path, pin });
    }
    Ok(problems)
}

/// Build the pin text for the current tree: a fixed header plus one
/// sorted, deterministic line per `.rs` file carrying unsafe code.
fn generate_pin(scan_root: &Path) -> Result<String, String> {
    let mut lines = String::from(PIN_HEADER);
    let mut count = 0;
    for rel_path in collect_rs_files(scan_root)
        .map_err(|err| format!("failed to walk {}: {err}", scan_root.display()))?
    {
        let source = match read_census_source(scan_root, &rel_path)? {
            Some(source) => source,
            None => continue,
        };
        match count_unsafe_tokens(&source) {
            Err(shape) => {
                return Err(format!(
                    "unmodeled `unsafe` usage in {rel_path}: {shape} — extend the gate and pin format after human review"
                ));
            }
            Ok(counts) if counts.total() > 0 => {
                lines.push_str(&rel_path);
                lines.push(' ');
                lines.push_str(&counts.render());
                lines.push('\n');
                count += 1;
            }
            Ok(_) => {}
        }
    }
    if count == 0 {
        return Err(format!(
            "no .rs file under {}/ carries unsafe code — nothing to pin; if this is expected, remove the gate",
            scan_root.display()
        ));
    }
    Ok(lines)
}

/// Every file under `root`, as `/`-separated paths relative to `root`,
/// sorted for deterministic output. Every FILE is collected, not only
/// `*.rs`: rustc can splice tokens from any UTF-8 file via `include!` or
/// `#[path = "…"]`, so a `.txt` sibling would otherwise smuggle unsafe
/// code past a census that only walks `.rs`. The pin file itself is
/// excluded (see module docs).
fn collect_rs_files(root: &Path) -> std::io::Result<Vec<String>> {
    let mut found = Vec::new();
    collect_rs_files_inner(root, root, &mut found)?;
    found.sort();
    Ok(found)
}

fn collect_rs_files_inner(root: &Path, dir: &Path, found: &mut Vec<String>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files_inner(root, &path, found)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| {
                    std::io::Error::other(format!(
                        "path {} escapes scan root {}",
                        path.display(),
                        root.display()
                    ))
                })?
                .to_string_lossy()
                .replace('\\', "/");
            if rel != PIN_FILE_IN_ROOT {
                found.push(rel);
            }
        }
    }
    Ok(())
}

/// True for `.rs` paths, case-insensitively: on a case-insensitive
/// filesystem (`evil.RS`) rustc resolves `mod evil;` to it just the same,
/// so an uppercase extension must not exempt a file from the census.
fn is_rust_source(rel_path: &str) -> bool {
    Path::new(rel_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
}

/// Read a census candidate. A non-UTF-8 `.rs` is a hard error (it would
/// compile or not as a whole; the gate never guesses). A non-UTF-8 file
/// with any other extension cannot be spliced as Rust tokens
/// (`include!`/`#[path]` of invalid UTF-8 is a compile error), so it is
/// skipped rather than allowed to wedge the gate.
fn read_census_source(scan_root: &Path, rel_path: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(scan_root.join(rel_path)) {
        Ok(source) => Ok(Some(source)),
        Err(err) if is_rust_source(rel_path) => Err(format!("failed to read {rel_path}: {err}")),
        Err(_) => Ok(None),
    }
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let generate = match args.as_slice() {
        [] => false,
        [flag] if flag == "--generate" => true,
        _ => {
            eprintln!(
                "usage: check_vendored_unsafe_counts [--generate]  (no args = check the tree against {PIN_PATH})"
            );
            return Err(ExitCode::BadArgs.as_i32());
        }
    };
    let repo_root = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let scan_root = repo_root.join(SCAN_ROOT);
    if generate {
        let pin = generate_pin(&scan_root).map_err(|err| {
            eprintln!("error [{}]: {err}", ExitCode::PolicyReject);
            ExitCode::PolicyReject.as_i32()
        })?;
        print!("{pin}");
        return Ok(());
    }
    let pin_path = repo_root.join(PIN_PATH);
    let pin_text = fs::read_to_string(&pin_path).map_err(|err| {
        eprintln!(
            "error [{}]: cannot read pin file {} ({err}) — generate it with check_vendored_unsafe_counts --generate after reviewing the census",
            ExitCode::ConfigError,
            pin_path.display()
        );
        ExitCode::ConfigError.as_i32()
    })?;
    let problems = check_tree(&scan_root, &pin_text).map_err(|err| {
        eprintln!("error [{}]: invalid pin: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    if problems.is_empty() {
        println!(
            "Vendored unsafe census: PASS ({SCAN_ROOT}/ matches {PIN_PATH}; AQ-248 vendored drift gate)"
        );
        return Ok(());
    }
    eprintln!("Vendored unsafe drift: {SCAN_ROOT}/ differs from {PIN_PATH} —");
    for problem in &problems {
        eprintln!("  {}", problem.describe());
    }
    eprintln!(
        "Review each delta against the vendored upstream tag (the vendor-refresh diff; \
         an increase is new unreviewed unsafe, a decrease means the pin is stale) and \
         update {PIN_PATH} in the SAME commit (AQ-248: vendored third_party/ is \
         governed by the vendor-refresh review, not the SAFETY-comment scanner). \
         Regenerate with: check_vendored_unsafe_counts --generate"
    );
    eprintln!(
        "Vendored unsafe census: FAIL ({} problem(s))",
        problems.len()
    );
    Err(ExitCode::PolicyReject.as_i32())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── counting: comments and literals are data, not code ─────────────

    #[test]
    fn comment_mentioning_unsafe_is_not_counted() {
        let source = "\
// unsafe { forged }
/* unsafe fn forged() {} */
/// unsafe impl Foo for Bar {}
/*! unsafe extern \"C\" {} */
fn real() {}
/* nested /* unsafe { deeper } */ still comment */
";
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    #[test]
    fn string_mentioning_unsafe_is_not_counted() {
        let source = r##"let a = "unsafe {";
let b = r#"unsafe fn"#;
let c = br#"unsafe impl"#;
let d = 'u';
let e = b'u';
let f = cr"unsafe extern";
"##;
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    #[test]
    fn unsafe_after_a_string_on_one_line_is_counted() {
        let source = "let fake = \"// unsafe\"; let n = unsafe { 1 };";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.blocks, 1);
        assert_eq!(counts.total(), 1);
    }

    #[test]
    fn raw_identifier_unsafe_is_not_counted() {
        let source = "fn r#unsafe() {}\nlet x = r#unsafe;";
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    // ── counting: category assignment ──────────────────────────────────

    #[test]
    fn categories_are_assigned_by_following_token() {
        let source = "\
unsafe fn a() {}
unsafe impl Send for B {}
unsafe extern \"C\" {
    fn c();
}
unsafe extern \"C\" {}
let _ = unsafe { 1 };
";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(
            counts,
            UnsafeCounts {
                blocks: 1,
                fns: 1,
                impls: 1,
                externs: 2,
                ..UnsafeCounts::default()
            }
        );
    }

    #[test]
    fn unsafe_split_across_lines_is_still_counted() {
        let source = "unsafe\n{ 1 };\nunsafe // comment\n{ 2 };";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.blocks, 2);
    }

    // ── counting: fail closed on unmodeled shapes ──────────────────────

    #[test]
    fn unsafe_trait_is_an_unmodeled_shape() {
        let err = count_unsafe_tokens("unsafe trait T {}").expect_err("must fail");
        assert_eq!(err.after, "trait");
        assert_eq!(err.line, 1);
    }

    #[test]
    fn unsafe_attribute_is_an_unmodeled_shape() {
        let err = count_unsafe_tokens("#[unsafe(no_mangle)]\nfn f() {}").expect_err("must fail");
        assert_eq!(err.after, "(");
        assert_eq!(err.line, 1);
    }

    #[test]
    fn dangling_unsafe_is_an_unmodeled_shape() {
        assert!(count_unsafe_tokens("let _ = unsafe;").is_err());
    }

    #[test]
    fn unmodeled_shape_reports_the_real_line() {
        let err = count_unsafe_tokens("fn a() {}\n\nunsafe trait T {}").expect_err("must fail");
        assert_eq!(err.line, 3);
    }

    // ── pin parsing ────────────────────────────────────────────────────

    #[test]
    fn pin_parses_headers_blanks_and_entries() {
        let pin = "# header\n\nboringtun/src/a.rs blocks=1 fns=2 impls=0 externs=3 includes=4 path_attrs=5 cfg_attrs=6\n";
        let entries = parse_pin(pin).expect("parses");
        assert_eq!(
            entries,
            vec![PinEntry {
                path: "boringtun/src/a.rs".to_string(),
                counts: UnsafeCounts {
                    blocks: 1,
                    fns: 2,
                    impls: 0,
                    externs: 3,
                    includes: 4,
                    path_attrs: 5,
                    cfg_attrs: 6,
                },
            }]
        );
    }

    #[test]
    fn zero_count_pin_entry_is_rejected() {
        let err = parse_pin(
            "third_party/a.rs blocks=0 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n",
        )
        .expect_err("zero entries must fail");
        assert!(err.contains("zero-count"), "{err}");
    }

    #[test]
    fn unknown_key_and_duplicate_path_and_bad_prefix_are_rejected() {
        assert!(parse_pin(
            "a.rs blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0 trait=1\n"
        )
        .is_err());
        assert!(
            parse_pin(
                "a.rs blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n\
                 a.rs blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n"
            )
            .is_err()
        );
        assert!(
            parse_pin(
                "/abs/a.rs blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n"
            )
            .is_err()
        );
        assert!(parse_pin(
            "../escape/a.rs blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n"
        )
        .is_err());
        assert!(parse_pin("a.rs blocks=1 fns=0\n").is_err());
    }

    #[test]
    fn pin_line_missing_a_splice_key_is_rejected() {
        // A pin edited to drop a splice column would silently un-pin
        // splice sites; the format is all-or-nothing.
        let err = parse_pin("a.rs blocks=1 fns=0 impls=0 externs=0 includes=0\n")
            .expect_err("missing path_attrs must fail");
        assert!(err.contains("all seven keys"), "{err}");
    }

    #[test]
    fn non_rs_relative_paths_are_allowed_in_the_pin() {
        // Every file is censused, so a prose file that mentions `unsafe`
        // can need a pin line; only absolute and `..`-escaping paths are
        // rejected.
        let entries = parse_pin(
            "README.md blocks=1 fns=0 impls=0 externs=0 includes=0 path_attrs=0 cfg_attrs=0\n",
        )
        .expect("parses");
        assert_eq!(entries[0].path, "README.md");
    }

    // ── drift detection: both directions fail ──────────────────────────

    fn write_tree(root: &Path, files: &[(&str, &str)]) {
        for (rel, contents) in files {
            let path = root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(path, contents).expect("write");
        }
    }

    fn pin_line(path: &str, counts: UnsafeCounts) -> String {
        format!("{path} {}\n", counts.render())
    }

    #[test]
    fn added_block_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[(
                "src/a.rs",
                "unsafe fn a() {}\nlet _ = unsafe { 1 };\nlet _ = unsafe { 2 };\n",
            )],
        );
        let pin = pin_line(
            "src/a.rs",
            UnsafeCounts {
                blocks: 1,
                fns: 1,
                ..UnsafeCounts::default()
            },
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        match &problems[0] {
            Problem::Drift { path, pin, actual } => {
                assert_eq!(path, "src/a.rs");
                assert_eq!(pin.blocks, 1);
                assert_eq!(actual.blocks, 2);
            }
            other => panic!("expected Drift, got {other:?}"),
        }
        assert!(
            problems[0].describe().contains("+1 blocks"),
            "{}",
            problems[0].describe()
        );
        assert!(problems[0].describe().contains("new unreviewed unsafe"));
    }

    #[test]
    fn removed_block_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/a.rs", "let _ = unsafe { 1 };\n")]);
        let pin = pin_line(
            "src/a.rs",
            UnsafeCounts {
                blocks: 2,
                ..UnsafeCounts::default()
            },
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        let description = problems[0].describe();
        assert!(description.contains("-1 blocks"), "{description}");
        assert!(description.contains("stale pin"), "{description}");
    }

    #[test]
    fn unpinned_unsafe_file_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/new.rs", "let _ = unsafe { 1 };\n")]);
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(matches!(problems[0], Problem::Unpinned { .. }));
    }

    #[test]
    fn stale_pin_entry_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/kept.rs", "let _ = unsafe { 1 };\n")]);
        let mut pin = pin_line(
            "src/kept.rs",
            UnsafeCounts {
                blocks: 1,
                ..UnsafeCounts::default()
            },
        );
        pin.push_str(&pin_line(
            "src/gone.rs",
            UnsafeCounts {
                blocks: 1,
                ..UnsafeCounts::default()
            },
        ));
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(matches!(&problems[0], Problem::StalePin { path, .. } if path == "src/gone.rs"));
    }

    #[test]
    fn unmodeled_shape_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/a.rs", "unsafe trait T {}\n")]);
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(matches!(problems[0], Problem::UnrecognizedShape { .. }));
    }

    #[test]
    fn zero_count_file_needs_no_pin_and_pinned_zero_drifts() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/clean.rs", "fn clean() {}\n")]);
        assert!(check_tree(root, "").expect("check").is_empty());
        let pin = pin_line(
            "src/clean.rs",
            UnsafeCounts {
                blocks: 1,
                ..UnsafeCounts::default()
            },
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].describe().contains("-1 blocks"));
    }

    // ── end to end: generate → check round trip, then a witness drift ──

    #[test]
    fn generate_then_check_roundtrip_and_witnesses_drift() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[
                ("src/a.rs", "unsafe fn a() {}\n// unsafe { not counted }\n"),
                (
                    "src/deep/b.rs",
                    "let _ = unsafe { 1 };\nlet _ = unsafe { 2 };\n",
                ),
                ("src/clean.rs", "fn clean() {}\n"),
            ],
        );
        let pin = generate_pin(root).expect("generate");
        assert!(
            pin.contains("src/a.rs blocks=0 fns=1 impls=0 externs=0"),
            "{pin}"
        );
        assert!(
            pin.contains("src/deep/b.rs blocks=2 fns=0 impls=0 externs=0"),
            "{pin}"
        );
        assert!(
            !pin.contains("src/clean.rs"),
            "zero-count files are not pinned: {pin}"
        );
        assert!(check_tree(root, &pin).expect("check").is_empty());

        // Witness: one added unsafe block must turn the gate red, and the
        // message must name the file, the direction and the remedy.
        write_tree(
            root,
            &[(
                "src/deep/b.rs",
                "let _ = unsafe { 1 };\nlet _ = unsafe { 2 };\nlet _ = unsafe { 3 };\n",
            )],
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        let description = problems[0].describe();
        assert!(description.contains("src/deep/b.rs"), "{description}");
        assert!(description.contains("+1 blocks"), "{description}");
    }

    #[test]
    fn generate_refuses_an_empty_tree() {
        let tmp = TempDir::new().expect("tempdir");
        assert!(generate_pin(tmp.path()).is_err());
    }

    // ── lexer hardening ────────────────────────────────────────────────

    #[test]
    fn multiline_raw_string_swallows_forged_unsafe() {
        let source = "let s = r#\"first\nunsafe { forged }\n\"#;\nlet _ = unsafe { 1 };\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.blocks, 1);
    }

    #[test]
    fn char_literal_confusion_does_not_blank_code() {
        // A `'` that opens a lifetime (not a char literal) must not swallow
        // the following real unsafe block, and a real char literal holding
        // a quote must not desync the lexer.
        let source = "let p: &'static u8 = x;\nlet q = '\"';\nlet _ = unsafe { 1 };\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.blocks, 1);
    }

    #[test]
    fn unterminated_string_degrades_to_more_stripping() {
        let source = "let s = \"unsafe { forged";
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    #[test]
    fn unterminated_block_comment_degrades_to_more_stripping() {
        let source = "/* unsafe { forged";
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    #[test]
    fn unsafe_identifiers_are_not_counted() {
        let source = "let unsafe_fn = 1; fn my_unsafe_impl() {} let x = unsafeThings;";
        assert_eq!(count_unsafe_tokens(source), Ok(UnsafeCounts::default()));
    }

    // ── splice evasions: unsafe smuggled past an .rs-only census ───────

    #[test]
    fn hash_path_to_non_rs_file_is_censused() {
        // Witness (review case K): `#[path = "evil.txt"] mod evil;` is a
        // zero-token edit to a pinned .rs that compiles `evil.txt`'s
        // unsafe code. The census must see the .txt file itself.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[
                ("src/a.rs", "#[path = \"evil.txt\"]\nmod evil;\n"),
                (
                    "src/evil.txt",
                    "pub fn forged() { let _ = unsafe { 1 }; }\n",
                ),
            ],
        );
        let problems = check_tree(root, "").expect("check");
        // Both the spliced .txt AND the host .rs (which now carries an
        // unpinned `#[path]` splice site) must be flagged.
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, Problem::Unpinned { path, .. } if path == "src/evil.txt")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, Problem::Unpinned { path, .. } if path == "src/a.rs")),
            "{problems:?}"
        );
    }

    #[test]
    fn include_of_non_rs_file_is_censused() {
        // Witness (review case L): `include!("evil.txt");` splices the
        // file's tokens into the compile; an .rs-only census is blind.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[
                ("src/a.rs", "include!(\"evil.txt\");\n"),
                ("src/evil.txt", "unsafe impl Forged for () {}\n"),
            ],
        );
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, Problem::Unpinned { path, .. } if path == "src/evil.txt")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, Problem::Unpinned { path, .. } if path == "src/a.rs")),
            "{problems:?}"
        );
    }

    #[test]
    fn uppercase_rs_extension_is_censused() {
        // Witness (review case M): on a case-insensitive filesystem
        // rustc resolves `mod evil;` to `evil.RS` just the same, so the
        // extension check must be case-insensitive.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/evil.RS", "let _ = unsafe { 1 };\n")]);
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            matches!(&problems[0], Problem::Unpinned { path, .. } if path == "src/evil.RS"),
            "{problems:?}"
        );
    }

    // ── splice-site pinning: the target is never parsed ────────────────
    //
    // Each test here is an evasion that slips past BOTH the census of
    // unsafe tokens (the spliced payload lives outside third_party/ or
    // not at all) and the raw-source out-of-root check (which reads only
    // the first chars of the target literal). The structural pin fails
    // the gate on the SITE, whatever the target spells.

    fn has_unpinned(problems: &[Problem], path: &str) -> bool {
        problems
            .iter()
            .any(|p| matches!(p, Problem::Unpinned { path: p2, .. } if p2 == path))
    }

    #[test]
    fn non_leading_parent_escape_is_pinned_as_a_splice_site() {
        // Evasion: `..` is not the leading segment, so the raw-source
        // out-of-root check never sees it; the target resolves outside
        // third_party/. The `#[path]` SITE itself is counted instead.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[(
                "src/a.rs",
                "#[path = \"sub/../../../outside.rs\"]\nmod x;\n",
            )],
        );
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(has_unpinned(&problems, "src/a.rs"), "{problems:?}");
        // And the census names the splice count, not just the file.
        assert!(
            problems[0].describe().contains("path_attrs=1"),
            "{}",
            problems[0].describe()
        );
    }

    #[test]
    fn computed_include_target_is_refused_outright() {
        // Evasion: the target is computed (concat!/env!/OUT_DIR!), so
        // its content is resolved at build time and no source census can
        // see it — the build script decides what is spliced. The gate
        // must refuse the shape, not merely pin the site.
        let err = count_unsafe_tokens("include!(concat!(\"..\", \"/x.rs\"));")
            .expect_err("computed target must fail");
        assert!(err.after.contains("computed `include!` target"), "{err}");
        let err = count_unsafe_tokens("include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));")
            .expect_err("OUT_DIR target must fail");
        assert!(err.after.contains("computed `include!` target"), "{err}");
        let err = count_unsafe_tokens("include!(some_path());").expect_err("expr target must fail");
        assert!(err.after.contains("computed `include!` target"), "{err}");
    }

    #[test]
    fn literal_include_targets_still_pass_the_raw_source_check() {
        // Plain and raw-string literal targets are legal shapes (the
        // site is pinned; the target's first chars are still checked
        // against absolute/`..` escapes).
        let counts = count_unsafe_tokens("include!(\"sub/x.txt\");\ninclude!(r\"y.txt\");")
            .expect("literal targets pass");
        assert_eq!(counts.includes, 2);
    }

    #[test]
    fn raw_string_path_target_is_pinned_as_a_splice_site() {
        // Evasion: the target is a raw string `r".."`, so the `= "` scan
        // of the raw-source check never matches. The `#[path]` SITE is
        // counted.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/a.rs", "#[path = r\"../x.rs\"]\nmod x;\n")]);
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(has_unpinned(&problems, "src/a.rs"), "{problems:?}");
    }

    #[test]
    fn parameterized_macro_alias_is_refused_not_merely_pinned() {
        // Evasion: a macro alias hides the splice behind a harmless
        // name and can be CALLED from another file, where the use site
        // has no countable token. The definition body's `include!($p)`
        // has a computed argument, so the gate refuses the definition
        // outright — such an alias can never be pinned and called.
        let err = count_unsafe_tokens("macro_rules! splice { ($p:expr) => { include!($p) } }\n")
            .expect_err("parameterized alias must fail");
        assert!(err.after.contains("computed `include!` target"), "{err}");
    }

    #[test]
    fn literal_target_macro_alias_is_pinned_at_the_definition_site() {
        // A NON-parameterized alias with a literal in-root target is
        // harmless (the target file is censused) and its definition
        // site is pinned: the body's real `include!` tokens count.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[(
                "src/a.rs",
                "macro_rules! splice { () => { include!(\"inside.txt\") } }\n",
            )],
        );
        let problems = check_tree(root, "").expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(has_unpinned(&problems, "src/a.rs"), "{problems:?}");
        assert!(
            problems[0].describe().contains("includes=1"),
            "{}",
            problems[0].describe()
        );
    }

    #[test]
    fn cfg_attr_wrapped_path_attr_is_counted_as_a_site() {
        // Evasion (final review case 1): `#[cfg_attr(unix, path =
        // "x.rs")]` never spells `#[path` — the wrapped attribute only
        // materializes when the condition is true — so the cfg_attr
        // TOKEN itself is the pinned site, active or not.
        let source = "\
#[cfg_attr(unix, path = \"darwin.rs\")]
mod a;
#[cfg_attr(any(), path = \"never.rs\")]
mod b;
# [ cfg_attr(unix, path = \"spaced.rs\") ]
mod c;
";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.cfg_attrs, 3);
        assert_eq!(counts.path_attrs, 0);
        assert_eq!(counts.total(), 3);
    }

    #[test]
    fn cfg_attr_added_to_a_pinned_file_drifts_the_pin() {
        // The final-review attack: a zero-unsafe-token edit to a pinned
        // file adds a cfg_attr-wrapped out-of-root splice. The cfg_attrs
        // column must drift.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/a.rs", "let _ = unsafe { 1 };\n")]);
        let pin = generate_pin(root).expect("generate");
        assert!(pin.contains("cfg_attrs=0"), "{pin}");
        assert!(check_tree(root, &pin).expect("check").is_empty());
        write_tree(
            root,
            &[(
                "src/a.rs",
                "let _ = unsafe { 1 };\n#[cfg_attr(unix, path = \"../../../outside.rs\")]\nmod evil;\n",
            )],
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        let description = problems[0].describe();
        assert!(description.contains("+1 cfg_attrs"), "{description}");
    }

    #[test]
    fn cfg_attr_in_a_comment_or_string_does_not_count() {
        let source = "// #[cfg_attr(unix, path = \"x.rs\")] in prose\n\
                      /* cfg_attr */\n\
                      let s = \"#[cfg_attr(unix, path = \\\"y.rs\\\")]\";\n\
                      let t = r\"cfg_attr\";\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.cfg_attrs, 0);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn cfg_attr_identifier_near_misses_count_over_not_under() {
        // A plain identifier or longer name may OVER-count (`cfg_attr`
        // as a binding, `cfg_attrs` is a different word and does not):
        // for a drift pin over-counting is the safe direction, under-
        // counting never happens.
        let source = "let cfg_attr = 1;\nlet cfg_attrs = 2;\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.cfg_attrs, 1);
    }

    #[test]
    fn splice_added_to_a_pinned_file_drifts_the_pin() {
        // A MOVED splice: the file was clean and pinned; adding one
        // `include!` changes includes=0 → 1 and must fail even though
        // the unsafe counts are unchanged.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(root, &[("src/a.rs", "let _ = unsafe { 1 };\n")]);
        let pin = generate_pin(root).expect("generate");
        assert!(pin.contains("includes=0 path_attrs=0"), "{pin}");
        assert!(check_tree(root, &pin).expect("check").is_empty());
        write_tree(
            root,
            &[(
                "src/a.rs",
                "let _ = unsafe { 1 };\ninclude!(\"extra.txt\");\n",
            )],
        );
        let problems = check_tree(root, &pin).expect("check");
        assert_eq!(problems.len(), 1, "{problems:?}");
        let description = problems[0].describe();
        assert!(description.contains("+1 includes"), "{description}");
        assert!(
            description.contains("new unreviewed unsafe code or splice site"),
            "{description}"
        );
    }

    #[test]
    fn generate_pins_splice_sites_alongside_unsafe_counts() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[
                (
                    "src/a.rs",
                    "#[path = \"b.txt\"]\nmod b;\ninclude!(\"c.txt\");\n",
                ),
                // A file with ONLY splice sites (no unsafe) still needs a
                // pin line: moving the splice must drift.
                ("src/only_splice.rs", "core::include!(\"d.txt\");\n"),
                // Comments and strings never count. (The comment spells
                // only literal-target shapes: the raw-source scan refuses
                // a computed `include!(` spelling even in prose — the
                // safe direction.)
                (
                    "src/prose.rs",
                    "// include!(\"x\") and #[path = \"y\"] in prose\n// let s = \"include_str!(\\\"z\\\")\";\nfn clean() {}\n",
                ),
            ],
        );
        let pin = generate_pin(root).expect("generate");
        assert!(
            pin.contains("src/a.rs blocks=0 fns=0 impls=0 externs=0 includes=1 path_attrs=1"),
            "{pin}"
        );
        assert!(
            pin.contains(
                "src/only_splice.rs blocks=0 fns=0 impls=0 externs=0 includes=1 path_attrs=0"
            ),
            "{pin}"
        );
        assert!(
            !pin.contains("src/prose.rs"),
            "prose mentioning splices is not pinned: {pin}"
        );
        assert!(check_tree(root, &pin).expect("check").is_empty());
    }

    #[test]
    fn whitespace_and_path_qualified_splice_variants_are_counted() {
        let source = "\
# [ path = \"a.rs\" ]
mod a;
#![path = \"b.rs\" ]
# ! [ path = \"c.rs\" ]
mod c;
include ! (\"d.txt\");
let _ = core::include!(\"e.txt\");
let _ = ::std::include !(\"f.txt\");
#[path_attr_that_is_not_path]
#[patch = \"nope\"]
";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.path_attrs, 3);
        assert_eq!(counts.includes, 3);
    }

    #[test]
    fn comments_and_strings_mentioning_splices_do_not_count() {
        // NOTE: the raw-source out-of-root/computed-target scan sees
        // string contents, so a string spelling `include!(` with a
        // non-literal argument would refuse (safe direction); these
        // fixtures spell only literal-target shapes and must count 0.
        let source = "// include!(\"x.rs\") in a comment\n\
                      /// #[path = \"y.rs\"] in a doc comment\n\
                      /* include !(\"z\") block */\n\
                      let s = \"include_str!(\\\"forged.rs\\\")\";\n\
                      let t = r\"#[path = \\\"raw\\\"]\";\n\
                      let u = \"# [path]\";\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.includes, 0);
        assert_eq!(counts.path_attrs, 0);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn include_identifiers_are_not_splice_counts() {
        // `include_something!`, `includes!`, `my_include!` and the word
        // `path` in identifiers are not splice sites.
        let source = "\
macro_rules! includes { () => {} }
includes!();
let include_this = 1;
let path_attr = 2;
struct Loader { path: String }
#[doc = \"path\"]
fn f() {}
";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.includes, 0);
        assert_eq!(counts.path_attrs, 0);
    }

    #[test]
    fn absolute_hash_path_fails_closed() {
        let err =
            count_unsafe_tokens("#[path = \"/etc/evil.rs\"]\nmod evil;").expect_err("must fail");
        assert!(err.after.contains("outside third_party/"), "{err}");
    }

    #[test]
    fn absolute_include_fails_closed() {
        let err = count_unsafe_tokens("include!(\"/etc/evil.rs\");").expect_err("must fail");
        assert!(err.after.contains("outside third_party/"), "{err}");
    }

    #[test]
    fn parent_escaping_splices_fail_closed() {
        assert!(count_unsafe_tokens("#[path = \"../../evil.rs\"]\nmod evil;").is_err());
        assert!(count_unsafe_tokens("include!(\"../evil.txt\");").is_err());
    }

    #[test]
    fn relative_in_root_splices_are_counted_not_refused() {
        // In-root splices are legal (the target file is censused), but
        // their SITES are pinned: they show up in the census and any
        // change to them drifts the pin.
        let source = "#[path = \"evil.txt\"]\nmod evil;\ninclude!(\"sub/dir.txt\");\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts.path_attrs, 1);
        assert_eq!(counts.includes, 1);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn include_str_and_include_bytes_are_not_splice_shapes() {
        // They yield data (a &str / &[u8]), not tokens: they can never
        // introduce unsafe code, so they are not splice sites and are
        // not counted (a `..`-escaping include_str! target is not an
        // escape from the census — its content is never compiled).
        let source = "const A: &str = include_str!(\"../x.txt\");\nconst B: &[u8] = include_bytes!(\"../y.bin\");\n";
        let counts = count_unsafe_tokens(source).expect("counts");
        assert_eq!(counts, UnsafeCounts::default());
        assert_eq!(counts.includes, 0);
        assert_eq!(counts.path_attrs, 0);
    }

    #[test]
    fn pin_file_itself_is_not_censused() {
        // The pin's own prose carries `unsafe` in comments; it is data,
        // policed by parse + StalePin/Unpinned, not by the census.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        write_tree(
            root,
            &[(
                "UNSAFE_COUNTS.pinned",
                "# counts of `unsafe` usage\nunsafe trait in prose\n",
            )],
        );
        assert!(check_tree(root, "").expect("check").is_empty());
    }

    #[test]
    fn non_utf8_rs_file_fails_the_gate() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        let path = root.join("src/binary.rs");
        fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        fs::write(&path, [0x66, 0x6e, 0xff, 0xfe]).expect("write");
        let err = check_tree(root, "").expect_err("non-UTF-8 .rs must fail");
        assert!(err.contains("failed to read src/binary.rs"), "{err}");
    }

    #[test]
    fn non_utf8_non_rs_file_is_skipped() {
        // Invalid UTF-8 cannot be spliced as Rust tokens, so a non-.rs
        // binary must not wedge the gate.
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();
        let path = root.join("src/blob.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        fs::write(&path, [0xff, 0xfe, 0x00, 0x01]).expect("write");
        assert!(check_tree(root, "").expect("check").is_empty());
    }
}

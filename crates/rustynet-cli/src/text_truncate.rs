//! Character-boundary-safe clipping for evidence and diagnostic text.
//!
//! Rust panics when a `&str` is sliced — or a `String` truncated — at a byte
//! offset that falls inside a multi-byte character. Every clipping site that
//! uses these helpers operates on text that arrived from outside the process:
//! subprocess stdout/stderr, a stage log file, a report JSON parsed off disk.
//! A non-ASCII character straddling the limit is therefore ordinary input, not
//! a pathological one, and the panic lands on exactly the paths that exist to
//! explain a failure — destroying the diagnostic at the moment it is needed.
//!
//! These exist so no call site has to remember the rule: clip through them and
//! the offset is walked back to a boundary first. Limits stay measured in
//! **bytes**, matching the `len()`-based limits the call sites already used —
//! the defect is the missing boundary walk, not the choice of unit, and
//! changing the unit here would silently reshape existing evidence output.
//!
//! `vm_lab::capability::sanitize_capability_message` performs the same walk
//! inline. It is not routed through here because it lives in the library crate
//! while these helpers serve the binary's `ops_*` modules; it is already
//! correct, so this is duplication of two lines, not of a defect.

/// Largest character-boundary offset at or below `index`.
///
/// Saturates at `text.len()` so an over-long limit is a no-op rather than an
/// out-of-range slice, and terminates at `0` in the worst case because
/// `is_char_boundary(0)` is always true. (`str::floor_char_boundary` is still
/// unstable, hence the hand-rolled walk.)
pub(crate) fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut boundary = index.min(text.len());
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}

/// `&text[..max_len]`, but clipped back to a character boundary first.
pub(crate) fn clip_str(text: &str, max_len: usize) -> &str {
    &text[..floor_char_boundary(text, max_len)]
}

/// [`String::truncate`], but clipped back to a character boundary first.
///
/// A drop-in replacement at any site whose length limit is a budget rather
/// than a boundary offset discovered by searching the text.
pub(crate) fn truncate_string_at_char_boundary(text: &mut String, max_len: usize) {
    let boundary = floor_char_boundary(text.as_str(), max_len);
    text.truncate(boundary);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 4-byte character exercises every possible misalignment against a cut
    /// offset: three interior bytes plus the boundary itself.
    #[test]
    fn floor_char_boundary_walks_back_out_of_every_multi_byte_position() {
        let text = format!("{}\u{1F600}{}", "a".repeat(8), "b".repeat(4));
        // The wide character occupies bytes 8..12.
        assert_eq!(floor_char_boundary(&text, 8), 8, "already a boundary");
        for interior in 9..12 {
            assert_eq!(
                floor_char_boundary(&text, interior),
                8,
                "offset {interior} is inside the wide character"
            );
        }
        assert_eq!(floor_char_boundary(&text, 12), 12, "boundary after it");
    }

    #[test]
    fn floor_char_boundary_saturates_instead_of_going_out_of_range() {
        let text = "\u{1F600}";
        assert_eq!(floor_char_boundary(text, usize::MAX), text.len());
        assert_eq!(floor_char_boundary(text, 0), 0);
        assert_eq!(floor_char_boundary("", 5), 0);
    }

    /// The whole point: these must not panic where the raw operations do.
    #[test]
    fn clip_and_truncate_never_split_a_character() {
        let text = format!("{}\u{2192}{}", "a".repeat(3), "b".repeat(3));
        // The 3-byte arrow occupies bytes 3..6, so 4 and 5 are interior.
        for interior in [4usize, 5] {
            assert!(
                !text.is_char_boundary(interior),
                "fixture must actually straddle {interior}"
            );
            assert_eq!(clip_str(&text, interior), "aaa");
            let mut owned = text.clone();
            truncate_string_at_char_boundary(&mut owned, interior);
            assert_eq!(owned, "aaa");
        }
    }

    #[test]
    fn ascii_behaviour_is_byte_exact() {
        assert_eq!(clip_str("abcdef", 4), "abcd");
        let mut owned = "abcdef".to_owned();
        truncate_string_at_char_boundary(&mut owned, 4);
        assert_eq!(owned, "abcd");
    }
}

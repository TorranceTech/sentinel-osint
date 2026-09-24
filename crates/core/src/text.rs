//! Sanitization of text that may contain external data.
//!
//! External strings (DNS TXT records, API error texts, certificate names)
//! can contain terminal escape sequences, newlines that forge log lines, or
//! bidirectional overrides that visually reorder text. Anything that may
//! carry such data is passed through [`sanitize_single_line`] before it is
//! displayed or stored as free text.

/// Replacement for removed characters.
pub const REPLACEMENT: char = '\u{FFFD}';

/// Returns `input` as a single, safe line of at most `max_chars` characters:
///
/// - control characters (C0 including `\n`, `\r`, `\t` and ESC; DEL; C1) are
///   replaced with U+FFFD;
/// - bidirectional controls and invisible format characters (U+200B–U+200F,
///   U+202A–U+202E, U+2060–U+2069, U+FEFF) are replaced with U+FFFD;
/// - if the text is longer than `max_chars`, it is truncated and ends with `…`.
#[must_use]
pub fn sanitize_single_line(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(input.len().min(max_chars * 4));
    for (count, c) in input.chars().enumerate() {
        if count + 1 == max_chars && input.chars().nth(max_chars).is_some() {
            out.push('…');
            break;
        }
        out.push(if is_unsafe(c) { REPLACEMENT } else { c });
    }
    out
}

/// Whether a character must not be shown verbatim.
#[must_use]
pub const fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_ordinary_text() {
        assert_eq!(
            sanitize_single_line("hello, wörld 日本", 100),
            "hello, wörld 日本"
        );
    }

    #[test]
    fn replaces_control_and_bidi_characters() {
        assert_eq!(
            sanitize_single_line("a\u{1b}[31mb\nc\rd\te\u{7f}f\u{9b}g", 100),
            "a\u{FFFD}[31mb\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f\u{FFFD}g"
        );
        assert_eq!(
            sanitize_single_line("evil\u{202E}txt.exe", 100),
            "evil\u{FFFD}txt.exe"
        );
        assert_eq!(
            sanitize_single_line("zero\u{200B}width", 100),
            "zero\u{FFFD}width"
        );
    }

    #[test]
    fn truncates_by_characters_not_bytes() {
        assert_eq!(sanitize_single_line("abcdef", 4), "abc…");
        assert_eq!(sanitize_single_line("abcd", 4), "abcd");
        assert_eq!(sanitize_single_line("ééééé", 3), "éé…");
        assert_eq!(sanitize_single_line("abc", 0), "");
    }
}

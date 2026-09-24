//! Data source implementations.
//!
//! Every source is documented in `docs/DATA-SOURCES.md` with its capability
//! level before it is implemented.

mod abusech;
pub mod abuseipdb;
mod api_key;
pub mod ct;
pub mod cymru;
pub mod dns;
pub mod malwarebazaar;
pub mod rdap;
pub mod urlhaus;
pub mod virustotal;

#[cfg(test)]
mod integration_tests;

/// Truncates `text` to at most `max_chars` characters (never splitting a
/// character). Returns the kept text and whether anything was cut.
pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((end, _)) => (text[..end].to_owned(), true),
        None => (text.to_owned(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_chars;

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate_chars("abcdef", 3), ("abc".to_owned(), true));
        assert_eq!(truncate_chars("ééé", 2), ("éé".to_owned(), true));
        assert_eq!(truncate_chars("abc", 3), ("abc".to_owned(), false));
        assert_eq!(truncate_chars("", 0), (String::new(), false));
    }
}

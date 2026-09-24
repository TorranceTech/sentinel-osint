//! Refanging of "defanged" indicators.
//!
//! Threat reports routinely defang indicators so they cannot be clicked or
//! resolved by accident: `evil[.]com`, `hxxps://evil[.]com/x`, `1.2.3[.]4`.
//! Analysts paste these straight from reports, so input is refanged before
//! validation.

/// Defanged notations that stand for a dot.
const DOT_NOTATIONS: [&str; 6] = ["[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}"];

/// Converts common defanged notations back to their original form.
///
/// Handles bracketed dots (`[.]`, `(.)`, `{.}`, `[dot]`, …, case-insensitive),
/// `[:]`, `[://]`, `[@]`, and the `hxxp`/`hxxps` scheme prefix.
///
/// ```
/// use sentinel_core::indicator::refang;
/// assert_eq!(refang("hxxps://evil[.]example[DOT]com/x"), "https://evil.example.com/x");
/// ```
#[must_use]
pub fn refang(input: &str) -> String {
    let mut out = input.to_owned();
    for notation in DOT_NOTATIONS {
        out = replace_ascii_case_insensitive(&out, notation, ".");
    }
    out = out
        .replace("[://]", "://")
        .replace("[:]", ":")
        .replace("[@]", "@");

    let lower_prefix = out.get(..4).map(str::to_ascii_lowercase);
    if lower_prefix.as_deref() == Some("hxxp") {
        out.replace_range(..4, "http");
    }
    out
}

/// Replaces every occurrence of an ASCII `needle`, ignoring ASCII case.
fn replace_ascii_case_insensitive(haystack: &str, needle: &str, replacement: &str) -> String {
    // ASCII lowercasing keeps every byte offset unchanged, so offsets found in
    // `lower` are valid char boundaries in `haystack`.
    let lower = haystack.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0;
    for (idx, matched) in lower.match_indices(needle) {
        out.push_str(&haystack[last..idx]);
        out.push_str(replacement);
        last = idx + matched.len();
    }
    out.push_str(&haystack[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::refang;

    #[test]
    fn refangs_common_notations() {
        let cases = [
            ("evil[.]com", "evil.com"),
            ("evil(.)com", "evil.com"),
            ("evil{.}com", "evil.com"),
            ("evil[dot]com", "evil.com"),
            ("evil[DOT]com", "evil.com"),
            ("1.2.3[.]4", "1.2.3.4"),
            ("hxxp://evil[.]com", "http://evil.com"),
            // Scheme case is normalized later by the URL parser.
            ("HXXPS[://]evil[.]com/a", "httpS://evil.com/a"),
            ("hxxps[:]//evil.com", "https://evil.com"),
            ("user[@]evil.com", "user@evil.com"),
        ];
        for (input, expected) in cases {
            assert_eq!(refang(input), expected, "{input}");
        }
    }

    #[test]
    fn leaves_normal_input_untouched() {
        assert_eq!(refang("example.com"), "example.com");
        assert_eq!(
            refang("https://example.com/hxxp"),
            "https://example.com/hxxp"
        );
    }

    #[test]
    fn handles_non_ascii_input() {
        assert_eq!(refang("bücher[.]de"), "bücher.de");
        assert_eq!(refang("日本"), "日本");
    }
}

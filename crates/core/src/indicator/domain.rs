//! Domain names.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::IndicatorError;

/// Special-use and non-public suffixes (RFC 6761, RFC 6762, RFC 8375, RFC 9476,
/// ICANN `.internal`). Names under these suffixes are syntactically valid,
/// but public sources cannot describe them, so they are rejected as
/// investigation targets. They may still appear as *related* entities, for
/// example an MX record pointing at `mail.corp.internal`.
const SPECIAL_USE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "invalid",
    "test",
    "example",
    "onion",
    "alt",
    "lan",
    "home.arpa",
    "arpa",
];

/// A validated, normalized DNS domain name.
///
/// Normalization:
/// - surrounding whitespace and a single trailing dot are removed;
/// - internationalized names are converted to ASCII (IDNA / punycode), which
///   also lowercases them: `Bücher.DE` → `xn--bcher-kva.de`.
///
/// Validation:
/// - at most 253 characters in total and 63 per label, no empty labels;
/// - labels contain only `a-z`, `0-9`, `-` and `_`, and don't start or end
///   with `-` (underscores are allowed because they are common in real DNS,
///   e.g. `_dmarc.example.com`);
/// - at least two labels, and a non-numeric top-level label;
/// - IP addresses, URLs and `host:port` are rejected with a specific error.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DomainName(String);

impl DomainName {
    /// Maximum length of a domain name in presentation format.
    pub const MAX_LENGTH: usize = 253;
    /// Maximum length of a single label.
    pub const MAX_LABEL_LENGTH: usize = 63;

    /// Parses and normalizes a domain name.
    ///
    /// # Errors
    /// Returns an [`IndicatorError`] describing why the input is not a valid
    /// domain name.
    pub fn parse(input: &str) -> Result<Self, IndicatorError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(IndicatorError::Empty);
        }
        if s.len() > Self::MAX_LENGTH + 1 {
            return Err(IndicatorError::InvalidDomain("exceeds 253 characters"));
        }
        if s.trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok()
        {
            return Err(IndicatorError::DomainIsIpAddress);
        }
        if s.contains("://") || s.contains(['/', '?', '#', '@', ':']) {
            return Err(IndicatorError::DomainLooksLikeUrl);
        }

        let s = s.strip_suffix('.').unwrap_or(s);
        let ascii = idna::domain_to_ascii(s).map_err(|_| {
            IndicatorError::InvalidDomain("not a valid (internationalized) domain name")
        })?;
        validate_ascii(&ascii).map_err(IndicatorError::InvalidDomain)?;
        Ok(Self(ascii))
    }

    /// The normalized name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The labels of the name, from left to right.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// Whether `self` is a strict subdomain of `parent`, respecting label
    /// boundaries: `www.example.com` is a subdomain of `example.com`;
    /// `evil-example.com` and `example.com.evil.test` are not, and a name is
    /// not a subdomain of itself.
    #[must_use]
    pub fn is_subdomain_of(&self, parent: &Self) -> bool {
        self.0
            .strip_suffix(parent.as_str())
            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
    }

    /// Whether the name is under a special-use or non-public suffix such as
    /// `.local`, `.internal`, `.onion` or `.home.arpa`.
    #[must_use]
    pub fn is_special_use(&self) -> bool {
        SPECIAL_USE_SUFFIXES.iter().any(|suffix| {
            self.0 == *suffix
                || self
                    .0
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

fn validate_ascii(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    if name.len() > DomainName::MAX_LENGTH {
        return Err("exceeds 253 characters");
    }

    let mut label_count = 0usize;
    let mut last_label = "";
    for label in name.split('.') {
        label_count += 1;
        if label.is_empty() {
            return Err("contains an empty label");
        }
        if label.len() > DomainName::MAX_LABEL_LENGTH {
            return Err("contains a label longer than 63 characters");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err("contains characters that are not allowed in a domain name");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("contains a label that starts or ends with a hyphen");
        }
        last_label = label;
    }

    if label_count < 2 {
        return Err("must have at least two labels (e.g. example.com)");
    }
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return Err("top-level label cannot be numeric");
    }
    Ok(())
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DomainName {
    type Error = IndicatorError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<DomainName> for String {
    fn from(value: DomainName) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> String {
        DomainName::parse(input)
            .unwrap_or_else(|e| panic!("{input:?} should be valid: {e}"))
            .to_string()
    }

    #[test]
    fn normalizes_valid_names() {
        assert_eq!(ok("example.com"), "example.com");
        assert_eq!(ok("  Example.COM.  "), "example.com");
        assert_eq!(ok("sub.domain.example.co.uk"), "sub.domain.example.co.uk");
        assert_eq!(ok("_dmarc.example.com"), "_dmarc.example.com");
        assert_eq!(ok("xn--bcher-kva.de"), "xn--bcher-kva.de");
        assert_eq!(ok("a-b.example"), "a-b.example");
    }

    #[test]
    fn converts_internationalized_names_to_ascii() {
        assert_eq!(ok("Bücher.de"), "xn--bcher-kva.de");
        assert_eq!(ok("例え.jp"), "xn--r8jz45g.jp");
    }

    #[test]
    fn rejects_ip_addresses_and_urls_with_specific_errors() {
        assert_eq!(
            DomainName::parse("8.8.8.8"),
            Err(IndicatorError::DomainIsIpAddress)
        );
        assert_eq!(
            DomainName::parse("[2001:db8::1]"),
            Err(IndicatorError::DomainIsIpAddress)
        );
        for input in [
            "https://example.com",
            "example.com/path",
            "example.com:443",
            "user@example.com",
            "example.com?q=1",
        ] {
            assert_eq!(
                DomainName::parse(input),
                Err(IndicatorError::DomainLooksLikeUrl),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_names() {
        let long_label = format!("{}.com", "a".repeat(64));
        let long_name = format!("{}.com", ["abcdefghij"; 25].join("."));
        let cases = [
            "",
            "   ",
            "localhost",
            "com",
            "example..com",
            ".example.com",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "exa$mple.com",
            "example.123",
            "1.2.3.999",
            "xn--.com",
            "example.com..",
            &long_label,
            &long_name,
        ];
        for input in cases {
            assert!(
                DomainName::parse(input).is_err(),
                "{input:?} should be invalid"
            );
        }
    }

    #[test]
    fn rejects_control_and_bidi_characters() {
        for input in [
            "exa\u{0}mple.com",
            "exa\u{1b}[31mmple.com",
            "exa\u{202e}mple.com",
        ] {
            assert!(
                DomainName::parse(input).is_err(),
                "{input:?} should be invalid"
            );
        }
    }

    #[test]
    fn detects_special_use_names() {
        for name in [
            "printer.local",
            "db.corp.internal",
            "foo.test",
            "abcdef.onion",
            "router.home.arpa",
            "4.3.2.1.in-addr.arpa",
            "my.example",
        ] {
            assert!(ok_domain(name).is_special_use(), "{name}");
        }
        for name in ["example.com", "local.com", "notlocal.org", "testing.io"] {
            assert!(!ok_domain(name).is_special_use(), "{name}");
        }
    }

    #[test]
    fn subdomain_checks_respect_label_boundaries() {
        let parent = ok_domain("example.com");
        for child in ["www.example.com", "a.b.example.com", "_dmarc.example.com"] {
            assert!(ok_domain(child).is_subdomain_of(&parent), "{child}");
        }
        for other in [
            "example.com",
            "evil-example.com",
            "testexample.com",
            "m.testexample.com",
            "example.com.evil.test",
            "example.com.attacker.test",
            "example.co",
            "com",
        ] {
            let Ok(other) = DomainName::parse(other) else {
                continue;
            };
            assert!(!other.is_subdomain_of(&parent), "{other}");
        }
    }

    fn ok_domain(input: &str) -> DomainName {
        DomainName::parse(input).unwrap()
    }
}

//! Certificate Transparency observations.
//!
//! A CT observation states what a CT source reported about one certificate:
//! the names it lists, its validity dates and its issuer. It is **not**
//! evidence that a name resolves, that a host is online or reachable, that
//! the certificate is deployed, or that anyone controls the name.
//!
//! Names are classified relative to the investigated domain with
//! [`classify_certificate_name`]. The raw name is kept next to the
//! normalized form. Malformed names are recorded as invalid, never repaired.

use serde::Serialize;

use crate::indicator::DomainName;
use crate::time::Timestamp;

/// Maximum characters of a raw certificate name that are kept.
pub const MAX_RAW_NAME_CHARS: usize = 256;

/// How a certificate name relates to the investigated domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameRelation {
    /// Exactly the investigated domain.
    Exact,
    /// `*.<investigated domain>`.
    Wildcard,
    /// A name under the investigated domain (possibly itself a wildcard,
    /// e.g. `*.api.example.com`).
    Subdomain,
    /// A valid DNS name outside the investigated domain (multi-domain
    /// certificates, look-alikes such as `example.com.evil.test`).
    Unrelated,
    /// Not a valid DNS name or wildcard pattern.
    Invalid,
}

impl NameRelation {
    /// Whether the name belongs to the investigated domain.
    #[must_use]
    pub const fn is_related(self) -> bool {
        matches!(self, Self::Exact | Self::Wildcard | Self::Subdomain)
    }
}

/// One name listed in a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificateName {
    /// The name as the source reported it (bounded).
    pub raw: String,
    /// The normalized DNS name without the `*.` wildcard label, if the name
    /// is a valid DNS name or wildcard.
    pub normalized: Option<DomainName>,
    /// Whether the name is a wildcard (`*.` prefix).
    pub wildcard: bool,
    /// Relation to the investigated domain.
    pub relation: NameRelation,
}

impl CertificateName {
    /// Presentation form: `*.example.com`, `www.example.com`, or the raw value
    /// for invalid names.
    #[must_use]
    pub fn display_name(&self) -> String {
        match (&self.normalized, self.wildcard) {
            (Some(name), true) => format!("*.{name}"),
            (Some(name), false) => name.to_string(),
            (None, _) => self.raw.clone(),
        }
    }
}

/// Classifies a certificate name against the investigated `target` domain.
///
/// Rules (applied after trimming spaces and removing one trailing dot):
/// - any control character (CR, LF, ESC, …) makes the name invalid;
/// - a single leading `*.` makes the name a wildcard. A `*` anywhere else
///   (`*example.com`, `a.*.example.com`, `*.*.example.com`) is invalid;
/// - the rest must be a valid domain name ([`DomainName::parse`]: IDNA, case
///   and label rules, no control characters);
/// - relation: equal to the target → `Exact` (or `Wildcard` for
///   `*.target`); a subdomain by label boundary → `Subdomain`; any other
///   valid name → `Unrelated`.
#[must_use]
pub fn classify_certificate_name(raw: &str, target: &DomainName) -> CertificateName {
    let kept: String = raw.chars().take(MAX_RAW_NAME_CHARS).collect();
    let invalid = || CertificateName {
        raw: kept.clone(),
        normalized: None,
        wildcard: false,
        relation: NameRelation::Invalid,
    };

    // Control characters (CR, LF, ESC, …) anywhere make the name invalid:
    // they are never trimmed away or "repaired".
    if raw.chars().any(char::is_control) {
        return invalid();
    }
    let trimmed = raw.trim_matches(' ');
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let (wildcard, rest) = match trimmed.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    // Also reject trailing-dot tricks such as "example.com.." and any
    // remaining wildcard characters.
    if rest.contains('*') || rest.ends_with('.') || raw.len() > 4 * MAX_RAW_NAME_CHARS {
        return invalid();
    }
    let Ok(name) = DomainName::parse(rest) else {
        return invalid();
    };

    let relation = if name == *target {
        if wildcard {
            NameRelation::Wildcard
        } else {
            NameRelation::Exact
        }
    } else if name.is_subdomain_of(target) {
        NameRelation::Subdomain
    } else {
        NameRelation::Unrelated
    };
    CertificateName {
        raw: kept,
        normalized: Some(name),
        wildcard,
        relation,
    }
}

/// A certificate as reported by a CT source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CtCertificate {
    /// The source's identifier of the log entry, e.g. crt.sh ID. This is
    /// **not** a certificate fingerprint.
    pub source_entry_id: Option<u64>,
    /// Serial number (lowercase hex), as reported. Only unique together
    /// with the issuer.
    pub serial_number: Option<String>,
    /// Issuer distinguished name, as reported (bounded).
    pub issuer: Option<String>,
    /// Subject common name, as reported (bounded).
    pub common_name: Option<String>,
    /// Start of validity.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub not_before: Option<Timestamp>,
    /// End of validity.
    #[serde(serialize_with = "crate::time::serialize_opt")]
    pub not_after: Option<Timestamp>,
    /// Names listed in the certificate (bounded), classified.
    pub names: Vec<CertificateName>,
    /// Email-address identities present in the certificate, counted but not
    /// stored (personal data).
    pub omitted_email_names: u32,
    /// How many source entries were merged into this certificate (for
    /// example precertificate and final certificate with the same issuer and
    /// serial).
    pub source_entries: u32,
    /// Problems with the record (fixed descriptions).
    pub issues: Vec<String>,
}

impl CtCertificate {
    /// Whether the certificate's validity ended before `now`.
    #[must_use]
    pub fn is_expired_at(&self, now: Timestamp) -> bool {
        self.not_after.is_some_and(|end| end < now)
    }

    /// Whether the certificate's validity starts after `now`.
    #[must_use]
    pub fn is_not_yet_valid_at(&self, now: Timestamp) -> bool {
        self.not_before.is_some_and(|start| start > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> DomainName {
        DomainName::parse("example.com").unwrap()
    }

    fn relation(raw: &str) -> NameRelation {
        classify_certificate_name(raw, &target()).relation
    }

    #[test]
    fn related_names() {
        assert_eq!(relation("example.com"), NameRelation::Exact);
        assert_eq!(relation("www.example.com"), NameRelation::Subdomain);
        assert_eq!(relation("api.example.com"), NameRelation::Subdomain);
        assert_eq!(relation("*.example.com"), NameRelation::Wildcard);
        assert_eq!(relation("*.api.example.com"), NameRelation::Subdomain);
    }

    #[test]
    fn boundary_confusion_is_unrelated() {
        for name in [
            "example.com.evil.test",
            "evil-example.com",
            "example.com.attacker.test",
            "m.testexample.com",
            "testexample.com",
            "example.co",
            "*.evil-example.com",
        ] {
            assert_eq!(relation(name), NameRelation::Unrelated, "{name}");
        }
    }

    #[test]
    fn normalization_trailing_dots_case_and_idna() {
        assert_eq!(relation("WWW.Example.COM."), NameRelation::Subdomain);
        assert_eq!(relation("  www.example.com  "), NameRelation::Subdomain);
        let idn = classify_certificate_name("Bücher.example.com", &target());
        assert_eq!(idn.relation, NameRelation::Subdomain);
        assert_eq!(
            idn.normalized.unwrap().as_str(),
            "xn--bcher-kva.example.com"
        );
        assert_eq!(idn.raw, "Bücher.example.com", "raw form is kept");
    }

    #[test]
    fn malformed_and_hostile_names_are_invalid() {
        for name in [
            "",
            "*",
            "*.",
            "*.com",
            "*example.com",
            "ex*ample.com",
            "a.*.example.com",
            "*.*.example.com",
            "**.example.com",
            "example.com..",
            "user@example.com",
            "AS207960 Test Intermediate - example.com",
            "www.example.com\r\nforged",
            "www.example.com\r",
            "\twww.example.com",
            "\u{1b}[31mwww.example.com",
            "www.exa\u{202e}mple.com",
            "xn--.example.com",
            "https://www.example.com/",
            "www.example.com:443",
        ] {
            let classified = classify_certificate_name(name, &target());
            assert_eq!(classified.relation, NameRelation::Invalid, "{name:?}");
            assert!(classified.normalized.is_none());
        }
        assert_eq!(
            relation("*.com"),
            NameRelation::Invalid,
            "single-label wildcard base"
        );
    }

    #[test]
    fn raw_names_are_bounded() {
        let huge = format!("{}.example.com", "a".repeat(100_000));
        let classified = classify_certificate_name(&huge, &target());
        assert_eq!(classified.relation, NameRelation::Invalid);
        assert_eq!(classified.raw.chars().count(), MAX_RAW_NAME_CHARS);
    }

    #[test]
    fn display_names() {
        assert_eq!(
            classify_certificate_name("*.Example.com", &target()).display_name(),
            "*.example.com"
        );
        assert_eq!(
            classify_certificate_name("bad name", &target()).display_name(),
            "bad name"
        );
    }
}

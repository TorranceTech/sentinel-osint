//! SPF analysis (RFC 7208).
//!
//! The parser is deliberately tolerant: it never fails. Anything it does not
//! understand is recorded as an invalid term, which yields `dns.spf.malformed`.
//! Only the target's own record is analyzed. `include:` and `redirect=` targets
//! are listed, not resolved (no recursive lookups).

use sentinel_core::evidence::is_spf_record;
use sentinel_core::{Finding, FindingCode, Severity};

use super::{QueryResult, finding, list, quote};

/// No SPF record.
pub(crate) const MISSING: FindingCode = FindingCode::from_static("dns.spf.missing");
/// More than one SPF record (RFC 7208 §4.5: permerror).
pub(crate) const MULTIPLE: FindingCode = FindingCode::from_static("dns.spf.multiple_records");
/// `-all`.
pub(crate) const HARDFAIL: FindingCode = FindingCode::from_static("dns.spf.hardfail");
/// `~all`.
pub(crate) const SOFTFAIL: FindingCode = FindingCode::from_static("dns.spf.softfail");
/// `?all`.
pub(crate) const NEUTRAL_ALL: FindingCode = FindingCode::from_static("dns.spf.neutral_all");
/// `+all` or `all`.
pub(crate) const PERMISSIVE_ALL: FindingCode = FindingCode::from_static("dns.spf.permissive_all");
/// No `all` and no `redirect=`.
pub(crate) const NO_ALL: FindingCode = FindingCode::from_static("dns.spf.no_all");
/// Policy delegated with `redirect=`.
pub(crate) const REDIRECT: FindingCode = FindingCode::from_static("dns.spf.redirect");
/// `include:` mechanisms.
pub(crate) const INCLUDES: FindingCode = FindingCode::from_static("dns.spf.includes");
/// More than 10 DNS-querying terms in the record itself (RFC 7208 §4.6.4).
pub(crate) const TOO_MANY_LOOKUPS: FindingCode =
    FindingCode::from_static("dns.spf.too_many_lookups");
/// `ptr` mechanism (RFC 7208 §5.5: SHOULD NOT be used).
pub(crate) const PTR: FindingCode = FindingCode::from_static("dns.spf.ptr_mechanism");
/// Terms that are not valid SPF.
pub(crate) const MALFORMED: FindingCode = FindingCode::from_static("dns.spf.malformed");

/// RFC 7208 §4.6.4.
const MAX_DNS_LOOKUPS: usize = 10;
/// Terms examined per record (bounds work on hostile records).
const MAX_TERMS: usize = 128;

/// Result qualifier of a mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

/// The parts of an SPF record relevant for analysis.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SpfSummary<'a> {
    /// Qualifier of the first `all` mechanism (later terms are never evaluated).
    pub(crate) all: Option<Qualifier>,
    pub(crate) includes: Vec<&'a str>,
    pub(crate) redirect: Option<&'a str>,
    /// Terms that cause DNS lookups (include, a, mx, ptr, exists, redirect).
    pub(crate) lookup_terms: usize,
    pub(crate) has_ptr: bool,
    pub(crate) invalid_terms: Vec<&'a str>,
    /// Whether more than [`MAX_TERMS`] terms were present.
    pub(crate) truncated: bool,
}

/// Parses an SPF record (one for which [`is_spf_record`] is true).
pub(crate) fn parse(record: &str) -> SpfSummary<'_> {
    let mut summary = SpfSummary::default();
    let body = record.get("v=spf1".len()..).unwrap_or("");
    let mut terms = body.split(' ').filter(|t| !t.is_empty());

    for term in terms.by_ref().take(MAX_TERMS) {
        parse_term(term, &mut summary);
    }
    summary.truncated = terms.next().is_some();
    summary
}

fn parse_term<'a>(term: &'a str, summary: &mut SpfSummary<'a>) {
    let (qualifier, explicit, rest) = match term.as_bytes().first() {
        Some(b'+') => (Qualifier::Pass, true, &term[1..]),
        Some(b'-') => (Qualifier::Fail, true, &term[1..]),
        Some(b'~') => (Qualifier::SoftFail, true, &term[1..]),
        Some(b'?') => (Qualifier::Neutral, true, &term[1..]),
        _ => (Qualifier::Pass, false, term),
    };

    // Mechanism name ends at ':' or '/'; a modifier is `name=value`.
    let name_end = rest.find([':', '/', '=']).unwrap_or(rest.len());
    let name = &rest[..name_end];
    let separator = rest.as_bytes().get(name_end).copied();
    let argument = rest.get(name_end + 1..).unwrap_or("");

    let valid = match (name.to_ascii_lowercase().as_str(), separator) {
        ("all", None) => {
            summary.all.get_or_insert(qualifier);
            true
        }
        ("include", Some(b':')) if is_domain_spec(argument) => {
            summary.includes.push(argument);
            summary.lookup_terms += 1;
            true
        }
        ("exists", Some(b':')) if is_domain_spec(argument) => {
            summary.lookup_terms += 1;
            true
        }
        ("a" | "mx", None | Some(b'/')) => {
            summary.lookup_terms += 1;
            true
        }
        ("a" | "mx", Some(b':')) if is_domain_spec(argument.split('/').next().unwrap_or("")) => {
            summary.lookup_terms += 1;
            true
        }
        ("ptr", None) => {
            summary.lookup_terms += 1;
            summary.has_ptr = true;
            true
        }
        ("ptr", Some(b':')) if is_domain_spec(argument) => {
            summary.lookup_terms += 1;
            summary.has_ptr = true;
            true
        }
        ("ip4", Some(b':')) => is_ip_network::<std::net::Ipv4Addr>(argument, 32),
        ("ip6", Some(b':')) => is_ip_network::<std::net::Ipv6Addr>(argument, 128),
        // Modifiers take no qualifier.
        (modifier, Some(b'=')) if !explicit && is_modifier_name(modifier) => {
            if modifier == "redirect" {
                if is_domain_spec(argument) {
                    summary.redirect.get_or_insert(argument);
                    summary.lookup_terms += 1;
                    true
                } else {
                    false
                }
            } else {
                // `exp=` and unknown modifiers are valid and ignored (§6).
                true
            }
        }
        _ => false,
    };
    if !valid {
        summary.invalid_terms.push(term);
    }
}

/// A (possibly macro-containing) domain specification: non-empty, printable
/// ASCII, no whitespace.
fn is_domain_spec(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
}

fn is_modifier_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_ip_network<T: std::str::FromStr>(value: &str, max_prefix: u8) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    address.parse::<T>().is_ok()
        && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|p| p <= max_prefix))
}

/// Derives SPF findings from the apex TXT query.
pub(crate) fn analyze(domain: &str, txt: &QueryResult) -> Vec<Finding> {
    if matches!(txt, QueryResult::Failed) {
        return Vec::new();
    }
    let spf: Vec<_> = txt
        .records()
        .iter()
        .filter_map(|(id, record)| {
            record
                .data()
                .txt()
                .filter(|t| is_spf_record(t))
                .map(|t| (*id, t))
        })
        .collect();

    match spf.as_slice() {
        [] => vec![finding(
            MISSING,
            Severity::Low,
            "No SPF record",
            format!(
                "No TXT record starting with v=spf1 was found at {domain}. Receivers cannot verify which hosts may send mail for this domain."
            ),
            txt.evidence(),
        )],
        [(id, record)] => analyze_record(domain, *id, record),
        several => vec![finding(
            MULTIPLE,
            Severity::Medium,
            "Multiple SPF records",
            format!(
                "{} SPF records were found at {domain}. RFC 7208 §4.5 requires exactly one; receivers return a permanent error and SPF is not evaluated.",
                several.len()
            ),
            several.iter().map(|(id, _)| *id).collect(),
        )],
    }
}

fn analyze_record(domain: &str, id: sentinel_core::ObservationId, record: &str) -> Vec<Finding> {
    let summary = parse(record);
    let evidence = || vec![id];
    let mut findings = Vec::new();

    let policy = match summary.all {
        Some(Qualifier::Fail) => Some((HARDFAIL, Severity::Info, "SPF policy: -all (fail)", "Mail from hosts not listed in the SPF record fails SPF.".to_owned())),
        Some(Qualifier::SoftFail) => Some((SOFTFAIL, Severity::Info, "SPF policy: ~all (softfail)", "Mail from hosts not listed in the SPF record soft-fails SPF: it is typically accepted but marked.".to_owned())),
        Some(Qualifier::Neutral) => Some((NEUTRAL_ALL, Severity::Low, "SPF policy: ?all (neutral)", "The record makes no assertion about hosts not listed in it.".to_owned())),
        Some(Qualifier::Pass) => Some((PERMISSIVE_ALL, Severity::Medium, "SPF policy: +all (pass)", "The record authorizes every host on the internet to send mail for this domain.".to_owned())),
        None => match summary.redirect {
            Some(target) => Some((REDIRECT, Severity::Info, "SPF policy delegated with redirect=", format!("The SPF policy of {domain} is taken from {}.", quote(target)))),
            None => Some((NO_ALL, Severity::Low, "SPF record has no all mechanism", "Without all or redirect=, hosts not listed in the record get the default neutral result (RFC 7208 §4.7).".to_owned())),
        },
    };
    if let Some((code, severity, title, detail)) = policy {
        findings.push(finding(code, severity, title, detail, evidence()));
    }

    if !summary.includes.is_empty() {
        findings.push(finding(
            INCLUDES,
            Severity::Info,
            "SPF includes other domains' policies",
            format!(
                "{} include mechanism(s): {}. Included policies were not resolved.",
                summary.includes.len(),
                list(summary.includes.iter().copied())
            ),
            evidence(),
        ));
    }
    if summary.lookup_terms > MAX_DNS_LOOKUPS {
        findings.push(finding(
            TOO_MANY_LOOKUPS,
            Severity::Medium,
            "SPF record exceeds the DNS lookup limit",
            format!(
                "The record itself contains {} DNS-querying terms; RFC 7208 §4.6.4 allows at most {MAX_DNS_LOOKUPS} per evaluation, so receivers return a permanent error.",
                summary.lookup_terms
            ),
            evidence(),
        ));
    }
    if summary.has_ptr {
        findings.push(finding(
            PTR,
            Severity::Low,
            "SPF record uses the ptr mechanism",
            "RFC 7208 §5.5 says ptr SHOULD NOT be used: it is slow, unreliable and places load on DNS.".to_owned(),
            evidence(),
        ));
    }
    if !summary.invalid_terms.is_empty() || summary.truncated {
        let mut detail = format!(
            "{} term(s) are not valid SPF: {}. Receivers return a permanent error for syntax errors.",
            summary.invalid_terms.len(),
            list(summary.invalid_terms.iter().copied())
        );
        if summary.truncated {
            detail.push_str(" The record had too many terms to analyze completely.");
        }
        findings.push(finding(
            MALFORMED,
            Severity::Low,
            "SPF record is malformed",
            detail,
            evidence(),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use sentinel_core::NoRecordsReason;

    use super::super::testing::{codes, empty, txt};
    use super::*;

    fn analyze_txt(texts: &[&str]) -> Vec<Finding> {
        analyze("example.com", &txt("example.com", texts))
    }

    #[test]
    fn parses_common_records() {
        let s =
            parse("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx include:_spf.example.net ~all");
        assert_eq!(s.all, Some(Qualifier::SoftFail));
        assert_eq!(s.includes, vec!["_spf.example.net"]);
        assert_eq!(s.lookup_terms, 3);
        assert!(s.invalid_terms.is_empty());
        assert!(!s.has_ptr);
    }

    #[test]
    fn classifies_the_all_qualifier() {
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 -all"])),
            vec!["dns.spf.hardfail"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 ~all"])),
            vec!["dns.spf.softfail"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 ?all"])),
            vec!["dns.spf.neutral_all"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 +all"])),
            vec!["dns.spf.permissive_all"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 all"])),
            vec!["dns.spf.permissive_all"]
        );
        assert_eq!(codes(&analyze_txt(&["v=spf1 mx"])), vec!["dns.spf.no_all"]);
        assert_eq!(
            codes(&analyze_txt(&["V=SPF1 MX -ALL"])),
            vec!["dns.spf.hardfail"]
        );
    }

    #[test]
    fn first_all_wins_and_later_terms_are_irrelevant() {
        assert_eq!(parse("v=spf1 -all +all").all, Some(Qualifier::Fail));
    }

    #[test]
    fn redirect_counts_as_policy() {
        let findings = analyze_txt(&["v=spf1 redirect=_spf.example.net"]);
        assert_eq!(codes(&findings), vec!["dns.spf.redirect"]);
        assert!(findings[0].detail().contains("_spf.example.net"));
    }

    #[test]
    fn reports_includes_lookup_limit_and_ptr() {
        let includes: Vec<String> = (0..11)
            .map(|i| format!("include:s{i}.example.net"))
            .collect();
        let record = format!("v=spf1 {} ptr -all", includes.join(" "));
        let findings = analyze_txt(&[&record]);
        assert_eq!(
            codes(&findings),
            vec![
                "dns.spf.hardfail",
                "dns.spf.includes",
                "dns.spf.too_many_lookups",
                "dns.spf.ptr_mechanism"
            ]
        );
        assert!(findings[1].detail().contains("and 1 more"));
    }

    #[test]
    fn missing_and_multiple_records() {
        assert_eq!(
            codes(&analyze_txt(&["google-site-verification=abc"])),
            vec!["dns.spf.missing"]
        );
        assert_eq!(
            codes(&analyze("example.com", &empty(NoRecordsReason::NoData))),
            vec!["dns.spf.missing"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=spf1 -all", "v=spf1 ~all"])),
            vec!["dns.spf.multiple_records"]
        );
    }

    #[test]
    fn failed_lookup_is_not_missing() {
        assert!(analyze("example.com", &QueryResult::Failed).is_empty());
    }

    #[test]
    fn malformed_terms_are_reported_not_fatal() {
        let findings = analyze_txt(&[
            "v=spf1 ip4:999.1.1.1 ip6:zz include: -redirect=x.example bogus:thing ip4:10.0.0.0/33 ~all",
        ]);
        assert_eq!(
            codes(&findings),
            vec!["dns.spf.softfail", "dns.spf.malformed"]
        );
        assert!(
            findings[1].detail().starts_with("6 term(s)"),
            "{}",
            findings[1].detail()
        );
    }

    #[test]
    fn hostile_content_is_sanitized_in_findings() {
        let findings = analyze_txt(&["v=spf1 \u{1b}[31mevil\u{202e} include:\u{7}x -all"]);
        for f in &findings {
            assert!(!f.detail().contains('\u{1b}'));
            assert!(!f.detail().contains('\u{202e}'));
            assert!(!f.detail().contains('\u{7}'));
        }
    }

    #[test]
    fn huge_records_are_bounded() {
        let record = format!("v=spf1 {}-all", "a ".repeat(10_000));
        let summary = parse(&record);
        assert!(summary.truncated);
        assert_eq!(summary.all, None); // -all is beyond the analyzed terms
        let findings = analyze_txt(&[&record]);
        assert!(codes(&findings).contains(&"dns.spf.malformed"));
    }

    #[test]
    fn parser_never_panics_on_arbitrary_input() {
        let nasty = [
            "v=spf1",
            "v=spf1 ",
            "v=spf1 +",
            "v=spf1 -",
            "v=spf1 :",
            "v=spf1 /",
            "v=spf1 =",
            "v=spf1 ip4:",
            "v=spf1 ip4:/",
            "v=spf1 ip6:::/",
            "v=spf1 a:/24",
            "v=spf1 é:ü",
            "v=spf1 ~ü",
            "v=spf1 redirect=",
            "v=spf1 \u{0}\u{0}",
            "v=spf1 a/999999999999",
        ];
        for input in nasty {
            let _ = parse(input);
            let _ = analyze_txt(&[input]);
        }
    }
}

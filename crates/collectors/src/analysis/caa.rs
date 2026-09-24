//! CAA analysis (RFC 8659).
//!
//! The raw CAA records stay in their observations. These findings summarize
//! them. Only the target name is queried: CAA is inherited from parent
//! domains (tree climbing, RFC 8659 §3), which is not performed here.

use std::collections::HashSet;

use sentinel_core::{DnsRecordData, DomainName, Finding, FindingCode, ObservationId, Severity};

use super::{QueryResult, finding, list};

/// No CAA records at the name.
pub(crate) const MISSING: FindingCode = FindingCode::from_static("dns.caa.missing");
/// `issue` restricts issuance to listed CAs.
pub(crate) const ISSUE: FindingCode = FindingCode::from_static("dns.caa.issue");
/// `issue ";"`: no CA may issue.
pub(crate) const ISSUE_FORBIDDEN: FindingCode = FindingCode::from_static("dns.caa.issue_forbidden");
/// `issuewild` restricts wildcard issuance.
pub(crate) const ISSUEWILD: FindingCode = FindingCode::from_static("dns.caa.issuewild");
/// `issuewild ";"`: no CA may issue wildcards.
pub(crate) const ISSUEWILD_FORBIDDEN: FindingCode =
    FindingCode::from_static("dns.caa.issuewild_forbidden");
/// CAA present but neither `issue` nor `issuewild`.
pub(crate) const NO_ISSUE_RESTRICTION: FindingCode =
    FindingCode::from_static("dns.caa.no_issue_restriction");
/// `iodef` reporting.
pub(crate) const IODEF: FindingCode = FindingCode::from_static("dns.caa.iodef");
/// Unknown tag with the critical flag.
pub(crate) const UNKNOWN_CRITICAL: FindingCode =
    FindingCode::from_static("dns.caa.unknown_critical_tag");
/// Identical records published more than once.
pub(crate) const DUPLICATE: FindingCode = FindingCode::from_static("dns.caa.duplicate_records");
/// Invalid issuer domain names.
pub(crate) const MALFORMED: FindingCode = FindingCode::from_static("dns.caa.malformed");

/// Property tags defined by RFC 8659 and later RFCs (8657, 9495, CA/B BR).
const KNOWN_TAGS: [&str; 7] = [
    "issue",
    "issuewild",
    "iodef",
    "contactemail",
    "contactphone",
    "issuemail",
    "issuevmc",
];

/// Issuance authorization of one tag (`issue` or `issuewild`).
#[derive(Debug, Default)]
struct Issuance<'a> {
    issuers: Vec<&'a str>,
    forbid: bool,
    evidence: Vec<ObservationId>,
}

/// Values of one kind, with the observations they came from.
#[derive(Debug, Default)]
struct Values<'a> {
    items: Vec<&'a str>,
    evidence: Vec<ObservationId>,
}

impl<'a> Values<'a> {
    fn push(&mut self, item: &'a str, id: ObservationId) {
        self.items.push(item);
        self.evidence.push(id);
    }
}

/// Everything the CAA records say, classified.
#[derive(Debug, Default)]
struct Tally<'a> {
    issue: Issuance<'a>,
    issuewild: Issuance<'a>,
    iodef: Values<'a>,
    unknown_critical: Values<'a>,
    invalid_issuers: Values<'a>,
    duplicates: Vec<ObservationId>,
}

fn tally(records: &[(ObservationId, sentinel_core::DnsRecord)]) -> Tally<'_> {
    let mut tally = Tally::default();
    let mut seen = HashSet::new();
    for (id, record) in records {
        let DnsRecordData::Caa {
            critical,
            tag,
            value,
        } = record.data()
        else {
            continue;
        };
        let tag_lower = tag.to_ascii_lowercase();
        if !seen.insert((*critical, tag_lower.clone(), value.as_str())) {
            tally.duplicates.push(*id);
        }
        match tag_lower.as_str() {
            kind @ ("issue" | "issuewild") => {
                let target = if kind == "issue" {
                    &mut tally.issue
                } else {
                    &mut tally.issuewild
                };
                target.evidence.push(*id);
                // issuer-domain-name [";" parameters]; empty means "no CA".
                let issuer = value.split(';').next().unwrap_or("").trim();
                if issuer.is_empty() {
                    target.forbid = true;
                } else if DomainName::parse(issuer).is_ok() {
                    target.issuers.push(issuer);
                } else {
                    tally.invalid_issuers.push(issuer, *id);
                }
            }
            "iodef" => tally.iodef.push(value, *id),
            known if KNOWN_TAGS.contains(&known) => {}
            _ if *critical => tally.unknown_critical.push(tag, *id),
            _ => {}
        }
    }
    tally
}

/// Derives CAA findings from the apex CAA query.
pub(crate) fn analyze(domain: &str, caa: &QueryResult) -> Vec<Finding> {
    match caa {
        QueryResult::Failed => return Vec::new(),
        QueryResult::Empty { .. } => {
            return vec![finding(
                MISSING,
                Severity::Info,
                "No CAA records",
                format!(
                    "No CAA records at {domain}. Parent domains were not checked; if none of them publish CAA either, any certificate authority may issue certificates for this name."
                ),
                caa.evidence(),
            )];
        }
        QueryResult::Records(_) => {}
    }

    let tally = tally(caa.records());
    let mut findings = issuance_findings(&tally.issue, ISSUE, ISSUE_FORBIDDEN, "certificates");
    findings.extend(issuance_findings(
        &tally.issuewild,
        ISSUEWILD,
        ISSUEWILD_FORBIDDEN,
        "wildcard certificates",
    ));
    if tally.issue.evidence.is_empty() && tally.issuewild.evidence.is_empty() {
        findings.push(finding(
            NO_ISSUE_RESTRICTION,
            Severity::Info,
            "CAA records do not restrict issuance",
            format!("CAA records exist at {domain} but none has an issue or issuewild tag, so they do not restrict which CA may issue."),
            caa.evidence(),
        ));
    }
    let listed = [
        (
            tally.iodef,
            IODEF,
            Severity::Info,
            "CAA violation reporting (iodef)",
            "CAs are asked to report policy violations to: {}",
        ),
        (
            tally.unknown_critical,
            UNKNOWN_CRITICAL,
            Severity::Low,
            "CAA record with unknown critical tag",
            "Tag(s) {} have the issuer-critical flag but are not known tags. RFC 8659 §4.1: a CA that does not understand a critical tag must not issue.",
        ),
        (
            tally.invalid_issuers,
            MALFORMED,
            Severity::Low,
            "CAA issuer is not a valid domain name",
            "Invalid issuer value(s): {}",
        ),
    ];
    for (values, code, severity, title, template) in listed {
        if !values.items.is_empty() {
            let detail = template.replace("{}", &list(values.items));
            findings.push(finding(code, severity, title, detail, values.evidence));
        }
    }
    if !tally.duplicates.is_empty() {
        findings.push(finding(
            DUPLICATE,
            Severity::Info,
            "Duplicate CAA records",
            format!(
                "{} CAA record(s) are exact duplicates of another record.",
                tally.duplicates.len()
            ),
            tally.duplicates,
        ));
    }
    findings
}

fn issuance_findings(
    issuance: &Issuance<'_>,
    restricted: FindingCode,
    forbidden: FindingCode,
    what: &str,
) -> Vec<Finding> {
    if issuance.evidence.is_empty() {
        return Vec::new();
    }
    if issuance.issuers.is_empty() && issuance.forbid {
        return vec![finding(
            forbidden,
            Severity::Info,
            &format!("CAA forbids issuance of {what}"),
            format!("No certificate authority is authorized to issue {what} for this name."),
            issuance.evidence.clone(),
        )];
    }
    if issuance.issuers.is_empty() {
        return Vec::new(); // Only invalid issuers: reported as malformed.
    }
    let mut unique: Vec<&str> = Vec::new();
    for issuer in &issuance.issuers {
        if !unique.iter().any(|u| u.eq_ignore_ascii_case(issuer)) {
            unique.push(issuer);
        }
    }
    vec![finding(
        restricted,
        Severity::Info,
        &format!("CAA restricts issuance of {what}"),
        format!("Authorized CA(s): {}", list(unique)),
        issuance.evidence.clone(),
    )]
}

#[cfg(test)]
mod tests {
    use sentinel_core::NoRecordsReason;

    use super::super::testing::{codes, empty, records};
    use super::*;

    fn caa(critical: bool, tag: &str, value: &str) -> DnsRecordData {
        DnsRecordData::Caa {
            critical,
            tag: tag.into(),
            value: value.into(),
        }
    }

    fn analyze_caa(data: Vec<DnsRecordData>) -> Vec<Finding> {
        analyze("example.com", &records("example.com", data))
    }

    #[test]
    fn typical_configuration() {
        let findings = analyze_caa(vec![
            caa(false, "issue", "letsencrypt.org"),
            caa(false, "issue", "digicert.com; cansignhttpexchanges=yes"),
            caa(false, "issuewild", ";"),
            caa(false, "iodef", "mailto:security@example.com"),
        ]);
        assert_eq!(
            codes(&findings),
            vec![
                "dns.caa.issue",
                "dns.caa.issuewild_forbidden",
                "dns.caa.iodef"
            ]
        );
        assert!(
            findings[0]
                .detail()
                .contains("letsencrypt.org, digicert.com")
        );
        assert_eq!(findings[0].evidence().len(), 2);
    }

    #[test]
    fn issue_forbidden_and_missing() {
        assert_eq!(
            codes(&analyze_caa(vec![caa(false, "issue", ";")])),
            vec!["dns.caa.issue_forbidden"]
        );
        assert_eq!(
            codes(&analyze("example.com", &empty(NoRecordsReason::NoData))),
            vec!["dns.caa.missing"]
        );
        assert!(analyze("example.com", &QueryResult::Failed).is_empty());
    }

    #[test]
    fn records_without_issue_tags_do_not_restrict() {
        assert_eq!(
            codes(&analyze_caa(vec![caa(
                false,
                "iodef",
                "https://example.com/caa"
            )])),
            vec!["dns.caa.no_issue_restriction", "dns.caa.iodef"]
        );
    }

    #[test]
    fn critical_unknown_tags_duplicates_and_malformed_issuers() {
        let findings = analyze_caa(vec![
            caa(false, "ISSUE", "letsencrypt.org"),
            caa(false, "issue", "letsencrypt.org"),
            caa(true, "futuretag", "x"),
            caa(false, "othertag", "ignored"),
            caa(false, "issue", "not a domain!"),
            caa(true, "issue", "Letsencrypt.org"),
        ]);
        assert_eq!(
            codes(&findings),
            vec![
                "dns.caa.issue",
                "dns.caa.unknown_critical_tag",
                "dns.caa.malformed",
                "dns.caa.duplicate_records"
            ]
        );
        // Case-insensitive de-duplication of listed issuers.
        assert_eq!(findings[0].detail(), "Authorized CA(s): letsencrypt.org");
    }

    #[test]
    fn hostile_values_are_sanitized_and_never_panic() {
        let long = "a".repeat(100_000);
        let findings = analyze_caa(vec![
            caa(false, "iodef", "mailto:\u{1b}]0;title\u{7}@example.com"),
            caa(true, "\u{202e}evil", "x"),
            caa(false, "issue", &long),
            caa(false, "issue", ""),
            caa(false, "", ""),
        ]);
        for f in &findings {
            assert!(!f.detail().contains('\u{1b}'));
            assert!(!f.detail().contains('\u{202e}'));
            assert!(f.detail().len() < 4096);
        }
    }
}

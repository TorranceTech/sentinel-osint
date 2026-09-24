//! DMARC analysis (RFC 7489).
//!
//! Findings state the published policy as a fact. A `p=none` policy is
//! reported as `dns.dmarc.policy_none`, not labeled "vulnerable". Only the
//! record at `_dmarc.<target>` is checked. For subdomains, receivers fall
//! back to the organizational domain's record, which is not looked up here.

use sentinel_core::evidence::is_dmarc_record;
use sentinel_core::{Finding, FindingCode, ObservationId, Severity};

use super::{QueryResult, finding, list};

/// No DMARC record.
pub(crate) const MISSING: FindingCode = FindingCode::from_static("dns.dmarc.missing");
/// More than one DMARC record (RFC 7489 §6.6.3: DMARC is not applied).
pub(crate) const MULTIPLE: FindingCode = FindingCode::from_static("dns.dmarc.multiple_records");
/// Syntax problems.
pub(crate) const MALFORMED: FindingCode = FindingCode::from_static("dns.dmarc.malformed");
/// `p=none`.
pub(crate) const POLICY_NONE: FindingCode = FindingCode::from_static("dns.dmarc.policy_none");
/// `p=quarantine`.
pub(crate) const POLICY_QUARANTINE: FindingCode =
    FindingCode::from_static("dns.dmarc.policy_quarantine");
/// `p=reject`.
pub(crate) const POLICY_REJECT: FindingCode = FindingCode::from_static("dns.dmarc.policy_reject");
/// `sp=none`.
pub(crate) const SUBDOMAIN_NONE: FindingCode =
    FindingCode::from_static("dns.dmarc.subdomain_policy_none");
/// `sp=quarantine`.
pub(crate) const SUBDOMAIN_QUARANTINE: FindingCode =
    FindingCode::from_static("dns.dmarc.subdomain_policy_quarantine");
/// `sp=reject`.
pub(crate) const SUBDOMAIN_REJECT: FindingCode =
    FindingCode::from_static("dns.dmarc.subdomain_policy_reject");
/// `pct` below 100.
pub(crate) const PCT_PARTIAL: FindingCode = FindingCode::from_static("dns.dmarc.pct_partial");
/// `rua` present.
pub(crate) const AGGREGATE_REPORTING: FindingCode =
    FindingCode::from_static("dns.dmarc.aggregate_reporting");
/// `rua` absent.
pub(crate) const NO_AGGREGATE_REPORTING: FindingCode =
    FindingCode::from_static("dns.dmarc.no_aggregate_reporting");
/// `ruf` present.
pub(crate) const FAILURE_REPORTING: FindingCode =
    FindingCode::from_static("dns.dmarc.failure_reporting");
/// `adkim=s` and/or `aspf=s`.
pub(crate) const STRICT_ALIGNMENT: FindingCode =
    FindingCode::from_static("dns.dmarc.strict_alignment");

/// Tags examined per record (bounds work on hostile records).
const MAX_TAGS: usize = 64;
/// Reporting URIs kept per tag.
const MAX_URIS: usize = 32;

/// A DMARC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Policy {
    None,
    Quarantine,
    Reject,
}

impl Policy {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

/// Identifier alignment mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Alignment {
    Relaxed,
    Strict,
}

impl Alignment {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "r" => Some(Self::Relaxed),
            "s" => Some(Self::Strict),
            _ => None,
        }
    }
}

/// The parsed tags of a DMARC record. `issues` holds fixed descriptions of
/// syntax problems, never record content.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DmarcRecord<'a> {
    pub(crate) policy: Option<Policy>,
    pub(crate) subdomain_policy: Option<Policy>,
    pub(crate) pct: Option<u8>,
    pub(crate) rua: Vec<&'a str>,
    pub(crate) ruf: Vec<&'a str>,
    pub(crate) adkim: Option<Alignment>,
    pub(crate) aspf: Option<Alignment>,
    pub(crate) issues: Vec<&'static str>,
}

/// Parses a DMARC record (one for which [`is_dmarc_record`] is true).
/// Never fails. Problems are collected in `issues`.
pub(crate) fn parse(record: &str) -> DmarcRecord<'_> {
    let mut parsed = DmarcRecord::default();
    let mut seen: Vec<String> = Vec::new();
    let mut tags = record.split(';').map(str::trim).filter(|t| !t.is_empty());

    for tag in tags.by_ref().take(MAX_TAGS) {
        let Some((name, value)) = tag.split_once('=') else {
            parsed.issue("a tag has no value (missing '=')");
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if seen.contains(&name) {
            parsed.issue("a tag appears more than once");
            continue;
        }
        seen.push(name.clone());

        match name.as_str() {
            "p" => match Policy::parse(value) {
                Some(policy) => parsed.policy = Some(policy),
                None => parsed.issue("p is not none, quarantine or reject"),
            },
            "sp" => match Policy::parse(value) {
                Some(policy) => parsed.subdomain_policy = Some(policy),
                None => parsed.issue("sp is not none, quarantine or reject"),
            },
            "pct" => match value.parse::<u8>() {
                Ok(pct) if pct <= 100 => parsed.pct = Some(pct),
                _ => parsed.issue("pct is not an integer between 0 and 100"),
            },
            "adkim" => match Alignment::parse(value) {
                Some(mode) => parsed.adkim = Some(mode),
                None => parsed.issue("adkim is not r or s"),
            },
            "aspf" => match Alignment::parse(value) {
                Some(mode) => parsed.aspf = Some(mode),
                None => parsed.issue("aspf is not r or s"),
            },
            "rua" => parsed.rua = uris(value),
            "ruf" => parsed.ruf = uris(value),
            // Valid tags not analyzed here; unknown tags are ignored (§6.3).
            _ => {}
        }
    }
    if tags.next().is_some() {
        parsed.issue("the record has too many tags to analyze completely");
    }
    if parsed.policy.is_none()
        && !parsed
            .issues
            .contains(&"p is not none, quarantine or reject")
    {
        parsed.issue("the required p tag is missing");
    }
    parsed
}

impl DmarcRecord<'_> {
    fn issue(&mut self, issue: &'static str) {
        if !self.issues.contains(&issue) {
            self.issues.push(issue);
        }
    }
}

fn uris(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .take(MAX_URIS)
        .collect()
}

/// Derives DMARC findings from the `_dmarc.<domain>` TXT query.
pub(crate) fn analyze(domain: &str, txt: &QueryResult) -> Vec<Finding> {
    if matches!(txt, QueryResult::Failed) {
        return Vec::new();
    }
    let records: Vec<(ObservationId, &str)> = txt
        .records()
        .iter()
        .filter_map(|(id, r)| {
            r.data()
                .txt()
                .filter(|t| is_dmarc_record(t))
                .map(|t| (*id, t))
        })
        .collect();

    match records.as_slice() {
        [] => vec![finding(
            MISSING,
            Severity::Low,
            "No DMARC record",
            format!(
                "No TXT record starting with v=DMARC1 was found at _dmarc.{domain}. For subdomains, receivers fall back to the organizational domain's DMARC record, which was not checked."
            ),
            txt.evidence(),
        )],
        [(id, record)] => analyze_record(*id, record),
        several => vec![finding(
            MULTIPLE,
            Severity::Medium,
            "Multiple DMARC records",
            format!(
                "{} DMARC records were found at _dmarc.{domain}. RFC 7489 §6.6.3: with more than one record, DMARC processing is not applied.",
                several.len()
            ),
            several.iter().map(|(id, _)| *id).collect(),
        )],
    }
}

fn analyze_record(id: ObservationId, record: &str) -> Vec<Finding> {
    let parsed = parse(record);
    let evidence = || vec![id];
    let mut findings = Vec::new();

    if !parsed.issues.is_empty() {
        findings.push(finding(
            MALFORMED,
            Severity::Low,
            "DMARC record is malformed",
            format!("Problems: {}.", parsed.issues.join("; ")),
            evidence(),
        ));
    }

    if let Some(policy) = parsed.policy {
        let (code, detail) = match policy {
            Policy::None => (
                POLICY_NONE,
                "Receivers are asked to take no action on messages that fail DMARC; the policy is used for monitoring and reporting.",
            ),
            Policy::Quarantine => (
                POLICY_QUARANTINE,
                "Receivers are asked to treat messages that fail DMARC as suspicious (e.g. deliver to spam).",
            ),
            Policy::Reject => (
                POLICY_REJECT,
                "Receivers are asked to reject messages that fail DMARC.",
            ),
        };
        findings.push(finding(
            code,
            Severity::Info,
            &format!("DMARC policy: {}", policy.as_str()),
            detail.to_owned(),
            evidence(),
        ));
    }

    if let Some(policy) = parsed.subdomain_policy {
        let code = match policy {
            Policy::None => SUBDOMAIN_NONE,
            Policy::Quarantine => SUBDOMAIN_QUARANTINE,
            Policy::Reject => SUBDOMAIN_REJECT,
        };
        findings.push(finding(
            code,
            Severity::Info,
            &format!("DMARC subdomain policy: {}", policy.as_str()),
            format!(
                "Subdomains without their own DMARC record use sp={}.",
                policy.as_str()
            ),
            evidence(),
        ));
    }

    if let Some(pct) = parsed.pct.filter(|pct| *pct < 100) {
        findings.push(finding(
            PCT_PARTIAL,
            Severity::Info,
            "DMARC policy applies to a subset of messages",
            format!("pct={pct}: the policy is applied to {pct}% of failing messages."),
            evidence(),
        ));
    }

    findings.extend(reporting_findings(&parsed, id));
    findings
}

/// Findings about reporting (`rua`, `ruf`) and identifier alignment.
fn reporting_findings(parsed: &DmarcRecord<'_>, id: ObservationId) -> Vec<Finding> {
    let evidence = || vec![id];
    let mut findings = Vec::new();
    if parsed.rua.is_empty() {
        findings.push(finding(
            NO_AGGREGATE_REPORTING,
            Severity::Info,
            "No DMARC aggregate reporting",
            "The record has no rua tag, so no aggregate reports are requested.".to_owned(),
            evidence(),
        ));
    } else {
        findings.push(finding(
            AGGREGATE_REPORTING,
            Severity::Info,
            "DMARC aggregate reports requested",
            format!("rua: {}", list(parsed.rua.iter().copied())),
            evidence(),
        ));
    }
    if !parsed.ruf.is_empty() {
        findings.push(finding(
            FAILURE_REPORTING,
            Severity::Info,
            "DMARC failure reports requested",
            format!("ruf: {}", list(parsed.ruf.iter().copied())),
            evidence(),
        ));
    }

    let strict: Vec<&str> = [
        ("DKIM (adkim=s)", parsed.adkim),
        ("SPF (aspf=s)", parsed.aspf),
    ]
    .into_iter()
    .filter(|(_, mode)| *mode == Some(Alignment::Strict))
    .map(|(name, _)| name)
    .collect();
    if !strict.is_empty() {
        findings.push(finding(
            STRICT_ALIGNMENT,
            Severity::Info,
            "DMARC strict identifier alignment",
            format!("Strict alignment is required for: {}.", strict.join(", ")),
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
        analyze("example.com", &txt("_dmarc.example.com", texts))
    }

    #[test]
    fn parses_a_complete_record() {
        let r = parse(
            "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@example.com, mailto:b@example.net; ruf=mailto:f@example.com; adkim=s; aspf=r; fo=1",
        );
        assert_eq!(r.policy, Some(Policy::Reject));
        assert_eq!(r.subdomain_policy, Some(Policy::Quarantine));
        assert_eq!(r.pct, Some(50));
        assert_eq!(r.rua, vec!["mailto:a@example.com", "mailto:b@example.net"]);
        assert_eq!(r.ruf, vec!["mailto:f@example.com"]);
        assert_eq!(r.adkim, Some(Alignment::Strict));
        assert_eq!(r.aspf, Some(Alignment::Relaxed));
        assert!(r.issues.is_empty());
    }

    #[test]
    fn reports_policies_as_facts() {
        assert_eq!(
            codes(&analyze_txt(&["v=DMARC1; p=none"])),
            vec!["dns.dmarc.policy_none", "dns.dmarc.no_aggregate_reporting"]
        );
        assert_eq!(
            codes(&analyze_txt(&[
                "v=DMARC1; p=quarantine; rua=mailto:d@example.com"
            ])),
            vec![
                "dns.dmarc.policy_quarantine",
                "dns.dmarc.aggregate_reporting"
            ]
        );
        let findings = analyze_txt(&[
            "v=DMARC1;p=REJECT;sp=none;pct=25;rua=mailto:d@example.com;ruf=mailto:f@example.com;adkim=s;aspf=s",
        ]);
        assert_eq!(
            codes(&findings),
            vec![
                "dns.dmarc.policy_reject",
                "dns.dmarc.subdomain_policy_none",
                "dns.dmarc.pct_partial",
                "dns.dmarc.aggregate_reporting",
                "dns.dmarc.failure_reporting",
                "dns.dmarc.strict_alignment",
            ]
        );
        assert!(findings.iter().all(|f| f.severity() == Severity::Info));
    }

    #[test]
    fn missing_multiple_and_non_dmarc_records() {
        assert_eq!(
            codes(&analyze("example.com", &empty(NoRecordsReason::NxDomain))),
            vec!["dns.dmarc.missing"]
        );
        assert_eq!(
            codes(&analyze_txt(&["some-verification=xyz"])),
            vec!["dns.dmarc.missing"]
        );
        assert_eq!(
            codes(&analyze_txt(&["v=DMARC1; p=none", "v=DMARC1; p=reject"])),
            vec!["dns.dmarc.multiple_records"]
        );
        assert!(analyze("example.com", &QueryResult::Failed).is_empty());
    }

    #[test]
    fn malformed_records_are_reported_with_fixed_texts() {
        let findings =
            analyze_txt(&["v=DMARC1; p=maybe; pct=150; adkim=x; garbage; p=none; rua=\u{1b}[31m"]);
        assert_eq!(codes(&findings)[0], "dns.dmarc.malformed");
        let detail = findings[0].detail();
        for expected in [
            "p is not none",
            "pct is not",
            "adkim is not",
            "no value",
            "more than once",
        ] {
            assert!(detail.contains(expected), "{detail}");
        }
        assert!(!detail.contains('\u{1b}'));
        // Hostile rua content is sanitized where it is quoted.
        assert!(findings.iter().all(|f| !f.detail().contains('\u{1b}')));
    }

    #[test]
    fn missing_policy_is_malformed() {
        let r = parse("v=DMARC1; rua=mailto:d@example.com");
        assert_eq!(r.issues, vec!["the required p tag is missing"]);
        assert_eq!(
            codes(&analyze_txt(&["v=DMARC1; rua=mailto:d@example.com"]))[0],
            "dns.dmarc.malformed"
        );
    }

    #[test]
    fn huge_records_are_bounded_and_never_panic() {
        let record = format!("v=DMARC1; p=none; {}", "x=y; ".repeat(10_000));
        assert!(
            parse(&record)
                .issues
                .iter()
                .any(|i| i.contains("too many tags"))
        );
        for input in [
            "v=DMARC1",
            "v=DMARC1;",
            "v=DMARC1;;;;",
            "v=DMARC1; =",
            "v=DMARC1; p=",
            "v=DMARC1; é=ü; p=none",
            "v=DMARC1; pct=-1",
        ] {
            let _ = parse(input);
            let _ = analyze_txt(&[input]);
        }
    }
}

//! Analyzers: derive [`Finding`]s from DNS observations.
//!
//! Analyzers are pure functions. They receive query results that already
//! carry the IDs of their observations and return findings that cite those
//! IDs as evidence. They never touch the network.
//!
//! Principles:
//! - **Facts, not scores.** A finding states what was observed and what the
//!   relevant RFC says about it. Severities follow fixed, documented rules
//!   (`docs/FINDINGS.md`), not a risk model.
//! - **Unknown is not absent.** If a query failed, nothing is concluded about
//!   it. For example, a failed TXT lookup never yields `dns.spf.missing`.
//! - **Untrusted input.** Records may be malformed, huge or hostile. Parsers
//!   are total (they never panic), and quoted values are sanitized and
//!   truncated before they are placed in a finding.

pub(crate) mod caa;
pub(crate) mod dmarc;
pub(crate) mod records;
pub(crate) mod spf;

use std::collections::BTreeMap;

use sentinel_core::text::sanitize_single_line;
use sentinel_core::{
    Confidence, DnsRecord, DnsRecordType, Finding, FindingCode, NoRecordsReason, ObservationId,
    Severity,
};

/// Confidence of DNS-derived facts and findings: answers come from a
/// recursive resolver without DNSSEC validation.
pub(crate) const DNS_CONFIDENCE: Confidence = Confidence::saturating(90);

/// Maximum length of an external value quoted in a finding.
const MAX_QUOTED_CHARS: usize = 128;
/// Maximum number of items listed in a finding.
const MAX_LISTED_ITEMS: usize = 10;

/// `dns.domain.nxdomain`: the target does not exist.
pub(crate) const NXDOMAIN: FindingCode = FindingCode::from_static("dns.domain.nxdomain");
/// `dns.records.limit_exceeded`: a response exceeded collection limits.
pub(crate) const LIMIT_EXCEEDED: FindingCode =
    FindingCode::from_static("dns.records.limit_exceeded");

/// The result of one DNS query, as seen by analyzers.
#[derive(Debug, Clone)]
pub(crate) enum QueryResult {
    /// Records, each with the ID of its observation.
    Records(Vec<(ObservationId, DnsRecord)>),
    /// A definitive negative answer, with the ID of its observation.
    Empty {
        evidence: ObservationId,
        reason: NoRecordsReason,
    },
    /// The query failed. Nothing can be concluded.
    Failed,
}

impl QueryResult {
    /// Every observation ID this result is based on.
    pub(crate) fn evidence(&self) -> Vec<ObservationId> {
        match self {
            Self::Records(records) => records.iter().map(|(id, _)| *id).collect(),
            Self::Empty { evidence, .. } => vec![*evidence],
            Self::Failed => Vec::new(),
        }
    }

    /// The records (empty unless `Records`).
    pub(crate) fn records(&self) -> &[(ObservationId, DnsRecord)] {
        match self {
            Self::Records(records) => records,
            _ => &[],
        }
    }

    const fn is_nxdomain(&self) -> bool {
        matches!(
            self,
            Self::Empty {
                reason: NoRecordsReason::NxDomain,
                ..
            }
        )
    }
}

/// All DNS results for one domain.
#[derive(Debug)]
pub(crate) struct DnsAnswers {
    pub(crate) domain: String,
    pub(crate) apex: BTreeMap<DnsRecordType, QueryResult>,
    pub(crate) dmarc: QueryResult,
}

impl DnsAnswers {
    pub(crate) fn apex(&self, record_type: DnsRecordType) -> &QueryResult {
        self.apex.get(&record_type).unwrap_or(&QueryResult::Failed)
    }
}

/// Runs every analyzer.
pub(crate) fn analyze(answers: &DnsAnswers) -> Vec<Finding> {
    // NXDOMAIN applies to the name, not a type: any apex query saying so is
    // authoritative for all of them. Email and CAA analysis would be noise.
    if let Some(result) = answers.apex.values().find(|r| r.is_nxdomain()) {
        return vec![finding(
            NXDOMAIN,
            Severity::Info,
            "Domain does not exist",
            format!(
                "The resolver answered NXDOMAIN for {}. No DNS records exist for this name.",
                answers.domain
            ),
            result.evidence(),
        )];
    }

    let mut findings = records::analyze(answers);
    findings.extend(spf::analyze(
        &answers.domain,
        answers.apex(DnsRecordType::Txt),
    ));
    findings.extend(dmarc::analyze(&answers.domain, &answers.dmarc));
    findings.extend(caa::analyze(
        &answers.domain,
        answers.apex(DnsRecordType::Caa),
    ));
    findings
}

/// Builds a finding with the standard DNS confidence.
pub(crate) fn finding(
    code: FindingCode,
    severity: Severity,
    title: &str,
    detail: String,
    evidence: Vec<ObservationId>,
) -> Finding {
    Finding::new(code, severity, title, detail, DNS_CONFIDENCE).with_evidence(evidence)
}

/// Sanitizes and truncates an external value for use inside a finding.
pub(crate) fn quote(value: &str) -> String {
    sanitize_single_line(value, MAX_QUOTED_CHARS)
}

/// Formats a bounded, sanitized, comma-separated list.
pub(crate) fn list<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let items: Vec<&str> = items.into_iter().collect();
    let mut shown: Vec<String> = items
        .iter()
        .take(MAX_LISTED_ITEMS)
        .map(|i| quote(i))
        .collect();
    if items.len() > MAX_LISTED_ITEMS {
        shown.push(format!("and {} more", items.len() - MAX_LISTED_ITEMS));
    }
    shown.join(", ")
}

#[cfg(test)]
pub(crate) mod testing {
    //! Helpers to build query results in analyzer tests.
    use sentinel_core::{DnsRecord, DnsRecordData, NoRecordsReason, ObservationId};

    use super::QueryResult;

    pub(crate) fn records(name: &str, data: Vec<DnsRecordData>) -> QueryResult {
        QueryResult::Records(
            data.into_iter()
                .map(|d| (ObservationId::new_random(), DnsRecord::new(name, 300, d)))
                .collect(),
        )
    }

    pub(crate) fn txt(name: &str, texts: &[&str]) -> QueryResult {
        records(
            name,
            texts
                .iter()
                .map(|t| DnsRecordData::Txt {
                    text: (*t).to_owned(),
                })
                .collect(),
        )
    }

    pub(crate) fn empty(reason: NoRecordsReason) -> QueryResult {
        QueryResult::Empty {
            evidence: ObservationId::new_random(),
            reason,
        }
    }

    pub(crate) fn codes(findings: &[sentinel_core::Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code().as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn list_is_bounded_and_sanitized() {
        let many: Vec<String> = (0..15).map(|i| format!("item{i}")).collect();
        let text = list(many.iter().map(String::as_str));
        assert!(text.ends_with("and 5 more"));
        assert_eq!(list(["a\u{1b}[2Jb"]), "a\u{FFFD}[2Jb");
        assert!(quote(&"x".repeat(1000)).chars().count() <= MAX_QUOTED_CHARS);
    }

    #[test]
    fn nxdomain_short_circuits_all_other_analysis() {
        let mut apex = BTreeMap::new();
        for t in [DnsRecordType::A, DnsRecordType::Txt, DnsRecordType::Caa] {
            apex.insert(t, empty(NoRecordsReason::NxDomain));
        }
        let answers = DnsAnswers {
            domain: "nonexistent.example".into(),
            apex,
            dmarc: empty(NoRecordsReason::NxDomain),
        };
        assert_eq!(codes(&analyze(&answers)), vec!["dns.domain.nxdomain"]);
    }

    #[test]
    fn failed_queries_yield_no_conclusions() {
        let answers = DnsAnswers {
            domain: "example.com".into(),
            apex: BTreeMap::new(), // every apex query failed
            dmarc: QueryResult::Failed,
        };
        assert!(analyze(&answers).is_empty());
    }
}

#[cfg(test)]
mod properties {
    //! Analyzers are fed attacker-controlled records: they must never panic,
    //! and whatever they write into a finding must be terminal-safe.
    use proptest::prelude::*;
    use sentinel_core::DnsRecordData;
    use sentinel_core::text::is_unsafe;

    use super::testing::{records, txt};
    use super::{caa, dmarc, spf};

    fn assert_safe(findings: &[sentinel_core::Finding]) {
        for finding in findings {
            assert!(
                !finding.detail().chars().any(is_unsafe),
                "{:?}",
                finding.detail()
            );
            assert!(!finding.title().chars().any(is_unsafe));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn spf_never_panics(body in any::<String>(), tokens in prop::collection::vec("[-+~?]?(all|include|a|mx|ptr|ip4|ip6|exists|redirect|exp)[:=/]?[ -~]{0,20}", 0..20)) {
            let _ = spf::parse(&format!("v=spf1 {body}"));
            let record = format!("v=spf1 {}", tokens.join(" "));
            let findings = spf::analyze("example.com", &txt("example.com", &[&record, &format!("v=spf1 {body}")]));
            assert_safe(&findings);
            assert_safe(&spf::analyze("example.com", &txt("example.com", &[&format!("v=spf1 {body}")])));
        }

        #[test]
        fn dmarc_never_panics(body in any::<String>(), tags in prop::collection::vec("(p|sp|pct|rua|ruf|adkim|aspf|fo|x)=[ -~]{0,20}", 0..16)) {
            let _ = dmarc::parse(&format!("v=DMARC1; {body}"));
            let structured = format!("v=DMARC1; {}", tags.join(";"));
            assert_safe(&dmarc::analyze("example.com", &txt("_dmarc.example.com", &[&structured])));
            assert_safe(&dmarc::analyze("example.com", &txt("_dmarc.example.com", &[&format!("v=DMARC1;{body}")])));
        }

        #[test]
        fn caa_never_panics(entries in prop::collection::vec((any::<bool>(), any::<String>(), any::<String>()), 0..12)) {
            let data = entries
                .into_iter()
                .map(|(critical, tag, value)| DnsRecordData::Caa { critical, tag, value })
                .collect();
            assert_safe(&caa::analyze("example.com", &records("example.com", data)));
        }
    }
}

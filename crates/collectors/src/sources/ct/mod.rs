//! Certificate Transparency collector (crt.sh).
//!
//! **Passive only.** One HTTPS request to crt.sh per investigated domain.
//! Names found in certificates are recorded as observations and
//! `covers_name`/`covers_wildcard` relationships. They are **candidates**:
//! they are never resolved, connected to, probed or permuted, and they are
//! not handed to the engine as pivots.
//!
//! Pipeline: fetch (hardened client, budgeted, 8 MiB cap) → parse
//! ([`parse`], bounded) → classify every name against the target (label
//! boundaries, IDNA, wildcard rules) → deduplicate certificates → sort →
//! bound → observations, relationships and findings.
//!
//! Deduplication:
//! - **certificates** by `(issuer, serial number)`, which RFC 5280 makes
//!   unique (a precertificate and its final certificate share it), or by
//!   the crt.sh entry ID when either is missing. Merged entries are
//!   counted in `source_entries`; their names are united;
//! - **names** are never collapsed across certificates (each certificate
//!   keeps its own list). Relationships are deduplicated per
//!   (certificate, name) edge, and findings list distinct names.

mod parse;

use std::collections::{BTreeSet, HashMap};

use sentinel_core::{
    CertificateId, CertificateName, Confidence, CtCertificate, DomainName, Finding, FindingCode,
    Indicator, NameRelation, Observation, ObservationData, ObservationId, RelationKind,
    Relationship, Severity, SourceId, Timestamp, classify_certificate_name,
};
use url::Url;

use self::parse::Entry;
use crate::analysis::list;
use crate::collector::{CollectContext, CollectFuture, Collection, Collector, CollectorError};
use crate::http::HttpRequest;

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("ct");
/// crt.sh, a public CT log aggregator.
pub const CRTSH_BASE: &str = "https://crt.sh/";
/// Maximum response size. Larger answers (very popular domains) fail
/// explicitly instead of being partially parsed.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Request timeout: crt.sh answers took 0.6–20+ s when measured.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(40);
/// Certificates kept after deduplication (most recent `not_before` first).
pub const MAX_CERTIFICATES: usize = 200;
/// Names kept per certificate.
pub const MAX_NAMES_PER_CERTIFICATE: usize = 100;
/// `covers_*` relationships created per investigation.
pub const MAX_RELATIONSHIPS: usize = 500;
/// Confidence of a clean record: an aggregator's view of CT logs; log
/// inclusion proofs are not verified.
pub const CONFIDENCE: Confidence = Confidence::saturating(80);
/// Confidence of a record with invalid fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(60);

/// `ct.certificates_observed`
pub const CERTIFICATES_OBSERVED: FindingCode = FindingCode::from_static("ct.certificates_observed");
/// `ct.no_certificates`
pub const NO_CERTIFICATES: FindingCode = FindingCode::from_static("ct.no_certificates");
/// `ct.additional_names_observed`
pub const ADDITIONAL_NAMES: FindingCode = FindingCode::from_static("ct.additional_names_observed");
/// `ct.wildcard_names_observed`
pub const WILDCARD_NAMES: FindingCode = FindingCode::from_static("ct.wildcard_names_observed");
/// `ct.expired_certificates`
pub const EXPIRED: FindingCode = FindingCode::from_static("ct.expired_certificates");
/// `ct.not_yet_valid_certificates`
pub const NOT_YET_VALID: FindingCode = FindingCode::from_static("ct.not_yet_valid_certificates");
/// `ct.unrelated_names_observed`
pub const UNRELATED_NAMES: FindingCode = FindingCode::from_static("ct.unrelated_names_observed");
/// `ct.invalid_records`
pub const INVALID_RECORDS: FindingCode = FindingCode::from_static("ct.invalid_records");
/// `ct.results_truncated`
pub const TRUNCATED: FindingCode = FindingCode::from_static("ct.results_truncated");

/// The CT collector.
pub struct CtCollector {
    base: Url,
    request_timeout: std::time::Duration,
}

impl Default for CtCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtCollector {
    /// A collector querying crt.sh over HTTPS.
    ///
    /// # Panics
    /// Never: the crt.sh URL is a valid constant.
    #[must_use]
    #[allow(clippy::expect_used)] // Invariant: CRTSH_BASE is a valid URL literal.
    pub fn new() -> Self {
        Self {
            base: Url::parse(CRTSH_BASE).expect("valid constant URL"),
            request_timeout: REQUEST_TIMEOUT,
        }
    }

    /// A collector pointed at a mock server, with a 1 s request timeout.
    /// Tests only.
    #[cfg(test)]
    pub(crate) const fn for_tests(base: Url) -> Self {
        Self {
            base,
            request_timeout: std::time::Duration::from_secs(1),
        }
    }

    /// `<base>?q=<domain>&output=json&deduplicate=Y`, built with the URL
    /// encoder (never string splicing).
    fn query_url(&self, domain: &DomainName) -> Url {
        let mut url = self.base.clone();
        url.query_pairs_mut()
            .clear()
            .append_pair("q", domain.as_str())
            .append_pair("output", "json")
            .append_pair("deduplicate", "Y");
        url
    }

    async fn run(
        &self,
        indicator: &Indicator,
        domain: &DomainName,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let response = ctx
            .send(
                HttpRequest::get(self.query_url(domain))
                    .max_body_bytes(MAX_RESPONSE_BYTES)
                    .timeout(self.request_timeout),
            )
            .await?;
        // A failed request is never "no certificates".
        if response.status() != 200 {
            return Err(CollectorError::UnexpectedStatus(response.status()));
        }
        let parsed =
            parse::parse_response(response.body()).map_err(CollectorError::InvalidResponse)?;
        let (certificates, limits) = build_certificates(parsed.entries, domain);
        let invalid_entries = parsed.invalid;
        let entries_beyond_limit = parsed.total.saturating_sub(parse::MAX_ENTRIES);

        let mut collection = Collection::new();
        let mut observed: Vec<(ObservationId, CtCertificate, Confidence)> = Vec::new();
        for certificate in certificates {
            let confidence = if certificate.issues.is_empty() {
                CONFIDENCE
            } else {
                DEGRADED_CONFIDENCE
            };
            let id = collection.observe(
                Observation::new(
                    indicator.clone(),
                    SOURCE,
                    ctx.now(),
                    ObservationData::CtCertificate(certificate.clone()),
                    confidence,
                    response.provenance(),
                )
                .with_raw_response_hash(response.raw_response_hash()),
            );
            observed.push((id, certificate, confidence));
        }

        let relationships_dropped = add_relationships(&mut collection, &observed);
        let summary = Summary {
            invalid_entries,
            entries_beyond_limit,
            certificates_beyond_limit: limits.certificates_dropped,
            names_beyond_limit: limits.names_dropped,
            relationships_dropped,
        };
        for finding in findings(domain, &observed, &summary, ctx.now()) {
            collection.find(finding);
        }
        Ok(collection)
    }
}

impl Collector for CtCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        indicator.as_domain().is_some()
    }

    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a> {
        Box::pin(async move {
            let Some(domain) = indicator.as_domain() else {
                return Err(CollectorError::RefusedTarget);
            };
            indicator
                .ensure_investigable()
                .map_err(|_| CollectorError::RefusedTarget)?;
            self.run(indicator, domain, ctx).await
        })
    }
}

/// What the limits cut.
#[derive(Debug, Default)]
struct Limits {
    certificates_dropped: usize,
    names_dropped: usize,
}

/// Classifies, deduplicates, sorts (most recent first) and bounds.
fn build_certificates(entries: Vec<Entry>, target: &DomainName) -> (Vec<CtCertificate>, Limits) {
    let mut limits = Limits::default();
    let mut certificates: Vec<CtCertificate> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        let key = match (&entry.issuer, &entry.serial_number, entry.id) {
            (Some(issuer), Some(serial), _) => Some(format!("{issuer}\u{0}{serial}")),
            (_, _, Some(id)) => Some(format!("id:{id}")),
            _ => None,
        };
        let (names, omitted_emails, dropped) = classify_names(&entry.names, target);
        limits.names_dropped += dropped;

        if let Some(position) = key.as_ref().and_then(|k| index.get(k)).copied() {
            let existing = &mut certificates[position];
            existing.source_entries += 1;
            for name in names {
                if existing.names.len() >= MAX_NAMES_PER_CERTIFICATE {
                    limits.names_dropped += 1;
                } else if !existing.names.iter().any(|n| n.raw == name.raw) {
                    existing.names.push(name);
                }
            }
            continue;
        }

        let mut issues = entry.issues;
        if dropped > 0 && !issues.iter().any(|i| i.starts_with("too many names")) {
            issues.push("too many names; the rest were ignored".to_owned());
        }
        if names.iter().any(|n| n.relation == NameRelation::Invalid) {
            issues.push("some names are not valid DNS names".to_owned());
        }
        if let Some(k) = key {
            index.insert(k, certificates.len());
        }
        certificates.push(CtCertificate {
            source_entry_id: entry.id,
            serial_number: entry.serial_number,
            issuer: entry.issuer,
            common_name: entry.common_name,
            not_before: entry.not_before,
            not_after: entry.not_after,
            names,
            omitted_email_names: omitted_emails,
            source_entries: 1,
            issues,
        });
    }

    // Most recent first; ties keep source order (stable sort) for determinism.
    certificates.sort_by_key(|c| std::cmp::Reverse(c.not_before));
    if certificates.len() > MAX_CERTIFICATES {
        limits.certificates_dropped = certificates.len() - MAX_CERTIFICATES;
        certificates.truncate(MAX_CERTIFICATES);
    }
    (certificates, limits)
}

/// Classifies names. Email identities are counted, not kept (personal data).
fn classify_names(raw: &[String], target: &DomainName) -> (Vec<CertificateName>, u32, usize) {
    let mut names: Vec<CertificateName> = Vec::new();
    let mut emails = 0u32;
    let mut dropped = 0usize;
    for name in raw {
        if name.contains('@') {
            emails = emails.saturating_add(1);
            continue;
        }
        let classified = classify_certificate_name(name, target);
        if names.iter().any(|n| n.raw == classified.raw) {
            continue;
        }
        if names.len() >= MAX_NAMES_PER_CERTIFICATE {
            dropped += 1;
            continue;
        }
        names.push(classified);
    }
    (names, emails, dropped)
}

/// `covers_name` / `covers_wildcard` edges from certificates with a source
/// ID to related names. Returns how many edges were not created (limit).
fn add_relationships(
    collection: &mut Collection,
    observed: &[(ObservationId, CtCertificate, Confidence)],
) -> usize {
    let mut created = 0usize;
    let mut dropped = 0usize;
    for (id, certificate, _) in observed {
        let Some(certificate_id) = certificate
            .source_entry_id
            .and_then(|entry| CertificateId::new("crtsh", &entry.to_string()))
        else {
            continue;
        };
        for name in certificate.names.iter().filter(|n| n.relation.is_related()) {
            let Some(domain) = name.normalized.clone() else {
                continue;
            };
            if created >= MAX_RELATIONSHIPS {
                dropped += 1;
                continue;
            }
            let kind = if name.wildcard {
                RelationKind::CoversWildcard
            } else {
                RelationKind::CoversName
            };
            if let Ok(relationship) =
                Relationship::new(certificate_id.clone(), kind, Indicator::from(domain), [*id])
            {
                collection.relate(relationship);
                created += 1;
            }
        }
    }
    dropped
}

/// Counts that feed the truncation finding.
struct Summary {
    invalid_entries: usize,
    entries_beyond_limit: usize,
    certificates_beyond_limit: usize,
    names_beyond_limit: usize,
    relationships_dropped: usize,
}

const CT_CAVEAT: &str = "CT data shows what certificates were logged; it does not show that a name resolves, that a host is online or reachable, or who controls it.";

fn finding(
    code: FindingCode,
    title: &str,
    detail: String,
    confidence: Confidence,
    evidence: impl IntoIterator<Item = ObservationId>,
) -> Finding {
    Finding::new(code, Severity::Info, title, detail, confidence).with_evidence(evidence)
}

#[allow(clippy::too_many_lines)] // One flat list of independent, documented findings.
fn findings(
    domain: &DomainName,
    observed: &[(ObservationId, CtCertificate, Confidence)],
    summary: &Summary,
    now: Timestamp,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let min_confidence = |ids: &[ObservationId]| {
        observed
            .iter()
            .filter(|(id, _, _)| ids.contains(id))
            .map(|(_, _, c)| *c)
            .min()
            .unwrap_or(CONFIDENCE)
    };
    let all_ids: Vec<ObservationId> = observed.iter().map(|(id, _, _)| *id).collect();

    if observed.is_empty() {
        findings.push(Finding::new(
            NO_CERTIFICATES,
            Severity::Info,
            "No certificates reported by the CT source",
            format!("The CT source returned no certificates for {domain}. This is an empty result, not a failed query; the source's coverage may be incomplete."),
            CONFIDENCE,
        ));
    } else {
        let entries: u32 = observed.iter().map(|(_, c, _)| c.source_entries).sum();
        let first = observed.iter().filter_map(|(_, c, _)| c.not_before).min();
        let last = observed.iter().filter_map(|(_, c, _)| c.not_after).max();
        let range = match (first, last) {
            (Some(a), Some(b)) => format!(
                " Validity dates span {} to {}.",
                a.format("%Y-%m-%d"),
                b.format("%Y-%m-%d")
            ),
            _ => String::new(),
        };
        findings.push(finding(
            CERTIFICATES_OBSERVED,
            "Certificates observed in CT logs",
            format!("{} certificate(s) ({entries} log entries) naming {domain} or its subdomains were reported.{range} {CT_CAVEAT}", observed.len()),
            min_confidence(&all_ids),
            all_ids.clone(),
        ));
    }

    // Distinct names by relation, with the certificates that list them.
    let collect = |pred: &dyn Fn(&CertificateName) -> bool| {
        let mut names = BTreeSet::new();
        let mut ids = Vec::new();
        for (id, certificate, _) in observed {
            let mut hit = false;
            for name in certificate.names.iter().filter(|n| pred(n)) {
                names.insert(name.display_name());
                hit = true;
            }
            if hit {
                ids.push(*id);
            }
        }
        (names, ids)
    };

    let (subdomains, ids) = collect(&|n| n.relation == NameRelation::Subdomain && !n.wildcard);
    if !subdomains.is_empty() {
        findings.push(finding(
            ADDITIONAL_NAMES,
            "Additional names observed in certificates",
            format!(
                "{} subdomain name(s) of {domain} appear in certificates: {}. {CT_CAVEAT}",
                subdomains.len(),
                list(subdomains.iter().map(String::as_str))
            ),
            min_confidence(&ids),
            ids,
        ));
    }
    let (wildcards, ids) = collect(&|n| n.wildcard && n.relation.is_related());
    if !wildcards.is_empty() {
        findings.push(finding(
            WILDCARD_NAMES,
            "Wildcard names observed in certificates",
            format!("Wildcard name(s): {}. A wildcard certificate covers any single label at that level; it does not list the actual hosts.", list(wildcards.iter().map(String::as_str))),
            min_confidence(&ids),
            ids,
        ));
    }
    let (unrelated, ids) = collect(&|n| n.relation == NameRelation::Unrelated);
    if !unrelated.is_empty() {
        findings.push(finding(
            UNRELATED_NAMES,
            "Certificates also list names outside the investigated domain",
            format!("{} name(s) outside {domain} appear in the same certificates (for example multi-domain certificates or look-alike names): {}. They were not treated as related and no relationships were created for them.", unrelated.len(), list(unrelated.iter().map(String::as_str))),
            min_confidence(&ids),
            ids,
        ));
    }

    let expired: Vec<ObservationId> = observed
        .iter()
        .filter(|(_, c, _)| c.is_expired_at(now))
        .map(|(id, _, _)| *id)
        .collect();
    if !expired.is_empty() {
        findings.push(finding(
            EXPIRED,
            "Expired certificates observed",
            format!("{} of the observed certificates had expired at collection time. Expiry is a fact about validity dates; it does not indicate compromise or misuse, and CT keeps historical certificates.", expired.len()),
            min_confidence(&expired),
            expired,
        ));
    }
    let future: Vec<ObservationId> = observed
        .iter()
        .filter(|(_, c, _)| c.is_not_yet_valid_at(now))
        .map(|(id, _, _)| *id)
        .collect();
    if !future.is_empty() {
        findings.push(finding(
            NOT_YET_VALID,
            "Certificates not yet valid",
            format!(
                "{} certificate(s) have a not_before date after the collection time.",
                future.len()
            ),
            min_confidence(&future),
            future,
        ));
    }

    let with_issues: Vec<ObservationId> = observed
        .iter()
        .filter(|(_, c, _)| !c.issues.is_empty())
        .map(|(id, _, _)| *id)
        .collect();
    if !with_issues.is_empty() || summary.invalid_entries > 0 {
        let mut issues: BTreeSet<&str> = observed
            .iter()
            .flat_map(|(_, c, _)| c.issues.iter().map(String::as_str))
            .collect();
        let entry_note = if summary.invalid_entries > 0 {
            format!(
                " {} array entries were not objects and were skipped.",
                summary.invalid_entries
            )
        } else {
            String::new()
        };
        if issues.is_empty() {
            issues.insert("malformed entries");
        }
        findings.push(finding(
            INVALID_RECORDS,
            "CT records with invalid fields",
            format!("{} certificate record(s) had problems: {}. Invalid fields were left empty and invalid names were excluded from relationships.{entry_note}", with_issues.len(), issues.into_iter().collect::<Vec<_>>().join("; ")),
            DEGRADED_CONFIDENCE,
            with_issues,
        ));
    }

    let cut: Vec<String> = [
        (
            summary.entries_beyond_limit,
            "source entries beyond the parsing limit",
        ),
        (
            summary.certificates_beyond_limit,
            "certificates beyond the kept limit (oldest dropped)",
        ),
        (
            summary.names_beyond_limit,
            "names beyond the per-certificate limit",
        ),
        (
            summary.relationships_dropped,
            "relationships beyond the relationship limit",
        ),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !cut.is_empty() {
        findings.push(finding(
            TRUNCATED,
            "CT results were truncated",
            format!(
                "Collection limits applied: {}. The response digest covers the full response.",
                cut.join("; ")
            ),
            CONFIDENCE,
            all_ids,
        ));
    }
    findings
}

#[cfg(test)]
mod tests;

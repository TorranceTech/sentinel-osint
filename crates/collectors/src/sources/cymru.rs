//! Team Cymru IP-to-ASN collector (DNS interface).
//!
//! Two kinds of DNS TXT queries, both to fixed Cymru zones:
//!
//! - `<reversed IP>.origin.asn.cymru.com` (IPv4) or
//!   `<reversed nibbles>.origin6.asn.cymru.com` (IPv6):
//!   `"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"`
//! - `AS<n>.asn.cymru.com`: `"15169 | US | arin | 2000-03-30 | GOOGLE, US"`
//!
//! Queries go through the shared [`DnsResolver`] and are charged to the
//! request budget. The collector only reports what Cymru states. A BGP
//! origin is a routing fact, not ownership, control or intent, and findings
//! say so.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, NaiveDate};
use sentinel_core::{
    Asn, AsnDescription, AsnOrigin, Confidence, DnsNoRecords, DnsRecordType, Finding, FindingCode,
    Indicator, NoRecordsReason, Observation, ObservationData, ObservationId, Provenance,
    RelationKind, Relationship, Severity, Sha256Digest, SourceId,
};

use super::truncate_chars;
use crate::analysis::{list, quote};
use crate::collector::{
    CollectContext, CollectFuture, Collection, Collector, CollectorError, CollectorScope,
};
use crate::dns::{DnsQueryError, DnsResolver};

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("cymru");
/// Timeout per DNS query.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
/// Confidence of a well-formed answer: BGP-derived, aggregated data.
pub const CONFIDENCE: Confidence = Confidence::saturating(85);
/// Confidence of an answer with invalid fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(50);

/// TXT records used from the origin answer.
const MAX_ORIGIN_RECORDS: usize = 4;
/// Origin ASNs kept per record.
const MAX_ASNS: usize = 8;
/// AS descriptions looked up per IP.
const MAX_DESCRIPTIONS: usize = 4;
/// Characters of source text kept verbatim.
const MAX_SOURCE_TEXT: usize = 512;
/// Characters of an AS name kept.
const MAX_NAME: usize = 256;

/// `asn.origin`: the IP is announced by one or more ASes.
pub const ORIGIN: FindingCode = FindingCode::from_static("asn.origin");
/// `asn.multiple_origins`: more than one origin AS (MOAS).
pub const MULTIPLE_ORIGINS: FindingCode = FindingCode::from_static("asn.multiple_origins");
/// `asn.not_announced`: no origin reported.
pub const NOT_ANNOUNCED: FindingCode = FindingCode::from_static("asn.not_announced");
/// `asn.prefix_mismatch`: the reported prefix does not contain the IP.
pub const PREFIX_MISMATCH: FindingCode = FindingCode::from_static("asn.prefix_mismatch");
/// `asn.response_malformed`: the answer had invalid fields.
pub const MALFORMED: FindingCode = FindingCode::from_static("asn.response_malformed");

/// The Cymru collector.
pub struct CymruCollector {
    resolver: Arc<dyn DnsResolver>,
}

impl CymruCollector {
    /// Creates the collector on top of a DNS resolver.
    #[must_use]
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self { resolver }
    }

    async fn query(&self, name: &str, ctx: &CollectContext) -> Result<Vec<String>, QueryFailure> {
        ctx.acquire_request().map_err(QueryFailure::Budget)?;
        let result = tokio::time::timeout(
            QUERY_TIMEOUT,
            self.resolver.lookup(name, DnsRecordType::Txt),
        )
        .await
        .unwrap_or(Err(DnsQueryError::Timeout));
        match result {
            Ok(records) => Ok(records
                .iter()
                .filter_map(|r| r.data().txt().map(str::to_owned))
                .collect()),
            Err(error) if error.is_negative_answer() => Err(QueryFailure::Negative(error)),
            Err(error) => Err(QueryFailure::Dns(error)),
        }
    }
}

enum QueryFailure {
    Budget(CollectorError),
    Negative(DnsQueryError),
    Dns(DnsQueryError),
}

impl Collector for CymruCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        indicator.as_ip().is_some()
    }

    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetAndPivots
    }

    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a> {
        Box::pin(async move {
            let Some(ip) = indicator.as_ip() else {
                return Err(CollectorError::RefusedTarget);
            };
            // Defense in depth: never ask a third party about a non-public IP.
            indicator
                .ensure_investigable()
                .map_err(|_| CollectorError::RefusedTarget)?;
            self.run(indicator, ip, ctx).await
        })
    }
}

impl CymruCollector {
    async fn run(
        &self,
        indicator: &Indicator,
        ip: IpAddr,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let origin_name = origin_query_name(ip);

        let texts = match self.query(&origin_name, ctx).await {
            Ok(texts) => texts,
            Err(QueryFailure::Negative(error)) => {
                let provenance = self.provenance(&origin_name);
                return Ok(Self::not_announced(
                    indicator,
                    ip,
                    &origin_name,
                    error,
                    provenance,
                    ctx,
                ));
            }
            Err(QueryFailure::Budget(error)) => return Err(error),
            Err(QueryFailure::Dns(error)) => return Err(CollectorError::Dns(error)),
        };

        let mut collection = Collection::new();
        let mut origins: Vec<(ObservationId, AsnOrigin, Confidence)> = Vec::new();
        for text in texts.iter().take(MAX_ORIGIN_RECORDS) {
            let origin = parse_origin(ip, text);
            let confidence = confidence_for(&origin.issues);
            let id = collection.observe(
                Observation::new(
                    indicator.clone(),
                    SOURCE,
                    ctx.now(),
                    ObservationData::AsnOrigin(origin.clone()),
                    confidence,
                    self.provenance(&origin_name),
                )
                .with_raw_response_hash(Sha256Digest::of(text.as_bytes())),
            );
            origins.push((id, origin, confidence));
        }
        if texts.len() > MAX_ORIGIN_RECORDS {
            collection.note_failure(format!("origin answer for {ip} had more than {MAX_ORIGIN_RECORDS} records; the rest were ignored"));
        }

        let descriptions = self
            .describe(indicator, &origins, &mut collection, ctx)
            .await;

        for (id, origin, _) in &origins {
            for asn in &origin.asns {
                if let Ok(relationship) =
                    Relationship::new(indicator.clone(), RelationKind::AnnouncedBy, *asn, [*id])
                {
                    collection.relate(relationship);
                }
            }
        }
        for finding in findings(ip, &origins, &descriptions) {
            collection.find(finding);
        }
        Ok(collection)
    }

    /// Looks up the description of each distinct origin AS (bounded).
    async fn describe(
        &self,
        indicator: &Indicator,
        origins: &[(ObservationId, AsnOrigin, Confidence)],
        collection: &mut Collection,
        ctx: &CollectContext,
    ) -> Vec<(ObservationId, AsnDescription, Confidence)> {
        let asns: BTreeSet<Asn> = origins
            .iter()
            .flat_map(|(_, o, _)| o.asns.iter().copied())
            .collect();
        let mut descriptions = Vec::new();
        for asn in asns.iter().copied().take(MAX_DESCRIPTIONS) {
            let name = format!("AS{}.asn.cymru.com", asn.number());
            match self.query(&name, ctx).await {
                Ok(texts) => {
                    let Some(text) = texts.first() else { continue };
                    let description = parse_description(asn, text);
                    let confidence = confidence_for(&description.issues);
                    let id = collection.observe(
                        Observation::new(
                            indicator.clone(),
                            SOURCE,
                            ctx.now(),
                            ObservationData::AsnDescription(description.clone()),
                            confidence,
                            self.provenance(&name),
                        )
                        .with_raw_response_hash(Sha256Digest::of(text.as_bytes())),
                    );
                    descriptions.push((id, description, confidence));
                }
                Err(QueryFailure::Negative(_)) => {}
                Err(QueryFailure::Budget(error)) => {
                    collection.note_failure(format!("description of {asn} not looked up: {error}"));
                }
                Err(QueryFailure::Dns(error)) => {
                    collection.note_failure(format!("description of {asn} failed: {error}"));
                }
            }
        }
        if asns.len() > MAX_DESCRIPTIONS {
            collection.note_failure(format!(
                "only the first {MAX_DESCRIPTIONS} origin ASes were described"
            ));
        }
        descriptions
    }

    fn provenance(&self, name: &str) -> Provenance {
        Provenance::dns(name, DnsRecordType::Txt, self.resolver.description())
    }

    /// Records a negative origin answer as evidence and reports it.
    fn not_announced(
        indicator: &Indicator,
        ip: IpAddr,
        origin_name: &str,
        error: DnsQueryError,
        provenance: Provenance,
        ctx: &CollectContext,
    ) -> Collection {
        let mut collection = Collection::new();
        let reason = if error == DnsQueryError::NxDomain {
            NoRecordsReason::NxDomain
        } else {
            NoRecordsReason::NoData
        };
        let id = collection.observe(Observation::new(
            indicator.clone(),
            SOURCE,
            ctx.now(),
            ObservationData::DnsNoRecords(DnsNoRecords::new(
                origin_name,
                DnsRecordType::Txt,
                reason,
            )),
            CONFIDENCE,
            provenance,
        ));
        collection.find(
            Finding::new(
                NOT_ANNOUNCED,
                Severity::Info,
                "No BGP origin reported",
                format!("The source reports no origin AS for {ip}; the address may not be announced in BGP."),
                CONFIDENCE,
            )
            .with_evidence([id]),
        );
        collection
    }
}

fn confidence_for(issues: &[String]) -> Confidence {
    if issues.is_empty() {
        CONFIDENCE
    } else {
        DEGRADED_CONFIDENCE
    }
}

/// `4.3.2.1.origin.asn.cymru.com` or the IPv6 nibble form.
pub(crate) fn origin_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(v6) => {
            // Least significant nibble first: byte 15 low, byte 15 high, …
            let mut name = String::with_capacity(64 + 22);
            for byte in v6.octets().iter().rev() {
                for nibble in [byte & 0x0f, byte >> 4] {
                    name.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                    name.push('.');
                }
            }
            name.push_str("origin6.asn.cymru.com");
            name
        }
    }
}

fn country(value: &str, issues: &mut Vec<String>) -> Option<String> {
    match value {
        "" => None,
        v if v.len() == 2 && v.bytes().all(|b| b.is_ascii_alphabetic()) => {
            Some(v.to_ascii_uppercase())
        }
        _ => {
            issues.push("country is not a two-letter code".to_owned());
            None
        }
    }
}

fn registry(value: &str, issues: &mut Vec<String>) -> Option<String> {
    match value {
        "" => None,
        v if (2..=16).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_lowercase()) => {
            Some(v.to_owned())
        }
        _ => {
            issues.push("registry is not a known registry identifier".to_owned());
            None
        }
    }
}

fn date(value: &str, issues: &mut Vec<String>) -> Option<NaiveDate> {
    if value.is_empty() {
        return None;
    }
    match NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        Ok(date) if (1980..=2100).contains(&date.year()) => Some(date),
        _ => {
            issues.push("allocation date is invalid".to_owned());
            None
        }
    }
}

/// Parses an origin answer. Never fails: problems become `issues`.
pub(crate) fn parse_origin(ip: IpAddr, text: &str) -> AsnOrigin {
    let (source_text, _) = truncate_chars(text, MAX_SOURCE_TEXT);
    let mut issues = Vec::new();
    let fields: Vec<&str> = text.split('|').map(str::trim).collect();
    if fields.len() != 5 {
        issues.push("answer does not have the expected 5 fields".to_owned());
    }
    let field = |i: usize| fields.get(i).copied().unwrap_or("");

    let mut asns = Vec::new();
    let tokens: Vec<&str> = field(0).split_whitespace().collect();
    for token in tokens.iter().take(MAX_ASNS) {
        match token.parse::<u32>().ok().and_then(Asn::new) {
            Some(asn) if !asns.contains(&asn) => asns.push(asn),
            Some(_) => {}
            None => issues.push("an AS number is invalid".to_owned()),
        }
    }
    if tokens.len() > MAX_ASNS {
        issues.push("too many AS numbers; the rest were ignored".to_owned());
    }
    if tokens.is_empty() {
        issues.push("no AS number in the answer".to_owned());
    }

    let prefix = match sentinel_core::IpPrefix::parse(field(1)) {
        Ok(prefix) if prefix.network().is_ipv4() == ip.is_ipv4() => Some(prefix),
        _ if field(1).is_empty() => None,
        _ => {
            issues.push("prefix is not a valid CIDR for this address family".to_owned());
            None
        }
    };

    let country = country(field(2), &mut issues);
    let registry = registry(field(3), &mut issues);
    let allocated = date(field(4), &mut issues);
    issues.dedup();
    AsnOrigin {
        ip,
        asns,
        prefix,
        country,
        registry,
        allocated,
        source_text,
        issues,
    }
}

/// Parses an AS description answer. Never fails: problems become `issues`.
pub(crate) fn parse_description(asn: Asn, text: &str) -> AsnDescription {
    let (source_text, _) = truncate_chars(text, MAX_SOURCE_TEXT);
    let mut issues = Vec::new();
    // The name is the last field and may itself contain '|'.
    let fields: Vec<&str> = text.splitn(5, '|').map(str::trim).collect();
    if fields.len() != 5 {
        issues.push("answer does not have the expected 5 fields".to_owned());
    }
    let field = |i: usize| fields.get(i).copied().unwrap_or("");
    if field(0).parse::<u32>().ok() != Some(asn.number()) {
        issues.push("answer is for a different AS number".to_owned());
    }
    let country = country(field(1), &mut issues);
    let registry = registry(field(2), &mut issues);
    let allocated = date(field(3), &mut issues);
    let name = match field(4) {
        "" => None,
        raw => {
            let (name, truncated) = truncate_chars(raw, MAX_NAME);
            if truncated {
                issues.push("AS name was truncated".to_owned());
            }
            Some(name)
        }
    };
    AsnDescription {
        asn,
        name,
        country,
        registry,
        allocated,
        source_text,
        issues,
    }
}

fn findings(
    ip: IpAddr,
    origins: &[(ObservationId, AsnOrigin, Confidence)],
    descriptions: &[(ObservationId, AsnDescription, Confidence)],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let describe = |asn: Asn| {
        descriptions
            .iter()
            .find(|(_, d, _)| d.asn == asn)
            .and_then(|(_, d, _)| d.name.as_deref())
            .map_or_else(
                || asn.to_string(),
                |name| format!("{asn} ({})", quote(name)),
            )
    };

    for (id, origin, confidence) in origins {
        if !origin.asns.is_empty() {
            let named: Vec<String> = origin.asns.iter().map(|a| describe(*a)).collect();
            let mut evidence = vec![*id];
            let mut min_confidence = *confidence;
            for (did, d, c) in descriptions {
                if origin.asns.contains(&d.asn) {
                    evidence.push(*did);
                    min_confidence = min_confidence.min(*c);
                }
            }
            let prefix = origin
                .prefix
                .map_or_else(String::new, |p| format!(" in prefix {p}"));
            findings.push(
                Finding::new(
                    ORIGIN,
                    Severity::Info,
                    "BGP origin reported",
                    format!(
                        "{ip} is announced by {}{prefix}, according to the source. A BGP origin identifies the network announcing the route; it does not establish ownership, control or intent.",
                        list(named.iter().map(String::as_str))
                    ),
                    min_confidence,
                )
                .with_evidence(evidence),
            );
            if origin.asns.len() > 1 {
                findings.push(
                    Finding::new(
                        MULTIPLE_ORIGINS,
                        Severity::Info,
                        "Multiple origin ASes",
                        format!("{} ASes originate the covering route (MOAS). This is common for anycast and some CDNs.", origin.asns.len()),
                        *confidence,
                    )
                    .with_evidence([*id]),
                );
            }
        }
        if let Some(prefix) = origin.prefix.filter(|p| !p.contains(ip)) {
            findings.push(
                Finding::new(
                    PREFIX_MISMATCH,
                    Severity::Info,
                    "Reported prefix does not contain the address",
                    format!("The source reported prefix {prefix}, which does not contain {ip}. The answer is inconsistent."),
                    *confidence,
                )
                .with_evidence([*id]),
            );
        }
    }

    let malformed: Vec<(ObservationId, &Vec<String>, Confidence)> = origins
        .iter()
        .map(|(id, o, c)| (*id, &o.issues, *c))
        .chain(descriptions.iter().map(|(id, d, c)| (*id, &d.issues, *c)))
        .filter(|(_, issues, _)| !issues.is_empty())
        .collect();
    if !malformed.is_empty() {
        let mut issues: Vec<&str> = malformed
            .iter()
            .flat_map(|(_, i, _)| i.iter().map(String::as_str))
            .collect();
        issues.sort_unstable();
        issues.dedup();
        findings.push(
            Finding::new(
                MALFORMED,
                Severity::Info,
                "ASN answer had invalid fields",
                format!(
                    "Problems: {}. The affected fields were left empty.",
                    issues.join("; ")
                ),
                DEGRADED_CONFIDENCE,
            )
            .with_evidence(malformed.iter().map(|(id, _, _)| *id)),
        );
    }
    findings
}

#[cfg(test)]
mod tests;

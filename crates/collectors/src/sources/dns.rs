//! DNS collector: passive DNS intelligence for a domain.
//!
//! Queries exactly nine fixed (name, type) pairs: A, AAAA, CNAME, MX, NS,
//! SOA, TXT and CAA at the target, plus TXT at `_dmarc.<target>`. There is no
//! subdomain enumeration, no wordlist, no zone transfer, no ANY query, and no
//! connection to any discovered host.
//!
//! Every query:
//! - takes one unit of the investigation's request budget;
//! - has its own timeout ([`QUERY_TIMEOUT`]);
//! - yields observations: one per record, or one "no records" observation
//!   (evidence of absence). A failed query yields a partial-failure note, not
//!   an observation, and no conclusions are drawn from it.
//!
//! Answers are bounded ([`MAX_RECORDS_PER_QUERY`], [`MAX_TXT_BYTES`],
//! [`MAX_RECORD_BYTES`]); exceeding a bound is reported as the
//! `dns.records.limit_exceeded` finding.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sentinel_core::{
    DnsNoRecords, DnsRecord, DnsRecordData, DnsRecordType, DomainName, Indicator, NoRecordsReason,
    Observation, ObservationData, ObservationId, Provenance, RelationKind, Relationship, Severity,
    Sha256Digest, SourceId, Timestamp,
};
use tokio::task::JoinSet;

use crate::analysis::{self, DNS_CONFIDENCE, DnsAnswers, LIMIT_EXCEEDED, QueryResult};
use crate::collector::{CollectContext, CollectFuture, Collection, Collector, CollectorError};
use crate::dns::{DnsQueryError, DnsResolver};

/// Source ID of the DNS collector.
pub const SOURCE: SourceId = SourceId::from_static("dns");
/// Timeout for a single DNS query.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
/// Records kept per query.
pub const MAX_RECORDS_PER_QUERY: usize = 32;
/// Bytes kept per TXT record (longer texts are truncated).
pub const MAX_TXT_BYTES: usize = 2048;
/// Maximum size of any other record's data; larger records are dropped.
pub const MAX_RECORD_BYTES: usize = 1024;

/// Record types queried at the target, in presentation order.
const APEX_TYPES: [DnsRecordType; 8] = [
    DnsRecordType::A,
    DnsRecordType::Aaaa,
    DnsRecordType::Cname,
    DnsRecordType::Mx,
    DnsRecordType::Ns,
    DnsRecordType::Soa,
    DnsRecordType::Txt,
    DnsRecordType::Caa,
];

/// The DNS collector.
pub struct DnsCollector {
    resolver: Arc<dyn DnsResolver>,
}

impl DnsCollector {
    /// Creates a collector that uses `resolver`.
    #[must_use]
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self { resolver }
    }
}

impl Collector for DnsCollector {
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
                return Err(CollectorError::InvalidResponse(
                    "the DNS collector only handles domains",
                ));
            };
            let queries = plan(domain);
            let outcomes = self.resolve_all(&queries, ctx).await;
            build_collection(
                indicator,
                domain,
                &queries,
                outcomes,
                ctx.now(),
                self.resolver.description(),
            )
        })
    }
}

/// One planned query.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Query {
    name: String,
    record_type: DnsRecordType,
    is_dmarc: bool,
}

/// What happened to a query.
#[derive(Debug)]
enum Outcome {
    Records(Vec<DnsRecord>),
    Negative(NoRecordsReason),
    Failed(Failure),
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Dns(DnsQueryError),
    Budget { limit: u32 },
    Incomplete,
}

impl Failure {
    fn describe(self) -> String {
        match self {
            Self::Dns(error) => error.to_string(),
            Self::Budget { limit } => format!("request budget of {limit} requests exhausted"),
            Self::Incomplete => "lookup did not complete".to_owned(),
        }
    }

    fn into_error(self) -> CollectorError {
        match self {
            Self::Dns(error) => CollectorError::Dns(error),
            Self::Budget { limit } => CollectorError::RequestBudgetExhausted { limit },
            Self::Incomplete => CollectorError::Dns(DnsQueryError::Failure),
        }
    }
}

/// The fixed query plan for a domain.
fn plan(domain: &DomainName) -> Vec<Query> {
    let apex = domain.as_str();
    let mut queries: Vec<Query> = APEX_TYPES
        .iter()
        .map(|&record_type| Query {
            name: apex.to_owned(),
            record_type,
            is_dmarc: false,
        })
        .collect();
    let dmarc = format!("_dmarc.{apex}");
    // A name at the length limit has no room for the _dmarc label.
    if dmarc.len() <= DomainName::MAX_LENGTH {
        queries.push(Query {
            name: dmarc,
            record_type: DnsRecordType::Txt,
            is_dmarc: true,
        });
    }
    queries
}

impl DnsCollector {
    /// Runs all queries concurrently, each charged to the request budget and
    /// bounded by [`QUERY_TIMEOUT`].
    async fn resolve_all(&self, queries: &[Query], ctx: &CollectContext) -> Vec<Outcome> {
        let mut outcomes: Vec<Outcome> = queries
            .iter()
            .map(|_| Outcome::Failed(Failure::Incomplete))
            .collect();
        let mut tasks = JoinSet::new();

        for (index, query) in queries.iter().enumerate() {
            if let Err(CollectorError::RequestBudgetExhausted { limit }) = ctx.acquire_request() {
                outcomes[index] = Outcome::Failed(Failure::Budget { limit });
                continue;
            }
            let resolver = Arc::clone(&self.resolver);
            let name = query.name.clone();
            let record_type = query.record_type;
            tasks.spawn(async move {
                let result =
                    tokio::time::timeout(QUERY_TIMEOUT, resolver.lookup(&name, record_type))
                        .await
                        .unwrap_or(Err(DnsQueryError::Timeout));
                (index, result)
            });
        }

        // A panicking resolver task leaves its query as `Incomplete`.
        while let Some(joined) = tasks.join_next().await {
            let Ok((index, result)) = joined else {
                continue;
            };
            outcomes[index] = match result {
                Ok(records) if records.is_empty() => Outcome::Negative(NoRecordsReason::NoData),
                Ok(records) => Outcome::Records(records),
                Err(DnsQueryError::NxDomain) => Outcome::Negative(NoRecordsReason::NxDomain),
                Err(DnsQueryError::NoRecords) => Outcome::Negative(NoRecordsReason::NoData),
                Err(error) => Outcome::Failed(Failure::Dns(error)),
            };
        }
        outcomes
    }
}

/// Turns query outcomes into observations, relationships, pivots and findings.
fn build_collection(
    indicator: &Indicator,
    domain: &DomainName,
    queries: &[Query],
    outcomes: Vec<Outcome>,
    collected_at: Timestamp,
    resolver: &str,
) -> Result<Collection, CollectorError> {
    let mut collection = Collection::new();
    let mut apex = BTreeMap::new();
    let mut dmarc = QueryResult::Failed;
    let mut limited: Vec<(String, Vec<ObservationId>)> = Vec::new();
    let mut first_failure = None;

    for (query, outcome) in queries.iter().zip(outcomes) {
        let observe =
            |collection: &mut Collection, data: ObservationData, digest: Option<Sha256Digest>| {
                let mut observation = Observation::new(
                    indicator.clone(),
                    SOURCE,
                    collected_at,
                    data,
                    DNS_CONFIDENCE,
                    Provenance::dns(&query.name, query.record_type, resolver),
                );
                if let Some(digest) = digest {
                    observation = observation.with_raw_response_hash(digest);
                }
                collection.observe(observation)
            };

        let result = match outcome {
            Outcome::Records(records) => {
                let digest = answer_digest(&records);
                let (records, was_limited) = apply_limits(records);
                let entries: Vec<(ObservationId, DnsRecord)> = records
                    .into_iter()
                    .map(|record| {
                        let id = observe(
                            &mut collection,
                            ObservationData::DnsRecord(record.clone()),
                            Some(digest),
                        );
                        (id, record)
                    })
                    .collect();
                if was_limited {
                    limited.push((
                        format!("{} {}", query.record_type, query.name),
                        entries.iter().map(|(id, _)| *id).collect(),
                    ));
                }
                QueryResult::Records(entries)
            }
            Outcome::Negative(reason) => {
                let data = ObservationData::DnsNoRecords(DnsNoRecords::new(
                    &query.name,
                    query.record_type,
                    reason,
                ));
                QueryResult::Empty {
                    evidence: observe(&mut collection, data, None),
                    reason,
                }
            }
            Outcome::Failed(failure) => {
                first_failure.get_or_insert(failure);
                collection.note_failure(format!(
                    "{} lookup for {} failed: {}",
                    query.record_type,
                    query.name,
                    failure.describe()
                ));
                QueryResult::Failed
            }
        };
        if query.is_dmarc {
            dmarc = result;
        } else {
            apex.insert(query.record_type, result);
        }
    }

    // Nothing at all was learned: this is a failure, not a partial result.
    if collection.observations().is_empty()
        && let Some(failure) = first_failure
    {
        return Err(failure.into_error());
    }

    add_relationships(&mut collection, indicator, &apex);

    let answers = DnsAnswers {
        domain: domain.as_str().to_owned(),
        apex,
        dmarc,
    };
    for finding in analysis::analyze(&answers) {
        collection.find(finding);
    }
    if !limited.is_empty() {
        let (what, evidence): (Vec<String>, Vec<Vec<ObservationId>>) = limited.into_iter().unzip();
        collection.find(analysis::finding(
            LIMIT_EXCEEDED,
            Severity::Info,
            "DNS answer exceeded collection limits",
            format!(
                "Answers for {} exceeded the collection limits ({MAX_RECORDS_PER_QUERY} records per query, {MAX_TXT_BYTES} bytes per TXT record, {MAX_RECORD_BYTES} bytes per other record) and were truncated. The raw response digest covers the full answer.",
                what.join(", ")
            ),
            evidence.into_iter().flatten().collect(),
        ));
    }
    Ok(collection)
}

/// Relationships from the target's records, and IP pivots.
fn add_relationships(
    collection: &mut Collection,
    target: &Indicator,
    apex: &BTreeMap<DnsRecordType, QueryResult>,
) {
    let mut relationships = Vec::new();
    let mut pivots = Vec::new();
    for result in apex.values() {
        for (id, record) in result.records() {
            let (kind, related): (RelationKind, Indicator) = match record.data() {
                DnsRecordData::A { address } => {
                    (RelationKind::ResolvesTo, IpAddr::V4(*address).into())
                }
                DnsRecordData::Aaaa { address } => {
                    (RelationKind::ResolvesTo, IpAddr::V6(*address).into())
                }
                DnsRecordData::Cname { target: name } => match DomainName::parse(name) {
                    Ok(name) => (RelationKind::AliasOf, name.into()),
                    Err(_) => continue,
                },
                DnsRecordData::Mx { exchange, .. } => match DomainName::parse(exchange) {
                    Ok(name) => (RelationKind::HasMailExchanger, name.into()),
                    Err(_) => continue, // e.g. null MX
                },
                DnsRecordData::Ns { nameserver } => match DomainName::parse(nameserver) {
                    Ok(name) => (RelationKind::HasNameserver, name.into()),
                    Err(_) => continue,
                },
                _ => continue,
            };
            if kind == RelationKind::ResolvesTo {
                pivots.push(related.clone());
            }
            if let Ok(relationship) = Relationship::new(target.clone(), kind, related, [*id]) {
                relationships.push(relationship);
            }
        }
    }
    for relationship in relationships {
        collection.relate(relationship);
    }
    for pivot in pivots {
        collection.pivot(pivot);
    }
}

/// Applies the size limits. Returns the kept records and whether anything
/// was truncated or dropped.
fn apply_limits(mut records: Vec<DnsRecord>) -> (Vec<DnsRecord>, bool) {
    let mut limited = records.len() > MAX_RECORDS_PER_QUERY;
    records.truncate(MAX_RECORDS_PER_QUERY);
    let kept = records
        .into_iter()
        .filter_map(|record| match record.data() {
            DnsRecordData::Txt { text } if text.len() > MAX_TXT_BYTES => {
                limited = true;
                let text = truncate_at_char_boundary(text, MAX_TXT_BYTES).to_owned();
                Some(DnsRecord::new(
                    record.name(),
                    record.ttl(),
                    DnsRecordData::Txt { text },
                ))
            }
            DnsRecordData::Txt { .. } => Some(record),
            data if record.name().len() + canonical_rdata(data).len() > MAX_RECORD_BYTES => {
                limited = true;
                None
            }
            _ => Some(record),
        })
        .collect();
    (kept, limited)
}

fn truncate_at_char_boundary(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// SHA-256 over the answer `RRset` in a canonical presentation form, computed
/// before collection limits are applied. Re-querying and hashing the same
/// answer the same way verifies the observations.
fn answer_digest(records: &[DnsRecord]) -> Sha256Digest {
    let mut canonical = String::new();
    for record in records {
        let _ = writeln!(
            canonical,
            "{} {} IN {} {}",
            record.name(),
            record.ttl(),
            record.record_type(),
            canonical_rdata(record.data())
        );
    }
    Sha256Digest::of(canonical.as_bytes())
}

fn canonical_rdata(data: &DnsRecordData) -> String {
    match data {
        DnsRecordData::A { address } => address.to_string(),
        DnsRecordData::Aaaa { address } => address.to_string(),
        DnsRecordData::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}."),
        DnsRecordData::Ns { nameserver } => format!("{nameserver}."),
        DnsRecordData::Cname { target } => format!("{target}."),
        DnsRecordData::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            format!("{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}")
        }
        // Debug formatting escapes quotes and control characters deterministically.
        DnsRecordData::Txt { text } => format!("{text:?}"),
        DnsRecordData::Caa {
            critical,
            tag,
            value,
        } => {
            format!("{} {tag} {value:?}", if *critical { 128 } else { 0 })
        }
    }
}

#[cfg(test)]
mod tests;

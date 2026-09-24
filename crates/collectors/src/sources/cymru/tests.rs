//! Cymru collector tests with a fake resolver (no network).

use sentinel_core::text::is_unsafe;
use sentinel_core::{SourceOutcome, TimeLimit};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig};
use crate::http::{HttpClient, HttpConfig};
use crate::testing::{Answer, FakeResolver, context};

const ORIGIN_V4: &str = "14.215.184.93.origin.asn.cymru.com";

fn ip(s: &str) -> Indicator {
    Indicator::parse_ip(s).unwrap()
}

fn resolver() -> FakeResolver {
    FakeResolver::default()
        .txt(
            ORIGIN_V4,
            &["15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02"],
        )
        .txt(
            "AS15133.asn.cymru.com",
            &["15133 | US | arin | 2007-03-19 | EDGECAST, US"],
        )
}

async fn collect(
    resolver: FakeResolver,
    target: &str,
    budget: u32,
) -> (Result<Collection, CollectorError>, Arc<FakeResolver>) {
    let resolver = Arc::new(resolver);
    let collector = CymruCollector::new(Arc::clone(&resolver) as Arc<dyn DnsResolver>);
    let ctx = context(HttpClient::new(HttpConfig::default()).unwrap(), budget);
    let result = collector.collect(&ip(target), &ctx).await;
    (result, resolver)
}

fn codes(collection: &Collection) -> Vec<&str> {
    collection
        .findings
        .iter()
        .map(|f| f.code().as_str())
        .collect()
}

fn origins(collection: &Collection) -> Vec<&AsnOrigin> {
    collection
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::AsnOrigin(origin) => Some(origin),
            _ => None,
        })
        .collect()
}

fn descriptions(collection: &Collection) -> Vec<&AsnDescription> {
    collection
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::AsnDescription(d) => Some(d),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn ipv4_origin_and_description() {
    let (result, _) = collect(resolver(), "93.184.215.14", 10).await;
    let collection = result.unwrap();

    let origin = origins(&collection)[0];
    assert_eq!(origin.asns, vec![Asn::new(15133).unwrap()]);
    assert_eq!(origin.prefix.unwrap().to_string(), "93.184.215.0/24");
    assert_eq!(origin.country.as_deref(), Some("US"));
    assert_eq!(origin.registry.as_deref(), Some("ripencc"));
    assert_eq!(origin.allocated.unwrap().to_string(), "2008-06-02");
    assert_eq!(
        origin.source_text,
        "15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02"
    );
    assert!(origin.issues.is_empty());

    let description = descriptions(&collection)[0];
    assert_eq!(description.name.as_deref(), Some("EDGECAST, US"));
    assert!(description.issues.is_empty());

    for observation in collection.observations() {
        assert_eq!(observation.source(), &SOURCE);
        assert_eq!(observation.confidence(), CONFIDENCE);
        assert!(observation.raw_response_hash().is_some());
        assert!(matches!(observation.provenance(), Provenance::Dns(_)));
    }
    assert_eq!(
        collection.observations()[0].raw_response_hash(),
        Some(Sha256Digest::of(
            b"15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02"
        ))
    );

    assert_eq!(collection.relationships.len(), 1);
    assert_eq!(
        collection.relationships[0].kind(),
        RelationKind::AnnouncedBy
    );
    assert_eq!(collection.relationships[0].target().to_string(), "AS15133");

    assert_eq!(codes(&collection), vec!["asn.origin"]);
    let finding = &collection.findings[0];
    assert!(
        finding
            .detail()
            .contains("AS15133 (EDGECAST, US) in prefix 93.184.215.0/24")
    );
    assert!(finding.detail().contains("does not establish ownership"));
    assert_eq!(finding.evidence().len(), 2, "cites origin and description");
    assert!(collection.failures.is_empty());
}

#[test]
fn ipv4_and_ipv6_query_names() {
    assert_eq!(
        origin_query_name("93.184.215.14".parse().unwrap()),
        ORIGIN_V4
    );
    let expected = format!(
        "8.8.8.8.{}0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com",
        "0.".repeat(16)
    );
    assert_eq!(
        origin_query_name("2001:4860:4860::8888".parse().unwrap()),
        expected
    );
}

#[tokio::test]
async fn ipv6_origin() {
    let name = origin_query_name("2001:4860:4860::8888".parse().unwrap());
    let resolver = FakeResolver::default()
        .txt(&name, &["15169 | 2001:4860::/32 | US | arin | 2005-03-14"])
        .txt(
            "AS15169.asn.cymru.com",
            &["15169 | US | arin | 2000-03-30 | GOOGLE, US"],
        );
    let (result, _) = collect(resolver, "2001:4860:4860::8888", 10).await;
    let collection = result.unwrap();
    assert_eq!(
        origins(&collection)[0].prefix.unwrap().to_string(),
        "2001:4860::/32"
    );
    assert_eq!(codes(&collection), vec!["asn.origin"]);
}

#[tokio::test]
async fn multiple_origins() {
    let resolver = FakeResolver::default()
        .txt(
            ORIGIN_V4,
            &["13335 209242 | 93.184.215.0/24 | US | arin | 2014-03-28"],
        )
        .txt(
            "AS13335.asn.cymru.com",
            &["13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"],
        );
    let (result, resolver) = collect(resolver, "93.184.215.14", 10).await;
    let collection = result.unwrap();
    assert_eq!(
        codes(&collection),
        vec!["asn.origin", "asn.multiple_origins"]
    );
    assert_eq!(collection.relationships.len(), 2);
    // Both origin ASes are described (AS209242 has no answer: nothing recorded).
    assert!(
        resolver
            .queried_names()
            .contains(&"AS209242.asn.cymru.com".to_owned())
    );
    assert_eq!(descriptions(&collection).len(), 1);
}

#[tokio::test]
async fn not_announced_and_nxdomain_are_negative_answers() {
    for answer in [
        Answer::Error(DnsQueryError::NoRecords),
        Answer::Error(DnsQueryError::NxDomain),
    ] {
        let resolver = FakeResolver::default().with(ORIGIN_V4, DnsRecordType::Txt, answer);
        let (result, _) = collect(resolver, "93.184.215.14", 10).await;
        let collection = result.unwrap();
        assert_eq!(codes(&collection), vec!["asn.not_announced"]);
        assert!(matches!(
            collection.observations()[0].data(),
            ObservationData::DnsNoRecords(_)
        ));
        assert!(collection.relationships.is_empty());
    }
}

#[tokio::test]
async fn failed_lookup_is_an_error_not_empty_data() {
    let resolver = FakeResolver::default().with(
        ORIGIN_V4,
        DnsRecordType::Txt,
        Answer::Error(DnsQueryError::Failure),
    );
    let (result, _) = collect(resolver, "93.184.215.14", 10).await;
    assert!(matches!(
        result,
        Err(CollectorError::Dns(DnsQueryError::Failure))
    ));
}

#[tokio::test(start_paused = true)]
async fn query_timeout() {
    let resolver = FakeResolver::default().with(ORIGIN_V4, DnsRecordType::Txt, Answer::Hang);
    let (result, _) = collect(resolver, "93.184.215.14", 10).await;
    assert!(matches!(
        result,
        Err(CollectorError::Dns(DnsQueryError::Timeout))
    ));
}

#[tokio::test(start_paused = true)]
async fn source_timeout_through_the_engine() {
    let resolver = FakeResolver::default().with(ORIGIN_V4, DnsRecordType::Txt, Answer::Hang);
    let config = EngineConfig {
        source_timeout: Duration::from_secs(2),
        ..EngineConfig::default()
    };
    let mut engine = Engine::new(
        HttpClient::new(HttpConfig::default()).unwrap(),
        Arc::new(FixedClock::default()),
        config,
    );
    engine
        .register(Arc::new(CymruCollector::new(Arc::new(resolver))))
        .unwrap();
    let run = engine.investigate(ip("93.184.215.14")).await.unwrap();
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
}

#[tokio::test]
async fn request_budget_is_enforced() {
    let (result, resolver) = collect(resolver(), "93.184.215.14", 0).await;
    assert!(matches!(
        result,
        Err(CollectorError::RequestBudgetExhausted { limit: 0 })
    ));
    assert!(resolver.queried_names().is_empty());

    // Enough for the origin, not for the description: partial result.
    let (result, resolver) = collect(resolver_fn(), "93.184.215.14", 1).await;
    let collection = result.unwrap();
    assert_eq!(resolver.queried_names(), vec![ORIGIN_V4.to_owned()]);
    assert_eq!(origins(&collection).len(), 1);
    assert_eq!(collection.failures.len(), 1);
    assert!(collection.failures[0].contains("request budget"));
}

fn resolver_fn() -> FakeResolver {
    resolver()
}

#[tokio::test]
async fn non_public_targets_are_refused_without_any_query() {
    for target in [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "::ffff:192.168.1.1",
        "fe80::1",
        "224.0.0.1",
        "192.0.2.1",
    ] {
        let (result, resolver) = collect(resolver(), target, 10).await;
        assert!(
            matches!(result, Err(CollectorError::RefusedTarget)),
            "{target}"
        );
        assert!(
            resolver.queried_names().is_empty(),
            "{target} must never be queried"
        );
    }
}

#[test]
fn missing_fields_are_reported_not_invented() {
    let origin = parse_origin("93.184.215.14".parse().unwrap(), "15133");
    assert_eq!(origin.asns, vec![Asn::new(15133).unwrap()]);
    assert_eq!(origin.prefix, None);
    assert_eq!(origin.country, None);
    assert_eq!(
        origin.issues,
        vec!["answer does not have the expected 5 fields"]
    );

    let empty_fields = parse_origin("93.184.215.14".parse().unwrap(), "15133 |  |  |  | ");
    assert!(
        empty_fields.issues.is_empty(),
        "empty optional fields are not errors"
    );
}

#[test]
fn invalid_values_are_dropped_with_issues() {
    let ip: IpAddr = "93.184.215.14".parse().unwrap();
    let cases = [
        (
            "0 | 93.184.215.0/24 | US | arin | 2008-06-02",
            "an AS number is invalid",
        ),
        (
            "99999999999 | 93.184.215.0/24 | US | arin | 2008-06-02",
            "an AS number is invalid",
        ),
        (
            "15133 | 93.184.215.1/24 | US | arin | 2008-06-02",
            "prefix is not a valid CIDR for this address family",
        ),
        (
            "15133 | 2001:db8::/32 | US | arin | 2008-06-02",
            "prefix is not a valid CIDR for this address family",
        ),
        (
            "15133 | 93.184.215.0/24 | USA | arin | 2008-06-02",
            "country is not a two-letter code",
        ),
        (
            "15133 | 93.184.215.0/24 | US | AR IN | 2008-06-02",
            "registry is not a known registry identifier",
        ),
        (
            "15133 | 93.184.215.0/24 | US | arin | 2008-13-45",
            "allocation date is invalid",
        ),
        (
            "15133 | 93.184.215.0/24 | US | arin | 9999-01-01",
            "allocation date is invalid",
        ),
        ("garbage", "an AS number is invalid"),
        (
            " | 93.184.215.0/24 | US | arin | 2008-06-02",
            "no AS number in the answer",
        ),
    ];
    for (text, issue) in cases {
        let origin = parse_origin(ip, text);
        assert!(
            origin.issues.iter().any(|i| i == issue),
            "{text}: {:?}",
            origin.issues
        );
    }
}

#[tokio::test]
async fn malformed_answers_reduce_confidence_and_are_reported() {
    let resolver = FakeResolver::default().txt(ORIGIN_V4, &["this is not a cymru answer"]);
    let (result, _) = collect(resolver, "93.184.215.14", 10).await;
    let collection = result.unwrap();
    assert_eq!(codes(&collection), vec!["asn.response_malformed"]);
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    assert!(collection.relationships.is_empty());
}

#[tokio::test]
async fn prefix_that_does_not_contain_the_ip_is_an_inconsistency() {
    let resolver =
        FakeResolver::default().txt(ORIGIN_V4, &["15133 | 9.9.9.0/24 | US | arin | 2008-06-02"]);
    let (result, _) = collect(resolver, "93.184.215.14", 10).await;
    assert_eq!(
        codes(&result.unwrap()),
        vec!["asn.origin", "asn.prefix_mismatch"]
    );
}

#[test]
fn description_for_another_as_is_flagged() {
    let d = parse_description(
        Asn::new(15133).unwrap(),
        "15169 | US | arin | 2000-03-30 | GOOGLE, US",
    );
    assert!(
        d.issues
            .contains(&"answer is for a different AS number".to_owned())
    );
    // Names may contain the separator.
    let d = parse_description(
        Asn::new(64500).unwrap(),
        "64500 | US | arin | 2000-03-30 | ACME | WEST",
    );
    assert_eq!(d.name.as_deref(), Some("ACME | WEST"));
}

#[tokio::test]
async fn oversized_and_hostile_answers_are_bounded_kept_faithful_and_sanitized() {
    let hostile_name = format!(
        "\u{1b}]0;pwned\u{7}\u{1b}[31mEVIL\r\nFORGED ünïcödé {}",
        "x".repeat(10_000)
    );
    let resolver = FakeResolver::default()
        .txt(
            ORIGIN_V4,
            &[&format!(
                "15133 | 93.184.215.0/24 | US | ripencc | 2008-06-02{}",
                " ".repeat(100_000)
            )],
        )
        .txt(
            "AS15133.asn.cymru.com",
            &[&format!("15133 | US | arin | 2007-03-19 | {hostile_name}")],
        );
    let (result, _) = collect(resolver, "93.184.215.14", 10).await;
    let collection = result.unwrap();

    assert!(origins(&collection)[0].source_text.chars().count() <= MAX_SOURCE_TEXT);
    let description = descriptions(&collection)[0];
    let name = description.name.as_deref().unwrap();
    assert_eq!(name.chars().count(), MAX_NAME);
    assert!(
        name.starts_with("\u{1b}]0;pwned"),
        "evidence keeps what the source said"
    );
    assert!(
        description
            .issues
            .contains(&"AS name was truncated".to_owned())
    );
    for finding in &collection.findings {
        assert!(
            !finding.detail().chars().any(is_unsafe),
            "{:?}",
            finding.detail()
        );
    }
}

#[tokio::test]
async fn at_most_four_origin_records_are_used() {
    let texts: Vec<String> = (0..10)
        .map(|i| format!("{} | 93.184.215.0/24 | US | arin | 2008-06-02", 64500 + i))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let resolver = FakeResolver::default().txt(ORIGIN_V4, &refs);
    let (result, resolver) = collect(resolver, "93.184.215.14", 100).await;
    let collection = result.unwrap();
    assert_eq!(origins(&collection).len(), MAX_ORIGIN_RECORDS);
    // 1 origin query + at most MAX_DESCRIPTIONS description queries.
    assert_eq!(resolver.queried_names().len(), 1 + MAX_DESCRIPTIONS);
    assert!(!collection.failures.is_empty());
}

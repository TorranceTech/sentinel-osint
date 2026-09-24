//! RDAP collector tests against local mock servers (bootstrap + registry),
//! through the real hardened HTTP client.

use std::time::Duration;

use sentinel_core::text::is_unsafe;
use sentinel_core::{IpPrefix, IpVersion, Provenance, Sha256Digest, SourceOutcome, TimeLimit};
use wiremock::matchers::{header_regex, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig};
use crate::http::{HttpClient, HttpConfig, HttpError, PolicyViolation};
use crate::testing::context;

const NETWORK_V4: &str = r#"{
    "objectClassName": "ip network",
    "handle": "NET-8-8-8-0-2",
    "name": "GOGL",
    "type": "DIRECT ALLOCATION",
    "ipVersion": "v4",
    "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255",
    "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
    "country": "US",
    "status": ["active"],
    "events": [{"eventAction": "registration", "eventDate": "2014-03-14T16:52:05-04:00"}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"], ["kind", {}, "text", "org"]]],
        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["kind", {}, "text", "group"], ["email", {}, "text", "network-abuse@google.com"]]]}]}]
}"#;

const NETWORK_V6: &str = r#"{
    "objectClassName": "ip network", "handle": "NET6-2001-4860-1", "name": "GOOGLE-IPV6", "ipVersion": "v6",
    "startAddress": "2001:4860::", "endAddress": "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff",
    "cidr0_cidrs": [{"v6prefix": "2001:4860::", "length": 32}]
}"#;

/// A bootstrap server and a registry server wired together.
struct Registry {
    bootstrap: MockServer,
    rdap: MockServer,
}

impl Registry {
    async fn start() -> Self {
        let bootstrap = MockServer::start().await;
        let rdap = MockServer::start().await;
        let service = format!("{}/", rdap.uri());
        for (file, prefix) in [
            ("/ipv4.json", "8.0.0.0/8"),
            ("/ipv6.json", "2001:4860::/32"),
        ] {
            Mock::given(path(file))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{"version": "1.0", "services": [[["{prefix}"], ["{service}"]]]}}"#
                )))
                .mount(&bootstrap)
                .await;
        }
        Self { bootstrap, rdap }
    }

    async fn network(&self, ip: &str, status: u16, body: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/ip/{ip}")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&self.rdap)
            .await;
    }

    fn collector(&self) -> RdapCollector {
        RdapCollector::for_tests(Url::parse(&format!("{}/", self.bootstrap.uri())).unwrap())
    }

    fn http(&self, extra: &[&MockServer]) -> HttpClient {
        self.http_with(
            HttpConfig {
                request_timeout: Duration::from_secs(2),
                ..HttpConfig::default()
            },
            extra,
        )
    }

    fn http_with(&self, config: HttpConfig, extra: &[&MockServer]) -> HttpClient {
        let mut servers = vec![*self.bootstrap.address(), *self.rdap.address()];
        servers.extend(extra.iter().map(|s| *s.address()));
        HttpClient::for_tests(config, servers).unwrap()
    }
}

fn ip(s: &str) -> Indicator {
    Indicator::parse_ip(s).unwrap()
}

fn registration(collection: &Collection) -> &NetworkRegistration {
    match collection.observations()[0].data() {
        ObservationData::NetworkRegistration(n) => n,
        other => panic!("unexpected observation {other:?}"),
    }
}

fn codes(collection: &Collection) -> Vec<&str> {
    collection
        .findings
        .iter()
        .map(|f| f.code().as_str())
        .collect()
}

fn blocked(result: Result<Collection, CollectorError>) -> PolicyViolation {
    match result {
        Err(CollectorError::Http(HttpError::Blocked(violation))) => violation,
        other => panic!("expected a policy violation, got {other:?}"),
    }
}

#[tokio::test]
async fn ipv4_registration_end_to_end() {
    let registry = Registry::start().await;
    Mock::given(path("/ip/8.8.8.8"))
        .and(header_regex("accept", r"^application/rdap\+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NETWORK_V4))
        .expect(1)
        .mount(&registry.rdap)
        .await;
    let ctx = context(registry.http(&[]), 10);
    let collection = registry
        .collector()
        .collect(&ip("8.8.8.8"), &ctx)
        .await
        .unwrap();

    let n = registration(&collection);
    assert_eq!(n.handle.as_deref(), Some("NET-8-8-8-0-2"));
    assert_eq!(n.cidrs, vec![IpPrefix::parse("8.8.8.0/24").unwrap()]);
    assert_eq!(n.organization.as_deref(), Some("Google LLC"));
    assert_eq!(n.abuse_email.as_deref(), Some("network-abuse@google.com"));

    let observation = &collection.observations()[0];
    assert_eq!(observation.source(), &SOURCE);
    assert_eq!(observation.confidence(), CONFIDENCE);
    assert_eq!(
        observation.raw_response_hash(),
        Some(Sha256Digest::of(NETWORK_V4.as_bytes()))
    );
    let Provenance::Https(provenance) = observation.provenance() else {
        panic!("https provenance")
    };
    assert_eq!(
        provenance.endpoint(),
        format!("{}/ip/8.8.8.8", registry.rdap.uri())
    );
    assert_eq!(provenance.status(), 200);

    assert_eq!(collection.relationships.len(), 1);
    assert_eq!(
        collection.relationships[0].kind(),
        RelationKind::RegisteredIn
    );
    assert_eq!(
        collection.relationships[0].target().to_string(),
        "8.8.8.0/24"
    );

    assert_eq!(codes(&collection), vec!["rdap.network"]);
    let detail = collection.findings[0].detail();
    assert!(detail.contains("network GOGL (NET-8-8-8-0-2)"));
    assert!(detail.contains("registrant organization Google LLC"));
    assert!(detail.contains("does not establish who operates"));
}

#[tokio::test]
async fn ipv6_registration() {
    let registry = Registry::start().await;
    registry
        .network("2001:4860:4860::8888", 200, NETWORK_V6)
        .await;
    let ctx = context(registry.http(&[]), 10);
    let collection = registry
        .collector()
        .collect(&ip("2001:4860:4860::8888"), &ctx)
        .await
        .unwrap();
    let n = registration(&collection);
    assert_eq!(n.ip_version, Some(IpVersion::V6));
    assert_eq!(
        collection.relationships[0].target().to_string(),
        "2001:4860::/32"
    );
}

#[tokio::test]
async fn bootstrap_is_fetched_once_and_cached() {
    let registry = Registry::start().await;
    registry.network("8.8.8.8", 200, NETWORK_V4).await;
    registry
        .network("8.8.4.4", 200, &NETWORK_V4.replace("8.8.8.", "8.8.4."))
        .await;
    let collector = registry.collector();
    let ctx = context(registry.http(&[]), 10);
    collector.collect(&ip("8.8.8.8"), &ctx).await.unwrap();
    collector.collect(&ip("8.8.4.4"), &ctx).await.unwrap();
    let bootstrap_requests = registry.bootstrap.received_requests().await.unwrap();
    assert_eq!(bootstrap_requests.len(), 1, "ipv4.json fetched once");
}

#[tokio::test]
async fn address_without_bootstrap_service() {
    let registry = Registry::start().await;
    let ctx = context(registry.http(&[]), 10);
    let result = registry.collector().collect(&ip("1.1.1.1"), &ctx).await;
    assert!(matches!(result, Err(CollectorError::InvalidResponse(_))));
    assert!(registry.rdap.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn valid_redirect_between_registries_is_followed() {
    let registry = Registry::start().await;
    let other = MockServer::start().await;
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(301)
                .insert_header("location", format!("{}/ip/8.8.8.8", other.uri())),
        )
        .mount(&registry.rdap)
        .await;
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NETWORK_V4))
        .mount(&other)
        .await;
    let ctx = context(registry.http(&[&other]), 10);
    let collection = registry
        .collector()
        .collect(&ip("8.8.8.8"), &ctx)
        .await
        .unwrap();
    let Provenance::Https(provenance) = collection.observations()[0].provenance() else {
        panic!()
    };
    assert!(
        provenance.endpoint().starts_with(&other.uri()),
        "provenance records the final registry"
    );
}

async fn redirect_to(target: &str) -> PolicyViolation {
    let registry = Registry::start().await;
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", target))
        .mount(&registry.rdap)
        .await;
    let ctx = context(registry.http(&[]), 10);
    blocked(registry.collector().collect(&ip("8.8.8.8"), &ctx).await)
}

#[tokio::test]
async fn redirect_to_http_is_blocked() {
    assert_eq!(
        redirect_to("http://rdap.example.net/ip/8.8.8.8").await,
        PolicyViolation::InsecureScheme
    );
}

#[tokio::test]
async fn redirect_to_private_and_loopback_is_blocked() {
    for target in [
        "https://10.0.0.1/ip/8.8.8.8",
        "https://127.0.0.1:1/ip/8.8.8.8",
        "https://[::1]/ip/8.8.8.8",
        "https://169.254.169.254/latest/meta-data/",
    ] {
        assert!(
            matches!(
                redirect_to(target).await,
                PolicyViolation::NonPublicAddress { .. }
            ),
            "{target}"
        );
    }
    assert_eq!(
        redirect_to("https://localhost:9/ip/8.8.8.8").await,
        PolicyViolation::NoPublicAddress
    );
}

#[tokio::test]
async fn redirect_chain_limit() {
    let registry = Registry::start().await;
    for i in 0..5 {
        Mock::given(path(format!("/hop{i}")))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/hop{}", registry.rdap.uri(), i + 1)),
            )
            .mount(&registry.rdap)
            .await;
    }
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/hop0", registry.rdap.uri())),
        )
        .mount(&registry.rdap)
        .await;
    let ctx = context(registry.http(&[]), 10);
    assert_eq!(
        blocked(registry.collector().collect(&ip("8.8.8.8"), &ctx).await),
        PolicyViolation::TooManyRedirects { max: 3 }
    );
}

#[tokio::test]
async fn bootstrap_pointing_at_a_private_address_is_blocked() {
    let bootstrap = MockServer::start().await;
    Mock::given(path("/ipv4.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"services": [[["8.0.0.0/8"], ["https://10.1.2.3/rdap/"]]]}"#),
        )
        .mount(&bootstrap)
        .await;
    let http = HttpClient::for_tests(HttpConfig::default(), vec![*bootstrap.address()]).unwrap();
    let collector = RdapCollector::for_tests(Url::parse(&format!("{}/", bootstrap.uri())).unwrap());
    let result = collector.collect(&ip("8.8.8.8"), &context(http, 10)).await;
    assert!(matches!(
        blocked(result),
        PolicyViolation::NonPublicAddress { .. }
    ));
}

#[tokio::test]
async fn malformed_and_unexpected_responses_fail_safely() {
    for body in [
        "not json {{{",
        "[]",
        r#"{"objectClassName": "domain"}"#,
        r#"{"handle": "X"}"#,
        "",
    ] {
        let registry = Registry::start().await;
        registry.network("8.8.8.8", 200, body).await;
        let ctx = context(registry.http(&[]), 10);
        let result = registry.collector().collect(&ip("8.8.8.8"), &ctx).await;
        assert!(
            matches!(result, Err(CollectorError::InvalidResponse(_))),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn error_statuses_are_failures_not_empty_data() {
    for status in [404, 429, 500] {
        let registry = Registry::start().await;
        registry
            .network("8.8.8.8", status, r#"{"errorCode": 1}"#)
            .await;
        let ctx = context(registry.http(&[]), 10);
        let result = registry.collector().collect(&ip("8.8.8.8"), &ctx).await;
        assert!(
            matches!(result, Err(CollectorError::UnexpectedStatus(s)) if s == status),
            "{status}"
        );
    }
}

#[tokio::test]
async fn optional_fields_absent_and_invalid_values_degrade_confidence() {
    let registry = Registry::start().await;
    registry
        .network(
            "8.8.8.8",
            200,
            r#"{"objectClassName": "ip network", "cidr0_cidrs": [{"v4prefix": "8.8.8.1", "length": 24}],
                "events": [{"eventAction": "registration", "eventDate": "31/12/2020"}]}"#,
        )
        .await;
    let ctx = context(registry.http(&[]), 10);
    let collection = registry
        .collector()
        .collect(&ip("8.8.8.8"), &ctx)
        .await
        .unwrap();
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    assert!(
        collection.relationships.is_empty(),
        "no relationship without a valid CIDR"
    );
    assert_eq!(codes(&collection), vec!["rdap.network", "rdap.incomplete"]);
    let detail = collection.findings[1].detail();
    assert!(detail.contains("a cidr0 entry is not a valid CIDR"));
    assert!(detail.contains("an event date is not a valid RFC 3339 timestamp"));
}

#[tokio::test]
async fn range_that_does_not_contain_the_ip_is_an_inconsistency() {
    let registry = Registry::start().await;
    registry
        .network("8.8.8.8", 200, r#"{"objectClassName": "ip network", "startAddress": "9.9.9.0", "endAddress": "9.9.9.255"}"#)
        .await;
    let ctx = context(registry.http(&[]), 10);
    let collection = registry
        .collector()
        .collect(&ip("8.8.8.8"), &ctx)
        .await
        .unwrap();
    assert_eq!(
        codes(&collection),
        vec!["rdap.network", "rdap.range_mismatch"]
    );
}

#[tokio::test]
async fn oversized_responses_are_rejected() {
    let registry = Registry::start().await;
    let huge = format!(
        r#"{{"objectClassName": "ip network", "name": "{}"}}"#,
        "x".repeat(MAX_RESPONSE_BYTES + 1)
    );
    registry.network("8.8.8.8", 200, &huge).await;
    let ctx = context(registry.http(&[]), 10);
    let result = registry.collector().collect(&ip("8.8.8.8"), &ctx).await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::ResponseTooLarge { .. }))
    ));
}

#[tokio::test]
async fn hostile_strings_are_kept_as_evidence_and_sanitized_in_findings() {
    let registry = Registry::start().await;
    let body = r#"{"objectClassName": "ip network", "name": "\u001b]0;pwned\u0007\u001b[2JNET\r\nFORGED LINE\u202e", "handle": "H\u0000",
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Évil\u001b[31m Corp"], ["kind", {}, "text", "org"]]]}]}"#;
    registry.network("8.8.8.8", 200, body).await;
    let ctx = context(registry.http(&[]), 10);
    let collection = registry
        .collector()
        .collect(&ip("8.8.8.8"), &ctx)
        .await
        .unwrap();
    assert!(
        registration(&collection)
            .name
            .as_deref()
            .unwrap()
            .contains('\u{1b}'),
        "evidence is faithful"
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
async fn request_timeout() {
    let registry = Registry::start().await;
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(NETWORK_V4)
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&registry.rdap)
        .await;
    let http = registry.http_with(
        HttpConfig {
            request_timeout: Duration::from_millis(300),
            ..HttpConfig::default()
        },
        &[],
    );
    let result = registry
        .collector()
        .collect(&ip("8.8.8.8"), &context(http, 10))
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::Timeout))
    ));
}

#[tokio::test]
async fn source_timeout_through_the_engine() {
    let registry = Registry::start().await;
    Mock::given(path("/ip/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(NETWORK_V4)
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&registry.rdap)
        .await;
    let config = EngineConfig {
        source_timeout: Duration::from_millis(500),
        ..EngineConfig::default()
    };
    let mut engine = Engine::new(registry.http(&[]), Arc::new(FixedClock::default()), config);
    engine.register(Arc::new(registry.collector())).unwrap();
    let run = engine.investigate(ip("8.8.8.8")).await.unwrap();
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
}

#[tokio::test]
async fn request_budget_covers_bootstrap_and_query() {
    let registry = Registry::start().await;
    registry.network("8.8.8.8", 200, NETWORK_V4).await;
    // No budget at all: nothing is sent.
    let result = registry
        .collector()
        .collect(&ip("8.8.8.8"), &context(registry.http(&[]), 0))
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::RequestBudgetExhausted { limit: 0 })
    ));
    assert!(
        registry
            .bootstrap
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    // Budget for the bootstrap only: the registry is never contacted.
    let result = registry
        .collector()
        .collect(&ip("8.8.8.8"), &context(registry.http(&[]), 1))
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::RequestBudgetExhausted { limit: 1 })
    ));
    assert!(registry.rdap.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn non_public_addresses_are_never_sent_to_a_registry() {
    let registry = Registry::start().await;
    let ctx = context(registry.http(&[]), 10);
    for target in [
        "10.0.0.1",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "::ffff:10.0.0.1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "0.0.0.0",
    ] {
        let result = registry.collector().collect(&ip(target), &ctx).await;
        assert!(
            matches!(result, Err(CollectorError::RefusedTarget)),
            "{target}"
        );
    }
    assert!(
        registry
            .bootstrap
            .received_requests()
            .await
            .unwrap()
            .is_empty()
    );
    assert!(registry.rdap.received_requests().await.unwrap().is_empty());
}

#[test]
fn query_urls_are_built_from_path_segments() {
    let base = Url::parse("https://rdap.example.net/registry/").unwrap();
    assert_eq!(
        query_url(&base, "8.8.8.8".parse().unwrap())
            .unwrap()
            .as_str(),
        "https://rdap.example.net/registry/ip/8.8.8.8"
    );
    assert_eq!(
        query_url(&base, "2001:db8::1".parse().unwrap())
            .unwrap()
            .as_str(),
        "https://rdap.example.net/registry/ip/2001:db8::1"
    );
    let no_slash = Url::parse("https://rdap.example.net/registry").unwrap();
    assert_eq!(
        query_url(&no_slash, "8.8.8.8".parse().unwrap())
            .unwrap()
            .as_str(),
        "https://rdap.example.net/registry/ip/8.8.8.8"
    );
}

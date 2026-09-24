//! CT collector tests against a mock crt.sh, through the real HTTP client.
//! The clock is fixed at 2026-09-23T12:00:00Z.

use std::sync::Arc;
use std::time::Duration;

use sentinel_core::text::is_unsafe;
use sentinel_core::{Provenance, Sha256Digest, SourceOutcome, TimeLimit};
use wiremock::matchers::{path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig};
use crate::http::{HttpClient, HttpConfig, HttpError, PolicyViolation};
use crate::testing::context;

/// Shaped like the observed crt.sh output: a precertificate/certificate pair
/// (same issuer + serial), an expired certificate with an email identity,
/// look-alike and unrelated names, and a not-yet-valid certificate.
const RESPONSE: &str = r#"[
  {"issuer_ca_id": 1, "issuer_name": "C=US, O=Example CA, CN=Example Issuing CA", "common_name": "example.com",
   "name_value": "*.example.com\nexample.com", "id": 1002, "not_before": "2026-07-29T22:10:08",
   "not_after": "2026-10-27T22:17:21", "serial_number": "0624D0AB", "result_count": 3},
  {"issuer_ca_id": 1, "issuer_name": "C=US, O=Example CA, CN=Example Issuing CA", "common_name": "example.com",
   "name_value": "example.com\n*.example.com", "id": 1001, "not_before": "2026-07-29T22:10:08",
   "not_after": "2026-10-27T22:17:21", "serial_number": "0624d0ab", "result_count": 3},
  {"issuer_ca_id": 2, "issuer_name": "C=US, O=Other CA, CN=Other CA", "common_name": "www.example.com",
   "name_value": "www.example.com\napi.example.com\nuser@example.com\nm.testexample.com\nexample.com.evil.test\nAS207960 Test Intermediate - example.com",
   "id": 900, "not_before": "2023-01-01T00:00:00", "not_after": "2024-01-01T00:00:00", "serial_number": "01"},
  {"issuer_ca_id": 2, "issuer_name": "C=US, O=Other CA, CN=Other CA", "common_name": "dev.example.com",
   "name_value": "dev.example.com\nWWW.EXAMPLE.COM.", "id": 950, "not_before": "2027-01-01T00:00:00",
   "not_after": "2027-04-01T00:00:00", "serial_number": "02"}
]"#;

async fn crtsh(status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(path("/"))
        .and(query_param("q", "example.com"))
        .and(query_param("output", "json"))
        .and(query_param("deduplicate", "Y"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;
    server
}

fn collector(server: &MockServer) -> CtCollector {
    CtCollector::for_tests(Url::parse(&format!("{}/", server.uri())).unwrap())
}

fn http(server: &MockServer) -> HttpClient {
    HttpClient::for_tests(
        HttpConfig {
            request_timeout: Duration::from_secs(2),
            ..HttpConfig::default()
        },
        vec![*server.address()],
    )
    .unwrap()
}

fn domain(s: &str) -> Indicator {
    Indicator::parse_domain(s).unwrap()
}

async fn collect(server: &MockServer) -> Result<Collection, CollectorError> {
    collector(server)
        .collect(&domain("example.com"), &context(http(server), 10))
        .await
}

fn certificates(collection: &Collection) -> Vec<&CtCertificate> {
    collection
        .observations()
        .iter()
        .filter_map(|o| match o.data() {
            ObservationData::CtCertificate(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn codes(collection: &Collection) -> Vec<&str> {
    collection
        .findings
        .iter()
        .map(|f| f.code().as_str())
        .collect()
}

#[tokio::test]
async fn collects_classifies_and_deduplicates_certificates() {
    let server = crtsh(200, RESPONSE).await;
    let collection = collect(&server).await.unwrap();
    let certs = certificates(&collection);

    // 4 entries → 3 certificates: the precertificate pair is merged.
    assert_eq!(certs.len(), 3);
    // Most recent not_before first.
    assert_eq!(certs[0].source_entry_id, Some(950));
    let pair = certs[1];
    assert_eq!(pair.source_entries, 2);
    assert_eq!(pair.serial_number.as_deref(), Some("0624d0ab"));
    assert_eq!(pair.names.len(), 2, "names united without duplicates");

    let expired = certs[2];
    assert_eq!(expired.omitted_email_names, 1);
    let relation_of = |raw: &str| {
        expired
            .names
            .iter()
            .find(|n| n.raw == raw)
            .map(|n| n.relation)
    };
    assert_eq!(
        relation_of("www.example.com"),
        Some(NameRelation::Subdomain)
    );
    assert_eq!(
        relation_of("m.testexample.com"),
        Some(NameRelation::Unrelated)
    );
    assert_eq!(
        relation_of("example.com.evil.test"),
        Some(NameRelation::Unrelated)
    );
    assert_eq!(
        relation_of("AS207960 Test Intermediate - example.com"),
        Some(NameRelation::Invalid)
    );
    assert!(
        expired.names.iter().all(|n| !n.raw.contains('@')),
        "emails are never stored"
    );
    assert!(
        expired
            .issues
            .contains(&"some names are not valid DNS names".to_owned())
    );

    for observation in collection.observations() {
        assert_eq!(observation.source(), &SOURCE);
        assert_eq!(
            observation.raw_response_hash(),
            Some(Sha256Digest::of(RESPONSE.as_bytes()))
        );
        let Provenance::Https(p) = observation.provenance() else {
            panic!("https provenance")
        };
        assert!(
            p.endpoint()
                .ends_with("/?q=example.com&output=json&deduplicate=Y"),
            "{}",
            p.endpoint()
        );
    }
    assert!(
        collection.pivots.is_empty(),
        "CT names are candidates, never engine pivots"
    );
}

#[tokio::test]
async fn relationships_only_for_related_valid_names() {
    let server = crtsh(200, RESPONSE).await;
    let collection = collect(&server).await.unwrap();
    let edges: Vec<(String, RelationKind, String)> = collection
        .relationships
        .iter()
        .map(|r| (r.source().to_string(), r.kind(), r.target().to_string()))
        .collect();
    for expected in [
        ("crtsh:1002", RelationKind::CoversWildcard, "example.com"),
        ("crtsh:1002", RelationKind::CoversName, "example.com"),
        ("crtsh:900", RelationKind::CoversName, "www.example.com"),
        ("crtsh:900", RelationKind::CoversName, "api.example.com"),
        ("crtsh:950", RelationKind::CoversName, "dev.example.com"),
        ("crtsh:950", RelationKind::CoversName, "www.example.com"),
    ] {
        assert!(
            edges.contains(&(expected.0.to_owned(), expected.1, expected.2.to_owned())),
            "missing {expected:?} in {edges:?}"
        );
    }
    assert_eq!(edges.len(), 6);
    assert!(
        !edges
            .iter()
            .any(|(_, _, t)| t.contains("testexample") || t.contains("evil"))
    );
}

#[tokio::test]
async fn factual_findings() {
    let server = crtsh(200, RESPONSE).await;
    let collection = collect(&server).await.unwrap();
    assert_eq!(
        codes(&collection),
        vec![
            "ct.certificates_observed",
            "ct.additional_names_observed",
            "ct.wildcard_names_observed",
            "ct.unrelated_names_observed",
            "ct.expired_certificates",
            "ct.not_yet_valid_certificates",
            "ct.invalid_records",
        ]
    );
    let detail = |code: &str| {
        collection
            .findings
            .iter()
            .find(|f| f.code().as_str() == code)
            .unwrap()
            .detail()
            .to_owned()
    };
    assert!(detail("ct.certificates_observed").starts_with("3 certificate(s) (4 log entries)"));
    assert!(detail("ct.certificates_observed").contains("does not show that a name resolves"));
    assert!(
        detail("ct.additional_names_observed")
            .contains("api.example.com, dev.example.com, www.example.com")
    );
    assert!(detail("ct.wildcard_names_observed").contains("*.example.com"));
    assert!(detail("ct.unrelated_names_observed").contains("m.testexample.com"));
    assert!(detail("ct.expired_certificates").contains("does not indicate compromise"));
    for finding in &collection.findings {
        assert_eq!(finding.severity(), Severity::Info);
        for word in ["malicious", "compromised", "attacker"] {
            assert!(
                !finding
                    .detail()
                    .to_lowercase()
                    .contains(&format!("is {word}")),
                "{word}"
            );
        }
    }
}

#[tokio::test]
async fn empty_result_is_not_a_failure() {
    let server = crtsh(200, "[]").await;
    let collection = collect(&server).await.unwrap();
    assert!(collection.observations().is_empty());
    assert_eq!(codes(&collection), vec!["ct.no_certificates"]);
}

#[tokio::test]
async fn failed_requests_are_never_empty_results() {
    for status in [404, 429, 500, 502, 503] {
        let server = crtsh(status, "[]").await;
        let result = collect(&server).await;
        assert!(
            matches!(result, Err(CollectorError::UnexpectedStatus(s)) if s == status),
            "{status}"
        );
    }
}

#[tokio::test]
async fn malformed_responses_fail_safely() {
    for body in [
        "<html>502 Bad Gateway</html>",
        "{",
        r#"{"error": "x"}"#,
        "null",
        "",
    ] {
        let server = crtsh(200, body).await;
        assert!(
            matches!(
                collect(&server).await,
                Err(CollectorError::InvalidResponse(_))
            ),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn wrong_types_and_nulls_degrade_but_do_not_fail() {
    let body = r#"[{"id": "x", "name_value": null, "not_before": 5}, 7, {"id": 5, "name_value": "a.example.com", "issuer_name": ["x"]}]"#;
    let server = crtsh(200, body).await;
    let collection = collect(&server).await.unwrap();
    assert_eq!(certificates(&collection).len(), 2);
    assert!(
        collection
            .observations()
            .iter()
            .all(|o| o.confidence() == DEGRADED_CONFIDENCE)
    );
    assert!(codes(&collection).contains(&"ct.invalid_records"));
    let detail = collection
        .findings
        .iter()
        .find(|f| f.code() == &INVALID_RECORDS)
        .unwrap()
        .detail();
    assert!(detail.contains("1 array entries were not objects"));
}

#[tokio::test]
async fn request_timeout() {
    let server = MockServer::start().await;
    Mock::given(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("[]")
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;
    // The collector's own request timeout (1 s in tests, 40 s in production)
    // applies even though the client default is longer.
    let started = std::time::Instant::now();
    let result = collect(&server).await;
    assert!(
        matches!(result, Err(CollectorError::Http(HttpError::Timeout))),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(CtCollector::new().request_timeout, REQUEST_TIMEOUT);
}

#[tokio::test]
async fn source_timeout_through_the_engine() {
    let server = MockServer::start().await;
    Mock::given(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("[]")
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;
    let config = EngineConfig {
        source_timeout: Duration::from_millis(500),
        ..EngineConfig::default()
    };
    let mut engine = Engine::new(http(&server), Arc::new(FixedClock::default()), config);
    engine.register(Arc::new(collector(&server))).unwrap();
    let run = engine.investigate(domain("example.com")).await.unwrap();
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
}

#[tokio::test]
async fn request_budget_is_enforced() {
    let server = crtsh(200, RESPONSE).await;
    let result = collector(&server)
        .collect(&domain("example.com"), &context(http(&server), 0))
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::RequestBudgetExhausted { limit: 0 })
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn oversized_responses_fail_explicitly() {
    let huge = format!(
        r#"[{{"name_value": "{}"}}]"#,
        "a".repeat(MAX_RESPONSE_BYTES)
    );
    let server = crtsh(200, &huge).await;
    assert!(matches!(
        collect(&server).await,
        Err(CollectorError::Http(HttpError::ResponseTooLarge { .. }))
    ));
}

#[tokio::test]
async fn hostile_values_are_kept_as_evidence_and_sanitized_in_findings() {
    let body = r#"[{"id": 7, "issuer_name": "CN=\u001b]0;pwned\u0007Evil\r\nCA", "common_name": "x",
        "name_value": "\u001b[31mwww.example.com\nfoo.example.com\r\nFORGED\n*.*.example.com\n*example.com\nbücher.example.com\nxn--.example.com\nwww.exa\u202emple.com",
        "not_before": "2026-01-01T00:00:00", "not_after": "2027-01-01T00:00:00", "serial_number": "0a"}]"#;
    let server = crtsh(200, body).await;
    let collection = collect(&server).await.unwrap();
    let cert = certificates(&collection)[0];
    assert!(
        cert.issuer.as_deref().unwrap().contains('\u{1b}'),
        "evidence is faithful"
    );

    let relation = |raw: &str| cert.names.iter().find(|n| n.raw == raw).map(|n| n.relation);
    assert_eq!(
        relation("\u{1b}[31mwww.example.com"),
        Some(NameRelation::Invalid)
    );
    assert_eq!(relation("foo.example.com\r"), Some(NameRelation::Invalid));
    assert_eq!(relation("*.*.example.com"), Some(NameRelation::Invalid));
    assert_eq!(relation("*example.com"), Some(NameRelation::Invalid));
    assert_eq!(relation("xn--.example.com"), Some(NameRelation::Invalid));
    assert_eq!(
        relation("www.exa\u{202e}mple.com"),
        Some(NameRelation::Invalid)
    );
    let idn = cert
        .names
        .iter()
        .find(|n| n.raw == "bücher.example.com")
        .unwrap();
    assert_eq!(idn.relation, NameRelation::Subdomain);
    assert_eq!(
        idn.normalized.as_ref().unwrap().as_str(),
        "xn--bcher-kva.example.com"
    );

    for finding in &collection.findings {
        assert!(
            !finding.detail().chars().any(is_unsafe),
            "{:?}",
            finding.detail()
        );
    }
    for relationship in &collection.relationships {
        assert!(!relationship.target().to_string().chars().any(is_unsafe));
    }
}

#[tokio::test]
async fn huge_result_sets_are_bounded() {
    let entries: Vec<String> = (0..1000)
        .map(|i| {
            let names: Vec<String> = (0..20).map(|j| format!("h{i}-{j}.example.com")).collect();
            format!(r#"{{"id": {i}, "issuer_name": "CN=CA", "serial_number": "{i:x}", "name_value": "{}", "not_before": "2025-01-01T00:00:00"}}"#, names.join("\\n"))
        })
        .collect();
    let server = crtsh(200, &format!("[{}]", entries.join(","))).await;
    let collection = collect(&server).await.unwrap();
    assert_eq!(certificates(&collection).len(), MAX_CERTIFICATES);
    assert_eq!(collection.relationships.len(), MAX_RELATIONSHIPS);
    assert!(codes(&collection).contains(&"ct.results_truncated"));
    let detail = collection
        .findings
        .iter()
        .find(|f| f.code() == &TRUNCATED)
        .unwrap()
        .detail();
    assert!(detail.contains("800 certificates beyond the kept limit"));
    assert!(detail.contains("relationships beyond the relationship limit"));
    assert!(collection.pivots.is_empty());
}

#[tokio::test]
async fn non_investigable_domains_are_refused_without_a_request() {
    let server = crtsh(200, RESPONSE).await;
    for name in ["printer.local", "db.corp.internal", "abc.onion"] {
        let result = collector(&server)
            .collect(&domain(name), &context(http(&server), 10))
            .await;
        assert!(
            matches!(result, Err(CollectorError::RefusedTarget)),
            "{name}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn production_endpoint_is_https_and_http_is_refused() {
    let production = CtCollector::new();
    assert_eq!(production.base.scheme(), "https");
    assert_eq!(production.base.host_str(), Some("crt.sh"));
    // The shared production client refuses a plain-HTTP CT endpoint.
    let insecure = CtCollector::for_tests(Url::parse("http://crt.sh/").unwrap());
    let ctx = context(HttpClient::new(HttpConfig::default()).unwrap(), 10);
    let result = insecure.collect(&domain("example.com"), &ctx).await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::Blocked(
            PolicyViolation::InsecureScheme
        )))
    ));
}

#[test]
fn query_is_url_encoded_from_the_validated_domain() {
    let production = CtCollector::new();
    let url = production.query_url(
        Indicator::parse_domain("Bücher.Example.com")
            .unwrap()
            .as_domain()
            .unwrap(),
    );
    assert_eq!(
        url.as_str(),
        "https://crt.sh/?q=xn--bcher-kva.example.com&output=json&deduplicate=Y"
    );
}

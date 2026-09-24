//! VirusTotal collector tests against a mock API, through the real HTTP client.

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use sentinel_core::text::is_unsafe;
use sentinel_core::{Provenance, Sha256Digest, SourceOutcome, TimeLimit};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig, EngineRun};
use crate::http::{HttpClient, HttpConfig, HttpError, PolicyViolation};
use crate::testing::{context, global_log_capture};

const KEY: &str = "virustotal-TEST-KEY-must-never-leak-9876543210";
const SHA: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
/// VirusTotal's URL identifier of `https://example.com/` (Python
/// `base64.urlsafe_b64encode(...).strip("=")`, as documented).
const EXAMPLE_URL_ID: &str = "aHR0cHM6Ly9leGFtcGxlLmNvbS8";
const NOT_FOUND_BODY: &str =
    r#"{"error": {"code": "NotFoundError", "message": "Resource not found"}}"#;

fn stats(malicious: u64, suspicious: u64) -> String {
    format!(
        r#"{{"harmless": 55, "malicious": {malicious}, "suspicious": {suspicious}, "timeout": 0, "undetected": 30}}"#
    )
}

fn object(object_type: &str, id: &str, stats: &str) -> String {
    format!(
        r#"{{"data": {{"type": "{object_type}", "id": "{id}", "links": {{"self": "https://www.virustotal.com/api/v3/x"}},
            "attributes": {{"last_analysis_date": 1758614400, "last_analysis_stats": {stats},
            "reputation": -7, "total_votes": {{"harmless": 2, "malicious": 5}}, "tags": ["cdn"],
            "whois": "Registrant Email: owner@example.net\nRegistrant Phone: +1.5550100",
            "last_analysis_results": {{"EngineA": {{"category": "malicious", "engine_name": "EngineA", "result": "phishing"}}}},
            "last_dns_records": [{{"type": "A", "value": "203.0.113.9"}}],
            "last_https_certificate": {{"subject": {{"CN": "pivot.example.org"}}}}}}}}}}"#
    )
}

/// A mock that answers only a correctly authenticated GET of `api_path`.
async fn api(api_path: &str, status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(api_path))
        .and(header("x-apikey", KEY))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;
    server
}

fn base(server: &MockServer) -> Url {
    Url::parse(&format!("{}/api/v3", server.uri())).unwrap()
}

fn collector(server: &MockServer, key: Option<&str>) -> VirusTotalCollector {
    VirusTotalCollector::for_tests(base(server), key.map(SecretString::from))
}

fn http(servers: &[&MockServer]) -> HttpClient {
    HttpClient::for_tests(
        HttpConfig {
            request_timeout: Duration::from_secs(2),
            ..HttpConfig::default()
        },
        servers.iter().map(|s| *s.address()).collect(),
    )
    .unwrap()
}

fn ip(s: &str) -> Indicator {
    Indicator::parse_ip(s).unwrap()
}

async fn collect(server: &MockServer, target: &Indicator) -> Result<Collection, CollectorError> {
    collector(server, Some(KEY))
        .collect(target, &context(http(&[server]), 10))
        .await
}

fn reputation(collection: &Collection) -> &ProviderReputation {
    match collection.observations()[0].data() {
        ObservationData::ProviderReputation(r) => r,
        other => panic!("unexpected {other:?}"),
    }
}

fn codes(collection: &Collection) -> Vec<&str> {
    collection
        .findings
        .iter()
        .map(|f| f.code().as_str())
        .collect()
}

async fn engine_run(
    collector: VirusTotalCollector,
    servers: &[&MockServer],
    config: EngineConfig,
    target: Indicator,
) -> EngineRun {
    let mut engine = Engine::new(http(servers), Arc::new(FixedClock::default()), config);
    engine.register(Arc::new(collector)).unwrap();
    engine.investigate(target).await.unwrap()
}

fn assert_attributed(collection: &Collection) {
    for finding in &collection.findings {
        assert_eq!(
            finding.severity(),
            Severity::Info,
            "no Sentinel severity ranking of provider claims"
        );
        assert!(
            finding.detail().contains("VirusTotal"),
            "{}",
            finding.detail()
        );
        let lower = finding.detail().to_lowercase();
        for verdict in [
            "is malicious",
            "is dangerous",
            "attacker",
            "compromised",
            "risk score",
            "threat score",
        ] {
            assert!(!lower.contains(verdict), "{verdict}: {}", finding.detail());
        }
    }
}

// --------------------------------------------------- indicator types

#[tokio::test]
async fn ipv4_report_with_provenance_and_evidence_integrity() {
    let body = object("ip_address", "8.8.8.8", &stats(0, 0));
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &body).await;
    let target = ip("8.8.8.8");
    let collection = collect(&server, &target).await.unwrap();
    let r = reputation(&collection);

    assert_eq!(r.provider, "virustotal");
    assert_eq!(r.metric("last_analysis_stats.malicious"), Some(0));
    assert_eq!(r.metric("last_analysis_stats.harmless"), Some(55));
    assert_eq!(r.metric("total_votes.malicious"), Some(5));
    assert_eq!(r.community_score, Some(-7));
    assert_eq!(r.tags, vec!["cdn"]);
    assert_eq!(
        r.last_analysis_at.unwrap().to_rfc3339(),
        "2025-09-23T08:00:00+00:00"
    );

    let observation = &collection.observations()[0];
    assert_eq!(observation.indicator(), &target);
    assert_eq!(observation.source(), &SOURCE);
    assert_eq!(observation.confidence(), CONFIDENCE);
    assert_eq!(
        observation.collected_at(),
        FixedClock::default().0,
        "collection time comes from the injected clock, not the provider"
    );
    assert_eq!(
        observation.raw_response_hash(),
        Some(Sha256Digest::of(body.as_bytes()))
    );
    let Provenance::Https(p) = observation.provenance() else {
        panic!("https provenance")
    };
    assert!(
        p.endpoint().ends_with("/api/v3/ip_addresses/8.8.8.8"),
        "{}",
        p.endpoint()
    );
    assert!(!p.endpoint().contains(KEY));

    assert_eq!(
        codes(&collection),
        vec!["ti.virustotal.observed", "ti.virustotal.no_detections"]
    );
    for finding in &collection.findings {
        assert_eq!(finding.evidence(), [observation.id()]);
        assert_eq!(finding.confidence(), CONFIDENCE);
    }
    assert!(
        collection.findings[1]
            .detail()
            .contains("Absence of detections is not evidence that the indicator is benign")
    );
    // Discarded data: per-engine results, WHOIS, DNS, certificates.
    let json = serde_json::to_string(&collection.observations()).unwrap();
    for dropped in [
        "owner@example.net",
        "5550100",
        "EngineA",
        "phishing",
        "203.0.113.9",
        "pivot.example.org",
        "links",
    ] {
        assert!(!json.contains(dropped), "{dropped} must not be stored");
    }
    // No pivots or relationships from VirusTotal content.
    assert!(collection.relationships.is_empty());
    assert!(collection.pivots.is_empty());
    assert_attributed(&collection);
}

#[tokio::test]
async fn ipv6_report() {
    let body = object("ip_address", "2001:4860:4860:0:0:0:0:8888", &stats(0, 0));
    let server = api("/api/v3/ip_addresses/2001:4860:4860::8888", 200, &body).await;
    let collection = collect(&server, &ip("2001:4860:4860::8888")).await.unwrap();
    assert!(reputation(&collection).issues.is_empty());
}

#[tokio::test]
async fn domain_report_with_detections_is_attributed_not_judged() {
    let body = object("domain", "example.com", &stats(4, 2));
    let server = api("/api/v3/domains/example.com", 200, &body).await;
    let collection = collect(&server, &Indicator::parse_domain("Example.COM.").unwrap())
        .await
        .unwrap();
    assert_eq!(
        codes(&collection),
        vec!["ti.virustotal.observed", "ti.virustotal.detections"]
    );
    let detections = &collection.findings[1];
    assert_eq!(
        detections.title(),
        "VirusTotal reports detections for this indicator"
    );
    assert!(
        detections
            .detail()
            .contains("4 engine(s) of 91 categorized example.com as malicious and 2 as suspicious"),
        "{}",
        detections.detail()
    );
    assert!(
        detections
            .detail()
            .contains("were not verified by Sentinel")
    );
    // Provider figures and Sentinel capture confidence stay separate.
    assert_eq!(collection.observations()[0].confidence(), CONFIDENCE);
    assert_eq!(detections.confidence(), CONFIDENCE);
    assert_attributed(&collection);
}

#[tokio::test]
async fn detection_counts_never_change_confidence_or_severity() {
    for (malicious, suspicious) in [(0, 0), (1, 0), (0, 1), (90, 0), (10_000, 0)] {
        let body = object("domain", "example.com", &stats(malicious, suspicious));
        let server = api("/api/v3/domains/example.com", 200, &body).await;
        let collection = collect(&server, &Indicator::parse_domain("example.com").unwrap())
            .await
            .unwrap();
        assert_eq!(collection.observations()[0].confidence(), CONFIDENCE);
        assert_attributed(&collection);
    }
}

#[tokio::test]
async fn url_lookup_uses_the_documented_identifier() {
    let body = object("url", SHA, &stats(0, 1));
    let server = api(&format!("/api/v3/urls/{EXAMPLE_URL_ID}"), 200, &body).await;
    let target = Indicator::parse_url("https://EXAMPLE.com").unwrap();
    let collection = collect(&server, &target).await.unwrap();
    assert_eq!(
        codes(&collection),
        vec!["ti.virustotal.observed", "ti.virustotal.detections"]
    );
    assert_eq!(collection.observations()[0].indicator(), &target);
    assert_attributed(&collection);
}

#[tokio::test]
async fn sha256_lookup_and_other_hashes_are_unsupported() {
    let body = object("file", SHA, &stats(12, 0));
    let server = api(&format!("/api/v3/files/{SHA}"), 200, &body).await;
    let target = Indicator::parse_file_hash(&SHA.to_uppercase()).unwrap();
    let collection = collect(&server, &target).await.unwrap();
    assert_eq!(
        reputation(&collection).metric("last_analysis_stats.malicious"),
        Some(12)
    );

    let c = collector(&server, Some(KEY));
    for other in [
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ] {
        let hash = Indicator::parse_file_hash(other).unwrap();
        assert!(!c.supports(&hash), "{other}");
        let result = c.collect(&hash, &context(http(&[&server]), 10)).await;
        assert!(matches!(result, Err(CollectorError::RefusedTarget)));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_response_about_another_object_is_rejected() {
    let body = object("ip_address", "1.1.1.1", &stats(9, 0));
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &body).await;
    assert!(matches!(
        collect(&server, &ip("8.8.8.8")).await,
        Err(CollectorError::InvalidResponse(
            "VirusTotal response describes a different object"
        ))
    ));
    let body = object("domain", "8.8.8.8", &stats(9, 0));
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &body).await;
    assert!(matches!(
        collect(&server, &ip("8.8.8.8")).await,
        Err(CollectorError::InvalidResponse(
            "VirusTotal response describes a different object type"
        ))
    ));
}

// --------------------------------------------------------- not found

#[tokio::test]
async fn documented_not_found_is_a_recorded_absence_not_an_empty_result() {
    let server = api("/api/v3/domains/example.com", 404, NOT_FOUND_BODY).await;
    let target = Indicator::parse_domain("example.com").unwrap();
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig::default(),
        target.clone(),
    )
    .await;
    let investigation = &run.investigation;
    assert_eq!(
        investigation.sources()[0].outcome(),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    let observation = &investigation.observations()[0];
    assert_eq!(
        observation.data(),
        &ObservationData::ProviderNoRecord(ProviderNoRecord {
            provider: "virustotal".into()
        })
    );
    assert_eq!(
        observation.raw_response_hash(),
        Some(Sha256Digest::of(NOT_FOUND_BODY.as_bytes()))
    );
    let findings = investigation.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code(), &NOT_FOUND);
    assert_eq!(findings[0].severity(), Severity::Info);
    assert_eq!(findings[0].evidence(), [observation.id()]);
    assert!(findings[0].detail().contains(
        "Absence from VirusTotal's dataset is not evidence that the indicator is benign"
    ));
    assert!(
        !findings
            .iter()
            .any(|f| f.code() == &NO_DETECTIONS || f.code() == &OBSERVED),
        "not found is not 'no detections'"
    );
}

#[tokio::test]
async fn an_undocumented_404_is_a_failure() {
    for body in [
        "<html>Not Found</html>",
        "",
        r#"{"error": {"code": "WrongCredentialsError"}}"#,
    ] {
        let server = api("/api/v3/domains/example.com", 404, body).await;
        let run = engine_run(
            collector(&server, Some(KEY)),
            &[&server],
            EngineConfig::default(),
            Indicator::parse_domain("example.com").unwrap(),
        )
        .await;
        assert_eq!(
            run.investigation.sources()[0].outcome(),
            &SourceOutcome::Failed {
                error: "unexpected not-found response from VirusTotal (HTTP 404)".into()
            },
            "{body:?}"
        );
        assert!(run.investigation.observations().is_empty());
        assert!(run.investigation.findings().is_empty());
    }
}

// ------------------------------------------------------ availability

#[tokio::test]
async fn missing_key_is_unavailable_and_sends_nothing() {
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, "{}").await;
    let missing = collector(&server, None);
    assert_eq!(
        missing.availability(),
        Availability::Unavailable {
            reason: "API key not configured (set SENTINEL_VIRUSTOTAL_KEY)"
        }
    );
    let direct = missing
        .collect(&ip("8.8.8.8"), &context(http(&[&server]), 10))
        .await;
    assert!(matches!(direct, Err(CollectorError::NotConfigured)));

    let run = engine_run(
        collector(&server, None),
        &[&server],
        EngineConfig::default(),
        ip("8.8.8.8"),
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::Unavailable {
            reason: "API key not configured (set SENTINEL_VIRUSTOTAL_KEY)".into()
        }
    );
    assert!(run.investigation.observations().is_empty());
    assert!(run.investigation.findings().is_empty());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_key_configuration_is_unavailable() {
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, "{}").await;
    for bad in ["", "key with spaces", "line\nbreak", "ünïcode"] {
        assert_eq!(
            collector(&server, Some(bad)).availability(),
            Availability::Unavailable {
                reason: "API key configuration is invalid"
            },
            "{bad:?}"
        );
    }
    let run = engine_run(
        collector(&server, Some("bad key")),
        &[&server],
        EngineConfig::default(),
        ip("8.8.8.8"),
    )
    .await;
    assert!(matches!(
        run.investigation.sources()[0].outcome(),
        SourceOutcome::Unavailable { .. }
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ---------------------------------------------------------- failures

#[tokio::test]
async fn error_statuses_are_distinct_failures_never_no_results() {
    let cases = [
        (400, "request rejected by VirusTotal as invalid (HTTP 400)"),
        (
            401,
            "API key rejected by VirusTotal (wrong key or inactive account) (HTTP 401)",
        ),
        (
            403,
            "operation not permitted for this VirusTotal API key (HTTP 403)",
        ),
        (429, "VirusTotal quota or rate limit exceeded (HTTP 429)"),
        (500, "VirusTotal server error (HTTP 500)"),
        (502, "VirusTotal server error (HTTP 502)"),
        (503, "VirusTotal server error (HTTP 503)"),
        (504, "VirusTotal server error (HTTP 504)"),
        (204, "unexpected HTTP status 204"),
        (409, "unexpected HTTP status 409"),
    ];
    for (status, expected) in cases {
        let body =
            r#"{"error": {"code": "QuotaExceededError", "message": "PROVIDER TEXT \u001b[2J"}}"#;
        let server = api("/api/v3/ip_addresses/8.8.8.8", status, body).await;
        let run = engine_run(
            collector(&server, Some(KEY)),
            &[&server],
            EngineConfig::default(),
            ip("8.8.8.8"),
        )
        .await;
        assert_eq!(
            run.investigation.sources()[0].outcome(),
            &SourceOutcome::Failed {
                error: expected.into()
            },
            "{status}"
        );
        assert!(run.investigation.observations().is_empty(), "{status}");
        assert!(
            run.investigation.findings().is_empty(),
            "{status}: a failure yields no findings"
        );
    }
}

#[tokio::test]
async fn malformed_and_incomplete_responses() {
    for body in [
        "<html>",
        "{",
        "[]",
        r#"{"data": null}"#,
        r#"{"data": {"type": "ip_address"}}"#,
    ] {
        let server = api("/api/v3/ip_addresses/8.8.8.8", 200, body).await;
        assert!(
            matches!(
                collect(&server, &ip("8.8.8.8")).await,
                Err(CollectorError::InvalidResponse(_))
            ),
            "{body:?}"
        );
    }
    // Valid JSON, missing and mistyped fields: kept, degraded, reported.
    let body = r#"{"data": {"type": "ip_address", "id": "8.8.8.8", "attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": "0"}, "reputation": [], "tags": {}}}}"#;
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, body).await;
    let collection = collect(&server, &ip("8.8.8.8")).await.unwrap();
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    assert_eq!(
        codes(&collection),
        vec![
            "ti.virustotal.observed",
            "ti.virustotal.response_incomplete"
        ],
        "incomplete counts are not 'no detections'"
    );
    assert_attributed(&collection);
}

#[tokio::test]
async fn never_analyzed_objects_yield_no_detection_statement() {
    let body = object(
        "domain",
        "example.com",
        r#"{"harmless": 0, "malicious": 0, "suspicious": 0, "timeout": 0, "undetected": 0}"#,
    );
    let server = api("/api/v3/domains/example.com", 200, &body).await;
    let collection = collect(&server, &Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    assert_eq!(codes(&collection), vec!["ti.virustotal.observed"]);
}

#[tokio::test]
async fn deep_nesting_and_huge_arrays_are_contained() {
    let deep = format!(
        r#"{{"data": {{"type": "ip_address", "id": "8.8.8.8", "attributes": {{"x": {}{}}}}}}}"#,
        "[".repeat(50_000),
        "]".repeat(50_000)
    );
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &deep).await;
    assert!(matches!(
        collect(&server, &ip("8.8.8.8")).await,
        Err(CollectorError::InvalidResponse(_))
    ));
    let tags: Vec<String> = (0..50_000).map(|i| format!("\"t{i}\"")).collect();
    let huge = object("ip_address", "8.8.8.8", &stats(0, 0)).replace(
        r#""tags": ["cdn"]"#,
        &format!(r#""tags": [{}]"#, tags.join(",")),
    );
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &huge).await;
    let collection = collect(&server, &ip("8.8.8.8")).await.unwrap();
    assert_eq!(reputation(&collection).tags.len(), 32);
    assert!(codes(&collection).contains(&"ti.virustotal.response_incomplete"));
}

#[tokio::test]
async fn request_timeout_and_source_timeout() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v3/ip_addresses/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{}")
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&server)
        .await;
    let fast = HttpClient::for_tests(
        HttpConfig {
            request_timeout: Duration::from_millis(300),
            ..HttpConfig::default()
        },
        vec![*server.address()],
    )
    .unwrap();
    let result = collector(&server, Some(KEY))
        .collect(&ip("8.8.8.8"), &context(fast, 10))
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::Timeout))
    ));

    let config = EngineConfig {
        source_timeout: Duration::from_millis(500),
        ..EngineConfig::default()
    };
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        config,
        ip("8.8.8.8"),
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
    assert!(run.investigation.findings().is_empty());
}

#[tokio::test]
async fn request_budget_is_consumed_and_enforced() {
    let body = object("ip_address", "8.8.8.8", &stats(0, 0));
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &body).await;
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            max_requests: 7,
            ..EngineConfig::default()
        },
        ip("8.8.8.8"),
    )
    .await;
    assert_eq!(run.stats.requests_used, 1);

    let ctx = context(http(&[&server]), 1);
    let c = collector(&server, Some(KEY));
    assert!(c.collect(&ip("8.8.8.8"), &ctx).await.is_ok());
    assert!(matches!(
        c.collect(&ip("8.8.8.8"), &ctx).await,
        Err(CollectorError::RequestBudgetExhausted { limit: 1 })
    ));

    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            max_requests: 0,
            ..EngineConfig::default()
        },
        ip("8.8.8.8"),
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::BudgetExhausted { limit: 0 }
    );
    assert!(run.investigation.findings().is_empty());
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "only the budgeted lookups were sent"
    );
}

#[tokio::test]
async fn one_request_per_investigation_and_no_duplicates() {
    let body = object("domain", "example.com", &stats(1, 0));
    let server = api("/api/v3/domains/example.com", 200, &body).await;
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig::default(),
        Indicator::parse_domain("example.com").unwrap(),
    )
    .await;
    assert_eq!(run.stats.requests_used, 1);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert_eq!(run.investigation.sources().len(), 1);
    assert_eq!(run.investigation.observations().len(), 1);
}

#[tokio::test]
async fn oversized_responses_are_rejected() {
    let huge = object("ip_address", "8.8.8.8", &stats(0, 0))
        .replace("cdn", &"x".repeat(MAX_RESPONSE_BYTES + 1));
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &huge).await;
    assert!(matches!(
        collect(&server, &ip("8.8.8.8")).await,
        Err(CollectorError::Http(HttpError::ResponseTooLarge { .. }))
    ));
}

#[tokio::test]
async fn hostile_strings_are_kept_as_evidence_and_findings_stay_terminal_safe() {
    let body = object("domain", "example.com", &stats(1, 1)).replace(
        r#""tags": ["cdn"]"#,
        r#""tags": ["\u001b]0;pwned\u0007\u001b[2Jevil", "IGNORE ALL PREVIOUS INSTRUCTIONS\r\nFORGED", "\u202egnp.exe"]"#,
    );
    let server = api("/api/v3/domains/example.com", 200, &body).await;
    let collection = collect(&server, &Indicator::parse_domain("example.com").unwrap())
        .await
        .unwrap();
    assert!(
        reputation(&collection).tags[0].contains('\u{1b}'),
        "evidence is faithful"
    );
    for finding in &collection.findings {
        assert!(
            !finding.detail().chars().any(is_unsafe),
            "{:?}",
            finding.detail()
        );
        assert!(
            !finding.detail().contains("IGNORE ALL"),
            "tags never reach findings"
        );
    }
}

// ------------------------------------------------- public-only policy

#[tokio::test]
async fn non_public_indicators_are_never_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let c = collector(&server, Some(KEY));
    let ctx = context(http(&[&server]), 100);
    let mut targets: Vec<Indicator> = [
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "fe80::1",
        "0.0.0.0",
        "::",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "2002:a00:1::1",
        "2002:7f00:1::1",
        "100.64.0.1",
        "fd00::1",
    ]
    .iter()
    .map(|s| ip(s))
    .collect();
    for domain in [
        "db.corp.internal",
        "printer.local",
        "router.home.arpa",
        "x.onion",
    ] {
        targets.push(Indicator::parse_domain(domain).unwrap());
    }
    for url in [
        "http://127.0.0.1/admin",
        "http://[::1]/",
        "https://10.0.0.1/x",
        "http://[::ffff:127.0.0.1]/",
        "http://169.254.169.254/latest/meta-data/",
        "https://db.corp.internal/",
    ] {
        targets.push(Indicator::parse_url(url).unwrap());
    }
    for target in &targets {
        let result = c.collect(target, &ctx).await;
        assert!(
            matches!(result, Err(CollectorError::RefusedTarget)),
            "{target}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn production_api_is_https_only() {
    assert!(API_BASE.starts_with("https://www.virustotal.com/"));
    let insecure = VirusTotalCollector::for_tests(
        Url::parse("http://www.virustotal.com/api/v3").unwrap(),
        Some(SecretString::from(KEY)),
    );
    let ctx = context(HttpClient::new(HttpConfig::default()).unwrap(), 10);
    let result = insecure.collect(&ip("8.8.8.8"), &ctx).await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::Blocked(
            PolicyViolation::InsecureScheme
        )))
    ));
}

#[tokio::test]
async fn redirect_to_plain_http_is_refused() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v3/ip_addresses/8.8.8.8"))
        .respond_with(ResponseTemplate::new(301).insert_header(
            "location",
            "http://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        ))
        .mount(&server)
        .await;
    let result = collect(&server, &ip("8.8.8.8")).await;
    assert!(
        matches!(
            result,
            Err(CollectorError::Http(HttpError::Blocked(
                PolicyViolation::InsecureScheme | PolicyViolation::CrossOriginRedirect
            )))
        ),
        "{result:?}"
    );
}

// --------------------------------------------------- secret leakage

#[tokio::test]
async fn cross_origin_redirect_never_receives_the_key() {
    let api_server = MockServer::start().await;
    let attacker = MockServer::start().await;
    Mock::given(path("/api/v3/ip_addresses/8.8.8.8"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/collect", attacker.uri())),
        )
        .mount(&api_server)
        .await;
    Mock::given(path("/collect"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&attacker)
        .await;

    let result = collector(&api_server, Some(KEY))
        .collect(
            &ip("8.8.8.8"),
            &context(http(&[&api_server, &attacker]), 10),
        )
        .await;
    assert!(matches!(
        result,
        Err(CollectorError::Http(HttpError::Blocked(
            PolicyViolation::CrossOriginRedirect
        )))
    ));
    assert!(
        attacker.received_requests().await.unwrap().is_empty(),
        "the key must not cross origins"
    );
}

#[tokio::test]
async fn an_echoed_key_is_redacted_before_storage() {
    let body = object("ip_address", "8.8.8.8", &stats(0, 0))
        .replace(
            r#""tags": ["cdn"]"#,
            &format!(r#""tags": ["key={KEY}", "{KEY}"]"#),
        )
        .replace("owner@example.net", KEY);
    let server = api("/api/v3/ip_addresses/8.8.8.8", 200, &body).await;
    let collection = collect(&server, &ip("8.8.8.8")).await.unwrap();
    let r = reputation(&collection);
    assert_eq!(r.tags, vec!["key=REDACTED", "REDACTED"]);
    assert!(r.issues.contains(&ECHOED_KEY_ISSUE.to_owned()));
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    let json = serde_json::to_string(&collection.observations()).unwrap()
        + &serde_json::to_string(&collection.findings).unwrap();
    assert!(!json.contains(KEY));
}

#[tokio::test]
async fn the_key_never_appears_in_logs_errors_statuses_or_output() {
    let logs = global_log_capture();

    let ok = api(
        "/api/v3/ip_addresses/8.8.8.8",
        200,
        &object("ip_address", "8.8.8.8", &stats(0, 0)),
    )
    .await;
    let denied = api(
        "/api/v3/ip_addresses/8.8.8.8",
        401,
        &format!(
            r#"{{"error": {{"code": "WrongCredentialsError", "message": "Wrong API key {KEY}"}}}}"#
        ),
    )
    .await;

    let mut texts: Vec<String> = Vec::new();
    texts.push(format!("{:?}", collector(&ok, Some(KEY))));
    let error = collect(&denied, &ip("8.8.8.8")).await.unwrap_err();
    texts.push(error.to_string());
    texts.push(format!("{error:?}"));
    for server in [&ok, &denied] {
        let run = engine_run(
            collector(server, Some(KEY)),
            &[server],
            EngineConfig::default(),
            ip("8.8.8.8"),
        )
        .await;
        texts.push(serde_json::to_string(&run.investigation).unwrap());
        texts.push(format!("{:?}", run.investigation));
    }
    let captured = logs.contents();
    let marker = format!(
        "127.0.0.1:{}/api/v3/ip_addresses/8.8.8.8",
        ok.address().port()
    );
    assert!(
        captured.contains("sending request") && captured.contains(&marker),
        "logging must be active"
    );
    texts.push(captured);
    for text in &texts {
        assert!(
            !text.contains(KEY),
            "API key leaked into: {}",
            &text[..text.len().min(300)]
        );
    }
    let received = ok.received_requests().await.unwrap();
    assert!(!received.is_empty());
    for request in received {
        assert!(
            !request.url.as_str().contains(KEY),
            "key must not be in the URL"
        );
        assert_eq!(
            request
                .headers
                .get("x-apikey")
                .map(|v| v.to_str().unwrap().to_owned()),
            Some(KEY.to_owned())
        );
    }
}

// ------------------------------------------------------- identifiers

#[test]
fn base64url_matches_rfc_4648_vectors_without_padding() {
    for (input, expected) in [
        (&b""[..], ""),
        (b"f", "Zg"),
        (b"fo", "Zm8"),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg"),
        (b"fooba", "Zm9vYmE"),
        (b"foobar", "Zm9vYmFy"),
        (b"\xff\xfe\xfd>?", "__79Pj8"),
    ] {
        assert_eq!(base64url_unpadded(input), expected);
    }
    // The documented example URL (value computed with the documented Python code).
    let url = HttpUrl::parse("http://www.somedomain.com/this/is/my/url").unwrap();
    assert_eq!(
        url_identifier(&url),
        "aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA"
    );
}

fn decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let values: Vec<u32> = text
        .bytes()
        .map(|c| u32::try_from(ALPHABET.iter().position(|a| *a == c).unwrap()).unwrap())
        .collect();
    let mut out = Vec::new();
    for chunk in values.chunks(4) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, v)| n | (v << (18 - 6 * i)));
        for i in 0..chunk.len() - 1 {
            out.push(u8::try_from((n >> (16 - 8 * i)) & 0xff).unwrap());
        }
    }
    out
}

proptest! {
    #[test]
    fn base64url_round_trips_and_is_path_safe(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let encoded = base64url_unpadded(&bytes);
        prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        prop_assert_eq!(encoded.len(), (bytes.len() * 4).div_ceil(3));
        prop_assert_eq!(decode(&encoded), bytes);
    }

    #[test]
    fn the_indicator_only_fills_one_path_segment(label in "[a-z0-9]{1,20}", path_part in "[a-zA-Z0-9/?#%._~-]{0,60}") {
        let c = VirusTotalCollector::new(Some(SecretString::from(KEY)));
        let domain = Indicator::parse_domain(&format!("{label}.example")).unwrap();
        let url = c.object_url(&domain).unwrap();
        prop_assert_eq!(url.host_str(), Some("www.virustotal.com"));
        prop_assert_eq!(url.path(), format!("/api/v3/domains/{label}.example"));
        if let Ok(target) = Indicator::parse_url(&format!("https://{label}.example/{path_part}")) {
            let url = c.object_url(&target).unwrap();
            prop_assert_eq!(url.host_str(), Some("www.virustotal.com"));
            prop_assert_eq!(url.scheme(), "https");
            prop_assert!(url.query().is_none() && url.fragment().is_none());
            let segments: Vec<&str> = url.path_segments().unwrap().collect();
            prop_assert_eq!(segments.len(), 4);
            prop_assert_eq!(&segments[..3], &["api", "v3", "urls"]);
        }
    }
}

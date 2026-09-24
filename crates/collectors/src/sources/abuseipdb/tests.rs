//! AbuseIPDB collector tests against a mock API, through the real HTTP client.

use std::sync::Arc;
use std::time::Duration;

use sentinel_core::text::is_unsafe;
use sentinel_core::{Provenance, Sha256Digest, SourceOutcome, TimeLimit};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig, EngineRun};
use crate::http::{HttpClient, HttpConfig, HttpError, PolicyViolation};
use crate::testing::{context, global_log_capture};

const KEY: &str = "abuseipdb-TEST-KEY-must-never-leak-0123456789";

fn clean(ip: &str, score: u64, total: u64, distinct: u64, last: &str) -> String {
    format!(
        r#"{{"data": {{"ipAddress": "{ip}", "isPublic": true, "ipVersion": 4, "isWhitelisted": false,
            "abuseConfidenceScore": {score}, "countryCode": "US", "usageType": "Content Delivery Network",
            "isp": "Google LLC", "domain": "google.com", "hostnames": ["dns.google"], "isTor": false,
            "totalReports": {total}, "numDistinctUsers": {distinct}, "lastReportedAt": {last}}}}}"#
    )
}

/// A mock that answers only a correctly authenticated, well-formed check.
async fn api(ip: &str, status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .and(query_param("ipAddress", ip))
        .and(query_param("maxAgeInDays", "90"))
        .and(header("key", KEY))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;
    server
}

fn endpoint(server: &MockServer) -> Url {
    Url::parse(&format!("{}/api/v2/check", server.uri())).unwrap()
}

fn collector(server: &MockServer, key: Option<&str>) -> AbuseIpDbCollector {
    AbuseIpDbCollector::for_tests(endpoint(server), key.map(SecretString::from))
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

async fn collect(server: &MockServer, target: &str) -> Result<Collection, CollectorError> {
    collector(server, Some(KEY))
        .collect(&ip(target), &context(http(&[server]), 10))
        .await
}

fn reputation(collection: &Collection) -> &IpReputation {
    match collection.observations()[0].data() {
        ObservationData::IpReputation(r) => r,
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
    collector: AbuseIpDbCollector,
    servers: &[&MockServer],
    config: EngineConfig,
    target: &str,
) -> EngineRun {
    let mut engine = Engine::new(http(servers), Arc::new(FixedClock::default()), config);
    engine.register(Arc::new(collector)).unwrap();
    engine.investigate(ip(target)).await.unwrap()
}

// ------------------------------------------------------------- success

#[tokio::test]
async fn ipv4_success_with_no_reports() {
    let body = clean("8.8.8.8", 0, 0, 0, "null");
    let server = api("8.8.8.8", 200, &body).await;
    let collection = collect(&server, "8.8.8.8").await.unwrap();
    let r = reputation(&collection);

    assert_eq!(r.provider, "abuseipdb");
    assert_eq!(r.metric(ABUSE_CONFIDENCE_SCORE), Some(0));
    assert_eq!(r.metric(TOTAL_REPORTS), Some(0));
    assert_eq!(r.window_days, Some(90));
    assert_eq!(r.hostnames, vec!["dns.google"]);
    assert_eq!(
        r.context_source.as_deref(),
        Some("IPinfo (as reported by AbuseIPDB)")
    );

    let observation = &collection.observations()[0];
    assert_eq!(observation.source(), &SOURCE);
    assert_eq!(observation.confidence(), CONFIDENCE);
    assert_eq!(
        observation.raw_response_hash(),
        Some(Sha256Digest::of(body.as_bytes()))
    );
    let Provenance::Https(p) = observation.provenance() else {
        panic!("https provenance")
    };
    assert!(
        p.endpoint()
            .ends_with("/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90"),
        "{}",
        p.endpoint()
    );
    assert!(!p.endpoint().contains(KEY));

    assert_eq!(
        codes(&collection),
        vec!["ti.abuseipdb.observed", "ti.abuseipdb.no_reports"]
    );
    assert!(
        collection.findings[1]
            .detail()
            .contains("Absence of reports is not evidence that the address is benign")
    );
    assert!(collection.relationships.is_empty());
    assert!(collection.pivots.is_empty());
}

#[tokio::test]
async fn ipv6_success() {
    let body = clean("2001:4860:4860::8888", 0, 0, 0, "null");
    let server = api("2001:4860:4860::8888", 200, &body).await;
    let collection = collect(&server, "2001:4860:4860::8888").await.unwrap();
    assert!(reputation(&collection).issues.is_empty());
}

#[tokio::test]
async fn reports_and_high_score_are_attributed_not_judged() {
    let body = clean("45.33.32.156", 95, 41, 12, r#""2026-09-20T08:15:00+00:00""#);
    let server2 = api("45.33.32.156", 200, &body).await;
    let collection = collect(&server2, "45.33.32.156").await.unwrap();

    assert_eq!(
        codes(&collection),
        vec![
            "ti.abuseipdb.observed",
            "ti.abuseipdb.abuse_reports",
            "ti.abuseipdb.high_abuse_confidence"
        ]
    );
    let high = collection
        .findings
        .iter()
        .find(|f| f.code() == &HIGH_ABUSE_CONFIDENCE)
        .unwrap();
    assert!(
        high.detail()
            .starts_with("AbuseIPDB reports an abuse confidence score of 95/100")
    );
    assert!(high.detail().contains("not independent proof of intent"));
    for finding in &collection.findings {
        assert_eq!(
            finding.severity(),
            Severity::Info,
            "no Sentinel severity ranking of provider claims"
        );
        let lower = finding.detail().to_lowercase();
        for verdict in [
            "is malicious",
            "attacker",
            "compromised",
            "botnet",
            "risk score",
        ] {
            assert!(!lower.contains(verdict), "{verdict}: {}", finding.detail());
        }
    }
    // Provider metric and Sentinel observation confidence stay separate.
    assert_eq!(
        reputation(&collection).metric(ABUSE_CONFIDENCE_SCORE),
        Some(95)
    );
    assert_eq!(collection.observations()[0].confidence(), CONFIDENCE);
    assert_eq!(high.confidence(), CONFIDENCE);
}

#[tokio::test]
async fn high_score_threshold_is_the_providers_documented_75() {
    for (score, expected) in [(74, false), (75, true), (100, true)] {
        let server = api(
            "45.33.32.156",
            200,
            &clean(
                "45.33.32.156",
                score,
                3,
                3,
                r#""2026-09-01T00:00:00+00:00""#,
            ),
        )
        .await;
        let collection = collect(&server, "45.33.32.156").await.unwrap();
        assert_eq!(
            codes(&collection).contains(&"ti.abuseipdb.high_abuse_confidence"),
            expected,
            "{score}"
        );
    }
}

#[tokio::test]
async fn allowlist_and_tor_flags() {
    let body = clean("45.33.32.156", 0, 0, 0, "null")
        .replace(r#""isWhitelisted": false"#, r#""isWhitelisted": true"#)
        .replace(r#""isTor": false"#, r#""isTor": true"#);
    let server = api("45.33.32.156", 200, &body).await;
    let collection = collect(&server, "45.33.32.156").await.unwrap();
    assert!(codes(&collection).contains(&"ti.abuseipdb.allowlisted"));
    assert!(codes(&collection).contains(&"ti.abuseipdb.tor"));
}

// ------------------------------------------------------ availability

#[tokio::test]
async fn missing_key_is_unavailable_not_no_reports() {
    let server = api("8.8.8.8", 200, &clean("8.8.8.8", 0, 0, 0, "null")).await;
    let missing = collector(&server, None);
    assert_eq!(
        missing.availability(),
        Availability::Unavailable {
            reason: "API key not configured (set SENTINEL_ABUSEIPDB_KEY)"
        }
    );
    // Defense in depth: even when called directly, nothing is sent.
    let direct = missing
        .collect(&ip("8.8.8.8"), &context(http(&[&server]), 10))
        .await;
    assert!(matches!(direct, Err(CollectorError::NotConfigured)));

    let run = engine_run(
        collector(&server, None),
        &[&server],
        EngineConfig::default(),
        "8.8.8.8",
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::Unavailable {
            reason: "API key not configured (set SENTINEL_ABUSEIPDB_KEY)".into()
        }
    );
    assert!(run.investigation.observations().is_empty());
    assert!(
        run.investigation.findings().is_empty(),
        "no 'no reports' finding without data"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_key_configuration_is_unavailable() {
    let server = api("8.8.8.8", 200, "{}").await;
    let long = "k".repeat(257);
    for bad in [
        "",
        " ",
        "key with spaces",
        "line\nbreak",
        "tab\tkey",
        "ünïcode",
        long.as_str(),
    ] {
        let c = collector(&server, Some(bad));
        assert_eq!(
            c.availability(),
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
        "8.8.8.8",
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
async fn error_statuses_are_failures_never_no_reports() {
    for status in [401, 403, 404, 422, 429, 500, 502, 503] {
        let server = api(
            "8.8.8.8",
            status,
            r#"{"errors": [{"detail": "nope", "status": 0}]}"#,
        )
        .await;
        let result = collect(&server, "8.8.8.8").await;
        assert!(
            matches!(result, Err(CollectorError::UnexpectedStatus(s)) if s == status),
            "{status}"
        );
        let run = engine_run(
            collector(&server, Some(KEY)),
            &[&server],
            EngineConfig::default(),
            "8.8.8.8",
        )
        .await;
        assert_eq!(
            run.investigation.sources()[0].outcome(),
            &SourceOutcome::Failed {
                error: format!("unexpected HTTP status {status}")
            }
        );
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
        r#"{"errors": []}"#,
        r#"{"data": null}"#,
        "[]",
    ] {
        let server = api("8.8.8.8", 200, body).await;
        assert!(
            matches!(
                collect(&server, "8.8.8.8").await,
                Err(CollectorError::InvalidResponse(_))
            ),
            "{body:?}"
        );
    }
    // Valid JSON, missing fields: kept, degraded, reported.
    let server = api("8.8.8.8", 200, r#"{"data": {"ipAddress": "8.8.8.8"}}"#).await;
    let collection = collect(&server, "8.8.8.8").await.unwrap();
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    assert_eq!(
        codes(&collection),
        vec!["ti.abuseipdb.observed", "ti.abuseipdb.response_incomplete"]
    );
    assert!(
        !codes(&collection).contains(&"ti.abuseipdb.no_reports"),
        "unknown count is not zero reports"
    );
}

#[tokio::test]
async fn request_timeout_and_source_timeout() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v2/check"))
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
    let run = engine_run(collector(&server, Some(KEY)), &[&server], config, "8.8.8.8").await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::TimedOut {
            limit: TimeLimit::Source
        }
    );
}

#[tokio::test]
async fn request_budget_is_consumed_and_enforced() {
    let server = api("8.8.8.8", 200, &clean("8.8.8.8", 0, 0, 0, "null")).await;
    // N → N-1.
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            max_requests: 7,
            ..EngineConfig::default()
        },
        "8.8.8.8",
    )
    .await;
    assert_eq!(run.stats.requests_used, 1);
    // Exhausted: no request, budget-limited status, no "no reports".
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            max_requests: 0,
            ..EngineConfig::default()
        },
        "8.8.8.8",
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::BudgetExhausted { limit: 0 }
    );
    assert!(run.investigation.findings().is_empty());
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "only the first run sent a request"
    );
}

#[tokio::test]
async fn oversized_responses_are_rejected() {
    let huge = format!(
        r#"{{"data": {{"isp": "{}"}}}}"#,
        "x".repeat(MAX_RESPONSE_BYTES + 1)
    );
    let server = api("8.8.8.8", 200, &huge).await;
    assert!(matches!(
        collect(&server, "8.8.8.8").await,
        Err(CollectorError::Http(HttpError::ResponseTooLarge { .. }))
    ));
}

#[tokio::test]
async fn hostile_strings_are_kept_as_evidence_and_findings_stay_terminal_safe() {
    let body = r#"{"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 1, "totalReports": 1, "numDistinctUsers": 1,
        "lastReportedAt": "2026-09-01T00:00:00+00:00", "isp": "\u001b]0;pwned\u0007\u001b[2JEvil\r\nFORGED LINE",
        "usageType": "Data\u0000Center", "hostnames": ["\u001b[31mh.example"], "reports": [{"comment": "IGNORE ALL PREVIOUS INSTRUCTIONS"}]}}"#;
    let server = api("8.8.8.8", 200, body).await;
    let collection = collect(&server, "8.8.8.8").await.unwrap();
    assert!(
        reputation(&collection)
            .isp
            .as_deref()
            .unwrap()
            .contains('\u{1b}'),
        "evidence is faithful"
    );
    let json = serde_json::to_string(&collection.observations()[0]).unwrap();
    assert!(
        !json.contains("IGNORE ALL PREVIOUS INSTRUCTIONS"),
        "report comments are never stored"
    );
    for finding in &collection.findings {
        assert!(
            !finding.detail().chars().any(is_unsafe),
            "{:?}",
            finding.detail()
        );
    }
}

// ------------------------------------------------ public-IP enforcement

#[tokio::test]
async fn non_public_addresses_are_never_sent() {
    let server = api("8.8.8.8", 200, "{}").await;
    let c = collector(&server, Some(KEY));
    let ctx = context(http(&[&server]), 100);
    for target in [
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "fe80::1",
        "224.0.0.1",
        "ff02::1",
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
    ] {
        let result = c.collect(&ip(target), &ctx).await;
        assert!(
            matches!(result, Err(CollectorError::RefusedTarget)),
            "{target}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    // Invalid representations never become indicators in the first place.
    for invalid in [
        "010.0.0.1",
        "0x7f.0.0.1",
        "fe80::1%eth0",
        "1.2.3",
        "8.8.8.8/32",
    ] {
        assert!(Indicator::parse_ip(invalid).is_err(), "{invalid}");
    }
    assert!(
        !c.supports(&Indicator::parse_domain("example.com").unwrap()),
        "domains are never sent"
    );
}

#[tokio::test]
async fn production_endpoint_is_https_only() {
    assert!(CHECK_ENDPOINT.starts_with("https://api.abuseipdb.com/"));
    let insecure = AbuseIpDbCollector::for_tests(
        Url::parse("http://api.abuseipdb.com/api/v2/check").unwrap(),
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

// --------------------------------------------------- secret leakage

#[tokio::test]
async fn cross_origin_redirect_never_receives_the_key() {
    let api_server = MockServer::start().await;
    let attacker = MockServer::start().await;
    Mock::given(path("/api/v2/check"))
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
    let body = format!(
        r#"{{"data": {{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0,
            "isp": "Your key is {KEY}", "domain": "{KEY}.example", "hostnames": ["{KEY}"]}}}}"#
    );
    let server = api("8.8.8.8", 200, &body).await;
    let collection = collect(&server, "8.8.8.8").await.unwrap();
    let r = reputation(&collection);
    assert_eq!(r.isp.as_deref(), Some("Your key is REDACTED"));
    assert!(
        r.issues
            .contains(&"response contained the API key; it was redacted".to_owned())
    );
    let json = serde_json::to_string(&collection.observations()).unwrap()
        + &serde_json::to_string(&collection.findings).unwrap();
    assert!(!json.contains(KEY));
}

#[tokio::test]
async fn the_key_never_appears_in_logs_errors_statuses_or_output() {
    let logs = global_log_capture();

    let ok = api("8.8.8.8", 200, &clean("8.8.8.8", 0, 0, 0, "null")).await;
    let denied = api(
        "8.8.8.8",
        401,
        r#"{"errors": [{"detail": "Authentication failed", "status": 401}]}"#,
    )
    .await;

    let mut texts: Vec<String> = Vec::new();
    // Debug formatting of the configured collector.
    texts.push(format!("{:?}", collector(&ok, Some(KEY))));
    // Errors (Display and Debug).
    let error = collect(&denied, "8.8.8.8").await.unwrap_err();
    texts.push(error.to_string());
    texts.push(format!("{error:?}"));
    // Full engine runs: statuses, observations, findings, JSON.
    for server in [&ok, &denied] {
        let run = engine_run(
            collector(server, Some(KEY)),
            &[server],
            EngineConfig::default(),
            "8.8.8.8",
        )
        .await;
        texts.push(serde_json::to_string(&run.investigation).unwrap());
        texts.push(format!("{:?}", run.investigation));
    }
    let captured = logs.contents();
    // This test's own traffic must be in the log (the capture is live).
    let marker = format!("127.0.0.1:{}/api/v2/check", ok.address().port());
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
    // The key was really sent, in the header only.
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
                .get("key")
                .map(|v| v.to_str().unwrap().to_owned()),
            Some(KEY.to_owned())
        );
    }
}

//! URLhaus collector tests against a mock API, through the real HTTP client.

use std::sync::Arc;
use std::time::Duration;

use sentinel_core::text::is_unsafe;
use sentinel_core::{HttpMethod, Provenance, Sha256Digest, SourceOutcome, TimeLimit};
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::clock::testing::FixedClock;
use crate::engine::{Engine, EngineConfig, EngineRun};
use crate::http::{HttpClient, HttpConfig, HttpError, PolicyViolation};
use crate::testing::{context, global_log_capture};

const KEY: &str = "urlhaus-TEST-AUTH-KEY-must-never-leak-24680";
const SSKY: &str =
    "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/";
const DOCUMENTED_URL: &str = parse::tests::DOCUMENTED_URL;
const DOCUMENTED_HOST: &str = parse::tests::DOCUMENTED_HOST;
const NO_RESULTS_BODY: &str = r#"{"query_status": "no_results"}"#;

fn form(field: &str, value: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair(field, value)
        .finish()
}

/// A mock that answers only an authenticated POST of exactly `field=value`.
async fn api(endpoint: &str, field: &str, value: &str, status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/{endpoint}/")))
        .and(header("auth-key", KEY))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string(form(field, value)))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(&server)
        .await;
    server
}

async fn host_api(host: &str, status: u16, body: &str) -> MockServer {
    api("host", "host", host, status, body).await
}

fn base(server: &MockServer) -> Url {
    Url::parse(&format!("{}/v1/", server.uri())).unwrap()
}

fn collector(server: &MockServer, key: Option<&str>) -> UrlhausCollector {
    UrlhausCollector::for_tests(base(server), key.map(SecretString::from))
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

fn domain(s: &str) -> Indicator {
    Indicator::parse_domain(s).unwrap()
}

async fn collect(server: &MockServer, target: &Indicator) -> Result<Collection, CollectorError> {
    collector(server, Some(KEY))
        .collect(target, &context(http(&[server]), 10))
        .await
}

fn listing(collection: &Collection) -> &ProviderListing {
    match collection.observations()[0].data() {
        ObservationData::ProviderListing(l) => l,
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
    collector: UrlhausCollector,
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
        assert_eq!(finding.severity(), Severity::Info, "{}", finding.code());
        assert!(finding.detail().contains("URLhaus"), "{}", finding.detail());
        assert!(
            !finding.detail().chars().any(is_unsafe),
            "{:?}",
            finding.detail()
        );
        let lower = finding.detail().to_lowercase();
        for verdict in [
            "is malicious",
            "is dangerous",
            "compromised=",
            "attacker",
            "risk score",
            "threat score",
        ] {
            assert!(!lower.contains(verdict), "{verdict}: {}", finding.detail());
        }
    }
}

// --------------------------------------------------- indicator types

#[tokio::test]
async fn url_listed_with_provenance_digest_and_evidence_integrity() {
    let server = api("url", "url", SSKY, 200, DOCUMENTED_URL).await;
    let target = Indicator::parse_url(SSKY).unwrap();
    let collection = collect(&server, &target).await.unwrap();
    let l = listing(&collection);
    assert_eq!(l.provider, "urlhaus");
    assert_eq!(
        l.attribute("threat").collect::<Vec<_>>(),
        ["malware_download"]
    );

    let observation = &collection.observations()[0];
    assert_eq!(observation.indicator(), &target);
    assert_eq!(observation.source(), &SOURCE);
    assert_eq!(observation.confidence(), CONFIDENCE);
    assert_eq!(observation.collected_at(), FixedClock::default().0);
    assert_eq!(
        observation.raw_response_hash(),
        Some(Sha256Digest::of(DOCUMENTED_URL.as_bytes()))
    );
    let Provenance::Https(p) = observation.provenance() else {
        panic!("https provenance")
    };
    assert_eq!(p.http_method(), HttpMethod::Post);
    assert!(p.endpoint().ends_with("/v1/url/"), "{}", p.endpoint());
    assert!(!p.endpoint().contains(KEY));

    assert_eq!(
        codes(&collection),
        vec![
            "ti.urlhaus.url_listed",
            "ti.urlhaus.url_online",
            "ti.urlhaus.blocklist_status"
        ]
    );
    let listed = &collection.findings[0];
    assert!(
        listed.detail().starts_with(&format!(
            "URLhaus reports {SSKY} in its malware URL database (threat: malware_download; url_status: online; added 2019-01-19 01:33 UTC; payload signature(s): Heodo)."
        )),
        "{}",
        listed.detail()
    );
    assert!(listed.detail().contains("Sentinel did not access the URL"));
    assert!(
        collection.findings[2]
            .detail()
            .contains("blacklists.spamhaus_dbl: abused_legit_malware, blacklists.surbl: listed")
    );
    for finding in &collection.findings {
        assert_eq!(finding.evidence(), [observation.id()]);
    }
    assert!(collection.relationships.is_empty());
    assert!(collection.pivots.is_empty());
    assert_attributed(&collection);
}

#[tokio::test]
async fn domain_host_listed() {
    let server = host_api("vektorex.com", 200, DOCUMENTED_HOST).await;
    let collection = collect(&server, &domain("VEKTOREX.com.")).await.unwrap();
    assert_eq!(
        codes(&collection),
        vec!["ti.urlhaus.host_listed", "ti.urlhaus.blocklist_status"]
    );
    assert_eq!(
        collection.findings[0].detail(),
        "URLhaus reports 120 malware URL(s) observed on vektorex.com (2 of 2 returned entries reported online; first seen 2019-01-15 07:09 UTC; latest entry added 2019-02-11 07:45 UTC). A listed host can be a compromised legitimate site or shared hosting; the listed URLs were not accessed or investigated by Sentinel."
    );
    assert!(
        !collection.findings[1].detail().contains("surbl"),
        "'not listed' is not a listing"
    );
    assert!(
        collection.pivots.is_empty() && collection.relationships.is_empty(),
        "listed URLs and hosts never become pivots or relationships"
    );
    assert_attributed(&collection);
}

#[tokio::test]
async fn ipv4_host_lookup_and_unsupported_types() {
    let body = r#"{"query_status": "ok", "host": "45.61.49.78", "firstseen": "2019-08-10 09:02:05 UTC", "url_count": "2",
        "urls": [{"id": "223622", "url": "http://45.61.49.78/razor/r4z0r.mips", "url_status": "offline", "date_added": "2019-08-10 09:02:05 UTC"}]}"#;
    let server = host_api("45.61.49.78", 200, body).await;
    let collection = collect(&server, &Indicator::parse_ip("45.61.49.78").unwrap())
        .await
        .unwrap();
    assert_eq!(codes(&collection), vec!["ti.urlhaus.host_listed"]);
    assert_eq!(listing(&collection).metric(RETURNED_URLS_ONLINE), Some(0));

    let c = collector(&server, Some(KEY));
    for other in [
        Indicator::parse_ip("2001:4860:4860::8888").unwrap(),
        Indicator::parse_file_hash(&"a".repeat(64)).unwrap(),
    ] {
        assert!(!c.supports(&other), "{other}");
        assert!(matches!(
            c.collect(&other, &context(http(&[&server]), 10)).await,
            Err(CollectorError::RefusedTarget)
        ));
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn invalid_urls_never_become_indicators() {
    for invalid in [
        "http://localhost/",
        "ftp://example.com/x",
        "http://user:pass@example.com/",
        "javascript:alert(1)",
        "example.com/no-scheme",
        "http://",
    ] {
        assert!(Indicator::parse_url(invalid).is_err(), "{invalid}");
    }
}

// ------------------------------------------ not found vs. empty vs. error

#[tokio::test]
async fn no_results_is_a_recorded_absence() {
    let server = host_api("example.com", 200, NO_RESULTS_BODY).await;
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig::default(),
        domain("example.com"),
    )
    .await;
    let inv = &run.investigation;
    assert_eq!(
        inv.sources()[0].outcome(),
        &SourceOutcome::Succeeded { observations: 1 }
    );
    let observation = &inv.observations()[0];
    assert_eq!(
        observation.data(),
        &ObservationData::ProviderNoRecord(ProviderNoRecord {
            provider: "urlhaus".into()
        })
    );
    assert_eq!(inv.findings().len(), 1);
    assert_eq!(inv.findings()[0].code(), &NO_RESULTS);
    assert!(
        inv.findings()[0]
            .detail()
            .contains("absence from it is not evidence that the indicator is benign")
    );
}

#[tokio::test]
async fn empty_and_malformed_bodies_are_failures_never_no_results() {
    for (body, error) in [
        (
            "",
            "invalid response from source: URLhaus response is not valid JSON",
        ),
        (
            "{}",
            "invalid response from source: URLhaus response has no query_status",
        ),
        (
            "[]",
            "invalid response from source: URLhaus response is not a JSON object",
        ),
        (
            r#"{"query_status": "invalid_host"}"#,
            "invalid response from source: URLhaus rejected the indicator as invalid",
        ),
        (
            r#"{"query_status": "unknown_auth_key"}"#,
            "invalid response from source: URLhaus returned an undocumented query_status",
        ),
        (
            r#"{"query_status": "ok", "host": "other.example"}"#,
            "invalid response from source: URLhaus response describes a different URL or host",
        ),
    ] {
        let server = host_api("example.com", 200, body).await;
        let run = engine_run(
            collector(&server, Some(KEY)),
            &[&server],
            EngineConfig::default(),
            domain("example.com"),
        )
        .await;
        assert_eq!(
            run.investigation.sources()[0].outcome(),
            &SourceOutcome::Failed {
                error: error.into()
            },
            "{body:?}"
        );
        assert!(run.investigation.observations().is_empty(), "{body:?}");
        assert!(run.investigation.findings().is_empty(), "{body:?}");
    }
}

#[tokio::test]
async fn error_statuses_are_distinct_failures() {
    for (status, expected) in [
        (400, "request rejected by URLhaus as invalid (HTTP 400)"),
        (
            401,
            "URLhaus rejected the request as unauthorized (check the Auth-Key) (HTTP 401)",
        ),
        (403, "URLhaus refused access (forbidden) (HTTP 403)"),
        (
            404,
            "unexpected HTTP 404 from URLhaus (not-found answers use query_status) (HTTP 404)",
        ),
        (429, "URLhaus rate limit exceeded (HTTP 429)"),
        (500, "URLhaus server error (HTTP 500)"),
        (502, "URLhaus server error (HTTP 502)"),
        (503, "URLhaus server error (HTTP 503)"),
        (204, "unexpected HTTP status 204"),
    ] {
        // Even a no_results body under an error status is a failure.
        let server = host_api("example.com", status, NO_RESULTS_BODY).await;
        let run = engine_run(
            collector(&server, Some(KEY)),
            &[&server],
            EngineConfig::default(),
            domain("example.com"),
        )
        .await;
        assert_eq!(
            run.investigation.sources()[0].outcome(),
            &SourceOutcome::Failed {
                error: expected.into()
            },
            "{status}"
        );
        assert!(run.investigation.findings().is_empty(), "{status}");
    }
}

#[tokio::test]
async fn incomplete_responses_are_degraded_and_reported() {
    let body = r#"{"query_status": "ok", "host": "example.com", "url_count": "x", "urls": "none"}"#;
    let server = host_api("example.com", 200, body).await;
    let collection = collect(&server, &domain("example.com")).await.unwrap();
    assert_eq!(
        collection.observations()[0].confidence(),
        DEGRADED_CONFIDENCE
    );
    assert_eq!(
        codes(&collection),
        vec!["ti.urlhaus.host_listed", "ti.urlhaus.response_incomplete"]
    );
    assert!(
        collection.findings[0]
            .detail()
            .starts_with("URLhaus reports an unknown number of malware URL(s)")
    );
    assert_attributed(&collection);
}

// ------------------------------------------------------ availability

#[tokio::test]
async fn missing_and_invalid_keys_are_unavailable_and_send_nothing() {
    let server = host_api("example.com", 200, NO_RESULTS_BODY).await;
    assert_eq!(
        collector(&server, None).availability(),
        Availability::Unavailable {
            reason: "API key not configured (set SENTINEL_ABUSECH_KEY)"
        }
    );
    assert_eq!(
        collector(&server, Some("bad key")).availability(),
        Availability::Unavailable {
            reason: "API key configuration is invalid"
        }
    );
    assert!(matches!(
        collector(&server, None)
            .collect(&domain("example.com"), &context(http(&[&server]), 10))
            .await,
        Err(CollectorError::NotConfigured)
    ));
    for key in [None, Some("bad key")] {
        let run = engine_run(
            collector(&server, key),
            &[&server],
            EngineConfig::default(),
            domain("example.com"),
        )
        .await;
        assert!(matches!(
            run.investigation.sources()[0].outcome(),
            SourceOutcome::Unavailable { .. }
        ));
        assert!(run.investigation.findings().is_empty());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ------------------------------------------------------ engine limits

#[tokio::test]
async fn request_timeout_and_source_timeout() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/host/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(NO_RESULTS_BODY)
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
    assert!(matches!(
        collector(&server, Some(KEY))
            .collect(&domain("example.com"), &context(fast, 10))
            .await,
        Err(CollectorError::Http(HttpError::Timeout))
    ));
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            source_timeout: Duration::from_millis(500),
            ..EngineConfig::default()
        },
        domain("example.com"),
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
    let server = host_api("example.com", 200, NO_RESULTS_BODY).await;
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig::default(),
        domain("example.com"),
    )
    .await;
    assert_eq!(run.stats.requests_used, 1);
    let ctx = context(http(&[&server]), 1);
    let c = collector(&server, Some(KEY));
    assert!(c.collect(&domain("example.com"), &ctx).await.is_ok());
    assert!(matches!(
        c.collect(&domain("example.com"), &ctx).await,
        Err(CollectorError::RequestBudgetExhausted { limit: 1 })
    ));
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig {
            max_requests: 0,
            ..EngineConfig::default()
        },
        domain("example.com"),
    )
    .await;
    assert_eq!(
        run.investigation.sources()[0].outcome(),
        &SourceOutcome::BudgetExhausted { limit: 0 }
    );
    assert!(run.investigation.findings().is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn oversized_responses_are_rejected() {
    let huge = format!(
        r#"{{"query_status": "ok", "host": "example.com", "pad": "{}"}}"#,
        "x".repeat(MAX_RESPONSE_BYTES + 1)
    );
    let server = host_api("example.com", 200, &huge).await;
    assert!(matches!(
        collect(&server, &domain("example.com")).await,
        Err(CollectorError::Http(HttpError::ResponseTooLarge { .. }))
    ));
}

// ------------------------------- returned indicators are data, not targets

/// Mandatory: URLs, hosts and download links in a URLhaus answer are never
/// contacted, resolved or pivoted to.
#[tokio::test]
async fn urls_returned_by_the_provider_are_never_accessed() {
    let malware_host = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("MZ payload"))
        .mount(&malware_host)
        .await;
    let listed = malware_host.uri();
    let urlhaus = MockServer::start().await;
    let body = format!(
        r#"{{"query_status": "ok", "host": "example.com", "firstseen": "2024-01-01 00:00:00 UTC", "url_count": "3",
            "urls": [
              {{"id": "1", "url": "{listed}/payload.exe", "url_status": "online", "date_added": "2024-01-01 00:00:00 UTC", "tags": ["exe"]}},
              {{"id": "2", "url": "{listed}/redirect", "url_status": "online", "urlhaus_reference": "{listed}/ref/2/"}},
              {{"id": "3", "url": "{u}/v1/download/aaaa/", "url_status": "offline"}}
            ],
            "urlhaus_reference": "{listed}/host/example.com/",
            "payloads": [{{"response_sha256": "{h}", "urlhaus_download": "{listed}/download/{h}/"}}]}}"#,
        u = urlhaus.uri(),
        h = "b".repeat(64)
    );
    Mock::given(method("POST"))
        .and(path("/v1/host/"))
        .and(header("auth-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&urlhaus)
        .await;

    // The client may reach both servers, so only Sentinel's own logic
    // keeps it from following the listed URLs.
    let run = engine_run(
        collector(&urlhaus, Some(KEY)),
        &[&urlhaus, &malware_host],
        EngineConfig::default(),
        domain("example.com"),
    )
    .await;
    assert!(
        malware_host.received_requests().await.unwrap().is_empty(),
        "a URL listed by URLhaus was accessed"
    );
    let requests = urlhaus.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "only the lookup itself");
    assert_eq!(requests[0].url.path(), "/v1/host/");
    assert_eq!(run.stats.requests_used, 1);

    let inv = &run.investigation;
    assert_eq!(inv.observations().len(), 1);
    assert!(inv.relationships().is_empty());
    assert_eq!(
        (run.stats.pivots_followed, run.stats.pivots_dropped),
        (0, 0),
        "no automatic pivot candidates"
    );
    assert_eq!(inv.sources().len(), 1, "no pivots were scheduled");
    let json = serde_json::to_string(inv).unwrap();
    assert!(!json.contains(&listed), "listed URLs are not stored");
    assert!(!json.contains("payload.exe"));
}

#[tokio::test]
async fn one_lookup_per_investigation() {
    let server = host_api("vektorex.com", 200, DOCUMENTED_HOST).await;
    let run = engine_run(
        collector(&server, Some(KEY)),
        &[&server],
        EngineConfig::default(),
        domain("vektorex.com"),
    )
    .await;
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert_eq!(run.stats.requests_used, 1);
    assert_eq!(run.investigation.observations().len(), 1);
}

// ------------------------------------------------- public-only policy

#[tokio::test]
async fn non_public_indicators_are_never_sent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NO_RESULTS_BODY))
        .mount(&server)
        .await;
    let c = collector(&server, Some(KEY));
    let ctx = context(http(&[&server]), 100);
    let mut targets: Vec<Indicator> = [
        "10.0.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
    ]
    .iter()
    .map(|s| Indicator::parse_ip(s).unwrap())
    .collect();
    for d in [
        "db.corp.internal",
        "printer.local",
        "router.home.arpa",
        "x.onion",
    ] {
        targets.push(domain(d));
    }
    for u in [
        "http://127.0.0.1/payload.exe",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[2002:7f00:1::1]/",
        "http://10.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "https://db.corp.internal/",
    ] {
        targets.push(Indicator::parse_url(u).unwrap());
    }
    for target in &targets {
        assert!(
            matches!(
                c.collect(target, &ctx).await,
                Err(CollectorError::RefusedTarget)
            ),
            "{target}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ----------------------------------------------------- HTTP security

#[tokio::test]
async fn production_api_is_https_only() {
    assert!(API_BASE.starts_with("https://urlhaus-api.abuse.ch/"));
    let insecure = UrlhausCollector::for_tests(
        Url::parse("http://urlhaus-api.abuse.ch/v1/").unwrap(),
        Some(SecretString::from(KEY)),
    );
    let ctx = context(HttpClient::new(HttpConfig::default()).unwrap(), 10);
    assert!(matches!(
        insecure.collect(&domain("example.com"), &ctx).await,
        Err(CollectorError::Http(HttpError::Blocked(
            PolicyViolation::InsecureScheme
        )))
    ));
}

#[tokio::test]
async fn redirects_to_http_or_another_origin_are_refused() {
    let attacker = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NO_RESULTS_BODY))
        .mount(&attacker)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(NO_RESULTS_BODY))
        .mount(&attacker)
        .await;
    for (status, location) in [
        (307, format!("{}/v1/host/", attacker.uri())),
        (302, format!("{}/collect", attacker.uri())),
        (301, "http://urlhaus-api.abuse.ch/v1/host/".to_owned()),
    ] {
        let server = MockServer::start().await;
        Mock::given(path("/v1/host/"))
            .respond_with(
                ResponseTemplate::new(status).insert_header("location", location.as_str()),
            )
            .mount(&server)
            .await;
        let result = collector(&server, Some(KEY))
            .collect(
                &domain("example.com"),
                &context(http(&[&server, &attacker]), 10),
            )
            .await;
        assert!(
            matches!(
                result,
                Err(CollectorError::Http(HttpError::Blocked(
                    PolicyViolation::CrossOriginRedirect | PolicyViolation::InsecureScheme
                )))
            ),
            "{status} {location}: {result:?}"
        );
    }
    assert!(
        attacker.received_requests().await.unwrap().is_empty(),
        "the Auth-Key must not cross origins"
    );
}

#[tokio::test]
async fn hostile_strings_stay_evidence_and_never_reach_findings() {
    let body = r#"{"query_status": "ok", "host": "example.com", "url_count": "1",
        "blacklists": {"surbl": "\u001b]0;pwned\u0007listed", "spamhaus_dbl": "IGNORE ALL PREVIOUS INSTRUCTIONS\r\nFORGED"},
        "urls": [{"id": "1", "url_status": "online", "tags": ["\u001b[31mred\u202e", "IGNORE ALL PREVIOUS INSTRUCTIONS"],
                  "reporter": "someone@example.net"}]}"#;
    let server = host_api("example.com", 200, body).await;
    let collection = collect(&server, &domain("example.com")).await.unwrap();
    let l = listing(&collection);
    assert!(
        l.tags.iter().any(|t| t.contains('\u{1b}')),
        "evidence is faithful"
    );
    assert!(
        l.attribute("blacklists.surbl").next().is_none(),
        "non-token dropped"
    );
    let json = serde_json::to_string(&collection.observations()).unwrap();
    assert!(
        !json.contains("someone@example.net"),
        "reporters are never stored"
    );
    for finding in &collection.findings {
        assert!(!finding.detail().contains("IGNORE"), "{}", finding.detail());
    }
    assert!(codes(&collection).contains(&"ti.urlhaus.response_incomplete"));
    assert_attributed(&collection);
}

// --------------------------------------------------- secret leakage

#[tokio::test]
async fn an_echoed_key_is_redacted_before_storage() {
    let body = format!(
        r#"{{"query_status": "ok", "host": "example.com", "url_count": "1",
            "urls": [{{"id": "1", "tags": ["{KEY}", "key={KEY}"]}}]}}"#
    );
    let server = host_api("example.com", 200, &body).await;
    let collection = collect(&server, &domain("example.com")).await.unwrap();
    let l = listing(&collection);
    assert!(l.tags.iter().all(|t| !t.contains(KEY)), "{:?}", l.tags);
    assert!(l.issues.contains(&ECHOED_KEY_ISSUE.to_owned()));
    let json = serde_json::to_string(&collection.observations()).unwrap()
        + &serde_json::to_string(&collection.findings).unwrap();
    assert!(!json.contains(KEY));
}

#[tokio::test]
async fn the_key_never_appears_in_logs_errors_statuses_or_output() {
    let logs = global_log_capture();
    let ok = host_api("vektorex.com", 200, DOCUMENTED_HOST).await;
    let denied = host_api(
        "vektorex.com",
        401,
        &format!(r#"{{"query_status": "unknown_auth_key", "key": "{KEY}"}}"#),
    )
    .await;
    let mut texts: Vec<String> = vec![format!("{:?}", collector(&ok, Some(KEY)))];
    let error = collect(&denied, &domain("vektorex.com")).await.unwrap_err();
    texts.push(error.to_string());
    texts.push(format!("{error:?}"));
    for server in [&ok, &denied] {
        let run = engine_run(
            collector(server, Some(KEY)),
            &[server],
            EngineConfig::default(),
            domain("vektorex.com"),
        )
        .await;
        texts.push(serde_json::to_string(&run.investigation).unwrap());
        texts.push(format!("{:?}", run.investigation));
    }
    let captured = logs.contents();
    let marker = format!("127.0.0.1:{}/v1/host/", ok.address().port());
    assert!(
        captured.contains("sending request") && captured.contains(&marker),
        "logging must be active"
    );
    texts.push(captured);
    for text in &texts {
        assert!(
            !text.contains(KEY),
            "key leaked into: {}",
            &text[..text.len().min(300)]
        );
    }
    for request in ok.received_requests().await.unwrap() {
        assert!(!request.url.as_str().contains(KEY));
        assert!(
            !String::from_utf8_lossy(&request.body).contains(KEY),
            "not in the body"
        );
        assert_eq!(
            request
                .headers
                .get("auth-key")
                .map(|v| v.to_str().unwrap().to_owned()),
            Some(KEY.to_owned())
        );
    }
}

//! HTTP client tests against local servers.
//!
//! Mock servers speak plain HTTP on loopback, which the production policy
//! forbids. Tests therefore use `HttpClient::for_tests`, which allows exactly
//! the listed mock server socket addresses and nothing else. That constructor
//! only exists under `cfg(test)`. Every other rule (redirect validation,
//! private/loopback refusal, resolver filtering, size caps) is the production
//! code path.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::header::HeaderName;
use secrecy::SecretString;
use sentinel_core::{AddressScope, Provenance, Sha256Digest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const SECRET: &str = "sk-TEST-SECRET-must-never-appear";

fn config() -> HttpConfig {
    HttpConfig {
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(2),
        max_body_bytes: 1024,
        max_concurrent_requests: 4,
    }
}

fn client_for(servers: &[&MockServer]) -> HttpClient {
    HttpClient::for_tests(config(), servers.iter().map(|s| *s.address()).collect()).unwrap()
}

fn url(server: &MockServer, path: &str) -> Url {
    Url::parse(&format!("{}{path}", server.uri())).unwrap()
}

async fn redirect(server: &MockServer, from: &str, to: &str) {
    Mock::given(path(from))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to))
        .mount(server)
        .await;
}

fn blocked(err: HttpError) -> PolicyViolation {
    match err {
        HttpError::Blocked(violation) => violation,
        other => panic!("expected a policy violation, got {other:?}"),
    }
}

/// A one-shot raw TCP server that replies with `response` verbatim, for
/// cases a mock server cannot express (chunked bodies, fake encodings).
async fn raw_server(response: Vec<u8>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        }
    });
    addr
}

// ---------------------------------------------------------------- success

#[tokio::test]
async fn successful_get_returns_body_hash_and_provenance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/check"))
        .and(header("x-apikey", SECRET))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"ok":true}"#))
        .expect(1)
        .mount(&server)
        .await;

    let request = HttpRequest::get(url(&server, "/v1/check?q=example.com"))
        .secret_header(
            HeaderName::from_static("x-apikey"),
            &SecretString::from(SECRET),
        )
        .unwrap();
    let response = client_for(&[&server]).send(request).await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(response.is_success());
    assert_eq!(response.body(), br#"{"ok":true}"#);
    assert_eq!(
        response.raw_response_hash(),
        Sha256Digest::of(br#"{"ok":true}"#)
    );
    let Provenance::Https(provenance) = response.provenance() else {
        panic!("expected https provenance");
    };
    assert_eq!(
        provenance.endpoint(),
        url(&server, "/v1/check?q=example.com").as_str()
    );
    assert!(!provenance.endpoint().contains(SECRET));
}

#[tokio::test]
async fn post_form_sends_url_encoded_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(wiremock::matchers::body_string("query=get_info&hash=abc"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let request = HttpRequest::post_form(
        url(&server, "/api"),
        [("query", "get_info"), ("hash", "abc")],
    );
    assert_eq!(
        client_for(&[&server]).send(request).await.unwrap().status(),
        200
    );
}

#[tokio::test]
async fn non_success_statuses_are_returned_to_the_collector() {
    let server = MockServer::start().await;
    Mock::given(path("/missing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let response = client_for(&[&server])
        .send(HttpRequest::get(url(&server, "/missing")))
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(!response.is_success());
}

#[tokio::test]
async fn sends_the_tool_user_agent() {
    let server = MockServer::start().await;
    Mock::given(header("user-agent", user_agent().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    client_for(&[&server])
        .send(HttpRequest::get(url(&server, "/")))
        .await
        .unwrap();
    assert!(user_agent().starts_with("sentinel-osint/"));
    assert!(user_agent().ends_with(" (+https://github.com/TorranceTech/sentinel-osint)"));
}

// ---------------------------------------------------------- time and size

#[tokio::test]
async fn slow_responses_time_out() {
    let server = MockServer::start().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&server)
        .await;
    let client = HttpClient::for_tests(
        HttpConfig {
            request_timeout: Duration::from_millis(300),
            ..config()
        },
        vec![*server.address()],
    )
    .unwrap();
    let started = Instant::now();
    let err = client
        .send(HttpRequest::get(url(&server, "/slow")))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn per_request_timeout_overrides_the_client_default() {
    let server = MockServer::start().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(700)))
        .mount(&server)
        .await;
    let client = HttpClient::for_tests(
        HttpConfig {
            request_timeout: Duration::from_millis(200),
            ..config()
        },
        vec![*server.address()],
    )
    .unwrap();
    let err = client
        .send(HttpRequest::get(url(&server, "/slow")))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::Timeout));
    let ok = client
        .send(HttpRequest::get(url(&server, "/slow")).timeout(Duration::from_secs(3)))
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn oversized_responses_are_rejected_by_content_length() {
    let server = MockServer::start().await;
    Mock::given(path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 2048]))
        .mount(&server)
        .await;
    let client = client_for(&[&server]);
    let err = client
        .send(HttpRequest::get(url(&server, "/big")))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpError::ResponseTooLarge { limit: 1024 }),
        "{err:?}"
    );

    // A request may raise its own limit (up to the global ceiling).
    let ok = client
        .send(HttpRequest::get(url(&server, "/big")).max_body_bytes(4096))
        .await
        .unwrap();
    assert_eq!(ok.body().len(), 2048);
}

#[tokio::test]
async fn oversized_chunked_responses_are_rejected_while_streaming() {
    // No Content-Length: only the streaming check can catch this.
    let mut response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for _ in 0..8 {
        response.extend_from_slice(b"200\r\n");
        response.extend_from_slice(&[b'x'; 512]);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    let addr = raw_server(response).await;
    let client = HttpClient::for_tests(config(), vec![addr]).unwrap();
    let err = client
        .send(HttpRequest::get(
            Url::parse(&format!("http://{addr}/")).unwrap(),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpError::ResponseTooLarge { limit: 1024 }),
        "{err:?}"
    );
}

#[tokio::test]
async fn compressed_bodies_are_never_decompressed() {
    // A gzip "bomb" is only dangerous if it is inflated. The client has no
    // decompression support, so it sees (and caps) the raw bytes.
    let payload: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    response.extend_from_slice(&payload);
    let addr = raw_server(response).await;
    let client = HttpClient::for_tests(config(), vec![addr]).unwrap();
    let body = client
        .send(HttpRequest::get(
            Url::parse(&format!("http://{addr}/")).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(body.body(), payload.as_slice());
}

#[tokio::test]
async fn concurrent_requests_are_bounded_by_the_client() {
    let server = MockServer::start().await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(400)))
        .mount(&server)
        .await;
    let client = HttpClient::for_tests(
        HttpConfig {
            max_concurrent_requests: 2,
            ..config()
        },
        vec![*server.address()],
    )
    .unwrap();

    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..6 {
        let client = client.clone();
        let target = url(&server, "/slow");
        tasks.spawn(async move {
            client
                .send(HttpRequest::get(target))
                .await
                .map(|r| r.status())
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap().unwrap(), 200);
    }
    // 6 requests, 2 at a time, 400 ms each: at least 3 waves.
    assert!(
        started.elapsed() >= Duration::from_millis(1150),
        "{:?}",
        started.elapsed()
    );
}

// -------------------------------------------------------------- redirects

#[tokio::test]
async fn valid_redirects_are_followed() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    redirect(&a, "/start", url(&b, "/final").as_str()).await;
    Mock::given(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("done"))
        .mount(&b)
        .await;

    let response = client_for(&[&a, &b])
        .send(HttpRequest::get(url(&a, "/start")))
        .await
        .unwrap();
    assert_eq!(response.body(), b"done");
    assert_eq!(response.final_url(), &url(&b, "/final"));
}

#[tokio::test]
async fn redirect_to_plain_http_is_blocked() {
    let a = MockServer::start().await;
    redirect(&a, "/start", "http://example.com/").await;
    let err = client_for(&[&a])
        .send(HttpRequest::get(url(&a, "/start")))
        .await
        .unwrap_err();
    assert_eq!(blocked(err), PolicyViolation::InsecureScheme);
}

#[tokio::test]
async fn redirect_to_private_address_is_blocked() {
    let a = MockServer::start().await;
    redirect(&a, "/start", "https://10.0.0.1/admin").await;
    let err = client_for(&[&a])
        .send(HttpRequest::get(url(&a, "/start")))
        .await
        .unwrap_err();
    assert!(matches!(
        blocked(err),
        PolicyViolation::NonPublicAddress {
            scope: AddressScope::Private,
            ..
        }
    ));
}

#[tokio::test]
async fn redirect_to_loopback_and_metadata_addresses_is_blocked() {
    let a = MockServer::start().await;
    // Same loopback IP as the mock server but another port: still refused,
    // because only the exact mock socket address is allowed in tests.
    let other_port = a.address().port().wrapping_add(1);
    let cases = [
        (
            format!("http://127.0.0.1:{other_port}/"),
            AddressScope::Loopback,
        ),
        ("https://[::1]/".to_owned(), AddressScope::Loopback),
        ("https://0x7f000001/".to_owned(), AddressScope::Loopback),
        (
            "https://169.254.169.254/latest/meta-data/".to_owned(),
            AddressScope::LinkLocal,
        ),
        (
            "https://[::ffff:169.254.169.254]/".to_owned(),
            AddressScope::LinkLocal,
        ),
    ];
    let client = client_for(&[&a]);
    for (i, (target, scope)) in cases.iter().enumerate() {
        let from = format!("/start{i}");
        redirect(&a, &from, target).await;
        let err = client
            .send(HttpRequest::get(url(&a, &from)))
            .await
            .unwrap_err();
        match blocked(err) {
            PolicyViolation::NonPublicAddress { scope: actual, .. } => {
                assert_eq!(actual, *scope, "{target}");
            }
            other => panic!("{target}: unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn redirect_to_a_name_resolving_to_loopback_is_blocked_by_the_resolver() {
    // The URL check passes (it is a name); the resolver refuses to hand
    // loopback addresses to the connector. This is the DNS-rebinding path.
    let a = MockServer::start().await;
    redirect(&a, "/start", "https://localhost:9/").await;
    let err = client_for(&[&a])
        .send(HttpRequest::get(url(&a, "/start")))
        .await
        .unwrap_err();
    assert_eq!(blocked(err), PolicyViolation::NoPublicAddress);
}

#[tokio::test]
async fn redirect_chains_are_limited() {
    let a = MockServer::start().await;
    // /ok1 → /ok2 → /ok3 → /done: exactly MAX_REDIRECTS hops.
    redirect(&a, "/ok1", url(&a, "/ok2").as_str()).await;
    redirect(&a, "/ok2", url(&a, "/ok3").as_str()).await;
    redirect(&a, "/ok3", url(&a, "/done").as_str()).await;
    // /r1 → … → /r4 → /done: one hop too many.
    for i in 1..=4 {
        let next = if i == 4 {
            "/done".to_owned()
        } else {
            format!("/r{}", i + 1)
        };
        redirect(&a, &format!("/r{i}"), url(&a, &next).as_str()).await;
    }
    Mock::given(path("/done"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&a)
        .await;
    let client = client_for(&[&a]);

    assert_eq!(MAX_REDIRECTS, 3);
    let ok = client
        .send(HttpRequest::get(url(&a, "/ok1")))
        .await
        .unwrap();
    assert_eq!(ok.final_url(), &url(&a, "/done"));

    let err = client
        .send(HttpRequest::get(url(&a, "/r1")))
        .await
        .unwrap_err();
    assert_eq!(blocked(err), PolicyViolation::TooManyRedirects { max: 3 });
}

#[tokio::test]
async fn authenticated_requests_never_follow_cross_origin_redirects() {
    let api = MockServer::start().await;
    let attacker = MockServer::start().await;
    redirect(&api, "/v1/lookup", url(&attacker, "/collect").as_str()).await;
    Mock::given(path("/collect"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&attacker)
        .await;

    let request = HttpRequest::get(url(&api, "/v1/lookup"))
        .secret_header(
            HeaderName::from_static("x-apikey"),
            &SecretString::from(SECRET),
        )
        .unwrap();
    let err = client_for(&[&api, &attacker])
        .send(request)
        .await
        .unwrap_err();

    assert_eq!(blocked(err), PolicyViolation::CrossOriginRedirect);
    let received = attacker.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "the API key must never reach another origin"
    );
}

#[tokio::test]
async fn authenticated_requests_follow_same_origin_redirects() {
    let api = MockServer::start().await;
    redirect(&api, "/v1/old", url(&api, "/v2/new").as_str()).await;
    Mock::given(path("/v2/new"))
        .and(header("x-apikey", SECRET))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&api)
        .await;
    let request = HttpRequest::get(url(&api, "/v1/old"))
        .secret_header(
            HeaderName::from_static("x-apikey"),
            &SecretString::from(SECRET),
        )
        .unwrap();
    assert_eq!(
        client_for(&[&api]).send(request).await.unwrap().status(),
        200
    );
}

// -------------------------------------------------------- production policy

#[tokio::test]
async fn production_client_refuses_non_https_and_non_public_before_any_io() {
    let client = HttpClient::new(config()).unwrap();
    let cases = [
        ("http://example.com/", PolicyViolation::InsecureScheme),
        (
            "https://user:pw@example.com/",
            PolicyViolation::CredentialsInUrl,
        ),
        ("https://localhost:1/", PolicyViolation::NoPublicAddress),
    ];
    for (target, expected) in cases {
        let err = client
            .send(HttpRequest::get(Url::parse(target).unwrap()))
            .await
            .unwrap_err();
        assert_eq!(blocked(err), expected, "{target}");
    }
    for target in [
        "https://127.0.0.1/",
        "https://10.1.2.3/",
        "https://[fe80::1]/",
        "https://169.254.169.254/",
    ] {
        let err = client
            .send(HttpRequest::get(Url::parse(target).unwrap()))
            .await
            .unwrap_err();
        assert!(
            matches!(blocked(err), PolicyViolation::NonPublicAddress { .. }),
            "{target}"
        );
    }
}

// ------------------------------------------------------ secrets and logs

/// Captures everything logged through `tracing` on this thread.
#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogCapture {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[tokio::test]
async fn secrets_never_appear_in_logs_or_errors() {
    let logs = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Other tests run in parallel without this subscriber; drop callsite
    // interest they cached so this thread's events are not filtered out.
    tracing::callsite::rebuild_interest_cache();

    let api = MockServer::start().await;
    let attacker = MockServer::start().await;
    Mock::given(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&api)
        .await;
    redirect(&api, "/redirect", url(&attacker, "/").as_str()).await;
    // A port nobody listens on, to produce a connection error.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let client =
        HttpClient::for_tests(config(), vec![*api.address(), *attacker.address(), closed]).unwrap();
    let key = SecretString::from(SECRET);
    let authed = |target: Url| {
        HttpRequest::get(target)
            .secret_header(HeaderName::from_static("x-apikey"), &key)
            .unwrap()
    };

    let mut errors = Vec::new();
    // Success, with a secret-looking query parameter (defense in depth).
    client
        .send(authed(url(&api, "/ok?apikey=URL-SECRET-must-never-appear")))
        .await
        .unwrap();
    // Cross-origin redirect refused.
    errors.push(
        client
            .send(authed(url(&api, "/redirect")))
            .await
            .unwrap_err(),
    );
    // Connection failure.
    errors.push(
        client
            .send(authed(Url::parse(&format!("http://{closed}/")).unwrap()))
            .await
            .unwrap_err(),
    );
    // Policy violation before sending.
    errors.push(
        client
            .send(authed(Url::parse("https://10.0.0.1/").unwrap()))
            .await
            .unwrap_err(),
    );

    let captured = logs.contents();
    assert!(
        captured.contains("sending request"),
        "logging must be active:\n{captured}"
    );
    assert!(captured.contains("REDACTED"));
    for leak in [SECRET, "URL-SECRET-must-never-appear"] {
        assert!(
            !captured.contains(leak),
            "secret leaked into logs:\n{captured}"
        );
        for err in &errors {
            assert!(!err.to_string().contains(leak));
            assert!(!format!("{err:?}").contains(leak));
        }
    }
}

#[tokio::test]
async fn logged_endpoints_cannot_inject_log_lines() {
    let logs = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // Other tests run in parallel without this subscriber; drop callsite
    // interest they cached so this thread's events are not filtered out.
    tracing::callsite::rebuild_interest_cache();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let target = url(&server, "/a%0d%0aFORGED-LOG-LINE?x=%1b[31m");
    client_for(&[&server])
        .send(HttpRequest::get(target))
        .await
        .unwrap();

    let captured = logs.contents();
    assert!(captured.contains("sending request"));
    for line in captured.lines() {
        assert!(
            !line.trim_start().starts_with("FORGED-LOG-LINE"),
            "log injection:\n{captured}"
        );
        assert!(!line.contains('\u{1b}'), "raw escape in log:\n{captured}");
    }
}

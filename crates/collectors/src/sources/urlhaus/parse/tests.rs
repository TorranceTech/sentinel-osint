use proptest::prelude::*;

use super::*;

/// The documented URL-lookup example (urlhaus-api.abuse.ch), unchanged.
pub(crate) const DOCUMENTED_URL: &str = r#"{
    "query_status": "ok",
    "id": "105821",
    "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/105821\/",
    "url": "http:\/\/sskymedia.com\/VMYB-ht_JAQo-gi\/INV\/99401FORPO\/20673114777\/US\/Outstanding-Invoices\/",
    "url_status": "online",
    "host": "sskymedia.com",
    "date_added": "2019-01-19 01:33:26 UTC",
    "last_online": null,
    "threat": "malware_download",
    "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "listed"},
    "reporter": "Cryptolaemus1",
    "larted": "true",
    "takedown_time_seconds": null,
    "tags": ["emotet", "epoch2", "heodo"],
    "payloads": [
      {"firstseen": "2019-01-19", "filename": "5616769081079106.doc", "file_type": "doc",
       "response_size": "179664", "response_md5": "fedfa8ad9ee7846b88c5da79b32f6551",
       "response_sha256": "dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403",
       "urlhaus_download": "https:\/\/urlhaus-api.abuse.ch\/v1\/download\/dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403\/",
       "signature": null,
       "virustotal": {"result": "16 \/ 58", "percent": "27.59", "link": "https:\/\/www.virustotal.com\/file\/dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403\/analysis\/1547871259\/"},
       "imphash": "4e4a95a7659118e966a42f4a73311fda", "ssdeep": "3072:+hcypCDJeA", "tlsh": "1D340235A5E2", "magika": "doc"},
      {"firstseen": "2019-01-19", "filename": "ATT932454259403171471.doc", "file_type": "doc",
       "response_size": "174928", "response_md5": "12c8aec5766ac3e6f26f2505e2f4a8f2",
       "response_sha256": "01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00",
       "urlhaus_download": "https:\/\/urlhaus-api.abuse.ch\/v1\/download\/01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b00\/",
       "signature": "Heodo", "virustotal": null}
    ]
}"#;

/// The documented host-lookup example. The documentation's version is
/// truncated (unclosed `urls` array) and spells `query_staus`; the array
/// is closed here, the spelling is kept.
pub(crate) const DOCUMENTED_HOST: &str = r#"{
    "query_staus": "ok",
    "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/host\/vektorex.com\/",
    "host": "vektorex.com",
    "firstseen": "2019-01-15 07:09:01 UTC",
    "url_count": "120",
    "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
    "urls": [
        {"id": "121319", "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/121319\/",
         "url": "http:\/\/vektorex.com\/source\/Z\/5016223.exe", "url_status": "online",
         "date_added": "2019-02-11 07:45:05 UTC", "threat": "malware_download", "reporter": "abuse_ch",
         "larted": "false", "takedown_time_seconds": null, "tags": ["AZORult", "exe"]},
        {"id": "121316", "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/121316\/",
         "url": "http:\/\/vektorex.com\/source\/Z\/Order%20839.png", "url_status": "online",
         "date_added": "2019-02-11 06:47:03 UTC", "threat": "malware_download", "reporter": "abuse_ch",
         "larted": "false", "takedown_time_seconds": null, "tags": ["exe", "Loki"]}
    ]
}"#;

fn url(s: &str) -> HttpUrl {
    HttpUrl::parse(s).unwrap()
}

fn domain(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

fn listed(answer: Answer) -> ProviderListing {
    match answer {
        Answer::Listed(listing) => listing,
        Answer::NoResults => panic!("expected a listing"),
    }
}

const SSKY: &str =
    "http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/";

#[test]
fn documented_url_example_keeps_classifications_and_drops_personal_and_pivot_data() {
    let target = url(SSKY);
    let l = listed(parse(DOCUMENTED_URL.as_bytes(), &Query::Url(&target)).unwrap());
    assert!(l.issues.is_empty(), "{:?}", l.issues);
    assert_eq!(l.entry_id.as_deref(), Some("105821"));
    assert_eq!(l.attribute("url_status").collect::<Vec<_>>(), ["online"]);
    assert_eq!(
        l.attribute("threat").collect::<Vec<_>>(),
        ["malware_download"]
    );
    assert_eq!(l.attribute("larted").collect::<Vec<_>>(), ["true"]);
    assert_eq!(
        l.attribute("blacklists.spamhaus_dbl").collect::<Vec<_>>(),
        ["abused_legit_malware"]
    );
    assert_eq!(
        l.attribute("blacklists.surbl").collect::<Vec<_>>(),
        ["listed"]
    );
    assert_eq!(
        l.attribute("payloads.signature").collect::<Vec<_>>(),
        ["Heodo"]
    );
    assert_eq!(l.metric(RETURNED_PAYLOADS), Some(2));
    assert_eq!(l.metric(TAKEDOWN_TIME_SECONDS), None);
    assert_eq!(
        l.date("date_added").unwrap().to_rfc3339(),
        "2019-01-19T01:33:26+00:00"
    );
    assert_eq!(l.date("last_online"), None);
    assert_eq!(l.tags, ["emotet", "epoch2", "heodo"]);

    let json = serde_json::to_string(&l).unwrap();
    for dropped in [
        "Cryptolaemus1",
        "5616769081079106.doc",
        "ATT932454259403171471",
        "urlhaus_download",
        "v1/download",
        "virustotal",
        "dc9f3b226bccb2f1",
        "fedfa8ad",
        "sskymedia",
        "http",
        "imphash",
    ] {
        assert!(!json.contains(dropped), "{dropped} must not be stored");
    }
}

#[test]
fn documented_host_example_counts_urls_without_storing_them() {
    let target = domain("vektorex.com");
    let l = listed(parse(DOCUMENTED_HOST.as_bytes(), &Query::Domain(&target)).unwrap());
    assert!(l.issues.is_empty(), "{:?}", l.issues);
    assert_eq!(l.metric(URL_COUNT), Some(120));
    assert_eq!(l.metric(RETURNED_URLS), Some(2));
    assert_eq!(l.metric(RETURNED_URLS_ONLINE), Some(2));
    assert_eq!(
        l.date("firstseen").unwrap().to_rfc3339(),
        "2019-01-15T07:09:01+00:00"
    );
    assert_eq!(
        l.date(LATEST_URL_ADDED).unwrap().to_rfc3339(),
        "2019-02-11T07:45:05+00:00"
    );
    assert_eq!(l.tags, ["AZORult", "Loki", "exe"]);
    assert_eq!(
        l.attribute("blacklists.surbl").collect::<Vec<_>>(),
        ["not listed"]
    );
    let json = serde_json::to_string(&l).unwrap();
    for dropped in [
        "5016223.exe",
        "Order",
        "121319",
        "abuse_ch",
        "urlhaus.abuse.ch",
        "http",
    ] {
        assert!(!json.contains(dropped), "{dropped} must not be stored");
    }
    // The documented key spelling is accepted too.
    let fixed = DOCUMENTED_HOST.replace("query_staus", "query_status");
    assert!(matches!(
        parse(fixed.as_bytes(), &Query::Domain(&target)).unwrap(),
        Answer::Listed(_)
    ));
}

#[test]
fn ipv4_host_without_blacklists_is_not_an_issue() {
    let body = r#"{"query_status": "ok", "host": "45.61.49.78", "firstseen": "2019-08-10 09:02:05 UTC",
        "url_count": "2", "urls": []}"#;
    let l = listed(parse(body.as_bytes(), &Query::Ip("45.61.49.78".parse().unwrap())).unwrap());
    assert!(l.issues.is_empty(), "{:?}", l.issues);
    assert_eq!(l.metric(RETURNED_URLS), Some(0));
}

#[test]
fn query_status_semantics() {
    let target = domain("example.com");
    let q = Query::Domain(&target);
    assert!(matches!(
        parse(br#"{"query_status": "no_results"}"#, &q).unwrap(),
        Answer::NoResults
    ));
    for (body, error) in [
        (
            r#"{"query_status": "invalid_host"}"#,
            "URLhaus rejected the indicator as invalid",
        ),
        (
            r#"{"query_status": "invalid_url"}"#,
            "URLhaus rejected the indicator as invalid",
        ),
        (
            r#"{"query_status": "http_post_expected"}"#,
            "URLhaus reports that the request was not a POST",
        ),
        (
            r#"{"query_status": "unknown_auth_key"}"#,
            "URLhaus returned an undocumented query_status",
        ),
        (
            r#"{"query_status": ""}"#,
            "URLhaus returned an undocumented query_status",
        ),
        (
            r#"{"query_status": 1}"#,
            "URLhaus response has no query_status",
        ),
        (
            r#"{"host": "example.com"}"#,
            "URLhaus response has no query_status",
        ),
        ("{}", "URLhaus response has no query_status"),
        ("[]", "URLhaus response is not a JSON object"),
        ("null", "URLhaus response is not a JSON object"),
        ("", "URLhaus response is not valid JSON"),
        ("<html>", "URLhaus response is not valid JSON"),
        (
            r#"{"query_status": "ok""#,
            "URLhaus response is not valid JSON",
        ),
    ] {
        assert_eq!(parse(body.as_bytes(), &q).unwrap_err(), error, "{body:?}");
    }
}

#[test]
fn identity_is_checked() {
    let target = domain("example.com");
    for (body, error) in [
        (
            r#"{"query_status": "ok", "host": "evil.example.net", "urls": []}"#,
            "URLhaus response describes a different URL or host",
        ),
        (
            r#"{"query_status": "ok", "urls": []}"#,
            "URLhaus response does not identify the URL or host",
        ),
    ] {
        assert_eq!(
            parse(body.as_bytes(), &Query::Domain(&target)).unwrap_err(),
            error
        );
    }
    assert!(
        parse(
            br#"{"query_status": "ok", "host": "EXAMPLE.com", "url_count": "1", "urls": []}"#,
            &Query::Domain(&target)
        )
        .is_ok()
    );
    let u = url("https://example.com/a");
    let other = r#"{"query_status": "ok", "url": "https://example.com/b", "id": "1"}"#;
    assert!(parse(other.as_bytes(), &Query::Url(&u)).is_err());
    let ip = r#"{"query_status": "ok", "host": "1.2.3.4", "urls": []}"#;
    assert!(parse(ip.as_bytes(), &Query::Ip("1.2.3.5".parse().unwrap())).is_err());
}

#[test]
fn timestamps() {
    let target = url("https://example.com/x");
    let with = |date_added: &str, last_online: &str| {
        let body = format!(
            r#"{{"query_status": "ok", "url": "https://example.com/x", "id": "1", "url_status": "offline",
                "threat": "malware_download", "larted": "false", "date_added": {date_added}, "last_online": {last_online}}}"#
        );
        listed(parse(body.as_bytes(), &Query::Url(&target)).unwrap())
    };
    let l = with(
        r#""2024-02-29 23:59:59 UTC""#,
        r#""2024-03-01 00:00:01 UTC""#,
    );
    assert_eq!(
        l.date("date_added").unwrap().to_rfc3339(),
        "2024-02-29T23:59:59+00:00"
    );
    assert_eq!(
        l.date("last_online").unwrap().to_rfc3339(),
        "2024-03-01T00:00:01+00:00"
    );
    assert!(l.issues.is_empty(), "{:?}", l.issues);

    // date_added is documented as UTC; last_online is not, so it needs the suffix.
    let l = with(r#""2024-02-29 23:59:59""#, r#""2024-03-01 00:00:01""#);
    assert!(l.date("date_added").is_some());
    assert!(l.date("last_online").is_none());
    assert_eq!(l.issues, ["last_online has no explicit UTC time zone"]);

    for (value, expected) in [
        (
            r#""2024-02-30 00:00:00 UTC""#,
            "date_added is not a documented timestamp",
        ),
        (
            r#""2024-01-01T00:00:00Z""#,
            "date_added is not a documented timestamp",
        ),
        (r#""yesterday""#, "date_added is not a documented timestamp"),
        (
            r#""1900-01-01 00:00:00 UTC""#,
            "date_added is outside the plausible date range",
        ),
        ("1705000000", "date_added has an unexpected type"),
    ] {
        let l = with(value, "null");
        assert!(l.date("date_added").is_none(), "{value}");
        assert_eq!(l.issues, [expected], "{value}");
    }
}

#[test]
fn missing_wrong_hostile_and_duplicate_values_become_issues() {
    let target = url("https://example.com/x");
    let body = r#"{"query_status": "ok", "url": "https://example.com/x", "id": "12a",
        "url_status": "\u001b[2Jonline", "threat": ["malware_download"], "blacklists": "listed",
        "takedown_time_seconds": "-5", "tags": [1, "", "ok", "ok"],
        "payloads": [
            {"response_sha256": "dc9f3b226bccb2f1fd4810cde541e5a10d59a1fe683f4a9462293b6ade8d8403", "signature": "Heodo\u0007"},
            {"response_sha256": "DC9F3B226BCCB2F1FD4810CDE541E5A10D59A1FE683F4A9462293B6ADE8D8403"},
            {"response_sha256": "short"},
            "not an object"
        ]}"#;
    let l = listed(parse(body.as_bytes(), &Query::Url(&target)).unwrap());
    assert!(l.entry_id.is_none());
    assert!(l.attributes.is_empty(), "{:?}", l.attributes);
    assert_eq!(l.tags, ["ok"]);
    assert_eq!(l.metric(RETURNED_PAYLOADS), Some(1));
    for expected in [
        "id is not a numeric identifier",
        "url_status is not a short token",
        "threat has an unexpected type",
        "larted is missing",
        "blacklists has an unexpected type",
        "takedown_time_seconds is not a non-negative integer",
        "a tag has an unexpected type",
        "a payload signature is not a short token",
        "duplicate payload entries were counted once",
        "a payload entry has no valid response_sha256",
        "a payload entry has an unexpected type",
    ] {
        assert!(
            l.issues.iter().any(|i| i == expected),
            "missing {expected:?}: {:?}",
            l.issues
        );
    }

    let host = domain("example.com");
    let body = r#"{"query_status": "ok", "host": "example.com", "url_count": 99999999999,
        "urls": [{"id": "1", "url_status": "online"}, {"id": "1", "url_status": "online"}, {"id": null}, 7]}"#;
    let l = listed(parse(body.as_bytes(), &Query::Domain(&host)).unwrap());
    assert_eq!(
        l.metric(RETURNED_URLS),
        Some(1),
        "duplicates are counted once"
    );
    assert_eq!(l.metric(RETURNED_URLS_ONLINE), Some(1));
    for expected in [
        "url_count is out of range",
        "duplicate URL entries were counted once",
        "a URL entry id is missing",
        "a URL entry has an unexpected type",
    ] {
        assert!(
            l.issues.iter().any(|i| i == expected),
            "missing {expected:?}: {:?}",
            l.issues
        );
    }
    let bare = listed(
        parse(
            br#"{"query_status": "ok", "host": "example.com"}"#,
            &Query::Domain(&host),
        )
        .unwrap(),
    );
    assert_eq!(bare.issues, ["url_count is missing", "urls is missing"]);
}

#[test]
fn deep_nesting_and_huge_values_are_contained() {
    let host = domain("example.com");
    let deep = format!(
        r#"{{"query_status": "ok", "host": "example.com", "x": {}{}}}"#,
        "[".repeat(100_000),
        "]".repeat(100_000)
    );
    assert!(parse(deep.as_bytes(), &Query::Domain(&host)).is_err());

    let urls: Vec<String> = (0..20_000)
        .map(|i| {
            format!(
                r#"{{"id": "{i}", "url_status": "offline", "tags": ["t{}"]}}"#,
                i % 100
            )
        })
        .collect();
    let body = format!(
        r#"{{"query_status": "ok", "host": "example.com", "url_count": "20000", "urls": [{}]}}"#,
        urls.join(",")
    );
    let l = listed(parse(body.as_bytes(), &Query::Domain(&host)).unwrap());
    assert_eq!(l.metric(RETURNED_URLS), Some(20_000));
    assert_eq!(l.tags.len(), MAX_TAGS);
    assert!(
        l.issues
            .iter()
            .any(|i| i == "tags has too many entries; the rest were ignored")
    );
    let long_tag = format!(
        r#"{{"query_status": "ok", "host": "example.com", "url_count": "1", "urls": [{{"id": "1", "tags": ["{}"]}}]}}"#,
        "y".repeat(100_000)
    );
    let l = listed(parse(long_tag.as_bytes(), &Query::Domain(&host)).unwrap());
    assert_eq!(l.tags[0].chars().count(), MAX_TAG_CHARS);
}

fn arbitrary_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        any::<f64>().prop_map(|n| serde_json::json!(n)),
        ".{0,40}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::Array),
            proptest::collection::btree_map(
                prop_oneof![
                    Just("query_status".to_owned()),
                    Just("host".to_owned()),
                    Just("url".to_owned()),
                    Just("urls".to_owned()),
                    Just("payloads".to_owned()),
                    Just("tags".to_owned()),
                    Just("blacklists".to_owned()),
                    Just("date_added".to_owned()),
                    Just("id".to_owned()),
                    "[a-z_]{1,12}",
                ],
                inner,
                0..8
            )
            .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let target = domain("example.com");
        let _ = parse(&bytes, &Query::Domain(&target));
    }

    #[test]
    fn arbitrary_documents_never_panic_and_stay_bounded(mut value in arbitrary_json(), ok in any::<bool>()) {
        if ok && let Some(map) = value.as_object_mut() {
            map.insert("query_status".into(), "ok".into());
            map.insert("host".into(), "example.com".into());
        }
        let body = serde_json::to_vec(&value).unwrap();
        let target = domain("example.com");
        if let Ok(Answer::Listed(l)) = parse(&body, &Query::Domain(&target)) {
            prop_assert!(l.tags.len() <= MAX_TAGS);
            for attribute in &l.attributes {
                prop_assert!(is_token(&attribute.value), "{:?}", attribute);
            }
        }
    }

    #[test]
    fn stored_classifications_are_always_terminal_safe(value in ".{0,60}") {
        let body = serde_json::json!({
            "query_status": "ok", "url": "https://example.com/x", "id": "1",
            "url_status": value, "threat": value, "larted": value,
            "blacklists": {"surbl": value, "spamhaus_dbl": value},
        });
        let target = url("https://example.com/x");
        let l = listed(parse(&serde_json::to_vec(&body).unwrap(), &Query::Url(&target)).unwrap());
        for attribute in &l.attributes {
            prop_assert!(!attribute.value.chars().any(sentinel_core::text::is_unsafe));
            prop_assert!(attribute.value.chars().count() <= MAX_TOKEN_CHARS);
        }
    }
}

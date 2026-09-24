//! Parsing of VirusTotal API v3 object responses.
//!
//! Documented shape (docs.virustotal.com, retrieved 2026-09-23; see
//! `docs/DATA-SOURCES.md`): `{"data": {"type": "<object type>", "id":
//! "<id>", "attributes": {...}}}`. Errors are `{"error": {"code": "...",
//! "message": "..."}}`.
//!
//! Only a fixed set of attributes is extracted: `last_analysis_stats`,
//! `last_analysis_date`, `reputation`, `total_votes` and `tags`. Everything
//! else (per-engine results, WHOIS, certificates, DNS records, HTTP
//! headers and cookies, file names, …) is never copied: it is either
//! personal data, a pivot source, or not needed for enrichment.
//!
//! The body (size-capped by the HTTP client) is parsed into a
//! `serde_json::Value` (recursion-limited). Problems with individual fields
//! become issues; values are never invented. A response about a different
//! object than the one queried is rejected as a whole.

use std::net::IpAddr;

use chrono::{DateTime, Datelike, Utc};
use sentinel_core::{DomainName, HashAlgorithm, Indicator, ProviderMetric, ProviderReputation};
use serde_json::{Map, Value};

use crate::sources::truncate_chars;

/// Provider identifier stored in observations.
pub(crate) const PROVIDER: &str = "virustotal";

/// `last_analysis_stats` counters present for every object type.
pub(crate) const REQUIRED_STATS: [&str; 5] = [
    "malicious",
    "suspicious",
    "undetected",
    "harmless",
    "timeout",
];
/// Counters documented only for file analyses.
const FILE_STATS: [&str; 3] = ["confirmed-timeout", "failure", "type-unsupported"];
/// Metric name prefix for `last_analysis_stats` counters.
pub const STATS_PREFIX: &str = "last_analysis_stats.";
/// Metric name prefix for `total_votes` counters.
pub const VOTES_PREFIX: &str = "total_votes.";

/// Engine counts above this are treated as corrupt (VirusTotal documents
/// "70+" engines).
const MAX_PLAUSIBLE_ENGINES: u64 = 10_000;
/// Vote counts above this are treated as corrupt.
const MAX_PLAUSIBLE_VOTES: u64 = 1_000_000_000;
/// `reputation` values outside ±this are treated as corrupt.
const MAX_ABS_REPUTATION: i64 = 1_000_000_000;
const MAX_TAGS: usize = 32;
const MAX_TAG_CHARS: usize = 64;

/// What the query expects the response to describe.
pub(crate) enum Expected<'a> {
    Ip(IpAddr),
    Domain(&'a DomainName),
    /// The URL identifier is VirusTotal's SHA-256 of its canonical form,
    /// which Sentinel cannot recompute; only its shape is checked.
    Url,
    Sha256(&'a str),
}

impl Expected<'_> {
    pub(crate) fn from_indicator(indicator: &Indicator) -> Option<Expected<'_>> {
        match indicator {
            Indicator::Ipv4(ip) => Some(Expected::Ip(IpAddr::V4(*ip))),
            Indicator::Ipv6(ip) => Some(Expected::Ip(IpAddr::V6(*ip))),
            Indicator::Domain(domain) => Some(Expected::Domain(domain)),
            Indicator::Url(_) => Some(Expected::Url),
            Indicator::FileHash(hash) if hash.algorithm() == HashAlgorithm::Sha256 => {
                Some(Expected::Sha256(hash.as_str()))
            }
            Indicator::FileHash(_) => None,
        }
    }

    /// The documented `type` of the object.
    const fn object_type(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip_address",
            Self::Domain(_) => "domain",
            Self::Url => "url",
            Self::Sha256(_) => "file",
        }
    }

    fn matches_id(&self, id: &str) -> bool {
        match self {
            Self::Ip(ip) => id.parse::<IpAddr>().is_ok_and(|got| got == *ip),
            Self::Domain(domain) => DomainName::parse(id).is_ok_and(|got| &got == *domain),
            Self::Url => is_lower_hex_sha256(id),
            Self::Sha256(hash) => id.eq_ignore_ascii_case(hash),
        }
    }

    const fn is_file(&self) -> bool {
        matches!(self, Self::Sha256(_))
    }
}

fn is_lower_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether a `404` body is VirusTotal's documented `NotFoundError`. Any
/// other `404` (a wrong path, a proxy page) is a failure, not "unknown to
/// VirusTotal".
pub(crate) fn is_not_found_error(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body).is_ok_and(|document| {
        document
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            == Some("NotFoundError")
    })
}

/// Parses an object response for `expected`.
///
/// # Errors
/// A fixed description if the body is not JSON, has no `data` object, or
/// describes a different object than the one queried.
pub(crate) fn parse_object(
    body: &[u8],
    expected: &Expected<'_>,
) -> Result<ProviderReputation, &'static str> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| "VirusTotal response is not valid JSON")?;
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .ok_or("VirusTotal response has no data object")?;
    if data.get("type").and_then(Value::as_str) != Some(expected.object_type()) {
        return Err("VirusTotal response describes a different object type");
    }
    match data.get("id").and_then(Value::as_str) {
        Some(id) if expected.matches_id(id.trim()) => {}
        Some(_) => return Err("VirusTotal response describes a different object"),
        None => return Err("VirusTotal response does not identify the object"),
    }

    let mut issues: Vec<String> = Vec::new();
    let mut issue = |text: &str| {
        if !issues.iter().any(|i| i == text) {
            issues.push(text.to_owned());
        }
    };

    let empty = Map::new();
    let attributes = match data.get("attributes") {
        Some(Value::Object(attributes)) => attributes,
        None | Some(Value::Null) => {
            issue("attributes is missing");
            &empty
        }
        Some(_) => {
            issue("attributes has an unexpected type");
            &empty
        }
    };

    let mut metrics = Vec::new();
    stats(attributes, expected.is_file(), &mut metrics, &mut issue);
    votes(attributes, &mut metrics, &mut issue);
    let community_score = reputation(attributes, &mut issue);
    let last_analysis_at = timestamp(attributes, "last_analysis_date", &mut issue);
    let tags = tags(attributes, &mut issue);

    Ok(ProviderReputation {
        provider: PROVIDER.into(),
        metrics,
        community_score,
        last_analysis_at,
        tags,
        issues,
    })
}

fn stats(
    attributes: &Map<String, Value>,
    is_file: bool,
    metrics: &mut Vec<ProviderMetric>,
    issue: &mut impl FnMut(&str),
) {
    let stats = match attributes.get("last_analysis_stats") {
        Some(Value::Object(stats)) => stats,
        None | Some(Value::Null) => {
            issue("last_analysis_stats is missing");
            return;
        }
        Some(_) => {
            issue("last_analysis_stats has an unexpected type");
            return;
        }
    };
    let optional: &[&str] = if is_file { &FILE_STATS } else { &[] };
    for (key, required) in REQUIRED_STATS
        .iter()
        .map(|k| (*k, true))
        .chain(optional.iter().map(|k| (*k, false)))
    {
        if let Some(value) = count(
            stats,
            key,
            required,
            MAX_PLAUSIBLE_ENGINES,
            "last_analysis_stats",
            issue,
        ) {
            metrics.push(ProviderMetric {
                name: format!("{STATS_PREFIX}{key}"),
                value,
                max: None,
            });
        }
    }
}

fn votes(
    attributes: &Map<String, Value>,
    metrics: &mut Vec<ProviderMetric>,
    issue: &mut impl FnMut(&str),
) {
    let votes = match attributes.get("total_votes") {
        Some(Value::Object(votes)) => votes,
        None | Some(Value::Null) => {
            issue("total_votes is missing");
            return;
        }
        Some(_) => {
            issue("total_votes has an unexpected type");
            return;
        }
    };
    for key in ["harmless", "malicious"] {
        if let Some(value) = count(votes, key, true, MAX_PLAUSIBLE_VOTES, "total_votes", issue) {
            metrics.push(ProviderMetric {
                name: format!("{VOTES_PREFIX}{key}"),
                value,
                max: None,
            });
        }
    }
}

/// A bounded non-negative integer inside `parent`.
fn count(
    map: &Map<String, Value>,
    key: &str,
    required: bool,
    max: u64,
    parent: &str,
    issue: &mut impl FnMut(&str),
) -> Option<u64> {
    match map.get(key) {
        None | Some(Value::Null) => {
            if required {
                issue(&format!("{parent}.{key} is missing"));
            }
            None
        }
        Some(value) => match value.as_u64() {
            Some(n) if n <= max => Some(n),
            Some(_) => {
                issue(&format!("{parent}.{key} is out of range"));
                None
            }
            None => {
                issue(&format!("{parent}.{key} is not a non-negative integer"));
                None
            }
        },
    }
}

fn reputation(attributes: &Map<String, Value>, issue: &mut impl FnMut(&str)) -> Option<i64> {
    match attributes.get("reputation") {
        None | Some(Value::Null) => {
            issue("reputation is missing");
            None
        }
        Some(value) => match value.as_i64() {
            Some(n) if n.abs() <= MAX_ABS_REPUTATION => Some(n),
            Some(_) => {
                issue("reputation is out of range");
                None
            }
            None => {
                issue("reputation is not an integer");
                None
            }
        },
    }
}

/// Documented as an integer "UTC timestamp" (seconds since the Unix epoch).
/// Absent for objects that were never analyzed.
fn timestamp(
    attributes: &Map<String, Value>,
    key: &str,
    issue: &mut impl FnMut(&str),
) -> Option<DateTime<Utc>> {
    match attributes.get(key) {
        None | Some(Value::Null) => None,
        Some(value) => {
            let Some(seconds) = value.as_i64() else {
                issue(&format!("{key} is not an integer UTC timestamp"));
                return None;
            };
            match DateTime::from_timestamp(seconds, 0) {
                Some(at) if (1990..=9999).contains(&at.year()) => Some(at),
                _ => {
                    issue(&format!("{key} is outside the plausible date range"));
                    None
                }
            }
        }
    }
}

fn tags(attributes: &Map<String, Value>, issue: &mut impl FnMut(&str)) -> Vec<String> {
    match attributes.get("tags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_TAGS {
                issue("tags has too many entries; the rest were ignored");
            }
            items
                .iter()
                .take(MAX_TAGS)
                .filter_map(|item| match item.as_str() {
                    Some(s) if !s.trim().is_empty() => {
                        let (kept, truncated) = truncate_chars(s.trim(), MAX_TAG_CHARS);
                        if truncated {
                            issue("a tag was truncated");
                        }
                        Some(kept)
                    }
                    Some(_) => None,
                    None => {
                        issue("a tag has an unexpected type");
                        None
                    }
                })
                .collect()
        }
        Some(_) => {
            issue("tags has an unexpected type");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    fn domain(s: &str) -> DomainName {
        DomainName::parse(s).unwrap()
    }

    fn ip_body(id: &str, attributes: &str) -> String {
        format!(r#"{{"data": {{"type": "ip_address", "id": "{id}", "attributes": {attributes}}}}}"#)
    }

    const CLEAN: &str = r#"{"last_analysis_date": 1671691600,
        "last_analysis_stats": {"harmless": 60, "malicious": 0, "suspicious": 0, "timeout": 0, "undetected": 30},
        "reputation": 0, "total_votes": {"harmless": 1, "malicious": 0}, "tags": [],
        "whois": "OrgTechEmail: someone@example.net\nOrgTechPhone: +1 555 0100",
        "last_analysis_results": {"EngineA": {"category": "harmless", "result": "clean"}},
        "last_https_certificate": {"subject": {"CN": "www.example.net"}},
        "as_owner": "Example AS", "network": "81.169.128.0/17"}"#;

    #[test]
    fn parses_the_documented_ip_shape_and_drops_everything_else() {
        let r = parse_object(
            ip_body("81.169.145.1", CLEAN).as_bytes(),
            &Expected::Ip("81.169.145.1".parse().unwrap()),
        )
        .unwrap();
        assert_eq!(r.provider, "virustotal");
        assert!(r.issues.is_empty(), "{:?}", r.issues);
        assert_eq!(r.metric("last_analysis_stats.malicious"), Some(0));
        assert_eq!(r.metric("last_analysis_stats.undetected"), Some(30));
        assert_eq!(r.metric("last_analysis_stats.harmless"), Some(60));
        assert_eq!(r.metric("total_votes.harmless"), Some(1));
        assert_eq!(r.community_score, Some(0));
        assert_eq!(
            r.last_analysis_at.unwrap().to_rfc3339(),
            "2022-12-22T06:46:40+00:00",
            "integer seconds are UTC"
        );
        let json = serde_json::to_string(&r).unwrap();
        for dropped in [
            "someone@example.net",
            "555",
            "EngineA",
            "www.example.net",
            "Example AS",
            "81.169.128.0",
        ] {
            assert!(!json.contains(dropped), "{dropped} must not be stored");
        }
    }

    #[test]
    fn identity_checks() {
        let ip = Expected::Ip("2001:db8::1".parse().unwrap());
        assert!(
            parse_object(ip_body("2001:0db8:0:0:0:0:0:1", CLEAN).as_bytes(), &ip).is_ok(),
            "semantic IPv6 comparison"
        );
        assert_eq!(
            parse_object(ip_body("2001:db8::2", CLEAN).as_bytes(), &ip).unwrap_err(),
            "VirusTotal response describes a different object"
        );
        let wrong_type = r#"{"data": {"type": "domain", "id": "2001:db8::1", "attributes": {}}}"#;
        assert_eq!(
            parse_object(wrong_type.as_bytes(), &ip).unwrap_err(),
            "VirusTotal response describes a different object type"
        );
        let no_id = r#"{"data": {"type": "ip_address", "attributes": {}}}"#;
        assert_eq!(
            parse_object(no_id.as_bytes(), &ip).unwrap_err(),
            "VirusTotal response does not identify the object"
        );

        let d = domain("example.com");
        let body = |id: &str| {
            format!(r#"{{"data": {{"type": "domain", "id": "{id}", "attributes": {CLEAN}}}}}"#)
        };
        assert!(parse_object(body("EXAMPLE.com.").as_bytes(), &Expected::Domain(&d)).is_ok());
        assert!(
            parse_object(
                body("example.com.evil.test").as_bytes(),
                &Expected::Domain(&d)
            )
            .is_err()
        );

        let file = |id: &str| {
            format!(r#"{{"data": {{"type": "file", "id": "{id}", "attributes": {CLEAN}}}}}"#)
        };
        assert!(parse_object(file(&SHA.to_uppercase()).as_bytes(), &Expected::Sha256(SHA)).is_ok());
        assert!(parse_object(file(&"0".repeat(64)).as_bytes(), &Expected::Sha256(SHA)).is_err());

        let url = |id: &str| {
            format!(r#"{{"data": {{"type": "url", "id": "{id}", "attributes": {CLEAN}}}}}"#)
        };
        assert!(parse_object(url(SHA).as_bytes(), &Expected::Url).is_ok());
        assert!(
            parse_object(
                url("aHR0cHM6Ly9leGFtcGxlLmNvbS8").as_bytes(),
                &Expected::Url
            )
            .is_err()
        );
    }

    #[test]
    fn file_only_counters_are_kept_for_files() {
        let attributes = r#"{"last_analysis_stats": {"harmless": 0, "malicious": 5, "suspicious": 1, "timeout": 0, "undetected": 60,
            "confirmed-timeout": 0, "failure": 2, "type-unsupported": 7}, "reputation": -3, "total_votes": {"harmless": 0, "malicious": 4},
            "names": ["C:\\Users\\alice\\Desktop\\invoice.exe"], "meaningful_name": "invoice.exe"}"#;
        let body =
            format!(r#"{{"data": {{"type": "file", "id": "{SHA}", "attributes": {attributes}}}}}"#);
        let r = parse_object(body.as_bytes(), &Expected::Sha256(SHA)).unwrap();
        assert_eq!(r.metric("last_analysis_stats.type-unsupported"), Some(7));
        assert_eq!(r.metric("last_analysis_stats.failure"), Some(2));
        assert_eq!(r.community_score, Some(-3));
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("alice") && !json.contains("invoice"),
            "file names are never stored"
        );
    }

    #[test]
    fn missing_wrong_and_absurd_values_become_issues() {
        let ip = Expected::Ip("8.8.8.8".parse().unwrap());
        let attributes = r#"{"last_analysis_stats": {"harmless": "3", "malicious": -1, "suspicious": 1e9, "undetected": 1.5},
            "reputation": "bad", "total_votes": [], "tags": "x", "last_analysis_date": "2024-01-01T00:00:00Z"}"#;
        let r = parse_object(ip_body("8.8.8.8", attributes).as_bytes(), &ip).unwrap();
        assert!(r.metrics.is_empty(), "{:?}", r.metrics);
        assert_eq!(r.community_score, None);
        assert!(r.last_analysis_at.is_none());
        for expected in [
            "last_analysis_stats.harmless is not a non-negative integer",
            "last_analysis_stats.malicious is not a non-negative integer",
            "last_analysis_stats.suspicious is not a non-negative integer",
            "last_analysis_stats.undetected is not a non-negative integer",
            "last_analysis_stats.timeout is missing",
            "reputation is not an integer",
            "total_votes has an unexpected type",
            "tags has an unexpected type",
            "last_analysis_date is not an integer UTC timestamp",
        ] {
            assert!(
                r.issues.iter().any(|i| i == expected),
                "missing {expected:?}: {:?}",
                r.issues
            );
        }
        let absurd = r#"{"last_analysis_stats": {"harmless": 99999, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0},
            "reputation": 99999999999, "total_votes": {"harmless": 0, "malicious": 0}, "last_analysis_date": -5}"#;
        let r = parse_object(ip_body("8.8.8.8", absurd).as_bytes(), &ip).unwrap();
        for expected in [
            "last_analysis_stats.harmless is out of range",
            "reputation is out of range",
            "last_analysis_date is outside the plausible date range",
        ] {
            assert!(
                r.issues.iter().any(|i| i == expected),
                "missing {expected:?}: {:?}",
                r.issues
            );
        }
        let empty =
            parse_object(br#"{"data": {"type": "ip_address", "id": "8.8.8.8"}}"#, &ip).unwrap();
        assert_eq!(
            empty.issues,
            vec![
                "attributes is missing",
                "last_analysis_stats is missing",
                "total_votes is missing",
                "reputation is missing"
            ]
        );
        let never = parse_object(
            ip_body("8.8.8.8", r#"{"last_analysis_date": null}"#).as_bytes(),
            &ip,
        )
        .unwrap();
        assert!(
            never.last_analysis_at.is_none()
                && !never
                    .issues
                    .iter()
                    .any(|i| i.contains("last_analysis_date"))
        );
    }

    #[test]
    fn rejects_non_documents_and_deep_nesting() {
        let ip = Expected::Ip("8.8.8.8".parse().unwrap());
        for body in [
            "",
            "<html>",
            "[]",
            "null",
            r#"{"error": {"code": "NotFoundError", "message": "x"}}"#,
            r#"{"data": []}"#,
            r#"{"data": "ip_address"}"#,
        ] {
            assert!(parse_object(body.as_bytes(), &ip).is_err(), "{body:?}");
        }
        let deep = format!(
            r#"{{"data": {{"type": "ip_address", "id": "8.8.8.8", "attributes": {{"x": {}{}}}}}}}"#,
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert!(parse_object(deep.as_bytes(), &ip).is_err());
    }

    #[test]
    fn huge_values_are_bounded_and_hostile_text_is_kept_faithfully() {
        let ip = Expected::Ip("8.8.8.8".parse().unwrap());
        let many: Vec<String> = (0..10_000).map(|i| format!("\"t{i}\"")).collect();
        let attributes = format!(
            r#"{{"tags": ["\u001b]0;pwned\u0007{}", {}], "last_analysis_results": {{"x": "{}"}}}}"#,
            "y".repeat(100_000),
            many.join(","),
            "z".repeat(1_000_000)
        );
        let r = parse_object(ip_body("8.8.8.8", &attributes).as_bytes(), &ip).unwrap();
        assert_eq!(r.tags.len(), MAX_TAGS);
        assert_eq!(r.tags[0].chars().count(), MAX_TAG_CHARS);
        assert!(r.tags[0].starts_with('\u{1b}'), "evidence is faithful");
        assert!(r.issues.iter().any(|i| i == "a tag was truncated"));
        assert!(
            r.issues
                .iter()
                .any(|i| i == "tags has too many entries; the rest were ignored")
        );
    }

    #[test]
    fn not_found_detection_is_strict() {
        assert!(is_not_found_error(
            br#"{"error": {"code": "NotFoundError", "message": "not found"}}"#
        ));
        for body in [
            "",
            "<html>404</html>",
            r#"{"error": {"code": "WrongCredentialsError"}}"#,
            r#"{"error": "NotFoundError"}"#,
            r#"{"data": {}}"#,
        ] {
            assert!(!is_not_found_error(body.as_bytes()), "{body:?}");
        }
    }
}

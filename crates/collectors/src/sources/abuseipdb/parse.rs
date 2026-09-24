//! Parsing of AbuseIPDB APIv2 `check` responses.
//!
//! Documented shape (docs.abuseipdb.com, retrieved 2026-09-23):
//!
//! ```json
//! {"data": {"ipAddress": "118.25.6.39", "isPublic": true, "ipVersion": 4,
//!   "isWhitelisted": false, "abuseConfidenceScore": 100, "countryCode": "CN",
//!   "usageType": "Data Center/Web Hosting/Transit", "isp": "…", "domain": "tencent.com",
//!   "hostnames": [], "isTor": false, "totalReports": 1, "numDistinctUsers": 1,
//!   "lastReportedAt": "2018-12-20T20:55:14+00:00"}}
//! ```
//!
//! Sentinel never sets `verbose`, so per-report data (comments, reporter
//! IDs, reporter countries, categories) is not requested. If a `reports`
//! array appears anyway, it is ignored and never stored.
//!
//! The body (size-capped by the HTTP client) is parsed into a
//! `serde_json::Value`, then a fixed set of fields is extracted with type,
//! range and size checks. Problems become issues; values are never invented.

use std::net::IpAddr;

use chrono::{DateTime, Datelike, Utc};
use sentinel_core::{IpReputation, ProviderMetric};
use serde_json::{Map, Value};

use crate::sources::truncate_chars;

/// Provider identifier stored in observations.
pub(crate) const PROVIDER: &str = "abuseipdb";
/// Metric name for AbuseIPDB's `abuseConfidenceScore` (0–100).
pub const ABUSE_CONFIDENCE_SCORE: &str = "abuse_confidence_score";
/// Metric name for AbuseIPDB's `totalReports` (reports within the window).
pub const TOTAL_REPORTS: &str = "total_reports";
/// Metric name for AbuseIPDB's `numDistinctUsers`.
pub const NUM_DISTINCT_USERS: &str = "num_distinct_users";
/// AbuseIPDB documents geolocation, usage type, ISP and domain as sourced from IPinfo.
pub(crate) const CONTEXT_SOURCE: &str = "IPinfo (as reported by AbuseIPDB)";

const MAX_TEXT: usize = 256;
const MAX_HOSTNAMES: usize = 10;
/// Report counts above this are treated as corrupt.
const MAX_PLAUSIBLE_REPORTS: u64 = 1_000_000_000;

/// Parses a `check` response for `queried_ip` with the given look-back window.
///
/// # Errors
/// A fixed description if the body is not JSON or has no `data` object.
pub(crate) fn parse_check(
    body: &[u8],
    queried_ip: IpAddr,
    window_days: u16,
) -> Result<IpReputation, &'static str> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| "AbuseIPDB response is not valid JSON")?;
    let data = document
        .get("data")
        .and_then(Value::as_object)
        .ok_or("AbuseIPDB response has no data object")?;

    let mut issues: Vec<String> = Vec::new();
    let mut issue = |text: &str| {
        if !issues.iter().any(|i| i == text) {
            issues.push(text.to_owned());
        }
    };

    match data
        .get("ipAddress")
        .and_then(Value::as_str)
        .map(|s| s.trim().parse::<IpAddr>())
    {
        Some(Ok(ip)) if ip == queried_ip => {}
        Some(Ok(_)) => issue("response is for a different address"),
        Some(Err(_)) => issue("ipAddress is not a valid address"),
        None => issue("ipAddress is missing"),
    }

    let mut metrics = Vec::new();
    let score = count(data, "abuseConfidenceScore", Some(100), &mut issue);
    if let Some(value) = score {
        metrics.push(ProviderMetric {
            name: ABUSE_CONFIDENCE_SCORE.into(),
            value,
            max: Some(100),
        });
    }
    let total = count(
        data,
        "totalReports",
        Some(MAX_PLAUSIBLE_REPORTS),
        &mut issue,
    );
    if let Some(value) = total {
        metrics.push(ProviderMetric {
            name: TOTAL_REPORTS.into(),
            value,
            max: None,
        });
    }
    let distinct = count(
        data,
        "numDistinctUsers",
        Some(MAX_PLAUSIBLE_REPORTS),
        &mut issue,
    );
    if let Some(value) = distinct {
        if total.is_some_and(|t| value > t) {
            issue("numDistinctUsers exceeds totalReports");
        }
        metrics.push(ProviderMetric {
            name: NUM_DISTINCT_USERS.into(),
            value,
            max: None,
        });
    }

    let last_reported_at = timestamp(data, "lastReportedAt", &mut issue);
    let is_allowlisted = flag(data, "isWhitelisted", &mut issue);
    let is_tor = flag(data, "isTor", &mut issue);
    let usage_type = text(data, "usageType", &mut issue);
    let isp = text(data, "isp", &mut issue);
    let domain = text(data, "domain", &mut issue);
    let country_code = text(data, "countryCode", &mut issue).and_then(|c| {
        if c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphabetic()) {
            Some(c.to_ascii_uppercase())
        } else {
            issue("countryCode is not a two-letter code");
            None
        }
    });
    let hostnames = hostnames(data, &mut issue);
    let has_context =
        usage_type.is_some() || isp.is_some() || domain.is_some() || country_code.is_some();

    Ok(IpReputation {
        provider: PROVIDER.into(),
        queried_ip,
        window_days: Some(window_days),
        metrics,
        last_reported_at,
        is_allowlisted,
        is_tor,
        usage_type,
        isp,
        domain,
        country_code,
        hostnames,
        context_source: has_context.then(|| CONTEXT_SOURCE.to_owned()),
        issues,
    })
}

/// A non-negative integer field, optionally bounded.
fn count(
    data: &Map<String, Value>,
    key: &str,
    max: Option<u64>,
    issue: &mut impl FnMut(&str),
) -> Option<u64> {
    match data.get(key) {
        None | Some(Value::Null) => {
            issue(&format!("{key} is missing"));
            None
        }
        Some(value) => match value.as_u64() {
            Some(n) if max.is_none_or(|m| n <= m) => Some(n),
            Some(_) => {
                issue(&format!("{key} is out of range"));
                None
            }
            None => {
                issue(&format!("{key} is not a non-negative integer"));
                None
            }
        },
    }
}

fn flag(data: &Map<String, Value>, key: &str, issue: &mut impl FnMut(&str)) -> Option<bool> {
    match data.get(key) {
        None | Some(Value::Null) => None, // documented as possibly null
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            issue(&format!("{key} has an unexpected type"));
            None
        }
    }
}

fn text(data: &Map<String, Value>, key: &str, issue: &mut impl FnMut(&str)) -> Option<String> {
    match data.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => {
            let (kept, truncated) = truncate_chars(s.trim(), MAX_TEXT);
            if truncated {
                issue(&format!("{key} was truncated"));
            }
            Some(kept)
        }
        Some(_) => {
            issue(&format!("{key} has an unexpected type"));
            None
        }
    }
}

/// RFC 3339 **with an explicit offset** only. A timestamp without an offset
/// is ambiguous and is not reinterpreted.
fn timestamp(
    data: &Map<String, Value>,
    key: &str,
    issue: &mut impl FnMut(&str),
) -> Option<DateTime<Utc>> {
    match data.get(key) {
        None | Some(Value::Null) => None, // no reports in the window
        Some(Value::String(s)) => match DateTime::parse_from_rfc3339(s.trim()) {
            Ok(reported) if (1990..=9999).contains(&reported.year()) => {
                Some(reported.with_timezone(&Utc))
            }
            Ok(_) => {
                issue(&format!("{key} is outside the plausible date range"));
                None
            }
            Err(_) => {
                issue(&format!(
                    "{key} is not an RFC 3339 timestamp with an offset"
                ));
                None
            }
        },
        Some(_) => {
            issue(&format!("{key} has an unexpected type"));
            None
        }
    }
}

fn hostnames(data: &Map<String, Value>, issue: &mut impl FnMut(&str)) -> Vec<String> {
    match data.get("hostnames") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            if items.len() > MAX_HOSTNAMES {
                issue("hostnames has too many entries; the rest were ignored");
            }
            items
                .iter()
                .take(MAX_HOSTNAMES)
                .filter_map(|item| match item.as_str() {
                    Some(s) if !s.trim().is_empty() => {
                        let (kept, truncated) = truncate_chars(s.trim(), MAX_TEXT);
                        if truncated {
                            issue("a hostname was truncated");
                        }
                        Some(kept)
                    }
                    _ => {
                        issue("a hostname has an unexpected type");
                        None
                    }
                })
                .collect()
        }
        Some(_) => {
            issue("hostnames has an unexpected type");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENTED: &str = r#"{"data": {"ipAddress": "118.25.6.39", "isPublic": true, "ipVersion": 4,
        "isWhitelisted": false, "abuseConfidenceScore": 100, "countryCode": "CN", "countryName": "China",
        "usageType": "Data Center/Web Hosting/Transit", "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
        "domain": "tencent.com", "hostnames": [], "isTor": false, "totalReports": 1, "numDistinctUsers": 1,
        "lastReportedAt": "2018-12-20T20:55:14+00:00",
        "reports": [{"reportedAt": "2018-12-20T20:55:14+00:00", "comment": "Invalid user oracle", "categories": [18, 22], "reporterId": 1, "reporterCountryCode": "US"}]}}"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_the_documented_example_and_ignores_reports() {
        let r = parse_check(DOCUMENTED.as_bytes(), ip("118.25.6.39"), 90).unwrap();
        assert_eq!(r.provider, "abuseipdb");
        assert_eq!(r.metric(ABUSE_CONFIDENCE_SCORE), Some(100));
        assert_eq!(r.metric(TOTAL_REPORTS), Some(1));
        assert_eq!(r.metric(NUM_DISTINCT_USERS), Some(1));
        assert_eq!(
            r.last_reported_at.unwrap().to_rfc3339(),
            "2018-12-20T20:55:14+00:00"
        );
        assert_eq!(r.is_allowlisted, Some(false));
        assert_eq!(r.is_tor, Some(false));
        assert_eq!(
            r.usage_type.as_deref(),
            Some("Data Center/Web Hosting/Transit")
        );
        assert_eq!(r.domain.as_deref(), Some("tencent.com"));
        assert_eq!(r.country_code.as_deref(), Some("CN"));
        assert_eq!(r.context_source.as_deref(), Some(CONTEXT_SOURCE));
        assert_eq!(r.window_days, Some(90));
        assert!(r.issues.is_empty(), "{:?}", r.issues);
        let json = serde_json::to_string(&r).unwrap();
        for private in [
            "Invalid user oracle",
            "reporterId",
            "categories",
            "reporterCountry",
        ] {
            assert!(!json.contains(private), "{private} must not be stored");
        }
    }

    #[test]
    fn timestamps() {
        let with = |ts: &str| {
            let body = format!(
                r#"{{"data": {{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0, "lastReportedAt": {ts}}}}}"#
            );
            parse_check(body.as_bytes(), ip("8.8.8.8"), 90).unwrap()
        };
        assert_eq!(
            with(r#""2026-01-01T10:00:00+02:00""#)
                .last_reported_at
                .unwrap()
                .to_rfc3339(),
            "2026-01-01T08:00:00+00:00"
        );
        assert!(with("null").last_reported_at.is_none());
        assert!(with("null").issues.is_empty());
        for (value, expected) in [
            (
                r#""2026-01-01T10:00:00""#,
                "lastReportedAt is not an RFC 3339 timestamp with an offset",
            ),
            (
                r#""yesterday""#,
                "lastReportedAt is not an RFC 3339 timestamp with an offset",
            ),
            (
                r#""1900-01-01T00:00:00+00:00""#,
                "lastReportedAt is outside the plausible date range",
            ),
            ("17", "lastReportedAt has an unexpected type"),
        ] {
            let r = with(value);
            assert!(r.last_reported_at.is_none(), "{value}");
            assert_eq!(r.issues, vec![expected], "{value}");
        }
    }

    #[test]
    fn missing_wrong_and_absurd_values_become_issues() {
        let body = r#"{"data": {"ipAddress": "9.9.9.9", "abuseConfidenceScore": 250, "totalReports": -1,
            "numDistinctUsers": "3", "isTor": "yes", "isWhitelisted": null, "countryCode": "USA", "isp": 42,
            "hostnames": "x", "unknownField": {"deep": [1,2,3]}}}"#;
        let r = parse_check(body.as_bytes(), ip("8.8.8.8"), 90).unwrap();
        assert!(r.metrics.is_empty());
        assert_eq!(
            (
                r.is_tor,
                r.is_allowlisted,
                r.isp.clone(),
                r.country_code.clone()
            ),
            (None, None, None, None)
        );
        for expected in [
            "response is for a different address",
            "abuseConfidenceScore is out of range",
            "totalReports is not a non-negative integer",
            "numDistinctUsers is not a non-negative integer",
            "isTor has an unexpected type",
            "countryCode is not a two-letter code",
            "isp has an unexpected type",
            "hostnames has an unexpected type",
        ] {
            assert!(
                r.issues.iter().any(|i| i == expected),
                "missing {expected:?}: {:?}",
                r.issues
            );
        }
        let empty = parse_check(br#"{"data": {}}"#, ip("8.8.8.8"), 90).unwrap();
        assert!(
            empty
                .issues
                .iter()
                .any(|i| i == "abuseConfidenceScore is missing")
        );
        assert!(empty.issues.iter().any(|i| i == "ipAddress is missing"));
        let inconsistent = parse_check(br#"{"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 5, "totalReports": 1, "numDistinctUsers": 7}}"#, ip("8.8.8.8"), 90).unwrap();
        assert!(
            inconsistent
                .issues
                .iter()
                .any(|i| i == "numDistinctUsers exceeds totalReports")
        );
    }

    #[test]
    fn ipv6_addresses_are_compared_semantically() {
        let body = r#"{"data": {"ipAddress": "2001:4860:4860:0:0:0:0:8888", "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0}}"#;
        let r = parse_check(body.as_bytes(), ip("2001:4860:4860::8888"), 90).unwrap();
        assert!(r.issues.is_empty(), "{:?}", r.issues);
    }

    #[test]
    fn rejects_non_documents_and_deep_nesting() {
        for body in [
            "",
            "<html>",
            "[]",
            "null",
            r#"{"errors": [{"detail": "x", "status": 401}]}"#,
            r#"{"data": []}"#,
        ] {
            assert!(
                parse_check(body.as_bytes(), ip("8.8.8.8"), 90).is_err(),
                "{body:?}"
            );
        }
        let deep = format!(
            r#"{{"data": {{"x": {}{}}}}}"#,
            "[".repeat(100_000),
            "]".repeat(100_000)
        );
        assert!(parse_check(deep.as_bytes(), ip("8.8.8.8"), 90).is_err());
    }

    #[test]
    fn huge_values_are_bounded_and_hostile_text_is_kept_faithfully() {
        let hostnames: Vec<String> = (0..1000).map(|i| format!("\"h{i}.example.net\"")).collect();
        let body = format!(
            r#"{{"data": {{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 3, "totalReports": 2, "numDistinctUsers": 2,
                "isp": "\u001b]0;pwned\u0007ISP\r\nFORGED {}", "hostnames": [{}]}}}}"#,
            "x".repeat(100_000),
            hostnames.join(",")
        );
        let r = parse_check(body.as_bytes(), ip("8.8.8.8"), 90).unwrap();
        assert_eq!(r.hostnames.len(), MAX_HOSTNAMES);
        assert_eq!(r.isp.as_ref().unwrap().chars().count(), MAX_TEXT);
        assert!(
            r.isp.as_ref().unwrap().starts_with('\u{1b}'),
            "evidence is faithful"
        );
        assert!(r.issues.iter().any(|i| i == "isp was truncated"));
        assert!(
            r.issues
                .iter()
                .any(|i| i == "hostnames has too many entries; the rest were ignored")
        );
    }
}

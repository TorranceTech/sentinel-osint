//! Parsing of URLhaus API `v1/url/` and `v1/host/` responses.
//!
//! Documented shape (urlhaus-api.abuse.ch, retrieved 2026-09-23; see
//! `docs/DATA-SOURCES.md`): a JSON object whose `query_status` is `ok`,
//! `no_results`, `invalid_url`/`invalid_host` or `http_post_expected`.
//! The documented host example spells the key `query_staus`; both spellings
//! are accepted because both appear in the official documentation.
//!
//! Extracted: the entry ID, `url_status`, `threat`, `larted`,
//! `blacklists.*`, `date_added`, `last_online`, `firstseen`, `url_count`,
//! `takedown_time_seconds`, tags, and payload signatures. Never copied:
//! `reporter` (a person's social-media handle), payload `filename`s,
//! `urlhaus_download` links, the `virustotal` sub-object, payload hashes
//! and fuzzy hashes, and the URLs listed for a host. Listed URLs are
//! counted, not stored, and nothing in a response is ever fetched.
//!
//! Classifications must be short tokens; anything else is dropped as an
//! issue, so provider text never reaches finding details.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sentinel_core::{
    DomainName, HttpUrl, ProviderAttribute, ProviderDate, ProviderListing, ProviderMetric,
};
use serde_json::{Map, Value};

#[cfg(test)]
use crate::sources::abusech::{MAX_TAG_CHARS, MAX_TOKEN_CHARS};
use crate::sources::abusech::{MAX_TAGS, count, is_token, tags, timestamp, token};

/// Provider identifier stored in observations.
pub(crate) const PROVIDER: &str = "urlhaus";

/// Host lookups: URLhaus's `url_count` (URLs observed on the host).
pub const URL_COUNT: &str = "url_count";
/// Host lookups: distinct URL entries in the returned list (at most 100
/// per the documentation), counted by Sentinel.
pub const RETURNED_URLS: &str = "returned_urls";
/// Host lookups: returned URL entries with `url_status = online`, counted
/// by Sentinel.
pub const RETURNED_URLS_ONLINE: &str = "returned_urls.online";
/// URL lookups: distinct payloads in the returned list, counted by Sentinel.
pub const RETURNED_PAYLOADS: &str = "returned_payloads";
/// URL lookups: URLhaus's `takedown_time_seconds`.
pub const TAKEDOWN_TIME_SECONDS: &str = "takedown_time_seconds";
/// Host lookups: the most recent `date_added` among returned URL entries.
pub const LATEST_URL_ADDED: &str = "returned_urls.latest_date_added";

const MAX_SIGNATURES: usize = 10;
const MAX_ENTRY_ID_DIGITS: usize = 20;

/// What was queried.
pub(crate) enum Query<'a> {
    Url(&'a HttpUrl),
    Domain(&'a DomainName),
    Ip(IpAddr),
}

/// A successful answer.
#[derive(Debug)]
pub(crate) enum Answer {
    /// `query_status = ok`.
    Listed(ProviderListing),
    /// `query_status = no_results`: URLhaus has no entry.
    NoResults,
}

/// Parses a lookup response for `query`.
///
/// # Errors
/// A fixed description if the body is not a JSON object, has no or an
/// error `query_status`, or describes another URL or host.
pub(crate) fn parse(body: &[u8], query: &Query<'_>) -> Result<Answer, &'static str> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| "URLhaus response is not valid JSON")?;
    let data = document
        .as_object()
        .ok_or("URLhaus response is not a JSON object")?;
    let status = data
        .get("query_status")
        .or_else(|| data.get("query_staus"))
        .and_then(Value::as_str)
        .ok_or("URLhaus response has no query_status")?;
    match status {
        "ok" => {}
        "no_results" => return Ok(Answer::NoResults),
        "invalid_url" | "invalid_host" => return Err("URLhaus rejected the indicator as invalid"),
        "http_post_expected" => return Err("URLhaus reports that the request was not a POST"),
        _ => return Err("URLhaus returned an undocumented query_status"),
    }
    check_identity(data, query)?;

    let mut issues: Vec<String> = Vec::new();
    let mut issue = |text: &str| {
        if !issues.iter().any(|i| i == text) {
            issues.push(text.to_owned());
        }
    };
    let mut listing = ProviderListing {
        provider: PROVIDER.into(),
        entry_id: None,
        attributes: Vec::new(),
        metrics: Vec::new(),
        dates: Vec::new(),
        tags: Vec::new(),
        issues: Vec::new(),
    };
    blacklists(data, &mut listing, &mut issue);
    match query {
        Query::Url(_) => url_entry(data, &mut listing, &mut issue),
        Query::Domain(_) | Query::Ip(_) => host_entry(data, &mut listing, &mut issue),
    }
    listing.issues = issues;
    Ok(Answer::Listed(listing))
}

/// A response about another URL or host is never attributed to the query.
fn check_identity(data: &Map<String, Value>, query: &Query<'_>) -> Result<(), &'static str> {
    let key = match query {
        Query::Url(_) => "url",
        Query::Domain(_) | Query::Ip(_) => "host",
    };
    let value = data
        .get(key)
        .and_then(Value::as_str)
        .ok_or("URLhaus response does not identify the URL or host")?;
    let same = match query {
        Query::Url(url) => HttpUrl::parse(value).is_ok_and(|got| &got == *url),
        Query::Domain(domain) => DomainName::parse(value).is_ok_and(|got| &got == *domain),
        Query::Ip(ip) => value.trim().parse::<IpAddr>().is_ok_and(|got| got == *ip),
    };
    if same {
        Ok(())
    } else {
        Err("URLhaus response describes a different URL or host")
    }
}

fn url_entry(
    data: &Map<String, Value>,
    listing: &mut ProviderListing,
    issue: &mut impl FnMut(&str),
) {
    listing.entry_id = entry_id(data.get("id"), "id", issue);
    for key in ["url_status", "threat", "larted"] {
        if let Some(value) = token(data, key, true, issue) {
            push_attribute(listing, key, value);
        }
    }
    if let Some(at) = timestamp(data, "date_added", true, issue) {
        push_date(listing, "date_added", at);
    }
    // Documented as "last timestamp" without a stated time zone: only an
    // explicit ` UTC` suffix is accepted.
    if let Some(at) = timestamp(data, "last_online", false, issue) {
        push_date(listing, "last_online", at);
    }
    if let Some(n) = count(
        data.get("takedown_time_seconds"),
        "takedown_time_seconds",
        issue,
    ) {
        push_metric(listing, TAKEDOWN_TIME_SECONDS, n);
    }
    listing.tags = tags(data.get("tags"), "tags", issue);
    payloads(data, listing, issue);
}

fn payloads(
    data: &Map<String, Value>,
    listing: &mut ProviderListing,
    issue: &mut impl FnMut(&str),
) {
    let items = match data.get("payloads") {
        None | Some(Value::Null) => return,
        Some(Value::Array(items)) => items,
        Some(_) => {
            issue("payloads has an unexpected type");
            return;
        }
    };
    let mut hashes = BTreeSet::new();
    let mut signatures = BTreeSet::new();
    for item in items {
        let Some(payload) = item.as_object() else {
            issue("a payload entry has an unexpected type");
            continue;
        };
        match payload.get("response_sha256").and_then(Value::as_str) {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                if !hashes.insert(h.to_ascii_lowercase()) {
                    issue("duplicate payload entries were counted once");
                }
            }
            _ => issue("a payload entry has no valid response_sha256"),
        }
        match payload.get("signature") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if is_token(s) => {
                signatures.insert(s.trim().to_owned());
            }
            Some(_) => issue("a payload signature is not a short token"),
        }
    }
    push_metric(listing, RETURNED_PAYLOADS, len(&hashes));
    if signatures.len() > MAX_SIGNATURES {
        issue("too many payload signatures; the rest were ignored");
    }
    for signature in signatures.into_iter().take(MAX_SIGNATURES) {
        push_attribute(listing, "payloads.signature", signature);
    }
}

fn host_entry(
    data: &Map<String, Value>,
    listing: &mut ProviderListing,
    issue: &mut impl FnMut(&str),
) {
    if let Some(at) = timestamp(data, "firstseen", true, issue) {
        push_date(listing, "firstseen", at);
    }
    match count(data.get("url_count"), URL_COUNT, issue) {
        Some(n) => push_metric(listing, URL_COUNT, n),
        None if data.get(URL_COUNT).is_none() => issue("url_count is missing"),
        None => {}
    }
    let items = match data.get("urls") {
        None | Some(Value::Null) => {
            issue("urls is missing");
            return;
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            issue("urls has an unexpected type");
            return;
        }
    };
    let mut ids = BTreeSet::new();
    let mut online = 0u64;
    let mut latest: Option<DateTime<Utc>> = None;
    let mut tag_set: BTreeSet<String> = BTreeSet::new();
    for item in items {
        let Some(entry) = item.as_object() else {
            issue("a URL entry has an unexpected type");
            continue;
        };
        let Some(id) = entry_id(entry.get("id"), "a URL entry id", issue) else {
            continue;
        };
        if !ids.insert(id) {
            issue("duplicate URL entries were counted once");
            continue;
        }
        if entry.get("url_status").and_then(Value::as_str) == Some("online") {
            online += 1;
        }
        if let Some(at) = timestamp(entry, "date_added", true, issue) {
            latest = latest.max(Some(at));
        }
        tag_set.extend(tags(entry.get("tags"), "a URL entry's tags", issue));
    }
    push_metric(listing, RETURNED_URLS, len(&ids));
    push_metric(listing, RETURNED_URLS_ONLINE, online);
    if let Some(at) = latest {
        push_date(listing, LATEST_URL_ADDED, at);
    }
    if tag_set.len() > MAX_TAGS {
        issue("tags has too many entries; the rest were ignored");
    }
    listing.tags = tag_set.into_iter().take(MAX_TAGS).collect();
}

/// `blacklists.spamhaus_dbl` and `blacklists.surbl`, as reported. Not
/// available for IPv4 hosts per the documentation, so absence is not an
/// issue.
fn blacklists(
    data: &Map<String, Value>,
    listing: &mut ProviderListing,
    issue: &mut impl FnMut(&str),
) {
    match data.get("blacklists") {
        None | Some(Value::Null) => {}
        Some(Value::Object(lists)) => {
            for key in ["spamhaus_dbl", "surbl"] {
                if let Some(value) = token(lists, key, false, issue) {
                    push_attribute(listing, &format!("blacklists.{key}"), value);
                }
            }
        }
        Some(_) => issue("blacklists has an unexpected type"),
    }
}

fn len<T>(set: &BTreeSet<T>) -> u64 {
    u64::try_from(set.len()).unwrap_or(u64::MAX)
}

fn push_attribute(listing: &mut ProviderListing, name: &str, value: String) {
    listing.attributes.push(ProviderAttribute {
        name: name.to_owned(),
        value,
    });
}

fn push_metric(listing: &mut ProviderListing, name: &str, value: u64) {
    listing.metrics.push(ProviderMetric {
        name: name.to_owned(),
        value,
        max: None,
    });
}

fn push_date(listing: &mut ProviderListing, name: &str, at: DateTime<Utc>) {
    listing.dates.push(ProviderDate {
        name: name.to_owned(),
        at,
    });
}

/// Entry IDs are documented as strings of digits; numbers are accepted.
fn entry_id(value: Option<&Value>, what: &str, issue: &mut impl FnMut(&str)) -> Option<String> {
    match value {
        None | Some(Value::Null) => {
            issue(&format!("{what} is missing"));
            None
        }
        Some(Value::Number(n)) if n.is_u64() => Some(n.to_string()),
        Some(Value::String(s))
            if !s.is_empty()
                && s.len() <= MAX_ENTRY_ID_DIGITS
                && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(s.clone())
        }
        Some(_) => {
            issue(&format!("{what} is not a numeric identifier"));
            None
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

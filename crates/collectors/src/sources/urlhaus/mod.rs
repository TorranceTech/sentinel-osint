//! URLhaus (abuse.ch) malware-URL database lookups.
//!
//! Verified against the official documentation at
//! <https://urlhaus-api.abuse.ch/> (retrieved 2026-09-23; see
//! `docs/DATA-SOURCES.md`):
//!
//! - `POST https://urlhaus-api.abuse.ch/v1/url/` with form field `url`
//! - `POST https://urlhaus-api.abuse.ch/v1/host/` with form field `host`
//!   ("IPv4 address, hostname or domain name")
//! - header `Auth-Key: <key>` (required)
//!
//! URLhaus is a database of malware URLs. Sentinel only asks it about the
//! investigation target. **Nothing a response contains is ever contacted,
//! resolved, downloaded or turned into a pivot**: listed URLs, hosts,
//! payload links and hashes are data, not destinations. The collector is
//! `TargetOnly` and emits no pivots or relationships.
//!
//! Provider classifications keep URLhaus's field names (`url_status`,
//! `threat`, `blacklists.*`); findings attribute every statement to
//! URLhaus and are always `info`.

mod parse;

use std::fmt;
use std::net::IpAddr;

use reqwest::header::{ACCEPT, HeaderName, HeaderValue};
use secrecy::SecretString;
use sentinel_core::{
    Confidence, Finding, FindingCode, Indicator, Observation, ObservationData, ObservationId,
    ProviderListing, ProviderNoRecord, Severity, SourceId,
};
use url::Url;

use crate::collector::{
    Availability, CollectContext, CollectFuture, Collection, Collector, CollectorError,
    CollectorScope,
};
use crate::http::{HttpRequest, HttpResponse};
use crate::sources::api_key::{ApiKey, ECHOED_KEY_ISSUE, redact_echoed_key};

pub use parse::{
    LATEST_URL_ADDED, RETURNED_PAYLOADS, RETURNED_URLS, RETURNED_URLS_ONLINE,
    TAKEDOWN_TIME_SECONDS, URL_COUNT,
};

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("urlhaus");
/// Environment variable holding the abuse.ch Auth-Key (shared by abuse.ch
/// platforms).
pub const API_KEY_ENV: &str = "SENTINEL_ABUSECH_KEY";
/// API base URL (with trailing slash, so endpoints join below it).
pub const API_BASE: &str = "https://urlhaus-api.abuse.ch/v1/";
/// Lookups return at most 100 URLs or payloads per the documentation.
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Sentinel's confidence that a clean response was captured and parsed
/// correctly. Not derived from URLhaus's classifications.
pub const CONFIDENCE: Confidence = Confidence::saturating(90);
/// Sentinel's confidence for a response with invalid or missing fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(60);

/// `ti.urlhaus.url_listed`
pub const URL_LISTED: FindingCode = FindingCode::from_static("ti.urlhaus.url_listed");
/// `ti.urlhaus.url_online`
pub const URL_ONLINE: FindingCode = FindingCode::from_static("ti.urlhaus.url_online");
/// `ti.urlhaus.host_listed`
pub const HOST_LISTED: FindingCode = FindingCode::from_static("ti.urlhaus.host_listed");
/// `ti.urlhaus.blocklist_status`
pub const BLOCKLIST_STATUS: FindingCode = FindingCode::from_static("ti.urlhaus.blocklist_status");
/// `ti.urlhaus.no_results`
pub const NO_RESULTS: FindingCode = FindingCode::from_static("ti.urlhaus.no_results");
/// `ti.urlhaus.response_incomplete`
pub const INCOMPLETE: FindingCode = FindingCode::from_static("ti.urlhaus.response_incomplete");

/// The URLhaus collector.
pub struct UrlhausCollector {
    base: Url,
    key: ApiKey,
}

impl fmt::Debug for UrlhausCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlhausCollector")
            .field("base", &self.base.as_str())
            .field("key", &self.key.state())
            .finish()
    }
}

impl UrlhausCollector {
    /// A collector for the production API. `key` is the configured
    /// abuse.ch Auth-Key, if any. It is validated but never inspected.
    ///
    /// # Panics
    /// Never: the base URL is a valid constant.
    #[must_use]
    #[allow(clippy::expect_used)] // Invariant: API_BASE is a valid URL literal.
    pub fn new(key: Option<SecretString>) -> Self {
        Self::with_base(Url::parse(API_BASE).expect("valid constant URL"), key)
    }

    /// A collector pointed at a mock server. Tests only.
    #[cfg(test)]
    pub(crate) fn for_tests(base: Url, key: Option<SecretString>) -> Self {
        Self::with_base(base, key)
    }

    fn with_base(base: Url, key: Option<SecretString>) -> Self {
        Self {
            base,
            key: ApiKey::new(key),
        }
    }

    /// The fixed endpoint and the single form field carrying the indicator.
    fn request(
        &self,
        indicator: &Indicator,
        key: &SecretString,
    ) -> Result<HttpRequest, CollectorError> {
        let (endpoint, field, value) = match indicator {
            Indicator::Url(url) => ("url/", "url", url.as_str().to_owned()),
            Indicator::Domain(domain) => ("host/", "host", domain.as_str().to_owned()),
            Indicator::Ipv4(ip) => ("host/", "host", ip.to_string()),
            Indicator::Ipv6(_) | Indicator::FileHash(_) => {
                return Err(CollectorError::RefusedTarget);
            }
        };
        let url = self
            .base
            .join(endpoint)
            .map_err(|_| CollectorError::InvalidResponse("invalid URLhaus API base URL"))?;
        Ok(HttpRequest::post_form(url, [(field, value.as_str())])
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .secret_header(HeaderName::from_static("auth-key"), key)?
            .max_body_bytes(MAX_RESPONSE_BYTES))
    }

    async fn run(
        &self,
        indicator: &Indicator,
        key: &SecretString,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let response = ctx.send(self.request(indicator, key)?).await?;
        if response.status() != 200 {
            return Err(status_error(response.status()));
        }
        let query = query(indicator).ok_or(CollectorError::RefusedTarget)?;
        match parse::parse(response.body(), &query).map_err(CollectorError::InvalidResponse)? {
            parse::Answer::NoResults => Ok(no_results(indicator, &response, ctx)),
            parse::Answer::Listed(mut listing) => {
                let fields = listing
                    .attributes
                    .iter_mut()
                    .map(|a| &mut a.value)
                    .chain(listing.tags.iter_mut())
                    .chain(listing.entry_id.iter_mut());
                if redact_echoed_key(key, fields) {
                    listing.issues.push(ECHOED_KEY_ISSUE.to_owned());
                }
                Ok(listed(indicator, &listing, &response, ctx))
            }
        }
    }
}

fn query(indicator: &Indicator) -> Option<parse::Query<'_>> {
    match indicator {
        Indicator::Url(url) => Some(parse::Query::Url(url)),
        Indicator::Domain(domain) => Some(parse::Query::Domain(domain)),
        Indicator::Ipv4(ip) => Some(parse::Query::Ip(IpAddr::V4(*ip))),
        Indicator::Ipv6(_) | Indicator::FileHash(_) => None,
    }
}

/// URLhaus documents no HTTP status codes; "not found" is reported in the
/// body (`no_results`). Every non-200 status is a failure with a fixed
/// text based on standard HTTP semantics, never "no results".
const fn status_error(status: u16) -> CollectorError {
    let meaning = match status {
        400 => "request rejected by URLhaus as invalid",
        401 => "URLhaus rejected the request as unauthorized (check the Auth-Key)",
        403 => "URLhaus refused access (forbidden)",
        404 => "unexpected HTTP 404 from URLhaus (not-found answers use query_status)",
        429 => "URLhaus rate limit exceeded",
        500..=599 => "URLhaus server error",
        _ => return CollectorError::UnexpectedStatus(status),
    };
    CollectorError::ProviderStatus { status, meaning }
}

fn observe(
    collection: &mut Collection,
    indicator: &Indicator,
    data: ObservationData,
    confidence: Confidence,
    response: &HttpResponse,
    ctx: &CollectContext,
) -> ObservationId {
    collection.observe(
        Observation::new(
            indicator.clone(),
            SOURCE,
            ctx.now(),
            data,
            confidence,
            response.provenance(),
        )
        .with_raw_response_hash(response.raw_response_hash()),
    )
}

fn no_results(indicator: &Indicator, response: &HttpResponse, ctx: &CollectContext) -> Collection {
    let mut collection = Collection::new();
    let id = observe(
        &mut collection,
        indicator,
        ObservationData::ProviderNoRecord(ProviderNoRecord {
            provider: parse::PROVIDER.into(),
        }),
        CONFIDENCE,
        response,
        ctx,
    );
    collection.find(finding(
        NO_RESULTS,
        "URLhaus has no entry for this indicator",
        format!("URLhaus answered no_results for {indicator}. URLhaus only tracks URLs used for malware distribution; absence from it is not evidence that the indicator is benign."),
        CONFIDENCE,
        id,
    ));
    collection
}

fn listed(
    indicator: &Indicator,
    listing: &ProviderListing,
    response: &HttpResponse,
    ctx: &CollectContext,
) -> Collection {
    let confidence = if listing.issues.is_empty() {
        CONFIDENCE
    } else {
        DEGRADED_CONFIDENCE
    };
    let mut collection = Collection::new();
    let id = observe(
        &mut collection,
        indicator,
        ObservationData::ProviderListing(listing.clone()),
        confidence,
        response,
        ctx,
    );
    for finding in findings(indicator, listing, id, confidence) {
        collection.find(finding);
    }
    collection
}

impl Collector for UrlhausCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    /// URLs, domains and IPv4 addresses. IPv6 hosts are not documented
    /// for the host endpoint, so they are not sent.
    fn supports(&self, indicator: &Indicator) -> bool {
        query(indicator).is_some()
    }

    /// The target only: URLhaus content never drives further lookups.
    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetOnly
    }

    fn availability(&self) -> Availability {
        self.key
            .availability("API key not configured (set SENTINEL_ABUSECH_KEY)")
    }

    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a> {
        Box::pin(async move {
            if !self.supports(indicator) {
                return Err(CollectorError::RefusedTarget);
            }
            // Defense in depth: never send a non-public IP, domain or URL
            // host to a third party.
            indicator
                .ensure_investigable()
                .map_err(|_| CollectorError::RefusedTarget)?;
            let ApiKey::Present(key) = &self.key else {
                return Err(CollectorError::NotConfigured);
            };
            self.run(indicator, key, ctx).await
        })
    }
}

fn finding(
    code: FindingCode,
    title: &str,
    detail: String,
    confidence: Confidence,
    id: ObservationId,
) -> Finding {
    Finding::new(code, Severity::Info, title, detail, confidence).with_evidence([id])
}

fn day(listing: &ProviderListing, name: &str) -> Option<String> {
    listing
        .date(name)
        .map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string())
}

/// `name: value` pairs of the given attributes that are present.
fn reported(listing: &ProviderListing, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .flat_map(|name| listing.attribute(name).map(move |v| format!("{name}: {v}")))
        .collect()
}

fn findings(
    indicator: &Indicator,
    listing: &ProviderListing,
    id: ObservationId,
    confidence: Confidence,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if matches!(indicator, Indicator::Url(_)) {
        let mut parts = reported(listing, &["threat", "url_status"]);
        if let Some(added) = day(listing, "date_added") {
            parts.push(format!("added {added}"));
        }
        let signatures: Vec<&str> = listing.attribute("payloads.signature").collect();
        if !signatures.is_empty() {
            parts.push(format!("payload signature(s): {}", signatures.join(", ")));
        }
        findings.push(finding(
            URL_LISTED,
            "URLhaus lists this URL as a malware URL",
            format!(
                "URLhaus reports {indicator} in its malware URL database ({}). The classification is URLhaus's, not a Sentinel verdict, and Sentinel did not access the URL.",
                if parts.is_empty() { "no details reported".to_owned() } else { parts.join("; ") }
            ),
            confidence,
            id,
        ));
        if listing.attribute("url_status").any(|s| s == "online") {
            findings.push(finding(
                URL_ONLINE,
                "URLhaus reports this URL as online",
                "URLhaus reports url_status: online, which URLhaus defines as currently serving a payload. This is URLhaus's observation; Sentinel did not access the URL.".to_owned(),
                confidence,
                id,
            ));
        }
    } else {
        let count = listing
            .metric(URL_COUNT)
            .map_or_else(|| "an unknown number of".to_owned(), |n| n.to_string());
        let mut parts = Vec::new();
        if let (Some(returned), Some(online)) = (
            listing.metric(RETURNED_URLS),
            listing.metric(RETURNED_URLS_ONLINE),
        ) {
            parts.push(format!(
                "{online} of {returned} returned entries reported online"
            ));
        }
        if let Some(first) = day(listing, "firstseen") {
            parts.push(format!("first seen {first}"));
        }
        if let Some(latest) = day(listing, LATEST_URL_ADDED) {
            parts.push(format!("latest entry added {latest}"));
        }
        let extra = if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join("; "))
        };
        findings.push(finding(
            HOST_LISTED,
            "URLhaus lists malware URLs on this host",
            format!("URLhaus reports {count} malware URL(s) observed on {indicator}{extra}. A listed host can be a compromised legitimate site or shared hosting; the listed URLs were not accessed or investigated by Sentinel."),
            confidence,
            id,
        ));
    }
    let listed_elsewhere: Vec<String> = ["blacklists.spamhaus_dbl", "blacklists.surbl"]
        .iter()
        .flat_map(|name| {
            listing
                .attribute(name)
                .filter(|v| *v != "not listed")
                .map(move |v| format!("{name}: {v}"))
        })
        .collect();
    if !listed_elsewhere.is_empty() {
        findings.push(finding(
            BLOCKLIST_STATUS,
            "URLhaus reports third-party blocklist listings",
            format!(
                "URLhaus reports these blocklist statuses: {}. They are reported by URLhaus and were not checked by Sentinel.",
                listed_elsewhere.join(", ")
            ),
            confidence,
            id,
        ));
    }
    if !listing.issues.is_empty() {
        findings.push(finding(
            INCOMPLETE,
            "URLhaus response had invalid or missing fields",
            format!(
                "Problems with the URLhaus response: {}. The affected fields were left empty.",
                listing.issues.join("; ")
            ),
            confidence,
            id,
        ));
    }
    findings
}

#[cfg(test)]
mod tests;

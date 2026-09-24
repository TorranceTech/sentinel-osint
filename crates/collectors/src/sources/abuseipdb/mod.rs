//! AbuseIPDB IP reputation (APIv2 `check` endpoint).
//!
//! Verified against the official documentation at <https://docs.abuseipdb.com/>
//! (retrieved 2026-09-23; see `docs/DATA-SOURCES.md`):
//!
//! - `GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=<n>`
//! - headers `Key: <api key>` and `Accept: application/json`
//! - `verbose` is **not** set, so no per-report comments or reporter data
//!   are requested.
//!
//! Provider claims stay provider claims: metrics keep AbuseIPDB's names,
//! findings attribute every statement to AbuseIPDB, and nothing is turned
//! into a Sentinel maliciousness verdict or score.
//!
//! The API key is held as a [`SecretString`], sent only in the `Key` header
//! through `HttpRequest::secret_header` (same-origin redirects only), and
//! never logged, formatted or stored. If a response echoes the key, it is
//! redacted before anything is stored.

mod parse;

use std::fmt;
use std::net::IpAddr;

use reqwest::header::{ACCEPT, HeaderName, HeaderValue};
use secrecy::SecretString;
use sentinel_core::{
    Confidence, Finding, FindingCode, Indicator, IpReputation, Observation, ObservationData,
    ObservationId, Severity, SourceId,
};
use url::Url;

use crate::collector::{
    Availability, CollectContext, CollectFuture, Collection, Collector, CollectorError,
    CollectorScope,
};
use crate::http::HttpRequest;
use crate::sources::api_key::{ApiKey, ECHOED_KEY_ISSUE, redact_echoed_key};

pub use parse::{ABUSE_CONFIDENCE_SCORE, NUM_DISTINCT_USERS, TOTAL_REPORTS};

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("abuseipdb");
/// Environment variable holding the API key.
pub const API_KEY_ENV: &str = "SENTINEL_ABUSEIPDB_KEY";
/// The `check` endpoint.
pub const CHECK_ENDPOINT: &str = "https://api.abuseipdb.com/api/v2/check";
/// Look-back window sent as `maxAgeInDays` (documented range 1–365, default 30).
pub const WINDOW_DAYS: u16 = 90;
/// Non-verbose `check` answers are small.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Sentinel's confidence that a clean response was captured and parsed correctly.
/// This is **not** the provider's abuse confidence.
pub const CONFIDENCE: Confidence = Confidence::saturating(90);
/// Sentinel's confidence for a response with invalid or missing fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(60);
/// Lower bound of the range AbuseIPDB itself documents as recommended for
/// blocking ("75%-100% is the recommended range for denial of service").
pub const PROVIDER_RECOMMENDED_BLOCK_THRESHOLD: u64 = 75;

/// `ti.abuseipdb.observed`
pub const OBSERVED: FindingCode = FindingCode::from_static("ti.abuseipdb.observed");
/// `ti.abuseipdb.no_reports`
pub const NO_REPORTS: FindingCode = FindingCode::from_static("ti.abuseipdb.no_reports");
/// `ti.abuseipdb.abuse_reports`
pub const ABUSE_REPORTS: FindingCode = FindingCode::from_static("ti.abuseipdb.abuse_reports");
/// `ti.abuseipdb.high_abuse_confidence`
pub const HIGH_ABUSE_CONFIDENCE: FindingCode =
    FindingCode::from_static("ti.abuseipdb.high_abuse_confidence");
/// `ti.abuseipdb.allowlisted`
pub const ALLOWLISTED: FindingCode = FindingCode::from_static("ti.abuseipdb.allowlisted");
/// `ti.abuseipdb.tor`
pub const TOR: FindingCode = FindingCode::from_static("ti.abuseipdb.tor");
/// `ti.abuseipdb.response_incomplete`
pub const INCOMPLETE: FindingCode = FindingCode::from_static("ti.abuseipdb.response_incomplete");

/// The AbuseIPDB collector.
pub struct AbuseIpDbCollector {
    endpoint: Url,
    key: ApiKey,
}

impl fmt::Debug for AbuseIpDbCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbuseIpDbCollector")
            .field("endpoint", &self.endpoint.as_str())
            .field("key", &self.key.state())
            .finish()
    }
}

impl AbuseIpDbCollector {
    /// A collector for the production endpoint. `key` is the configured API
    /// key, if any. It is validated but never inspected otherwise.
    ///
    /// # Panics
    /// Never: the endpoint is a valid constant.
    #[must_use]
    #[allow(clippy::expect_used)] // Invariant: CHECK_ENDPOINT is a valid URL literal.
    pub fn new(key: Option<SecretString>) -> Self {
        Self::with_endpoint(Url::parse(CHECK_ENDPOINT).expect("valid constant URL"), key)
    }

    /// A collector pointed at a mock server. Tests only.
    #[cfg(test)]
    pub(crate) fn for_tests(endpoint: Url, key: Option<SecretString>) -> Self {
        Self::with_endpoint(endpoint, key)
    }

    fn with_endpoint(endpoint: Url, key: Option<SecretString>) -> Self {
        Self {
            endpoint,
            key: ApiKey::new(key),
        }
    }

    fn request(&self, ip: IpAddr, key: &SecretString) -> Result<HttpRequest, CollectorError> {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut()
            .clear()
            .append_pair("ipAddress", &ip.to_string())
            .append_pair("maxAgeInDays", &WINDOW_DAYS.to_string());
        Ok(HttpRequest::get(url)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .secret_header(HeaderName::from_static("key"), key)?
            .max_body_bytes(MAX_RESPONSE_BYTES))
    }

    async fn run(
        &self,
        indicator: &Indicator,
        ip: IpAddr,
        key: &SecretString,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let response = ctx.send(self.request(ip, key)?).await?;
        // 401, 403, 404, 422, 429 and 5xx are failures, never "no reports".
        if response.status() != 200 {
            return Err(CollectorError::UnexpectedStatus(response.status()));
        }
        let mut reputation = parse::parse_check(response.body(), ip, WINDOW_DAYS)
            .map_err(CollectorError::InvalidResponse)?;
        let echoed = redact_echoed_key(
            key,
            [
                &mut reputation.usage_type,
                &mut reputation.isp,
                &mut reputation.domain,
                &mut reputation.country_code,
            ]
            .into_iter()
            .flatten()
            .chain(reputation.hostnames.iter_mut()),
        );
        if echoed {
            reputation.issues.push(ECHOED_KEY_ISSUE.to_owned());
        }

        let confidence = if reputation.issues.is_empty() {
            CONFIDENCE
        } else {
            DEGRADED_CONFIDENCE
        };
        let mut collection = Collection::new();
        let id = collection.observe(
            Observation::new(
                indicator.clone(),
                SOURCE,
                ctx.now(),
                ObservationData::IpReputation(reputation.clone()),
                confidence,
                response.provenance(),
            )
            .with_raw_response_hash(response.raw_response_hash()),
        );
        for finding in findings(ip, &reputation, id, confidence) {
            collection.find(finding);
        }
        Ok(collection)
    }
}

impl Collector for AbuseIpDbCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        indicator.as_ip().is_some()
    }

    /// Runs on the target and on public IP pivots (bounded by the engine's
    /// pivot limits, which also bound the provider quota used).
    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetAndPivots
    }

    fn availability(&self) -> Availability {
        self.key
            .availability("API key not configured (set SENTINEL_ABUSEIPDB_KEY)")
    }

    fn collect<'a>(
        &'a self,
        indicator: &'a Indicator,
        ctx: &'a CollectContext,
    ) -> CollectFuture<'a> {
        Box::pin(async move {
            let Some(ip) = indicator.as_ip() else {
                return Err(CollectorError::RefusedTarget);
            };
            // Defense in depth: never send a non-public IP to a third party.
            indicator
                .ensure_investigable()
                .map_err(|_| CollectorError::RefusedTarget)?;
            let ApiKey::Present(key) = &self.key else {
                return Err(CollectorError::NotConfigured);
            };
            self.run(indicator, ip, key, ctx).await
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

fn findings(
    ip: IpAddr,
    reputation: &IpReputation,
    id: ObservationId,
    confidence: Confidence,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let window = reputation
        .window_days
        .map_or_else(String::new, |d| format!(" (last {d} days)"));
    let score = reputation.metric(ABUSE_CONFIDENCE_SCORE);
    let total = reputation.metric(TOTAL_REPORTS);
    let distinct = reputation.metric(NUM_DISTINCT_USERS);

    let mut parts: Vec<String> = Vec::new();
    if let Some(score) = score {
        parts.push(format!("abuse confidence score {score}/100"));
    }
    if let Some(total) = total {
        let users = distinct.map_or_else(String::new, |d| format!(" from {d} distinct user(s)"));
        parts.push(format!("{total} report(s){users}"));
    }
    if let Some(last) = reputation.last_reported_at {
        parts.push(format!(
            "last reported {}",
            last.format("%Y-%m-%d %H:%M UTC")
        ));
    }
    let summary = if parts.is_empty() {
        "no usable metrics".to_owned()
    } else {
        parts.join(", ")
    };
    findings.push(finding(
        OBSERVED,
        "AbuseIPDB reputation data retrieved",
        format!("AbuseIPDB reports for {ip}{window}: {summary}. These are the provider's own figures, not a Sentinel verdict."),
        confidence,
        id,
    ));

    match total {
        Some(0) => findings.push(finding(
            NO_REPORTS,
            "No AbuseIPDB reports in the window",
            format!("AbuseIPDB has no abuse reports for {ip}{window}. Absence of reports is not evidence that the address is benign."),
            confidence,
            id,
        )),
        Some(total) => findings.push(finding(
            ABUSE_REPORTS,
            "AbuseIPDB users reported this address",
            format!("AbuseIPDB users submitted {total} abuse report(s) for {ip}{window}. Reports are third-party claims and were not verified by Sentinel."),
            confidence,
            id,
        )),
        None => {}
    }
    if let Some(score) = score.filter(|s| *s >= PROVIDER_RECOMMENDED_BLOCK_THRESHOLD) {
        findings.push(finding(
            HIGH_ABUSE_CONFIDENCE,
            "AbuseIPDB reports a high abuse confidence score",
            format!("AbuseIPDB reports an abuse confidence score of {score}/100 for {ip}. AbuseIPDB documents 75-100 as its recommended range for blocking; the score is AbuseIPDB's evaluation based on its users' reports, not independent proof of intent."),
            confidence,
            id,
        ));
    }
    if reputation.is_allowlisted == Some(true) {
        findings.push(finding(
            ALLOWLISTED,
            "AbuseIPDB lists this address on an allow-list",
            "AbuseIPDB reports that the address appears on one of its whitelists; AbuseIPDB states this should generally not be used as a basis for action.".to_owned(),
            confidence,
            id,
        ));
    }
    if reputation.is_tor == Some(true) {
        findings.push(finding(
            TOR,
            "AbuseIPDB flags this address as Tor",
            format!("AbuseIPDB reports {ip} as a Tor node. Tor traffic can originate from many unrelated users."),
            confidence,
            id,
        ));
    }
    if !reputation.issues.is_empty() {
        findings.push(finding(
            INCOMPLETE,
            "AbuseIPDB response had invalid or missing fields",
            format!(
                "Problems: {}. The affected fields were left empty.",
                reputation.issues.join("; ")
            ),
            confidence,
            id,
        ));
    }
    findings
}

#[cfg(test)]
mod tests;

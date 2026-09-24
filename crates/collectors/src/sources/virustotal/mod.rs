//! VirusTotal API v3 object lookups (IP address, domain, URL, file).
//!
//! Verified against the official documentation at
//! <https://docs.virustotal.com/reference/overview> (retrieved 2026-09-23;
//! see `docs/DATA-SOURCES.md`):
//!
//! - `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`
//! - `GET https://www.virustotal.com/api/v3/domains/{domain}`
//! - `GET https://www.virustotal.com/api/v3/urls/{id}`, where `id` is the
//!   unpadded URL-safe base64 of the URL (VirusTotal canonicalizes it)
//! - `GET https://www.virustotal.com/api/v3/files/{sha256}`
//! - header `x-apikey: <api key>`
//!
//! Lookups only: nothing is uploaded, submitted or re-scanned, and no
//! relationship endpoint is called. One request per investigation target;
//! VirusTotal content never becomes a pivot.
//!
//! Provider claims stay provider claims: the engine counts keep
//! VirusTotal's names, findings attribute every statement to VirusTotal,
//! and nothing becomes a Sentinel verdict, severity or score.
//!
//! The API key is held as a [`SecretString`], sent only in the `x-apikey`
//! header through `HttpRequest::secret_header` (same-origin redirects
//! only), and never logged, formatted or stored.

mod parse;

use std::fmt;

use reqwest::header::{ACCEPT, HeaderName, HeaderValue};
use secrecy::SecretString;
use sentinel_core::{
    Confidence, Finding, FindingCode, HashAlgorithm, HttpUrl, Indicator, Observation,
    ObservationData, ObservationId, ProviderNoRecord, ProviderReputation, Severity, SourceId,
};
use url::Url;

use crate::collector::{
    Availability, CollectContext, CollectFuture, Collection, Collector, CollectorError,
    CollectorScope,
};
use crate::http::{HttpRequest, HttpResponse};
use crate::sources::api_key::{ApiKey, ECHOED_KEY_ISSUE, redact_echoed_key};

pub use parse::{STATS_PREFIX, VOTES_PREFIX};

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("virustotal");
/// Environment variable holding the API key.
pub const API_KEY_ENV: &str = "SENTINEL_VIRUSTOTAL_KEY";
/// API v3 base URL.
pub const API_BASE: &str = "https://www.virustotal.com/api/v3";
/// Object reports include WHOIS, certificates and per-engine results that
/// are discarded after parsing; file reports can be large.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Sentinel's confidence that a clean response was captured and parsed
/// correctly. This is **not** derived from VirusTotal's engine counts.
pub const CONFIDENCE: Confidence = Confidence::saturating(90);
/// Sentinel's confidence for a response with invalid or missing fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(60);

/// `ti.virustotal.observed`
pub const OBSERVED: FindingCode = FindingCode::from_static("ti.virustotal.observed");
/// `ti.virustotal.detections`
pub const DETECTIONS: FindingCode = FindingCode::from_static("ti.virustotal.detections");
/// `ti.virustotal.no_detections`
pub const NO_DETECTIONS: FindingCode = FindingCode::from_static("ti.virustotal.no_detections");
/// `ti.virustotal.not_found`
pub const NOT_FOUND: FindingCode = FindingCode::from_static("ti.virustotal.not_found");
/// `ti.virustotal.response_incomplete`
pub const INCOMPLETE: FindingCode = FindingCode::from_static("ti.virustotal.response_incomplete");

/// The VirusTotal collector.
pub struct VirusTotalCollector {
    base: Url,
    key: ApiKey,
}

impl fmt::Debug for VirusTotalCollector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirusTotalCollector")
            .field("base", &self.base.as_str())
            .field("key", &self.key.state())
            .finish()
    }
}

impl VirusTotalCollector {
    /// A collector for the production API. `key` is the configured API key,
    /// if any. It is validated but never inspected otherwise.
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

    /// `{base}/{collection}/{id}`. The indicator only ever fills one
    /// percent-encoded path segment of the fixed API host.
    fn object_url(&self, indicator: &Indicator) -> Result<Url, CollectorError> {
        let (collection, id) = match indicator {
            Indicator::Ipv4(ip) => ("ip_addresses", ip.to_string()),
            Indicator::Ipv6(ip) => ("ip_addresses", ip.to_string()),
            Indicator::Domain(domain) => ("domains", domain.as_str().to_owned()),
            Indicator::Url(url) => ("urls", url_identifier(url)),
            Indicator::FileHash(hash) if hash.algorithm() == HashAlgorithm::Sha256 => {
                ("files", hash.as_str().to_owned())
            }
            Indicator::FileHash(_) => return Err(CollectorError::RefusedTarget),
        };
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| CollectorError::InvalidResponse("API base URL cannot have a path"))?
            .pop_if_empty()
            .push(collection)
            .push(&id);
        Ok(url)
    }

    fn request(
        &self,
        indicator: &Indicator,
        key: &SecretString,
    ) -> Result<HttpRequest, CollectorError> {
        Ok(HttpRequest::get(self.object_url(indicator)?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .secret_header(HeaderName::from_static("x-apikey"), key)?
            .max_body_bytes(MAX_RESPONSE_BYTES))
    }

    async fn run(
        &self,
        indicator: &Indicator,
        key: &SecretString,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let response = ctx.send(self.request(indicator, key)?).await?;
        match response.status() {
            200 => {}
            404 if parse::is_not_found_error(response.body()) => {
                return Ok(not_found(indicator, &response, ctx));
            }
            status => return Err(status_error(status)),
        }
        let expected =
            parse::Expected::from_indicator(indicator).ok_or(CollectorError::RefusedTarget)?;
        let mut reputation = parse::parse_object(response.body(), &expected)
            .map_err(CollectorError::InvalidResponse)?;
        if redact_echoed_key(key, reputation.tags.iter_mut()) {
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
                ObservationData::ProviderReputation(reputation.clone()),
                confidence,
                response.provenance(),
            )
            .with_raw_response_hash(response.raw_response_hash()),
        );
        for finding in findings(indicator, &reputation, id, confidence) {
            collection.find(finding);
        }
        Ok(collection)
    }
}

/// VirusTotal's URL identifier: the URL in unpadded URL-safe base64
/// (RFC 4648 §5 alphabet, as in the documented examples). VirusTotal
/// canonicalizes the URL server-side.
fn url_identifier(url: &HttpUrl) -> String {
    base64url_unpadded(url.as_str().as_bytes())
}

fn base64url_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        // A chunk of k bytes encodes to k + 1 characters without padding.
        for i in 0..=chunk.len() {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(ALPHABET[index as usize]));
        }
    }
    out
}

/// Documented error statuses map to fixed descriptions; the provider's
/// `message` is never echoed. None of them is "no results".
const fn status_error(status: u16) -> CollectorError {
    let meaning = match status {
        400 => "request rejected by VirusTotal as invalid",
        401 => "API key rejected by VirusTotal (wrong key or inactive account)",
        403 => "operation not permitted for this VirusTotal API key",
        404 => "unexpected not-found response from VirusTotal",
        429 => "VirusTotal quota or rate limit exceeded",
        500..=599 => "VirusTotal server error",
        _ => return CollectorError::UnexpectedStatus(status),
    };
    CollectorError::ProviderStatus { status, meaning }
}

/// VirusTotal's documented `NotFoundError`: evidence that its dataset has
/// no object for the indicator (Sentinel never submits one).
fn not_found(indicator: &Indicator, response: &HttpResponse, ctx: &CollectContext) -> Collection {
    let mut collection = Collection::new();
    let id = collection.observe(
        Observation::new(
            indicator.clone(),
            SOURCE,
            ctx.now(),
            ObservationData::ProviderNoRecord(ProviderNoRecord {
                provider: parse::PROVIDER.into(),
            }),
            CONFIDENCE,
            response.provenance(),
        )
        .with_raw_response_hash(response.raw_response_hash()),
    );
    collection.find(finding(
        NOT_FOUND,
        "VirusTotal has no record of this indicator",
        format!("VirusTotal has no record of {indicator}. Sentinel does not submit indicators for analysis. Absence from VirusTotal's dataset is not evidence that the indicator is benign."),
        CONFIDENCE,
        id,
    ));
    collection
}

impl Collector for VirusTotalCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        match indicator {
            Indicator::Ipv4(_) | Indicator::Ipv6(_) | Indicator::Domain(_) | Indicator::Url(_) => {
                true
            }
            Indicator::FileHash(hash) => hash.algorithm() == HashAlgorithm::Sha256,
        }
    }

    /// The target only: the public API allows 4 requests per minute, and
    /// provider lookups of pivots are not needed for enrichment.
    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetOnly
    }

    fn availability(&self) -> Availability {
        self.key
            .availability("API key not configured (set SENTINEL_VIRUSTOTAL_KEY)")
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

fn stat(reputation: &ProviderReputation, name: &str) -> Option<u64> {
    reputation.metric(&format!("{STATS_PREFIX}{name}"))
}

fn findings(
    indicator: &Indicator,
    reputation: &ProviderReputation,
    id: ObservationId,
    confidence: Confidence,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let counts: Vec<(&str, Option<u64>)> = parse::REQUIRED_STATS
        .iter()
        .map(|name| (*name, stat(reputation, name)))
        .collect();
    let complete = counts.iter().all(|(_, value)| value.is_some());
    let engines: u64 = counts.iter().filter_map(|(_, value)| *value).sum();
    let malicious = stat(reputation, "malicious");
    let suspicious = stat(reputation, "suspicious");
    let analyzed = reputation.last_analysis_at.map_or_else(
        || "date not reported".to_owned(),
        |at| format!("analyzed {}", at.format("%Y-%m-%d %H:%M UTC")),
    );

    let mut parts: Vec<String> = Vec::new();
    let known: Vec<String> = counts
        .iter()
        .filter_map(|(name, value)| value.map(|v| format!("{v} {name}")))
        .collect();
    if !known.is_empty() {
        parts.push(format!("last analysis {} ({analyzed})", known.join(", ")));
    }
    if let Some(score) = reputation.community_score {
        parts.push(format!("community reputation {score}"));
    }
    if let (Some(h), Some(m)) = (
        reputation.metric(&format!("{VOTES_PREFIX}harmless")),
        reputation.metric(&format!("{VOTES_PREFIX}malicious")),
    ) {
        parts.push(format!("community votes {h} harmless / {m} malicious"));
    }
    let summary = if parts.is_empty() {
        "no usable figures".to_owned()
    } else {
        parts.join("; ")
    };
    findings.push(finding(
        OBSERVED,
        "VirusTotal report retrieved",
        format!("VirusTotal reports for {indicator}: {summary}. These are VirusTotal's figures, not a Sentinel verdict."),
        confidence,
        id,
    ));

    let flagged = malicious.unwrap_or(0) + suspicious.unwrap_or(0);
    if flagged > 0 {
        let of = if complete {
            format!(" of {engines}")
        } else {
            String::new()
        };
        findings.push(finding(
            DETECTIONS,
            "VirusTotal reports detections for this indicator",
            format!(
                "In VirusTotal's last analysis ({analyzed}), {} engine(s){of} categorized {indicator} as malicious and {} as suspicious. Engine results are third-party claims, can be false positives, and were not verified by Sentinel.",
                malicious.map_or_else(|| "an unknown number of".to_owned(), |m| m.to_string()),
                suspicious.map_or_else(|| "an unknown number".to_owned(), |s| s.to_string()),
            ),
            confidence,
            id,
        ));
    } else if complete && engines > 0 {
        findings.push(finding(
            NO_DETECTIONS,
            "No detections in VirusTotal's last analysis",
            format!("None of the {engines} engine result(s) in VirusTotal's last analysis ({analyzed}) categorized {indicator} as malicious or suspicious. Absence of detections is not evidence that the indicator is benign."),
            confidence,
            id,
        ));
    }
    if !reputation.issues.is_empty() {
        findings.push(finding(
            INCOMPLETE,
            "VirusTotal response had invalid or missing fields",
            format!(
                "Problems with the VirusTotal response: {}. The affected fields were left empty.",
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

//! RDAP collector: registration data of the network containing an IP.
//!
//! Flow:
//! 1. Fetch the IANA bootstrap file for the address family (`ipv4.json` /
//!    `ipv6.json`) through the hardened HTTP client, once per process. The
//!    parsed file is cached; concurrent investigations wait for one fetch.
//! 2. Pick the most specific HTTPS service covering the IP.
//! 3. `GET <service>/ip/<address>` with `Accept: application/rdap+json`.
//!    Registries may redirect to each other: redirects are followed by the
//!    HTTP client under the network policy (HTTPS only, public addresses
//!    only, at most 3 hops, no secrets involved).
//! 4. Parse the response defensively ([`parse::parse_network`]).
//!
//! There is no second SSRF implementation here. Every request, including the
//! bootstrap, goes through `CollectContext::send`, which charges the request
//! budget and uses the shared `HttpClient` and its `NetworkPolicy`.

mod bootstrap;
mod parse;

use std::net::IpAddr;
use std::sync::Arc;

use reqwest::header::{ACCEPT, HeaderValue};
use sentinel_core::{
    Confidence, Finding, FindingCode, Indicator, NetworkRegistration, Observation, ObservationData,
    ObservationId, RelationKind, Relationship, Severity, SourceId,
};
use tokio::sync::OnceCell;
use url::Url;

use self::bootstrap::Bootstrap;
use crate::analysis::quote;
use crate::collector::{
    CollectContext, CollectFuture, Collection, Collector, CollectorError, CollectorScope,
};
use crate::http::HttpRequest;

/// Source ID.
pub const SOURCE: SourceId = SourceId::from_static("rdap");
/// IANA RDAP bootstrap base (RFC 9224).
pub const IANA_BOOTSTRAP: &str = "https://data.iana.org/rdap/";
/// Maximum size of an RDAP response.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Maximum size of a bootstrap file (the real ones are a few KiB).
pub const MAX_BOOTSTRAP_BYTES: usize = 512 * 1024;
/// Confidence of a clean response from the authoritative registry.
pub const CONFIDENCE: Confidence = Confidence::saturating(95);
/// Confidence of a response with invalid or missing fields.
pub const DEGRADED_CONFIDENCE: Confidence = Confidence::saturating(70);

/// `rdap.network`: registration data is available.
pub const NETWORK: FindingCode = FindingCode::from_static("rdap.network");
/// `rdap.incomplete`: the response had invalid or truncated fields.
pub const INCOMPLETE: FindingCode = FindingCode::from_static("rdap.incomplete");
/// `rdap.range_mismatch`: the registered range does not contain the IP.
pub const RANGE_MISMATCH: FindingCode = FindingCode::from_static("rdap.range_mismatch");

const RDAP_JSON: HeaderValue =
    HeaderValue::from_static("application/rdap+json, application/json;q=0.5");

/// The RDAP collector.
pub struct RdapCollector {
    bootstrap_base: Url,
    allow_http: bool,
    ipv4: OnceCell<Arc<Bootstrap>>,
    ipv6: OnceCell<Arc<Bootstrap>>,
}

impl Default for RdapCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl RdapCollector {
    /// A collector using the IANA bootstrap registry.
    ///
    /// # Panics
    /// Never: the IANA URL is a valid constant.
    #[must_use]
    #[allow(clippy::expect_used)] // Invariant: IANA_BOOTSTRAP is a valid URL literal.
    pub fn new() -> Self {
        Self::with_bootstrap(
            Url::parse(IANA_BOOTSTRAP).expect("valid constant URL"),
            false,
        )
    }

    /// A collector using a mock bootstrap server over plain HTTP. Tests only.
    #[cfg(test)]
    pub(crate) fn for_tests(bootstrap_base: Url) -> Self {
        Self::with_bootstrap(bootstrap_base, true)
    }

    fn with_bootstrap(bootstrap_base: Url, allow_http: bool) -> Self {
        Self {
            bootstrap_base,
            allow_http,
            ipv4: OnceCell::new(),
            ipv6: OnceCell::new(),
        }
    }

    /// The parsed bootstrap for the family of `ip`, fetched at most once.
    async fn bootstrap(
        &self,
        ip: IpAddr,
        ctx: &CollectContext,
    ) -> Result<Arc<Bootstrap>, CollectorError> {
        let (cell, file) = if ip.is_ipv4() {
            (&self.ipv4, "ipv4.json")
        } else {
            (&self.ipv6, "ipv6.json")
        };
        cell.get_or_try_init(|| async {
            let url = self
                .bootstrap_base
                .join(file)
                .map_err(|_| CollectorError::InvalidResponse("invalid RDAP bootstrap URL"))?;
            let response = ctx
                .send(HttpRequest::get(url).max_body_bytes(MAX_BOOTSTRAP_BYTES))
                .await?;
            if !response.is_success() {
                return Err(CollectorError::UnexpectedStatus(response.status()));
            }
            Bootstrap::parse(response.body(), self.allow_http)
                .map(Arc::new)
                .map_err(CollectorError::InvalidResponse)
        })
        .await
        .cloned()
    }

    async fn run(
        &self,
        indicator: &Indicator,
        ip: IpAddr,
        ctx: &CollectContext,
    ) -> Result<Collection, CollectorError> {
        let bootstrap = self.bootstrap(ip, ctx).await?;
        let service = bootstrap
            .service_for(ip)
            .ok_or(CollectorError::InvalidResponse(
                "the RDAP bootstrap has no service for this address",
            ))?;
        let url = query_url(service, ip)?;

        let response = ctx
            .send(
                HttpRequest::get(url)
                    .header(ACCEPT, RDAP_JSON)
                    .max_body_bytes(MAX_RESPONSE_BYTES),
            )
            .await?;
        if response.status() != 200 {
            return Err(CollectorError::UnexpectedStatus(response.status()));
        }
        let network =
            parse::parse_network(response.body(), ip).map_err(CollectorError::InvalidResponse)?;
        let confidence = if network.issues.is_empty() {
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
                ObservationData::NetworkRegistration(network.clone()),
                confidence,
                response.provenance(),
            )
            .with_raw_response_hash(response.raw_response_hash()),
        );

        // The most specific reported CIDR that actually contains the IP.
        if let Some(prefix) = network
            .cidrs
            .iter()
            .filter(|p| p.contains(ip))
            .max_by_key(|p| p.len())
            && let Ok(relationship) =
                Relationship::new(indicator.clone(), RelationKind::RegisteredIn, *prefix, [id])
        {
            collection.relate(relationship);
        }
        for finding in findings(ip, &network, id, confidence) {
            collection.find(finding);
        }
        Ok(collection)
    }
}

/// `<service>/ip/<address>`, built with path segments (no string splicing).
fn query_url(service: &Url, ip: IpAddr) -> Result<Url, CollectorError> {
    let mut url = service.clone();
    url.path_segments_mut()
        .map_err(|()| CollectorError::InvalidResponse("RDAP service URL cannot be a base"))?
        .pop_if_empty()
        .push("ip")
        .push(&ip.to_string());
    Ok(url)
}

impl Collector for RdapCollector {
    fn id(&self) -> SourceId {
        SOURCE
    }

    fn supports(&self, indicator: &Indicator) -> bool {
        indicator.as_ip().is_some()
    }

    fn scope(&self) -> CollectorScope {
        CollectorScope::TargetAndPivots
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
            // Defense in depth: never ask a registry about a non-public IP.
            indicator
                .ensure_investigable()
                .map_err(|_| CollectorError::RefusedTarget)?;
            self.run(indicator, ip, ctx).await
        })
    }
}

fn findings(
    ip: IpAddr,
    network: &NetworkRegistration,
    id: ObservationId,
    confidence: Confidence,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut parts: Vec<String> = Vec::new();
    match (&network.name, &network.handle) {
        (Some(name), Some(handle)) => {
            parts.push(format!("network {} ({})", quote(name), quote(handle)));
        }
        (Some(name), None) => parts.push(format!("network {}", quote(name))),
        (None, Some(handle)) => parts.push(format!("network {}", quote(handle))),
        (None, None) => {}
    }
    if let (Some(start), Some(end)) = (network.start_address, network.end_address) {
        parts.push(format!("range {start} – {end}"));
    }
    if !network.cidrs.is_empty() {
        let cidrs: Vec<String> = network.cidrs.iter().map(ToString::to_string).collect();
        parts.push(format!("CIDR {}", cidrs.join(", ")));
    }
    if let Some(kind) = &network.network_type {
        parts.push(format!("type {}", quote(kind)));
    }
    if let Some(country) = &network.country {
        parts.push(format!("country {country}"));
    }
    if let Some(organization) = &network.organization {
        parts.push(format!("registrant organization {}", quote(organization)));
    }
    if parts.is_empty() {
        parts.push("an ip network object without identifying fields".to_owned());
    }
    findings.push(
        Finding::new(
            NETWORK,
            Severity::Info,
            "RDAP registration data available",
            format!(
                "The registry reports {} for {ip}. Registration data describes the allocation holder of record; it does not establish who operates a specific host.",
                parts.join(", ")
            ),
            confidence,
        )
        .with_evidence([id]),
    );

    if network.range_contains_queried_ip() == Some(false) {
        findings.push(
            Finding::new(
                RANGE_MISMATCH,
                Severity::Info,
                "Registered range does not contain the address",
                format!("The registry returned a network whose range does not contain {ip}. The response is inconsistent."),
                confidence,
            )
            .with_evidence([id]),
        );
    }
    if !network.issues.is_empty() {
        findings.push(
            Finding::new(
                INCOMPLETE,
                Severity::Info,
                "RDAP response had invalid or truncated fields",
                format!(
                    "Problems: {}. The affected fields were left empty or truncated.",
                    network.issues.join("; ")
                ),
                confidence,
            )
            .with_evidence([id]),
        );
    }
    findings
}

#[cfg(test)]
mod tests;

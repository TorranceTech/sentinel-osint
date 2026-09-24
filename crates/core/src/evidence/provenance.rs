//! Provenance: how and from where an observation was collected.

use serde::Serialize;
use url::Url;

use super::DnsRecordType;

/// How an observation was collected. Detailed enough for an analyst to
/// reproduce the query, and guaranteed free of secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Provenance {
    /// A DNS query.
    Dns(DnsProvenance),
    /// An HTTPS API request.
    Https(HttpsProvenance),
}

impl Provenance {
    /// Provenance for a DNS query.
    ///
    /// `resolver` describes the resolver used, e.g. `system` or `1.1.1.1:53`.
    #[must_use]
    pub fn dns(
        query_name: impl Into<String>,
        record_type: DnsRecordType,
        resolver: impl Into<String>,
    ) -> Self {
        Self::Dns(DnsProvenance {
            query_name: query_name.into(),
            record_type,
            resolver: resolver.into(),
        })
    }

    /// Provenance for an HTTPS request. The URL is sanitized with
    /// [`sanitize_url`] before it is stored.
    #[must_use]
    pub fn https(method: HttpMethod, url: &Url, status: u16) -> Self {
        Self::Https(HttpsProvenance {
            http_method: method,
            endpoint: sanitize_url(url),
            status,
        })
    }
}

/// DNS query details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsProvenance {
    query_name: String,
    record_type: DnsRecordType,
    resolver: String,
}

impl DnsProvenance {
    /// Queried name.
    #[must_use]
    pub fn query_name(&self) -> &str {
        &self.query_name
    }

    /// Queried record type.
    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        self.record_type
    }

    /// Resolver description.
    #[must_use]
    pub fn resolver(&self) -> &str {
        &self.resolver
    }
}

/// HTTP method of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// `GET`
    Get,
    /// `POST`
    Post,
}

/// HTTPS request details. Only constructible through [`Provenance::https`],
/// so the endpoint is always sanitized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpsProvenance {
    http_method: HttpMethod,
    endpoint: String,
    status: u16,
}

impl HttpsProvenance {
    /// HTTP method.
    #[must_use]
    pub const fn http_method(&self) -> HttpMethod {
        self.http_method
    }

    /// Sanitized endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// HTTP status code of the response.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
}

/// Query parameter names whose values are always redacted. Matched
/// case-insensitively as substrings, so `apikey`, `api_key`, `X-Auth-Token`,
/// … are all covered.
const SENSITIVE_PARAM_MARKERS: [&str; 7] = [
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "signature",
];

/// Placeholder for redacted values.
pub const REDACTED: &str = "REDACTED";

/// Removes secrets from a URL before it is stored or displayed.
///
/// API keys are never *supposed* to be in URLs (they go in headers). This is
/// defense in depth:
/// - userinfo (`user:pass@`) and the fragment are removed;
/// - values of query parameters with sensitive names are replaced with
///   [`REDACTED`].
#[must_use]
pub fn sanitize_url(url: &Url) -> String {
    let mut clean = url.clone();
    // These can only fail for URLs that cannot have credentials
    // (cannot-be-a-base), in which case there is nothing to remove.
    let _ = clean.set_username("");
    let _ = clean.set_password(None);
    clean.set_fragment(None);

    if clean.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| {
                let value = if is_sensitive_param(&name) {
                    REDACTED.to_owned()
                } else {
                    value.into_owned()
                };
                (name.into_owned(), value)
            })
            .collect();
        if pairs.is_empty() {
            clean.set_query(None);
        } else {
            clean.query_pairs_mut().clear().extend_pairs(pairs);
        }
    }
    clean.into()
}

fn is_sensitive_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_PARAM_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sanitize(s: &str) -> String {
        sanitize_url(&Url::parse(s).unwrap())
    }

    #[test]
    fn keeps_ordinary_urls_intact() {
        assert_eq!(
            sanitize("https://crt.sh/?q=example.com&output=json"),
            "https://crt.sh/?q=example.com&output=json"
        );
        assert_eq!(
            sanitize("https://www.virustotal.com/api/v3/domains/example.com"),
            "https://www.virustotal.com/api/v3/domains/example.com"
        );
    }

    #[test]
    fn removes_credentials_and_fragment() {
        assert_eq!(
            sanitize("https://user:hunter2@api.example.com/v1#frag"),
            "https://api.example.com/v1"
        );
    }

    #[test]
    fn redacts_sensitive_query_parameters() {
        let clean = sanitize(
            "https://api.example.com/check?ip=8.8.8.8&apikey=SECRET1&API_KEY=SECRET2&access_token=SECRET3&sig=ok",
        );
        assert!(!clean.contains("SECRET"), "{clean}");
        assert!(clean.contains("ip=8.8.8.8"));
        assert!(clean.contains("apikey=REDACTED"));
        assert!(clean.contains("API_KEY=REDACTED"));
        assert!(clean.contains("access_token=REDACTED"));
    }

    #[test]
    fn https_provenance_is_always_sanitized() {
        let url = Url::parse("https://api.example.com/check?key=SECRET").unwrap();
        let Provenance::Https(p) = Provenance::https(HttpMethod::Get, &url, 200) else {
            panic!("expected https provenance");
        };
        assert_eq!(p.endpoint(), "https://api.example.com/check?key=REDACTED");
        assert_eq!(p.status(), 200);
        assert_eq!(p.http_method(), HttpMethod::Get);
    }
}

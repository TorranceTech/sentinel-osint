//! RDAP bootstrap (RFC 9224): which RDAP service is authoritative for an IP.
//!
//! The IANA registry files (`ipv4.json`, `ipv6.json`) map CIDR blocks to RDAP
//! base URLs. The file is fetched through the hardened HTTP client like any
//! other response and is **untrusted**: entries are validated, bounded, and
//! only HTTPS base URLs without credentials are accepted. The HTTP client
//! then applies the full network policy again (public addresses, redirects)
//! when the service is actually contacted.

use std::net::IpAddr;

use sentinel_core::IpPrefix;
use serde_json::Value;
use url::Url;

/// Service entries examined.
const MAX_SERVICES: usize = 2048;
/// Prefixes examined per service entry.
const MAX_PREFIXES_PER_SERVICE: usize = 4096;
/// Base URLs kept per service entry.
const MAX_URLS_PER_SERVICE: usize = 8;

/// A parsed bootstrap registry.
#[derive(Debug)]
pub(crate) struct Bootstrap {
    entries: Vec<(IpPrefix, Vec<Url>)>,
}

impl Bootstrap {
    /// Parses a bootstrap document. Invalid entries are skipped; a document
    /// without a single usable entry is an error.
    ///
    /// `allow_http` exists only so tests can point at plain-HTTP mock servers.
    pub(crate) fn parse(body: &[u8], allow_http: bool) -> Result<Self, &'static str> {
        let document: Value =
            serde_json::from_slice(body).map_err(|_| "RDAP bootstrap is not valid JSON")?;
        let services = document
            .get("services")
            .and_then(Value::as_array)
            .ok_or("RDAP bootstrap has no services array")?;

        let mut entries = Vec::new();
        for service in services.iter().take(MAX_SERVICES) {
            let Some([prefixes, urls, ..]) = service.as_array().map(Vec::as_slice) else {
                continue;
            };
            let urls: Vec<Url> = urls
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(|u| Url::parse(u).ok())
                .filter(|u| is_acceptable_base(u, allow_http))
                .take(MAX_URLS_PER_SERVICE)
                .collect();
            if urls.is_empty() {
                continue;
            }
            for prefix in prefixes
                .as_array()
                .into_iter()
                .flatten()
                .take(MAX_PREFIXES_PER_SERVICE)
                .filter_map(Value::as_str)
                .filter_map(|p| IpPrefix::parse(p).ok())
            {
                entries.push((prefix, urls.clone()));
            }
        }
        if entries.is_empty() {
            return Err("RDAP bootstrap contains no usable services");
        }
        Ok(Self { entries })
    }

    /// The base URL of the most specific service covering `ip`.
    pub(crate) fn service_for(&self, ip: IpAddr) -> Option<&Url> {
        self.entries
            .iter()
            .filter(|(prefix, _)| prefix.contains(ip))
            .max_by_key(|(prefix, _)| prefix.len())
            .and_then(|(_, urls)| urls.first())
    }
}

/// HTTPS (or HTTP in tests), no credentials, no query or fragment.
fn is_acceptable_base(url: &Url, allow_http: bool) -> bool {
    let scheme_ok = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    scheme_ok
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.host().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IANA_LIKE: &str = r#"{
        "version": "1.0",
        "publication": "2026-01-01T00:00:00Z",
        "services": [
            [["8.0.0.0/8"], ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"]],
            [["8.8.0.0/16"], ["https://rdap.more-specific.example/"]],
            [["2001:4800::/23"], ["https://rdap.arin.net/registry/"]],
            [["93.0.0.0/8"], ["https://rdap.db.ripe.net/"]]
        ]
    }"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn selects_the_most_specific_https_service() {
        let bootstrap = Bootstrap::parse(IANA_LIKE.as_bytes(), false).unwrap();
        assert_eq!(
            bootstrap.service_for(ip("8.8.8.8")).unwrap().as_str(),
            "https://rdap.more-specific.example/"
        );
        assert_eq!(
            bootstrap.service_for(ip("8.1.1.1")).unwrap().as_str(),
            "https://rdap.arin.net/registry/"
        );
        assert_eq!(
            bootstrap.service_for(ip("93.184.215.14")).unwrap().as_str(),
            "https://rdap.db.ripe.net/"
        );
        assert_eq!(
            bootstrap.service_for(ip("2001:4860::1")).unwrap().as_str(),
            "https://rdap.arin.net/registry/"
        );
        assert!(bootstrap.service_for(ip("1.1.1.1")).is_none());
    }

    #[test]
    fn rejects_insecure_and_unsafe_service_urls() {
        let doc = r#"{"services": [
            [["8.0.0.0/8"], ["http://rdap.example/"]],
            [["9.0.0.0/8"], ["https://user:pw@rdap.example/"]],
            [["10.0.0.0/8"], ["ftp://rdap.example/"]],
            [["11.0.0.0/8"], ["https://rdap.example/?redirect=evil"]],
            [["12.0.0.0/8"], ["javascript:alert(1)"]],
            [["13.0.0.0/8"], ["https://ok.example/"]]
        ]}"#;
        let bootstrap = Bootstrap::parse(doc.as_bytes(), false).unwrap();
        for blocked in ["8.1.1.1", "9.1.1.1", "10.1.1.1", "11.1.1.1", "12.1.1.1"] {
            assert!(bootstrap.service_for(ip(blocked)).is_none(), "{blocked}");
        }
        assert!(bootstrap.service_for(ip("13.1.1.1")).is_some());
        // Tests may use plain HTTP explicitly.
        let test_bootstrap = Bootstrap::parse(doc.as_bytes(), true).unwrap();
        assert!(test_bootstrap.service_for(ip("8.1.1.1")).is_some());
    }

    #[test]
    fn malformed_documents_fail_safely() {
        for doc in [
            "",
            "not json",
            "[]",
            r#"{"services": "nope"}"#,
            r#"{"services": []}"#,
            r#"{"services": [[], [1, 2], [["x"], ["https://a.example/"]], [["8.8.8.1/24"], ["https://a.example/"]]]}"#,
            r#"{"services": [[["8.0.0.0/8"], [null, 7, {}]]]}"#,
        ] {
            assert!(Bootstrap::parse(doc.as_bytes(), false).is_err(), "{doc}");
        }
        // Deep nesting hits serde_json's recursion limit instead of the stack.
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(Bootstrap::parse(deep.as_bytes(), false).is_err());
    }

    #[test]
    fn huge_documents_are_bounded() {
        let prefixes: Vec<String> = (0..20_000)
            .map(|i| format!("\"10.{}.{}.0/24\"", (i / 256) % 256, i % 256))
            .collect();
        let doc = format!(
            r#"{{"services": [[[{}], ["https://a.example/"]]]}}"#,
            prefixes.join(",")
        );
        let bootstrap = Bootstrap::parse(doc.as_bytes(), false).unwrap();
        assert_eq!(bootstrap.entries.len(), MAX_PREFIXES_PER_SERVICE);
    }
}

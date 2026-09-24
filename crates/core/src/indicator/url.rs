//! HTTP(S) URLs as indicators.
//!
//! Sentinel never *fetches* URL indicators. A URL is an observable to be
//! looked up in intelligence sources, not a destination.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use super::{DomainName, IndicatorError};

/// A validated `http` or `https` URL.
///
/// Normalized per the WHATWG URL standard (lowercase scheme and host, IDNA
/// host, default port removed). URLs with embedded credentials are rejected
/// so that credentials are never forwarded to third-party sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HttpUrl(Url);

/// The host part of an [`HttpUrl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlHost {
    /// A domain name.
    Domain(DomainName),
    /// An IP address literal.
    Ip(IpAddr),
}

impl HttpUrl {
    /// Maximum accepted URL length.
    pub const MAX_LENGTH: usize = 2048;

    /// Parses and validates a URL.
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if the URL is malformed, too long, not
    /// `http(s)`, contains credentials, or has an invalid host.
    pub fn parse(input: &str) -> Result<Self, IndicatorError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(IndicatorError::Empty);
        }
        if s.len() > Self::MAX_LENGTH {
            return Err(IndicatorError::TooLong {
                max: Self::MAX_LENGTH,
            });
        }
        let url =
            Url::parse(s).map_err(|_| IndicatorError::InvalidUrl("not a valid absolute URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(IndicatorError::InvalidUrl(
                "only http and https URLs are supported",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(IndicatorError::InvalidUrl(
                "URLs containing credentials are not accepted",
            ));
        }
        match url.host() {
            Some(Host::Domain(domain)) => {
                DomainName::parse(domain)
                    .map_err(|_| IndicatorError::InvalidUrl("host is not a valid domain name"))?;
            }
            Some(Host::Ipv4(_) | Host::Ipv6(_)) => {}
            None => return Err(IndicatorError::InvalidUrl("URL has no host")),
        }
        Ok(Self(url))
    }

    /// The normalized URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The parsed URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }

    /// The URL's host. Always present for a validated `HttpUrl`.
    #[must_use]
    pub fn host(&self) -> Option<UrlHost> {
        match self.0.host()? {
            Host::Domain(domain) => DomainName::parse(domain).ok().map(UrlHost::Domain),
            Host::Ipv4(ip) => Some(UrlHost::Ip(IpAddr::V4(ip))),
            Host::Ipv6(ip) => Some(UrlHost::Ip(IpAddr::V6(ip))),
        }
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<String> for HttpUrl {
    type Error = IndicatorError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<HttpUrl> for String {
    fn from(value: HttpUrl) -> Self {
        value.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_urls() {
        let url = HttpUrl::parse("HTTPS://Example.COM:443/Path?q=1").unwrap();
        assert_eq!(url.as_str(), "https://example.com/Path?q=1");
        assert_eq!(
            url.host(),
            Some(UrlHost::Domain(DomainName::parse("example.com").unwrap()))
        );
    }

    #[test]
    fn accepts_ip_hosts() {
        let url = HttpUrl::parse("http://203.0.113.5/payload.bin").unwrap();
        assert_eq!(
            url.host(),
            Some(UrlHost::Ip("203.0.113.5".parse().unwrap()))
        );
    }

    #[test]
    fn rejects_invalid_urls() {
        let too_long = format!("https://example.com/{}", "a".repeat(HttpUrl::MAX_LENGTH));
        for input in [
            "",
            "example.com",
            "ftp://example.com/file",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pass@example.com/",
            "https://user@example.com/",
            "https://exa_mple..com/",
            too_long.as_str(),
        ] {
            assert!(
                HttpUrl::parse(input).is_err(),
                "{input:?} should be invalid"
            );
        }
    }
}

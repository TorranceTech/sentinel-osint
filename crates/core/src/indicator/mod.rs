//! Indicators: the observables Sentinel investigates and correlates.
//!
//! Parsing is split into two layers:
//!
//! 1. **Syntax.** `Indicator::parse_*` refangs, normalizes and validates the
//!    input. Any syntactically valid indicator is accepted, including private
//!    IPs and special-use domains, because such values legitimately show up
//!    as *related* entities (an A record pointing at `10.0.0.5` is itself a
//!    finding).
//! 2. **Investigation policy.** [`Indicator::ensure_investigable`] decides
//!    whether an indicator may be the *target* of an investigation, meaning
//!    whether it can be sent to public sources. Only globally routable IPs and
//!    public domain names qualify.

mod domain;
mod hash;
mod refang;
mod url;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::net::{self, AddressScope};

pub use domain::DomainName;
pub use hash::{FileHash, HashAlgorithm};
pub use refang::refang;
pub use url::{HttpUrl, UrlHost};

/// A validated, normalized indicator.
///
/// Serialized as `{"type": "<indicator type>", "value": "<normalized value>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Indicator {
    /// A domain name.
    Domain(DomainName),
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    Ipv6(Ipv6Addr),
    /// An `http(s)` URL.
    Url(HttpUrl),
    /// A file hash (MD5, SHA-1 or SHA-256).
    FileHash(FileHash),
}

/// The type of an [`Indicator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    /// Domain name.
    Domain,
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// URL.
    Url,
    /// File hash.
    FileHash,
}

impl IndicatorType {
    /// Machine-readable identifier (`domain`, `ipv4`, …), same as the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Url => "url",
            Self::FileHash => "file_hash",
        }
    }

    /// Human-readable label (`Domain`, `IPv4`, …).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Domain => "Domain",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Url => "URL",
            Self::FileHash => "File hash",
        }
    }
}

impl fmt::Display for IndicatorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an input could not be accepted as an indicator.
///
/// Error messages never echo arbitrary user input back, so they are safe to
/// print to a terminal. Only values that have already been validated
/// (IP addresses, normalized domain names) are included.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IndicatorError {
    /// The input is empty or only whitespace.
    #[error("input is empty")]
    Empty,
    /// The input exceeds the accepted length.
    #[error("input exceeds the maximum length of {max} bytes")]
    TooLong {
        /// The maximum accepted length.
        max: usize,
    },
    /// Not a valid domain name.
    #[error("invalid domain name: {0}")]
    InvalidDomain(&'static str),
    /// A domain was expected but an IP address was given.
    #[error("expected a domain name but got an IP address; investigate it as an IP instead")]
    DomainIsIpAddress,
    /// A domain was expected but the input looks like a URL or `host:port`.
    #[error("expected a bare domain name (e.g. example.com), not a URL or host:port")]
    DomainLooksLikeUrl,
    /// Not a valid IP address.
    #[error("invalid IP address")]
    InvalidIpAddress,
    /// Not a valid file hash.
    #[error("invalid file hash: {0}")]
    InvalidFileHash(&'static str),
    /// Not a valid URL.
    #[error("invalid URL: {0}")]
    InvalidUrl(&'static str),
    /// The value parsed as a different indicator type than requested.
    #[error("expected an indicator of type {expected} but got {actual}")]
    TypeMismatch {
        /// Requested type.
        expected: IndicatorType,
        /// Actual type of the parsed value.
        actual: IndicatorType,
    },
    /// The IP address is not globally routable.
    #[error("{ip} is a {scope} address; only publicly routable addresses can be investigated")]
    NonPublicAddress {
        /// The rejected address.
        ip: IpAddr,
        /// Its scope.
        scope: AddressScope,
    },
    /// The domain is under a special-use or non-public suffix.
    #[error(
        "{0} is a special-use or non-public domain and cannot be investigated with public sources"
    )]
    SpecialUseDomain(DomainName),
}

impl Indicator {
    /// Maximum accepted raw input length, checked before any processing.
    pub const MAX_INPUT_LENGTH: usize = 2048;

    /// Parses a domain name (refanging first).
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if the input is not a valid domain name.
    pub fn parse_domain(input: &str) -> Result<Self, IndicatorError> {
        DomainName::parse(&prepare(input)?).map(Self::Domain)
    }

    /// Parses an IPv4 or IPv6 address (refanging first). IPv6 may be given
    /// in brackets (`[2001:db8::1]`).
    ///
    /// Octal-looking IPv4 notation (`010.0.0.1`) and zone IDs are rejected.
    ///
    /// # Errors
    /// Returns [`IndicatorError::InvalidIpAddress`] if the input is not an IP address.
    pub fn parse_ip(input: &str) -> Result<Self, IndicatorError> {
        let prepared = prepare(input)?;
        let unbracketed = prepared
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(&prepared);
        unbracketed
            .parse::<IpAddr>()
            .map(Self::from)
            .map_err(|_| IndicatorError::InvalidIpAddress)
    }

    /// Parses an `http(s)` URL (refanging first).
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if the input is not an acceptable URL.
    pub fn parse_url(input: &str) -> Result<Self, IndicatorError> {
        HttpUrl::parse(&prepare(input)?).map(Self::Url)
    }

    /// Parses a file hash.
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if the input is not a supported hex digest.
    pub fn parse_file_hash(input: &str) -> Result<Self, IndicatorError> {
        FileHash::parse(&prepare(input)?).map(Self::FileHash)
    }

    /// Parses a value that must be of exactly the given type.
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if parsing fails or the value is of another
    /// type (e.g. an IPv6 address when [`IndicatorType::Ipv4`] was requested).
    pub fn parse(expected: IndicatorType, input: &str) -> Result<Self, IndicatorError> {
        let indicator = match expected {
            IndicatorType::Domain => Self::parse_domain(input),
            IndicatorType::Ipv4 | IndicatorType::Ipv6 => Self::parse_ip(input),
            IndicatorType::Url => Self::parse_url(input),
            IndicatorType::FileHash => Self::parse_file_hash(input),
        }?;
        let actual = indicator.indicator_type();
        if actual == expected {
            Ok(indicator)
        } else {
            Err(IndicatorError::TypeMismatch { expected, actual })
        }
    }

    /// Checks whether this indicator may be the target of an investigation,
    /// i.e. whether it is appropriate to send to public sources.
    ///
    /// # Errors
    /// - [`IndicatorError::NonPublicAddress`] for private, loopback,
    ///   link-local, reserved (…) addresses, including URL hosts.
    /// - [`IndicatorError::SpecialUseDomain`] for `.local`, `.internal`,
    ///   `.onion` and similar names, including URL hosts.
    pub fn ensure_investigable(&self) -> Result<(), IndicatorError> {
        match self {
            Self::Domain(domain) => ensure_public_domain(domain),
            Self::Ipv4(ip) => ensure_public_ip(IpAddr::V4(*ip)),
            Self::Ipv6(ip) => ensure_public_ip(IpAddr::V6(*ip)),
            Self::Url(url) => match url.host() {
                Some(UrlHost::Domain(domain)) => ensure_public_domain(&domain),
                Some(UrlHost::Ip(ip)) => ensure_public_ip(ip),
                None => Err(IndicatorError::InvalidUrl("URL has no host")),
            },
            Self::FileHash(_) => Ok(()),
        }
    }

    /// The type of this indicator.
    #[must_use]
    pub const fn indicator_type(&self) -> IndicatorType {
        match self {
            Self::Domain(_) => IndicatorType::Domain,
            Self::Ipv4(_) => IndicatorType::Ipv4,
            Self::Ipv6(_) => IndicatorType::Ipv6,
            Self::Url(_) => IndicatorType::Url,
            Self::FileHash(_) => IndicatorType::FileHash,
        }
    }

    /// The IP address, if this is an IP indicator.
    #[must_use]
    pub const fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Self::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            _ => None,
        }
    }

    /// The domain name, if this is a domain indicator.
    #[must_use]
    pub const fn as_domain(&self) -> Option<&DomainName> {
        match self {
            Self::Domain(domain) => Some(domain),
            _ => None,
        }
    }
}

fn ensure_public_ip(ip: IpAddr) -> Result<(), IndicatorError> {
    let scope = net::classify(ip);
    if scope.is_global() {
        Ok(())
    } else {
        Err(IndicatorError::NonPublicAddress { ip, scope })
    }
}

fn ensure_public_domain(domain: &DomainName) -> Result<(), IndicatorError> {
    if domain.is_special_use() {
        Err(IndicatorError::SpecialUseDomain(domain.clone()))
    } else {
        Ok(())
    }
}

/// Bounds, trims and refangs raw input.
fn prepare(input: &str) -> Result<String, IndicatorError> {
    if input.len() > Indicator::MAX_INPUT_LENGTH {
        return Err(IndicatorError::TooLong {
            max: Indicator::MAX_INPUT_LENGTH,
        });
    }
    let refanged = refang(input.trim());
    let trimmed = refanged.trim();
    if trimmed.is_empty() {
        return Err(IndicatorError::Empty);
    }
    Ok(trimmed.to_owned())
}

impl From<IpAddr> for Indicator {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::Ipv4(v4),
            IpAddr::V6(v6) => Self::Ipv6(v6),
        }
    }
}

impl From<DomainName> for Indicator {
    fn from(domain: DomainName) -> Self {
        Self::Domain(domain)
    }
}

impl fmt::Display for Indicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => domain.fmt(f),
            Self::Ipv4(ip) => ip.fmt(f),
            Self::Ipv6(ip) => ip.fmt(f),
            Self::Url(url) => url.fmt(f),
            Self::FileHash(hash) => hash.fmt(f),
        }
    }
}

/// Wire representation shared by `Serialize` and `Deserialize`.
#[derive(Serialize, Deserialize)]
struct IndicatorRepr {
    #[serde(rename = "type")]
    kind: IndicatorType,
    value: String,
}

impl Serialize for Indicator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        IndicatorRepr {
            kind: self.indicator_type(),
            value: self.to_string(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Indicator {
    /// Deserialization re-validates the value: serialized data is not trusted.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = IndicatorRepr::deserialize(deserializer)?;
        Self::parse(repr.kind, &repr.value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_type() {
        assert_eq!(
            Indicator::parse_domain("Example.com").unwrap().to_string(),
            "example.com"
        );
        assert_eq!(
            Indicator::parse_ip("8.8.8.8").unwrap().indicator_type(),
            IndicatorType::Ipv4
        );
        assert_eq!(
            Indicator::parse_ip("[2001:4860:4860::8888]")
                .unwrap()
                .indicator_type(),
            IndicatorType::Ipv6
        );
        assert_eq!(
            Indicator::parse_ip("2001:4860:4860:0:0:0:0:8888")
                .unwrap()
                .to_string(),
            "2001:4860:4860::8888"
        );
        assert_eq!(
            Indicator::parse_url("hxxps://evil[.]example.net/a")
                .unwrap()
                .to_string(),
            "https://evil.example.net/a"
        );
        assert_eq!(
            Indicator::parse_file_hash("D41D8CD98F00B204E9800998ECF8427E")
                .unwrap()
                .indicator_type(),
            IndicatorType::FileHash
        );
    }

    #[test]
    fn refangs_before_parsing() {
        assert_eq!(
            Indicator::parse_domain("evil[.]example[.]net")
                .unwrap()
                .to_string(),
            "evil.example.net"
        );
        assert_eq!(
            Indicator::parse_ip("8.8.8[.]8").unwrap().to_string(),
            "8.8.8.8"
        );
    }

    #[test]
    fn rejects_ambiguous_ip_notation() {
        for input in [
            "010.0.0.1",
            "1.2.3",
            "0x7f.0.0.1",
            "fe80::1%eth0",
            "256.1.1.1",
        ] {
            assert_eq!(
                Indicator::parse_ip(input),
                Err(IndicatorError::InvalidIpAddress),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_oversized_input_before_processing() {
        let huge = "a".repeat(Indicator::MAX_INPUT_LENGTH + 1);
        assert_eq!(
            Indicator::parse_domain(&huge),
            Err(IndicatorError::TooLong {
                max: Indicator::MAX_INPUT_LENGTH
            })
        );
    }

    #[test]
    fn parse_enforces_the_requested_type() {
        assert_eq!(
            Indicator::parse(IndicatorType::Ipv4, "2001:4860:4860::8888"),
            Err(IndicatorError::TypeMismatch {
                expected: IndicatorType::Ipv4,
                actual: IndicatorType::Ipv6,
            })
        );
        assert!(Indicator::parse(IndicatorType::Ipv6, "2001:4860:4860::8888").is_ok());
    }

    #[test]
    fn syntax_accepts_private_values_but_policy_rejects_them() {
        let private = Indicator::parse_ip("10.1.2.3").unwrap();
        assert!(matches!(
            private.ensure_investigable(),
            Err(IndicatorError::NonPublicAddress {
                scope: AddressScope::Private,
                ..
            })
        ));

        let metadata = Indicator::parse_ip("169.254.169.254").unwrap();
        assert!(metadata.ensure_investigable().is_err());

        let internal = Indicator::parse_domain("db.corp.internal").unwrap();
        assert!(matches!(
            internal.ensure_investigable(),
            Err(IndicatorError::SpecialUseDomain(_))
        ));

        assert!(
            Indicator::parse_ip("8.8.8.8")
                .unwrap()
                .ensure_investigable()
                .is_ok()
        );
        assert!(
            Indicator::parse_domain("example.com")
                .unwrap()
                .ensure_investigable()
                .is_ok()
        );
    }

    #[test]
    fn policy_applies_to_url_hosts() {
        for input in [
            "http://127.0.0.1/admin",
            "http://0x7f.1/admin", // WHATWG parsing turns this into 127.0.0.1
            "http://[::1]/",
            "http://printer.local/",
        ] {
            let url = Indicator::parse_url(input).unwrap();
            assert!(url.ensure_investigable().is_err(), "{input}");
        }
        let public = Indicator::parse_url("https://example.com/x").unwrap();
        assert!(public.ensure_investigable().is_ok());
    }

    #[test]
    fn error_messages_do_not_echo_raw_input() {
        let hostile = "\u{1b}]0;pwned\u{7}.com";
        let err = Indicator::parse_domain(hostile).unwrap_err().to_string();
        assert!(!err.contains('\u{1b}'));
        assert!(!err.contains("pwned"));
    }
}

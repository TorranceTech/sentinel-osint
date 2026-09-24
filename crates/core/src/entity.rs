//! Entities: the nodes that relationships connect.
//!
//! Every [`Indicator`] is an entity. Some entities, such as autonomous
//! systems, are not indicators you would investigate directly, but they are
//! part of the infrastructure picture.

use std::fmt;

use serde::{Serialize, Serializer};

use crate::indicator::{Indicator, IndicatorType};
use crate::net::IpPrefix;

/// An autonomous system number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Asn(u32);

impl Asn {
    /// Creates an ASN. Returns `None` for 0, which is reserved and means
    /// "no AS" (RFC 7607).
    #[must_use]
    pub const fn new(number: u32) -> Option<Self> {
        if number == 0 {
            None
        } else {
            Some(Self(number))
        }
    }

    /// Parses `15169`, `AS15169` or `as15169`.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        let digits = s
            .get(..2)
            .filter(|prefix| prefix.eq_ignore_ascii_case("as"))
            .map_or(s, |_| &s[2..]);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok().and_then(Self::new)
    }

    /// The AS number.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.0
    }

    /// Whether this ASN is reserved for private use (RFC 6996).
    #[must_use]
    pub const fn is_private_use(self) -> bool {
        matches!(self.0, 64_512..=65_534 | 4_200_000_000..=4_294_967_294)
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// Identifier of a certificate *as known to a source*, e.g. `crtsh:28361964045`
/// (a CT source's log-entry ID). It is not a certificate fingerprint.
///
/// Format: `<namespace>:<id>`, namespace `[a-z0-9]{1,16}`, id
/// `[A-Za-z0-9._-]{1,128}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CertificateId(String);

impl CertificateId {
    /// Creates an identifier; `None` if either part is invalid.
    #[must_use]
    pub fn new(namespace: &str, id: &str) -> Option<Self> {
        let namespace_ok = (1..=16).contains(&namespace.len())
            && namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        let id_ok = (1..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        (namespace_ok && id_ok).then(|| Self(format!("{namespace}:{id}")))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CertificateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A node in the investigation's relationship graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Entity {
    /// An indicator (domain, IP, URL, file hash).
    Indicator(Indicator),
    /// An autonomous system.
    AutonomousSystem(Asn),
    /// A registered IP network (allocation), as reported by a registry.
    Network(IpPrefix),
    /// A certificate, as identified by a source.
    Certificate(CertificateId),
}

/// The type of an [`Entity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
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
    /// Autonomous system.
    AutonomousSystem,
    /// Registered IP network.
    Network,
    /// Certificate.
    Certificate,
}

impl EntityType {
    /// Machine-readable identifier, same as the serialized form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Url => "url",
            Self::FileHash => "file_hash",
            Self::AutonomousSystem => "autonomous_system",
            Self::Network => "network",
            Self::Certificate => "certificate",
        }
    }

    /// Whether this is an IP address type.
    #[must_use]
    pub const fn is_ip(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<IndicatorType> for EntityType {
    fn from(value: IndicatorType) -> Self {
        match value {
            IndicatorType::Domain => Self::Domain,
            IndicatorType::Ipv4 => Self::Ipv4,
            IndicatorType::Ipv6 => Self::Ipv6,
            IndicatorType::Url => Self::Url,
            IndicatorType::FileHash => Self::FileHash,
        }
    }
}

impl Entity {
    /// The type of this entity.
    #[must_use]
    pub fn entity_type(&self) -> EntityType {
        match self {
            Self::Indicator(indicator) => indicator.indicator_type().into(),
            Self::AutonomousSystem(_) => EntityType::AutonomousSystem,
            Self::Network(_) => EntityType::Network,
            Self::Certificate(_) => EntityType::Certificate,
        }
    }
}

impl From<Indicator> for Entity {
    fn from(value: Indicator) -> Self {
        Self::Indicator(value)
    }
}

impl From<IpPrefix> for Entity {
    fn from(value: IpPrefix) -> Self {
        Self::Network(value)
    }
}

impl From<CertificateId> for Entity {
    fn from(value: CertificateId) -> Self {
        Self::Certificate(value)
    }
}

impl From<Asn> for Entity {
    fn from(value: Asn) -> Self {
        Self::AutonomousSystem(value)
    }
}

impl fmt::Display for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Indicator(indicator) => indicator.fmt(f),
            Self::AutonomousSystem(asn) => asn.fmt(f),
            Self::Network(prefix) => prefix.fmt(f),
            Self::Certificate(id) => id.fmt(f),
        }
    }
}

/// Serialized as `{"type": "<entity type>", "value": "<value>"}`, the same
/// shape as [`Indicator`].
impl Serialize for Entity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Repr {
            #[serde(rename = "type")]
            kind: EntityType,
            value: String,
        }
        Repr {
            kind: self.entity_type(),
            value: self.to_string(),
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asn_notations() {
        assert_eq!(Asn::parse("15169"), Asn::new(15169));
        assert_eq!(Asn::parse("AS15169"), Asn::new(15169));
        assert_eq!(Asn::parse(" as15169 "), Asn::new(15169));
        assert_eq!(Asn::parse("AS4294967295").map(Asn::number), Some(u32::MAX));
    }

    #[test]
    fn rejects_invalid_asns() {
        for input in [
            "",
            "AS",
            "0",
            "AS0",
            "AS-1",
            "AS15169x",
            "4294967296",
            "ASé",
        ] {
            assert_eq!(Asn::parse(input), None, "{input:?}");
        }
    }

    #[test]
    fn detects_private_use_asns() {
        assert!(Asn::new(64_512).unwrap().is_private_use());
        assert!(Asn::new(4_200_000_000).unwrap().is_private_use());
        assert!(!Asn::new(15169).unwrap().is_private_use());
    }

    #[test]
    fn certificate_ids() {
        assert_eq!(
            CertificateId::new("crtsh", "28361964045").unwrap().as_str(),
            "crtsh:28361964045"
        );
        for (ns, id) in [
            ("", "1"),
            ("CRTSH", "1"),
            ("crtsh", ""),
            ("crtsh", "1 2"),
            ("crtsh", "a:b"),
            ("crtsh", "\u{1b}1"),
        ] {
            assert!(CertificateId::new(ns, id).is_none(), "{ns}:{id}");
        }
        assert!(CertificateId::new("crtsh", &"1".repeat(129)).is_none());
    }

    #[test]
    fn entity_types() {
        let ip: Entity = Indicator::parse_ip("8.8.8.8").unwrap().into();
        assert_eq!(ip.entity_type(), EntityType::Ipv4);
        let asn: Entity = Asn::new(15169).unwrap().into();
        assert_eq!(asn.entity_type(), EntityType::AutonomousSystem);
        assert_eq!(asn.to_string(), "AS15169");
    }
}

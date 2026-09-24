//! DNS record observations.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// DNS record types collected by Sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Mail exchanger.
    Mx,
    /// Authoritative nameserver.
    Ns,
    /// Text record (SPF, DMARC, verification tokens, …).
    Txt,
    /// Canonical name (alias).
    Cname,
    /// Start of authority.
    Soa,
    /// Certification Authority Authorization.
    Caa,
}

impl DnsRecordType {
    /// The standard mnemonic (`A`, `AAAA`, `MX`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Txt => "TXT",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Caa => "CAA",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single DNS resource record, as returned by the resolver.
///
/// Names inside records come from the DNS, which may be controlled by an
/// adversary. They are stored **as received** (only lowercased and stripped
/// of the trailing dot via [`normalize_name`]) and are **not** validated as
/// [`DomainName`](crate::DomainName)s. Renderers must sanitize them before
/// display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsRecord {
    name: String,
    ttl: u32,
    data: DnsRecordData,
}

impl DnsRecord {
    /// Creates a record. The owner `name` is normalized with [`normalize_name`].
    #[must_use]
    pub fn new(name: &str, ttl: u32, data: DnsRecordData) -> Self {
        Self {
            name: normalize_name(name),
            ttl,
            data,
        }
    }

    /// Owner name of the record.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Time to live, in seconds.
    #[must_use]
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Record data.
    #[must_use]
    pub const fn data(&self) -> &DnsRecordData {
        &self.data
    }

    /// Record type.
    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        self.data.record_type()
    }
}

/// Typed record data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum DnsRecordData {
    /// A record.
    A {
        /// Address.
        address: Ipv4Addr,
    },
    /// AAAA record.
    Aaaa {
        /// Address.
        address: Ipv6Addr,
    },
    /// MX record.
    Mx {
        /// Preference (lower is preferred).
        preference: u16,
        /// Mail server host name.
        exchange: String,
    },
    /// NS record.
    Ns {
        /// Nameserver host name.
        nameserver: String,
    },
    /// TXT record. Multiple character-strings are concatenated, as SPF and
    /// DMARC evaluation requires (RFC 7208 §3.3).
    Txt {
        /// Text content.
        text: String,
    },
    /// CNAME record.
    Cname {
        /// Canonical name.
        target: String,
    },
    /// SOA record.
    Soa {
        /// Primary nameserver.
        mname: String,
        /// Responsible mailbox, in DNS name form.
        rname: String,
        /// Zone serial.
        serial: u32,
        /// Refresh interval (seconds).
        refresh: u32,
        /// Retry interval (seconds).
        retry: u32,
        /// Expire limit (seconds).
        expire: u32,
        /// Negative-caching TTL (seconds).
        minimum: u32,
    },
    /// CAA record.
    Caa {
        /// Issuer-critical flag.
        critical: bool,
        /// Property tag (`issue`, `issuewild`, `iodef`, …).
        tag: String,
        /// Property value.
        value: String,
    },
}

impl DnsRecordData {
    /// The record type of this data.
    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        match self {
            Self::A { .. } => DnsRecordType::A,
            Self::Aaaa { .. } => DnsRecordType::Aaaa,
            Self::Mx { .. } => DnsRecordType::Mx,
            Self::Ns { .. } => DnsRecordType::Ns,
            Self::Txt { .. } => DnsRecordType::Txt,
            Self::Cname { .. } => DnsRecordType::Cname,
            Self::Soa { .. } => DnsRecordType::Soa,
            Self::Caa { .. } => DnsRecordType::Caa,
        }
    }
}

impl DnsRecordData {
    /// The text of a TXT record, if this is one.
    #[must_use]
    pub fn txt(&self) -> Option<&str> {
        match self {
            Self::Txt { text } => Some(text),
            _ => None,
        }
    }
}

/// Whether a TXT record text is an SPF record: it starts with the version
/// section `v=spf1`, followed by a space or the end (RFC 7208 §4.5). The
/// version is matched case-insensitively.
#[must_use]
pub fn is_spf_record(text: &str) -> bool {
    starts_with_version(text, "v=spf1", |rest| {
        rest.is_empty() || rest.starts_with(' ')
    })
}

/// Whether a TXT record text (at `_dmarc.<domain>`) is a DMARC record: it
/// starts with the `v=DMARC1` tag (RFC 7489 §6.6.3), followed by the end,
/// `;` or whitespace.
#[must_use]
pub fn is_dmarc_record(text: &str) -> bool {
    starts_with_version(text.trim_start(), "v=dmarc1", |rest| {
        rest.is_empty() || rest.starts_with(';') || rest.starts_with([' ', '\t'])
    })
}

fn starts_with_version(text: &str, version: &str, valid_rest: impl Fn(&str) -> bool) -> bool {
    text.get(..version.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(version))
        && valid_rest(&text[version.len()..])
}

/// Why a DNS query returned no records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoRecordsReason {
    /// The name exists but has no records of the queried type (NOERROR/NODATA).
    NoData,
    /// The name does not exist (NXDOMAIN).
    NxDomain,
}

/// Evidence of absence: a query that returned no records. Findings such as
/// "no DMARC record" cite this observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsNoRecords {
    name: String,
    record_type: DnsRecordType,
    reason: NoRecordsReason,
}

impl DnsNoRecords {
    /// Creates the observation. `name` is normalized with [`normalize_name`].
    #[must_use]
    pub fn new(name: &str, record_type: DnsRecordType, reason: NoRecordsReason) -> Self {
        Self {
            name: normalize_name(name),
            record_type,
            reason,
        }
    }

    /// Queried name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Queried type.
    #[must_use]
    pub const fn record_type(&self) -> DnsRecordType {
        self.record_type
    }

    /// Why there were no records.
    #[must_use]
    pub const fn reason(&self) -> NoRecordsReason {
        self.reason
    }
}

/// Normalizes a DNS name from a response: ASCII-lowercases it and removes a
/// single trailing dot. No other changes are made. The value stays faithful
/// to what the source returned.
#[must_use]
pub fn normalize_name(name: &str) -> String {
    let name = name.strip_suffix('.').unwrap_or(name);
    name.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_owner_names() {
        let record = DnsRecord::new(
            "Example.COM.",
            300,
            DnsRecordData::A {
                address: Ipv4Addr::new(93, 184, 215, 14),
            },
        );
        assert_eq!(record.name(), "example.com");
        assert_eq!(record.record_type(), DnsRecordType::A);
        assert_eq!(record.ttl(), 300);
    }

    #[test]
    fn record_type_mnemonics() {
        assert_eq!(DnsRecordType::Aaaa.to_string(), "AAAA");
        assert_eq!(DnsRecordType::Cname.as_str(), "CNAME");
    }

    #[test]
    fn recognizes_spf_records() {
        assert!(is_spf_record("v=spf1 -all"));
        assert!(is_spf_record("V=SPF1 include:_spf.example.com ~all"));
        assert!(is_spf_record("v=spf1"));
        assert!(!is_spf_record("v=spf10 -all"));
        assert!(!is_spf_record(" v=spf1 -all"));
        assert!(!is_spf_record("v=spf"));
        assert!(!is_spf_record("google-site-verification=abc"));
        assert!(!is_spf_record("é")); // multi-byte input must not panic
    }

    #[test]
    fn recognizes_dmarc_records() {
        assert!(is_dmarc_record("v=DMARC1; p=reject"));
        assert!(is_dmarc_record("v=DMARC1;p=none"));
        assert!(is_dmarc_record("v=dmarc1"));
        assert!(!is_dmarc_record("v=DMARC10; p=none"));
        assert!(!is_dmarc_record("p=reject; v=DMARC1"));
        assert!(!is_dmarc_record("v=spf1 -all"));
    }

    #[test]
    fn no_records_observation_normalizes_the_name() {
        let absent = DnsNoRecords::new(
            "_DMARC.Example.com.",
            DnsRecordType::Txt,
            NoRecordsReason::NxDomain,
        );
        assert_eq!(absent.name(), "_dmarc.example.com");
        assert_eq!(absent.reason(), NoRecordsReason::NxDomain);
    }

    #[test]
    fn normalize_keeps_unusual_content_faithful() {
        // Not a valid domain name, but it is what the source said.
        assert_eq!(normalize_name("Weird_Host.Example."), "weird_host.example");
        assert_eq!(normalize_name("."), "");
    }
}

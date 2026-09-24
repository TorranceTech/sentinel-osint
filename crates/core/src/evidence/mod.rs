//! Evidence: observations and their provenance.
//!
//! An [`Observation`] is a single **fact** reported by a source about an
//! indicator: "the A record of example.com is 93.184.215.14, according to the
//! system resolver at 17:40:12Z". Observations never contain interpretation.
//! Judgments such as "DMARC is not enforced" are [`Finding`](crate::Finding)s
//! that cite observations as evidence.

mod ct;
mod digest;
mod dns;
mod infra;
mod provenance;
mod reputation;

use std::borrow::Cow;
use std::fmt;

use serde::Serialize;
use uuid::Uuid;

use crate::confidence::Confidence;
use crate::indicator::Indicator;
use crate::time::Timestamp;

pub use ct::{
    CertificateName, CtCertificate, MAX_RAW_NAME_CHARS, NameRelation, classify_certificate_name,
};
pub use digest::{DigestParseError, Sha256Digest};
pub use dns::{
    DnsNoRecords, DnsRecord, DnsRecordData, DnsRecordType, NoRecordsReason, is_dmarc_record,
    is_spf_record, normalize_name,
};
pub use infra::{AsnDescription, AsnOrigin, IpVersion, NetworkRegistration};
pub use provenance::{
    DnsProvenance, HttpMethod, HttpsProvenance, Provenance, REDACTED, sanitize_url,
};
pub use reputation::{
    IpReputation, ProviderAttribute, ProviderDate, ProviderListing, ProviderMetric,
    ProviderNoRecord, ProviderReputation,
};

/// Unique identifier of an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ObservationId(Uuid);

impl ObservationId {
    /// Generates a new random identifier.
    #[must_use]
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for ObservationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifier of a data source (`dns`, `rdap`, `crtsh`, `virustotal`, …).
///
/// Lowercase ASCII letters, digits, `_` and `-`, 1–32 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SourceId(Cow<'static, str>);

impl SourceId {
    /// Maximum length of a source identifier.
    pub const MAX_LENGTH: usize = 32;

    /// Creates a source ID from a static string.
    ///
    /// Intended for constants. When used in a `const` item, an invalid ID
    /// is a **compile-time** error:
    ///
    /// ```
    /// use sentinel_core::SourceId;
    /// const DNS: SourceId = SourceId::from_static("dns");
    /// ```
    ///
    /// # Panics
    /// Panics if `id` is not a valid source identifier.
    #[must_use]
    pub const fn from_static(id: &'static str) -> Self {
        assert!(is_valid_source_id(id), "invalid source id");
        Self(Cow::Borrowed(id))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

const fn is_valid_source_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > SourceId::MAX_LENGTH {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

/// The payload of an observation.
///
/// Each collector adds the variant(s) it needs. New variants are additive,
/// which is why the enum is `#[non_exhaustive]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ObservationData {
    /// A DNS resource record.
    DnsRecord(DnsRecord),
    /// A DNS query that returned no records (evidence of absence).
    DnsNoRecords(DnsNoRecords),
    /// IP → origin AS (BGP) mapping.
    AsnOrigin(AsnOrigin),
    /// AS number → description.
    AsnDescription(AsnDescription),
    /// RDAP IP network registration.
    NetworkRegistration(NetworkRegistration),
    /// A certificate reported by a Certificate Transparency source.
    CtCertificate(CtCertificate),
    /// An IP reputation claim by a threat-intelligence provider.
    IpReputation(IpReputation),
    /// A reputation summary by a provider covering several indicator types.
    ProviderReputation(ProviderReputation),
    /// The provider has no record of the indicator.
    ProviderNoRecord(ProviderNoRecord),
    /// An entry of a provider's threat database matching the indicator.
    ProviderListing(ProviderListing),
}

/// A single fact collected from a source, with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    id: ObservationId,
    indicator: Indicator,
    source: SourceId,
    #[serde(serialize_with = "crate::time::serialize")]
    collected_at: Timestamp,
    data: ObservationData,
    confidence: Confidence,
    provenance: Provenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_response_hash: Option<Sha256Digest>,
}

impl Observation {
    /// Creates an observation with a fresh random ID.
    ///
    /// - `indicator`: the subject the fact is about.
    /// - `collected_at`: when the response was received (supplied by the
    ///   caller; the core never reads the clock).
    #[must_use]
    pub fn new(
        indicator: Indicator,
        source: SourceId,
        collected_at: Timestamp,
        data: ObservationData,
        confidence: Confidence,
        provenance: Provenance,
    ) -> Self {
        Self {
            id: ObservationId::new_random(),
            indicator,
            source,
            collected_at,
            data,
            confidence,
            provenance,
            raw_response_hash: None,
        }
    }

    /// Attaches the SHA-256 digest of the raw response this observation was
    /// derived from.
    #[must_use]
    pub const fn with_raw_response_hash(mut self, digest: Sha256Digest) -> Self {
        self.raw_response_hash = Some(digest);
        self
    }

    /// Unique ID.
    #[must_use]
    pub const fn id(&self) -> ObservationId {
        self.id
    }

    /// The indicator this observation is about.
    #[must_use]
    pub const fn indicator(&self) -> &Indicator {
        &self.indicator
    }

    /// The source that produced it.
    #[must_use]
    pub const fn source(&self) -> &SourceId {
        &self.source
    }

    /// When it was collected (UTC).
    #[must_use]
    pub const fn collected_at(&self) -> Timestamp {
        self.collected_at
    }

    /// The observed data.
    #[must_use]
    pub const fn data(&self) -> &ObservationData {
        &self.data
    }

    /// Confidence in the observed data.
    #[must_use]
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// How it was collected.
    #[must_use]
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// Digest of the raw response, if recorded.
    #[must_use]
    pub const fn raw_response_hash(&self) -> Option<Sha256Digest> {
        self.raw_response_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use chrono::Utc;

    #[test]
    fn source_id_validation() {
        assert!(is_valid_source_id("dns"));
        assert!(is_valid_source_id("cymru_asn"));
        assert!(is_valid_source_id("abuse-ch"));
        assert!(!is_valid_source_id(""));
        assert!(!is_valid_source_id("DNS"));
        assert!(!is_valid_source_id("dns lookup"));
        assert!(!is_valid_source_id(&"a".repeat(33)));
    }

    #[test]
    #[should_panic(expected = "invalid source id")]
    fn from_static_rejects_invalid_ids() {
        let _ = SourceId::from_static("Not Valid");
    }

    #[test]
    fn observation_ids_are_unique() {
        assert_ne!(ObservationId::new_random(), ObservationId::new_random());
    }

    #[test]
    fn builds_an_observation() {
        let at = Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, 12).unwrap();
        let body = br#"{"answer":"93.184.215.14"}"#;
        let obs = Observation::new(
            Indicator::parse_domain("example.com").unwrap(),
            SourceId::from_static("dns"),
            at,
            ObservationData::DnsRecord(DnsRecord::new(
                "example.com",
                300,
                DnsRecordData::A {
                    address: "93.184.215.14".parse().unwrap(),
                },
            )),
            Confidence::CERTAIN,
            Provenance::dns("example.com", DnsRecordType::A, "system"),
        )
        .with_raw_response_hash(Sha256Digest::of(body));

        assert_eq!(obs.source().as_str(), "dns");
        assert_eq!(obs.collected_at(), at);
        assert_eq!(obs.raw_response_hash(), Some(Sha256Digest::of(body)));
        assert_eq!(obs.confidence(), Confidence::CERTAIN);
    }
}

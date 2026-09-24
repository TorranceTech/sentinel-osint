//! # sentinel-core
//!
//! The domain model of Sentinel OSINT.
//!
//! This crate defines what an investigation *is*:
//!
//! - [`Indicator`]: a validated, normalized indicator (domain, IP, URL, file hash).
//! - [`Observation`]: a single fact collected from a source, carrying
//!   [`Provenance`], a collection timestamp, a [`Confidence`] and an optional
//!   integrity hash of the raw response.
//! - [`Relationship`]: a typed, evidence-backed edge between two [`Entity`]s.
//! - [`Finding`]: an analytic judgment derived from observations.
//! - [`Investigation`]: the aggregate that ties everything together and
//!   enforces referential integrity between findings, relationships and
//!   their evidence.
//!
//! ## Design constraints
//!
//! - **No I/O.** This crate never touches the network or the filesystem, and
//!   it never reads the system clock. Timestamps are always passed in by the
//!   caller. (Random UUIDs are the only source of non-determinism.)
//! - **Validate once, at the boundary.** Parsing functions normalize and
//!   validate input. Once a value exists, it is valid.
//! - **Facts are kept faithful.** Data from external sources is stored as
//!   received (bounded by collectors) and is sanitized only when rendered.
//!   External content is data, never instructions.

pub mod confidence;
pub mod entity;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod indicator;
pub mod investigation;
pub mod net;
pub mod relationship;
pub mod text;
pub mod time;

pub use confidence::{Confidence, ConfidenceLevel};
pub use entity::{Asn, CertificateId, Entity, EntityType};
pub use error::ModelError;
pub use evidence::{
    AsnDescription, AsnOrigin, CertificateName, CtCertificate, DnsNoRecords, DnsRecord,
    DnsRecordData, DnsRecordType, HttpMethod, IpReputation, IpVersion, NameRelation,
    NetworkRegistration, NoRecordsReason, Observation, ObservationData, ObservationId, Provenance,
    ProviderAttribute, ProviderDate, ProviderListing, ProviderMetric, ProviderNoRecord,
    ProviderReputation, Sha256Digest, SourceId, classify_certificate_name,
};
pub use finding::{Finding, FindingCode, Severity};
pub use indicator::{
    DomainName, FileHash, HashAlgorithm, HttpUrl, Indicator, IndicatorError, IndicatorType,
};
pub use investigation::{
    Investigation, InvestigationId, SourceOutcome, SourceStatus, TimeLimit, ToolInfo,
};
pub use net::{AddressScope, IpPrefix, PrefixError};
pub use relationship::{RelationKind, Relationship};
pub use time::Timestamp;

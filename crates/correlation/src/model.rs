//! Correlation types. Every correlation is built through
//! [`Draft::build`], which rejects missing or unknown evidence, so a
//! correlation without valid evidence cannot exist.

use std::fmt;

use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};

use sentinel_core::time::format_rfc3339;
use sentinel_core::{
    Confidence, Entity, Finding, FindingCode, InvestigationId, Observation, ObservationId,
    Provenance, Relationship, Severity, Sha256Digest, SourceId, Timestamp,
};

use crate::index::EvidenceIndex;

/// Limitation added when the evidence of a correlation was collected at
/// different times.
pub const NOT_SIMULTANEOUS: &str = "The observations were collected at different times; they may not describe the same moment or state.";

/// Deterministic identifier of a correlation: `corr-` followed by 32 hex
/// digits, derived from the kind, the subjects and the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CorrelationId([u8; 16]);

impl CorrelationId {
    fn derive(kind: CorrelationKind, subjects: &[Entity], evidence: &[ObservationId]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_str().as_bytes());
        for subject in subjects {
            hasher.update(b"\x1fs");
            hasher.update(subject.entity_type().as_str().as_bytes());
            hasher.update(b":");
            hasher.update(subject.to_string().as_bytes());
        }
        for id in evidence {
            hasher.update(b"\x1fe");
            hasher.update(id.as_uuid().as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(bytes)
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("corr-")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Serialize for CorrelationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// What a correlation connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKind {
    /// Domain → IP (DNS) → origin AS (BGP) and/or registered network (RDAP).
    DomainIpInfrastructure,
    /// Certificates (CT) that list the investigated domain.
    DomainCertificate,
    /// Related CT names that also appear in DNS data already collected.
    CtDnsNames,
    /// Several providers made claims about the same indicator.
    MultipleSources,
    /// Provider claims about the same indicator disagree.
    SourceDisagreement,
    /// Several indicators connect to the same AS, network, IP or certificate.
    SharedInfrastructure,
}

impl CorrelationKind {
    /// Machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DomainIpInfrastructure => "domain_ip_infrastructure",
            Self::DomainCertificate => "domain_certificate",
            Self::CtDnsNames => "ct_dns_names",
            Self::MultipleSources => "multiple_sources",
            Self::SourceDisagreement => "source_disagreement",
            Self::SharedInfrastructure => "shared_infrastructure",
        }
    }

    /// The stable finding code of this kind (`correlation.<kind>`).
    #[must_use]
    pub const fn finding_code(self) -> FindingCode {
        match self {
            Self::DomainIpInfrastructure => {
                FindingCode::from_static("correlation.domain_ip_infrastructure")
            }
            Self::DomainCertificate => FindingCode::from_static("correlation.domain_certificate"),
            Self::CtDnsNames => FindingCode::from_static("correlation.ct_dns_names"),
            Self::MultipleSources => FindingCode::from_static("correlation.multiple_sources"),
            Self::SourceDisagreement => FindingCode::from_static("correlation.source_disagreement"),
            Self::SharedInfrastructure => {
                FindingCode::from_static("correlation.shared_infrastructure")
            }
        }
    }

    /// Finding title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::DomainIpInfrastructure => "Domain, address and network context are connected",
            Self::DomainCertificate => "Certificates list the investigated domain",
            Self::CtDnsNames => "Certificate names also appear in DNS data",
            Self::MultipleSources => "Several providers report on the same indicator",
            Self::SourceDisagreement => "Providers disagree about the same indicator",
            Self::SharedInfrastructure => "Several indicators share an infrastructure element",
        }
    }
}

/// A provider's own reading of its claim, used only to detect
/// disagreement. It is the provider's, not a Sentinel verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStance {
    /// The provider reports something (reports, detections, a listing).
    Flags,
    /// The provider has data and reports nothing.
    DoesNotFlag,
    /// The provider has no record of the indicator.
    NoRecord,
    /// The provider's data is incomplete for this reading.
    Unclear,
}

impl ProviderStance {
    /// Machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flags => "flags",
            Self::DoesNotFlag => "does_not_flag",
            Self::NoRecord => "no_record",
            Self::Unclear => "unclear",
        }
    }
}

/// One provider's claim about an indicator, as recorded in one observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderClaim {
    /// The provider (source).
    pub provider: SourceId,
    /// The observation holding the claim.
    pub observation: ObservationId,
    /// The provider's stance.
    pub stance: ProviderStance,
    /// The provider's figures or classification, in the provider's terms.
    pub summary: String,
    /// When the observation was collected (copied from it).
    #[serde(serialize_with = "serialize_ts")]
    pub collected_at: Timestamp,
}

/// A disagreement between pieces of evidence. Never resolved by Sentinel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    /// What disagrees (written by Sentinel).
    pub description: String,
    /// The evidence on every side.
    pub evidence: Vec<ObservationId>,
}

/// When the evidence of a correlation was collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObservedWindow {
    /// Earliest collection time.
    #[serde(serialize_with = "serialize_ts")]
    pub first: Timestamp,
    /// Latest collection time.
    #[serde(serialize_with = "serialize_ts")]
    pub last: Timestamp,
}

// `serialize_with` hands us a reference; the signature is fixed.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_ts<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_rfc3339(ts))
}

/// An explainable connection between existing observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Correlation {
    id: CorrelationId,
    kind: CorrelationKind,
    finding_code: FindingCode,
    summary: String,
    subjects: Vec<Entity>,
    links: Vec<Relationship>,
    claims: Vec<ProviderClaim>,
    supporting: Vec<ObservationId>,
    conflicts: Vec<Conflict>,
    gaps: Vec<String>,
    observed: ObservedWindow,
    evidence: Vec<ObservationId>,
    evidence_confidence: Confidence,
    limitations: Vec<String>,
}

impl Correlation {
    /// Deterministic ID.
    #[must_use]
    pub const fn id(&self) -> CorrelationId {
        self.id
    }

    /// Kind.
    #[must_use]
    pub const fn kind(&self) -> CorrelationKind {
        self.kind
    }

    /// One-paragraph explanation (written by Sentinel).
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// The entities this correlation is about (all present in the
    /// investigation).
    #[must_use]
    pub fn subjects(&self) -> &[Entity] {
        &self.subjects
    }

    /// The existing relationships it composes.
    #[must_use]
    pub fn links(&self) -> &[Relationship] {
        &self.links
    }

    /// Provider claims (provider correlations).
    #[must_use]
    pub fn claims(&self) -> &[ProviderClaim] {
        &self.claims
    }

    /// Context evidence that is not a link or a claim.
    #[must_use]
    pub fn supporting(&self) -> &[ObservationId] {
        &self.supporting
    }

    /// Disagreements between pieces of evidence.
    #[must_use]
    pub fn conflicts(&self) -> &[Conflict] {
        &self.conflicts
    }

    /// Missing evidence and why it is missing.
    #[must_use]
    pub fn gaps(&self) -> &[String] {
        &self.gaps
    }

    /// When the evidence was collected.
    #[must_use]
    pub const fn observed(&self) -> ObservedWindow {
        self.observed
    }

    /// Every observation cited anywhere in the correlation (sorted, unique).
    #[must_use]
    pub fn evidence(&self) -> &[ObservationId] {
        &self.evidence
    }

    /// The lowest capture confidence among the evidence. It describes the
    /// quality of the evidence, never how likely anything is malicious.
    #[must_use]
    pub const fn evidence_confidence(&self) -> Confidence {
        self.evidence_confidence
    }

    /// Caveats.
    #[must_use]
    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    /// The `correlation.*` finding describing this correlation: `info`,
    /// citing all of its evidence, with the evidence confidence.
    #[must_use]
    pub fn finding(&self) -> Finding {
        Finding::new(
            self.finding_code.clone(),
            Severity::Info,
            self.kind.title(),
            format!("{} (correlation {})", self.summary, self.id),
            self.evidence_confidence,
        )
        .with_evidence(self.evidence.iter().copied())
    }

    /// Resolves every cited observation through the investigation:
    /// source, collection time, provenance, digest and confidence.
    #[must_use]
    pub fn provenance<'a>(&self, index: &EvidenceIndex<'a>) -> Vec<ProvenanceStep<'a>> {
        self.evidence
            .iter()
            .filter_map(|id| index.observation(*id))
            .map(ProvenanceStep::of)
            .collect()
    }
}

/// One auditable step of a correlation's provenance chain.
#[derive(Debug, Clone, Copy)]
pub struct ProvenanceStep<'a> {
    /// The observation.
    pub observation: ObservationId,
    /// Its source.
    pub source: &'a SourceId,
    /// When it was collected.
    pub collected_at: Timestamp,
    /// How it was collected.
    pub provenance: &'a Provenance,
    /// Digest of the raw response, if recorded.
    pub digest: Option<Sha256Digest>,
    /// Sentinel's capture confidence.
    pub confidence: Confidence,
}

impl<'a> ProvenanceStep<'a> {
    fn of(observation: &'a Observation) -> Self {
        Self {
            observation: observation.id(),
            source: observation.source(),
            collected_at: observation.collected_at(),
            provenance: observation.provenance(),
            digest: observation.raw_response_hash(),
            confidence: observation.confidence(),
        }
    }
}

/// Why a correlation could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationError {
    /// No evidence, or a conflict without evidence.
    MissingEvidence,
    /// Cited evidence is not part of the investigation.
    UnknownObservation(ObservationId),
    /// A subject is not part of the investigation.
    UnknownEntity,
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEvidence => {
                f.write_str("a correlation must cite at least one observation")
            }
            Self::UnknownObservation(id) => {
                write!(f, "observation {id} is not part of the investigation")
            }
            Self::UnknownEntity => f.write_str("a subject is not part of the investigation"),
        }
    }
}

impl std::error::Error for CorrelationError {}

/// Unvalidated parts of a correlation.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    /// Sentinel-written explanation.
    pub summary: String,
    /// Subjects (must exist in the investigation).
    pub subjects: Vec<Entity>,
    /// Existing relationships composed.
    pub links: Vec<Relationship>,
    /// Provider claims.
    pub claims: Vec<ProviderClaim>,
    /// Context evidence.
    pub supporting: Vec<ObservationId>,
    /// Conflicts.
    pub conflicts: Vec<Conflict>,
    /// Gaps.
    pub gaps: Vec<String>,
    /// Caveats.
    pub limitations: Vec<String>,
}

impl Draft {
    /// Validates and completes the draft.
    ///
    /// # Errors
    /// - [`CorrelationError::MissingEvidence`] if nothing is cited, or a
    ///   conflict cites nothing;
    /// - [`CorrelationError::UnknownObservation`] if an ID is not in the
    ///   investigation;
    /// - [`CorrelationError::UnknownEntity`] if a subject is not in it.
    pub fn build(
        self,
        kind: CorrelationKind,
        index: &EvidenceIndex<'_>,
    ) -> Result<Correlation, CorrelationError> {
        if self.conflicts.iter().any(|c| c.evidence.is_empty()) {
            return Err(CorrelationError::MissingEvidence);
        }
        let mut evidence: Vec<ObservationId> = self
            .links
            .iter()
            .flat_map(|l| l.evidence().iter().copied())
            .chain(self.claims.iter().map(|c| c.observation))
            .chain(self.supporting.iter().copied())
            .chain(
                self.conflicts
                    .iter()
                    .flat_map(|c| c.evidence.iter().copied()),
            )
            .collect();
        evidence.sort_unstable();
        evidence.dedup();
        if evidence.is_empty() {
            return Err(CorrelationError::MissingEvidence);
        }
        let mut observations = Vec::with_capacity(evidence.len());
        for id in &evidence {
            observations.push(
                index
                    .observation(*id)
                    .ok_or(CorrelationError::UnknownObservation(*id))?,
            );
        }
        let mut subjects = self.subjects;
        subjects.sort();
        subjects.dedup();
        if !subjects.iter().all(|s| index.knows_entity(s)) {
            return Err(CorrelationError::UnknownEntity);
        }

        let first = observations.iter().map(|o| o.collected_at()).min();
        let last = observations.iter().map(|o| o.collected_at()).max();
        let (Some(first), Some(last)) = (first, last) else {
            return Err(CorrelationError::MissingEvidence);
        };
        let evidence_confidence = observations
            .iter()
            .map(|o| o.confidence())
            .min()
            .unwrap_or(Confidence::saturating(0));

        let mut links = self.links;
        links.sort_by(|a, b| {
            (a.kind(), a.source(), a.target()).cmp(&(b.kind(), b.source(), b.target()))
        });
        links.dedup_by(|a, b| a.is_same_edge(b));
        let mut claims = self.claims;
        claims.sort_by(|a, b| {
            (&a.provider, a.collected_at, a.observation).cmp(&(
                &b.provider,
                b.collected_at,
                b.observation,
            ))
        });
        claims.dedup_by_key(|c| c.observation);
        let mut supporting = self.supporting;
        supporting.sort_unstable();
        supporting.dedup();
        let mut conflicts = self.conflicts;
        for conflict in &mut conflicts {
            conflict.evidence.sort_unstable();
            conflict.evidence.dedup();
        }
        let mut limitations = self.limitations;
        if first != last {
            limitations.push(NOT_SIMULTANEOUS.to_owned());
        }
        limitations.dedup();

        Ok(Correlation {
            id: CorrelationId::derive(kind, &subjects, &evidence),
            kind,
            finding_code: kind.finding_code(),
            summary: self.summary,
            subjects,
            links,
            claims,
            supporting,
            conflicts,
            gaps: self.gaps,
            observed: ObservedWindow { first, last },
            evidence,
            evidence_confidence,
            limitations,
        })
    }
}

/// The result of correlating one investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorrelationReport {
    /// The investigation this report was derived from.
    pub investigation: InvestigationId,
    /// Correlations, ordered by kind, subjects and ID.
    pub correlations: Vec<Correlation>,
    /// One `correlation.*` finding per correlation, in the same order.
    pub findings: Vec<Finding>,
    /// Caveats about the whole report (truncation, duplicate input IDs).
    pub limitations: Vec<String>,
}

impl CorrelationReport {
    /// Correlations of one kind.
    pub fn of_kind(&self, kind: CorrelationKind) -> impl Iterator<Item = &Correlation> {
        self.correlations.iter().filter(move |c| c.kind() == kind)
    }
}

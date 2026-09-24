//! The investigation aggregate.

use std::fmt;

use chrono::TimeDelta;
use serde::Serialize;
use uuid::Uuid;

use crate::error::ModelError;
use crate::evidence::{Observation, ObservationId, SourceId};
use crate::finding::Finding;
use crate::indicator::{Indicator, IndicatorError};
use crate::relationship::Relationship;
use crate::text::sanitize_single_line;
use crate::time::Timestamp;

/// Unique identifier of an investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct InvestigationId(Uuid);

impl InvestigationId {
    /// Generates a new random identifier.
    #[must_use]
    pub fn new_random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The tool that produced an investigation, recorded for reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolInfo {
    /// Tool name.
    pub name: &'static str,
    /// Tool version.
    pub version: &'static str,
}

impl ToolInfo {
    /// This build of Sentinel OSINT.
    pub const CURRENT: Self = Self {
        name: "sentinel-osint",
        version: env!("CARGO_PKG_VERSION"),
    };
}

/// The result of running one source during an investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceOutcome {
    /// The source ran and returned data (possibly zero observations).
    Succeeded {
        /// Number of observations produced.
        observations: usize,
    },
    /// The source ran but some of its queries failed. The observations it
    /// did produce are valid; conclusions that depend on the failed queries
    /// are not drawn.
    Partial {
        /// Number of observations produced.
        observations: usize,
        /// Sanitized summaries of the failed parts.
        errors: Vec<String>,
    },
    /// The source was not run because it is not usable, e.g. its API key
    /// is not configured or its configuration is invalid. This is **not** a
    /// "no data" answer.
    Unavailable {
        /// Why (fixed text; never contains secrets).
        reason: String,
    },
    /// The source did not run because the investigation's request budget
    /// was used up. This is **not** a "no data" answer.
    BudgetExhausted {
        /// The budget.
        limit: u32,
    },
    /// No indicator the source supports appeared in the investigation, so
    /// it never ran.
    Unsupported,
    /// The source failed. The investigation continues without it.
    Failed {
        /// Sanitized error summary.
        error: String,
    },
    /// The source did not finish in time and was cancelled.
    TimedOut {
        /// Which time limit was hit.
        limit: TimeLimit,
    },
}

impl SourceOutcome {
    /// Returns the outcome with its free-text fields passed through
    /// [`sanitize_single_line`], so they are safe for terminals and logs.
    fn sanitized(self) -> Self {
        match self {
            Self::Unavailable { reason } => Self::Unavailable {
                reason: sanitize_single_line(&reason, MAX_OUTCOME_TEXT),
            },
            Self::Failed { error } => Self::Failed {
                error: sanitize_single_line(&error, MAX_OUTCOME_TEXT),
            },
            Self::Partial {
                observations,
                errors,
            } => Self::Partial {
                observations,
                errors: errors
                    .iter()
                    .take(MAX_OUTCOME_ERRORS)
                    .map(|e| sanitize_single_line(e, MAX_OUTCOME_TEXT))
                    .collect(),
            },
            other => other,
        }
    }
}

/// Maximum length (in characters) of outcome texts.
const MAX_OUTCOME_TEXT: usize = 300;
/// Maximum number of error texts kept for a partial outcome.
const MAX_OUTCOME_ERRORS: usize = 20;

/// A time limit that cancelled a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeLimit {
    /// The per-source timeout.
    Source,
    /// The global investigation deadline.
    Investigation,
}

/// Status of one source run against one indicator (the target or a pivot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceStatus {
    source: SourceId,
    indicator: Indicator,
    #[serde(flatten)]
    outcome: SourceOutcome,
    #[serde(serialize_with = "crate::time::serialize")]
    started_at: Timestamp,
    #[serde(serialize_with = "crate::time::serialize")]
    finished_at: Timestamp,
}

impl SourceStatus {
    /// Creates a source status.
    ///
    /// - Free-text fields of the outcome are sanitized (control and bidi
    ///   characters replaced, length bounded), because error texts may
    ///   indirectly contain external data.
    /// - If `finished_at` is earlier than `started_at` (clock adjustments),
    ///   it is clamped to `started_at`.
    #[must_use]
    pub fn new(
        source: SourceId,
        indicator: Indicator,
        outcome: SourceOutcome,
        started_at: Timestamp,
        finished_at: Timestamp,
    ) -> Self {
        Self {
            source,
            indicator,
            outcome: outcome.sanitized(),
            started_at,
            finished_at: finished_at.max(started_at),
        }
    }

    /// The source.
    #[must_use]
    pub const fn source(&self) -> &SourceId {
        &self.source
    }

    /// The indicator the source ran against.
    #[must_use]
    pub const fn indicator(&self) -> &Indicator {
        &self.indicator
    }

    /// What happened.
    #[must_use]
    pub const fn outcome(&self) -> &SourceOutcome {
        &self.outcome
    }

    /// When the source started.
    #[must_use]
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// When the source finished.
    #[must_use]
    pub const fn finished_at(&self) -> Timestamp {
        self.finished_at
    }

    /// How long the source took.
    #[must_use]
    pub fn duration(&self) -> TimeDelta {
        self.finished_at - self.started_at
    }
}

/// An investigation of one target indicator.
///
/// Invariants, enforced by construction:
/// - the target passed [`Indicator::ensure_investigable`];
/// - every relationship and finding cites only observations that belong to
///   this investigation;
/// - identical relationships are stored once, with their evidence merged;
/// - `finished_at`, if set, is not earlier than `started_at`.
#[derive(Debug, Clone, Serialize)]
pub struct Investigation {
    id: InvestigationId,
    target: Indicator,
    tool: ToolInfo,
    #[serde(serialize_with = "crate::time::serialize")]
    started_at: Timestamp,
    #[serde(serialize_with = "crate::time::serialize_opt")]
    finished_at: Option<Timestamp>,
    observations: Vec<Observation>,
    relationships: Vec<Relationship>,
    findings: Vec<Finding>,
    sources: Vec<SourceStatus>,
}

impl Investigation {
    /// Starts an investigation of `target`.
    ///
    /// # Errors
    /// Returns [`IndicatorError`] if the target may not be investigated with
    /// public sources (private IP, special-use domain, …).
    pub fn new(target: Indicator, started_at: Timestamp) -> Result<Self, IndicatorError> {
        target.ensure_investigable()?;
        Ok(Self {
            id: InvestigationId::new_random(),
            target,
            tool: ToolInfo::CURRENT,
            started_at,
            finished_at: None,
            observations: Vec::new(),
            relationships: Vec::new(),
            findings: Vec::new(),
            sources: Vec::new(),
        })
    }

    /// Adds an observation and returns its ID.
    pub fn add_observation(&mut self, observation: Observation) -> ObservationId {
        let id = observation.id();
        self.observations.push(observation);
        id
    }

    /// Adds a relationship. If the same edge already exists, the evidence is
    /// merged into it instead.
    ///
    /// # Errors
    /// [`ModelError::UnknownObservation`] if any cited evidence is not part
    /// of this investigation.
    pub fn add_relationship(&mut self, relationship: Relationship) -> Result<(), ModelError> {
        self.ensure_known(relationship.evidence())?;
        if let Some(existing) = self
            .relationships
            .iter_mut()
            .find(|r| r.is_same_edge(&relationship))
        {
            existing.merge_evidence(&relationship);
        } else {
            self.relationships.push(relationship);
        }
        Ok(())
    }

    /// Adds a finding.
    ///
    /// # Errors
    /// [`ModelError::UnknownObservation`] if any cited evidence is not part
    /// of this investigation.
    pub fn add_finding(&mut self, finding: Finding) -> Result<(), ModelError> {
        self.ensure_known(finding.evidence())?;
        self.findings.push(finding);
        Ok(())
    }

    /// Records the outcome of a source.
    pub fn record_source(&mut self, status: SourceStatus) {
        self.sources.push(status);
    }

    /// Marks the investigation as finished.
    ///
    /// # Errors
    /// [`ModelError::FinishedBeforeStart`] if `at` is earlier than the start.
    pub fn finish(&mut self, at: Timestamp) -> Result<(), ModelError> {
        if at < self.started_at {
            return Err(ModelError::FinishedBeforeStart);
        }
        self.finished_at = Some(at);
        Ok(())
    }

    fn ensure_known(&self, ids: &[ObservationId]) -> Result<(), ModelError> {
        match ids.iter().find(|id| self.observation(**id).is_none()) {
            Some(unknown) => Err(ModelError::UnknownObservation(*unknown)),
            None => Ok(()),
        }
    }

    /// Investigation ID.
    #[must_use]
    pub const fn id(&self) -> InvestigationId {
        self.id
    }

    /// The investigated indicator.
    #[must_use]
    pub const fn target(&self) -> &Indicator {
        &self.target
    }

    /// The tool that produced the investigation.
    #[must_use]
    pub const fn tool(&self) -> &ToolInfo {
        &self.tool
    }

    /// When it started.
    #[must_use]
    pub const fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// When it finished, if it has.
    #[must_use]
    pub const fn finished_at(&self) -> Option<Timestamp> {
        self.finished_at
    }

    /// Total duration, if finished.
    #[must_use]
    pub fn duration(&self) -> Option<TimeDelta> {
        self.finished_at.map(|end| end - self.started_at)
    }

    /// All observations, in insertion order.
    #[must_use]
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Looks up an observation by ID.
    #[must_use]
    pub fn observation(&self, id: ObservationId) -> Option<&Observation> {
        self.observations.iter().find(|o| o.id() == id)
    }

    /// Observations produced by one source.
    pub fn observations_from<'a>(
        &'a self,
        source: &'a SourceId,
    ) -> impl Iterator<Item = &'a Observation> + 'a {
        self.observations
            .iter()
            .filter(move |o| o.source() == source)
    }

    /// All relationships.
    #[must_use]
    pub fn relationships(&self) -> &[Relationship] {
        &self.relationships
    }

    /// All findings, in insertion order.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The status of every source that was considered.
    #[must_use]
    pub fn sources(&self) -> &[SourceStatus] {
        &self.sources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::Confidence;
    use crate::evidence::{DnsRecord, DnsRecordData, DnsRecordType, ObservationData, Provenance};
    use crate::finding::{FindingCode, Severity};
    use crate::relationship::RelationKind;
    use chrono::{TimeZone, Utc};

    const DNS: SourceId = SourceId::from_static("dns");

    fn t(sec: u32) -> Timestamp {
        Utc.with_ymd_and_hms(2026, 9, 23, 17, 40, sec).unwrap()
    }

    fn domain() -> Indicator {
        Indicator::parse_domain("example.com").unwrap()
    }

    fn a_record(ip: &str) -> Observation {
        Observation::new(
            domain(),
            DNS,
            t(1),
            ObservationData::DnsRecord(DnsRecord::new(
                "example.com",
                300,
                DnsRecordData::A {
                    address: ip.parse().unwrap(),
                },
            )),
            Confidence::CERTAIN,
            Provenance::dns("example.com", DnsRecordType::A, "system"),
        )
    }

    fn resolves_to(ip: &str, evidence: ObservationId) -> Relationship {
        Relationship::new(
            domain(),
            RelationKind::ResolvesTo,
            Indicator::parse_ip(ip).unwrap(),
            [evidence],
        )
        .unwrap()
    }

    #[test]
    fn rejects_non_investigable_targets() {
        let private = Indicator::parse_ip("192.168.0.1").unwrap();
        assert!(Investigation::new(private, t(0)).is_err());
    }

    #[test]
    fn enforces_referential_integrity() {
        let mut inv = Investigation::new(domain(), t(0)).unwrap();
        let foreign = ObservationId::new_random();
        assert_eq!(
            inv.add_relationship(resolves_to("93.184.215.14", foreign)),
            Err(ModelError::UnknownObservation(foreign))
        );

        let finding = Finding::new(
            FindingCode::from_static("test.finding"),
            Severity::Info,
            "t",
            "d",
            Confidence::CERTAIN,
        )
        .with_evidence([foreign]);
        assert_eq!(
            inv.add_finding(finding),
            Err(ModelError::UnknownObservation(foreign))
        );
        assert!(inv.relationships().is_empty());
        assert!(inv.findings().is_empty());
    }

    #[test]
    fn merges_duplicate_relationships() {
        let mut inv = Investigation::new(domain(), t(0)).unwrap();
        let first = inv.add_observation(a_record("93.184.215.14"));
        let second = inv.add_observation(a_record("93.184.215.14"));

        inv.add_relationship(resolves_to("93.184.215.14", first))
            .unwrap();
        inv.add_relationship(resolves_to("93.184.215.14", second))
            .unwrap();

        assert_eq!(inv.relationships().len(), 1);
        assert_eq!(inv.relationships()[0].evidence(), &[first, second]);
    }

    #[test]
    fn looks_up_observations() {
        let mut inv = Investigation::new(domain(), t(0)).unwrap();
        let id = inv.add_observation(a_record("93.184.215.14"));
        assert!(inv.observation(id).is_some());
        assert_eq!(inv.observations_from(&DNS).count(), 1);
        assert_eq!(
            inv.observations_from(&SourceId::from_static("rdap"))
                .count(),
            0
        );
    }

    #[test]
    fn finish_validates_time_and_computes_duration() {
        let mut inv = Investigation::new(domain(), t(10)).unwrap();
        assert_eq!(inv.finish(t(5)), Err(ModelError::FinishedBeforeStart));
        assert_eq!(inv.duration(), None);
        inv.finish(t(12)).unwrap();
        assert_eq!(inv.duration(), Some(TimeDelta::seconds(2)));
    }

    #[test]
    fn source_status_clamps_negative_durations() {
        let status = SourceStatus::new(
            DNS,
            domain(),
            SourceOutcome::Succeeded { observations: 1 },
            t(10),
            t(9),
        );
        assert_eq!(status.duration(), TimeDelta::zero());
    }

    #[test]
    fn source_status_sanitizes_outcome_text() {
        let status = SourceStatus::new(
            DNS,
            domain(),
            SourceOutcome::Failed {
                error: format!("bad\u{1b}[31m\nline{}", "x".repeat(1000)),
            },
            t(0),
            t(1),
        );
        let SourceOutcome::Failed { error } = status.outcome() else {
            panic!("expected failure");
        };
        assert!(!error.contains('\u{1b}') && !error.contains('\n'));
        assert!(error.chars().count() <= MAX_OUTCOME_TEXT);
    }
}

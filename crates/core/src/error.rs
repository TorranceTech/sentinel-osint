//! Errors raised when an operation would violate a model invariant.

use crate::entity::EntityType;
use crate::evidence::ObservationId;
use crate::relationship::RelationKind;

/// A model invariant would be violated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ModelError {
    /// A relationship connects entity types it is not defined for.
    #[error("relationship `{kind}` cannot connect {source_type} to {target_type}")]
    InvalidRelationship {
        /// The relationship kind.
        kind: RelationKind,
        /// Type of the source entity.
        source_type: EntityType,
        /// Type of the target entity.
        target_type: EntityType,
    },
    /// A relationship or finding claims no evidence where evidence is required.
    #[error("a relationship must cite at least one observation as evidence")]
    MissingEvidence,
    /// Cited evidence does not exist in the investigation.
    #[error("observation {0} is cited as evidence but is not part of the investigation")]
    UnknownObservation(ObservationId),
    /// The investigation would finish before it started.
    #[error("an investigation cannot finish before it started")]
    FinishedBeforeStart,
}

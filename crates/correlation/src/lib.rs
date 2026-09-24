//! Explainable, I/O-free correlation of a finished investigation.
//!
//! [`correlate`] takes an [`Investigation`] and returns a
//! [`CorrelationReport`]: compositions of the investigation's own
//! observations and relationships (chains, groupings, provider agreement
//! and disagreement), each citing its evidence by ID. See
//! `docs/CORRELATION.md`.
//!
//! Guarantees:
//! - **No I/O.** `correlate` is synchronous and receives nothing but the
//!   investigation. This crate depends only on `sentinel-core`, `serde` and
//!   `sha2`; `tests/no_io.rs` enforces the dependency list and scans the
//!   source for network, DNS, process, file and environment APIs.
//! - **No new facts or pivots.** Every subject already appears in the
//!   investigation, and every cited observation exists in it; a
//!   correlation without evidence cannot be built.
//! - **No scores or verdicts.** Provider claims are listed in the
//!   providers' terms; disagreements are kept, never resolved. All
//!   `correlation.*` findings are `info`.
//! - **Deterministic.** Ordered indexes, sorted output, content-derived
//!   IDs; no clock or randomness.

mod index;
mod model;
mod rules;

use sentinel_core::Investigation;

pub use index::EvidenceIndex;
pub use model::{
    Conflict, Correlation, CorrelationError, CorrelationId, CorrelationKind, CorrelationReport,
    Draft, NOT_SIMULTANEOUS, ObservedWindow, ProvenanceStep, ProviderClaim, ProviderStance,
};
pub use rules::{
    CERTIFICATE_IS_NOT_PROOF, CT_NAMES_NOT_RESOLVED, MAX_CERTIFICATE_GROUPS, MAX_LINKS, MOAS,
    NOT_RESOLVED, OWN_CLASSIFICATIONS, ROUTING_IS_NOT_OWNERSHIP, SHARING_IS_NOT_ATTRIBUTION,
};

/// Correlates a finished investigation. Pure: no I/O, no clock, no
/// randomness; the same investigation always yields the same report.
#[must_use]
pub fn correlate(investigation: &Investigation) -> CorrelationReport {
    let index = EvidenceIndex::new(investigation);
    let mut emit = rules::Emit::new(&index);
    let mut limitations = rules::run(&index, &mut emit);

    let mut correlations = emit.built;
    // By kind, then by what they are about; the ID breaks ties. The order
    // does not depend on observation IDs where subjects differ.
    correlations
        .sort_by(|a, b| (a.kind(), a.subjects(), a.id()).cmp(&(b.kind(), b.subjects(), b.id())));
    correlations.dedup_by_key(|c| c.id());
    if index.duplicate_ids() > 0 {
        limitations.push(format!(
            "{} observation(s) reused an ID already present and were ignored.",
            index.duplicate_ids()
        ));
    }
    if !emit.rejected.is_empty() {
        limitations.push(format!(
            "{} candidate correlation(s) were rejected because their evidence was missing or unknown.",
            emit.rejected.len()
        ));
    }
    let findings = correlations.iter().map(Correlation::finding).collect();
    CorrelationReport {
        investigation: investigation.id(),
        correlations,
        findings,
        limitations,
    }
}

#[cfg(test)]
mod tests;

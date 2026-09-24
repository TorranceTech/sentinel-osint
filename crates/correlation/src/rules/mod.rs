//! Correlation rules. Each rule reads the index and emits drafts; drafts
//! are validated by [`Draft::build`](crate::model::Draft::build).

mod certificates;
mod infrastructure;
mod providers;
mod shared;

use std::net::IpAddr;

use sentinel_core::{Entity, Indicator};

use crate::index::EvidenceIndex;
use crate::model::{Correlation, CorrelationError, CorrelationKind, Draft};

pub use certificates::{CERTIFICATE_IS_NOT_PROOF, CT_NAMES_NOT_RESOLVED};
pub use infrastructure::{MOAS, ROUTING_IS_NOT_OWNERSHIP};
pub use providers::{NOT_RESOLVED, OWN_CLASSIFICATIONS};
pub use shared::{MAX_CERTIFICATE_GROUPS, SHARING_IS_NOT_ATTRIBUTION};

/// Links listed per correlation where a list could be huge.
pub const MAX_LINKS: usize = 100;
/// Names quoted in a summary.
const MAX_QUOTED: usize = 10;

/// Collects built correlations and build errors.
pub(crate) struct Emit<'i, 'a> {
    index: &'i EvidenceIndex<'a>,
    pub(crate) built: Vec<Correlation>,
    pub(crate) rejected: Vec<CorrelationError>,
}

impl<'i, 'a> Emit<'i, 'a> {
    pub(crate) const fn new(index: &'i EvidenceIndex<'a>) -> Self {
        Self {
            index,
            built: Vec::new(),
            rejected: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, kind: CorrelationKind, draft: Draft) {
        match draft.build(kind, self.index) {
            Ok(correlation) => self.built.push(correlation),
            Err(error) => self.rejected.push(error),
        }
    }
}

/// Runs every rule. Returns report-level limitations.
pub(crate) fn run(index: &EvidenceIndex<'_>, emit: &mut Emit<'_, '_>) -> Vec<String> {
    let mut limitations = Vec::new();
    infrastructure::correlate(index, emit);
    certificates::correlate(index, emit);
    providers::correlate(index, emit);
    limitations.extend(shared::correlate(index, emit));
    limitations
}

fn ip_of(entity: &Entity) -> Option<IpAddr> {
    match entity {
        Entity::Indicator(indicator) => indicator.as_ip(),
        _ => None,
    }
}

fn indicator_entity(indicator: &Indicator) -> Entity {
    Entity::Indicator(indicator.clone())
}

fn joined(items: impl IntoIterator<Item = String>) -> String {
    items.into_iter().collect::<Vec<_>>().join(", ")
}

/// At most [`MAX_QUOTED`] items, then "and N more".
fn joined_bounded(items: impl IntoIterator<Item = String>) -> String {
    let all: Vec<String> = items.into_iter().collect();
    let shown = all
        .iter()
        .take(MAX_QUOTED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if all.len() > MAX_QUOTED {
        format!("{shown} and {} more", all.len() - MAX_QUOTED)
    } else {
        shown
    }
}

/// ` (source statuses: cymru failed, rdap timed out)` for an indicator, or
/// nothing if every source run succeeded.
fn source_status_text(index: &EvidenceIndex<'_>, indicator: &Indicator) -> String {
    let statuses: Vec<String> = index
        .unsuccessful_sources(indicator)
        .iter()
        .map(|s| format!("{} {}", s.source(), outcome_label(s.outcome())))
        .collect();
    if statuses.is_empty() {
        String::new()
    } else {
        format!(" (source status: {})", statuses.join(", "))
    }
}

const fn outcome_label(outcome: &sentinel_core::SourceOutcome) -> &'static str {
    use sentinel_core::SourceOutcome as O;
    match outcome {
        O::Succeeded { .. } => "succeeded",
        O::Partial { .. } => "partial",
        O::Unavailable { .. } => "unavailable",
        O::BudgetExhausted { .. } => "not run (budget exhausted)",
        O::Unsupported => "unsupported",
        O::Failed { .. } => "failed",
        O::TimedOut { .. } => "timed out",
    }
}
